{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE DeriveFunctor #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Network.Wai.Middleware.WebAuthn
  ( Identifier(..)
  , Handler(..)
  , Config(..)
  , defaultConfig
  , mkMiddleware
  )
  where

import Control.Monad.IO.Class
import Control.Monad.Trans.Cont
import WebAuthn as W
import qualified Data.Aeson as J
import Data.Text (Text)
import Data.Hashable (Hashable)
import Data.String
import Network.Wai
import GHC.Generics (Generic)
import Network.HTTP.Types
import Paths_wai_middleware_webauthn
import qualified Data.X509.CertificateStore as X509
import Network.Wai.Middleware.WebAuthn.Utils

newtype Identifier = Identifier { unIdentifier :: Text }
  deriving (Show, Eq, Ord, J.FromJSON, J.ToJSON, J.FromJSONKey, J.ToJSONKey, Hashable)

data Handler = Handler
  { findCredentials :: Identifier -> IO [AttestedCredentialData]
  -- ^ We don't expect users to have user-friendly interface to enumerate credential IDs at the moment; provide a function to look up a public key from a user name.
  -- cf. https://developers.yubico.com/WebAuthn/WebAuthn_Developer_Guide/Resident_Keys.html
  , findPublicKey :: CredentialId -> IO (Maybe (Identifier, CredentialPublicKey))
  , onAttestation :: User -> AttestedCredentialData -> AttestationStatement -> SignCount -> IO Response
  , onAssertion :: Identifier -> Maybe SignCount -> IO Response
  }

data Config a = Config
  { handler :: !a
  , endpoint :: !Text
  , rpId :: !PublicKeyCredentialRpEntity
  , certStore :: !FilePath
  } deriving (Functor, Generic)
instance J.FromJSON a => J.FromJSON (Config a)

defaultConfig :: a -> Config a
defaultConfig a = Config
  { handler = a
  , endpoint = "webauthn"
  , rpId = "localhost"
  , certStore = "cacert.pem"
  }

data AttestationRequest = AttestationRequest
  { response :: AuthenticatorAttestationResponse
  , challenge :: Challenge
  , user :: User
  }
  deriving Generic
instance J.FromJSON AttestationRequest

data AssertionRequest = AssertionRequest
  { credential :: PublicKeyCredential AuthenticatorAssertionResponse
  , challenge :: Challenge
  }
  deriving Generic
instance J.FromJSON AssertionRequest

-- | Create a web authentication middleware.
--
-- * @GET /webauthn/lib.js@ returns a JavaScript library containing helper functions.
--
mkMiddleware :: Config Handler -> IO Middleware
mkMiddleware Config{..} = do
  libJSPath <- getDataFileName "lib.js"
  certificateStore <- X509.readCertificateStore certStore >>= \case
    Nothing -> fail $ "Failed to obtain certification store from " <> certStore
    Just a -> pure a

  return $ \app req sendResp -> case pathInfo req of
    x : xs | x == endpoint -> case xs of
      ["lib.js"] -> sendResp $ responseFile status200 headers libJSPath Nothing
      ["challenge"] -> do
        challenge <- newChallengeDef
        sendResp $ responseJSON challenge
      ["lookup", name] -> findCredentials handler (Identifier name)
        >>= sendResp . responseJSON
      ["attest"] -> evalContT $ do
        AttestationRequest{..} <- jsonBody sendResp req

        liftIO $ do
          rg <- W.verifyAttestation
            def
              { certificateStore
              , options = def
                { rp = rpId
                , challenge = challenge
                , user
                }
              , response
              }

          case rg of
            Left e -> sendResp $ responseBuilder status403 headers $ fromString $ show e
            Right (cd, st, count) -> onAttestation handler user cd st count >>= sendResp
      ["assert"] -> evalContT $ do
        AssertionRequest{..} <- jsonBody sendResp req
        (name, pub) <- ContT $ \k -> findPublicKey handler credential.id
          >>= maybe (sendResp unauthorised) k

        liftIO $ case verifyAssertion def
          { options = def { challenge }
          , relyingParty = rpId
          , credential
          , credentialPublicKey = pub
          } of
          Left e -> sendResp $ responseBuilder status403 headers $ fromString $ show e
          Right count -> onAssertion handler name count >>= sendResp

      _ -> sendResp $ responseBuilder status404 headers "Not Found"
    _ -> app req sendResp
