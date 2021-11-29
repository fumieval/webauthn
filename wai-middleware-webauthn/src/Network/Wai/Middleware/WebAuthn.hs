{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE DeriveFunctor #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Network.Wai.Middleware.WebAuthn
  ( Identifier(..)
  , Handler(..)
  , StaticKeys
  , staticKeys
  , Config(..)
  , defaultConfig
  , requestIdentifier
  , mkMiddleware
  , volatileTokenAuthorisation
  )
  where

import Control.Concurrent
import Control.Monad (forever, unless)
import Control.Monad.IO.Class
import Control.Monad.Trans.Cont
import Crypto.Random (getRandomBytes)
import WebAuthn as W
import qualified Data.Aeson as J
import Data.Text (Text)
import Data.Hashable (Hashable)
import Data.IORef
import Data.String
import qualified Data.Text.Encoding as T
import qualified Data.ByteString.Base64 as B
import qualified Data.ByteString.Lazy as BL
import Network.Wai
import qualified Data.Map.Strict as M
import GHC.Generics (Generic)
import GHC.Clock
import Network.HTTP.Types
import Paths_wai_middleware_webauthn
import qualified Data.X509.CertificateStore as X509

newtype Identifier = Identifier { unIdentifier :: Text }
  deriving (Show, Eq, Ord, J.FromJSON, J.ToJSON, J.FromJSONKey, J.ToJSONKey, Hashable)

data Handler = Handler
  { findCredentials :: Identifier -> IO [AttestedCredentialData]
  , findPublicKey :: CredentialId -> IO (Maybe (Identifier, CredentialPublicKey))
  , onAttestation :: User -> AttestedCredentialData -> AttestationStatement -> SignCount -> IO Response
  , onAssertion :: Identifier -> Maybe SignCount -> IO Response
  }

type StaticKeys = M.Map Identifier [AttestedCredentialData]

staticKeys :: StaticKeys -> Handler
staticKeys authorisedKeys = Handler
  { findCredentials = \ident -> pure
    $ maybe [] Prelude.id
    $ M.lookup ident authorisedKeys
  , findPublicKey = \cid -> pure $ M.lookup cid authorisedMap
  , onAttestation = \_ _ _ _ -> pure $ responseLBS status200 [] "ok"
  , onAssertion = \_ _ -> pure $ responseLBS status200 [] "ok"
  }
  where
    authorisedMap = M.fromList
      [(cid, (name, pub)) | (name, ks) <- M.toList authorisedKeys, AttestedCredentialData _ cid pub <- ks]

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

requestIdentifier :: Request -> Maybe Identifier
requestIdentifier = fmap (Identifier . T.decodeUtf8) . lookup "Authorization" . requestHeaders

headers :: [Header]
headers = [("Access-Control-Allow-Origin", "*")]

responseJSON :: J.ToJSON a => a -> Response
responseJSON val = responseLBS status200 ((hContentType, "application/json") : headers) $ J.encode val

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

jsonBody :: J.FromJSON a => (Response -> IO ResponseReceived) -> Request -> ContT ResponseReceived IO a
jsonBody sendResp req = do
  body <- liftIO $ lazyRequestBody req
  ContT $ \k -> case J.eitherDecode body of
    Left err -> sendResp $ responseBuilder status400 headers $ fromString err
    Right a -> k a

-- | An opinionated authorisation mechanism for demo
-- On verified attestation, it returns AttestedCredentialData in JSON.
-- On verified assertion, it returns a token as plain text and stores it in memory.
volatileTokenAuthorisation :: (String -> IO ()) -- ^ logger
  -> Double -- timeout in seconds
  -> IO (Handler -> Handler, Middleware)
volatileTokenAuthorisation logger timeout = do
  vTokens <- newIORef M.empty

  -- expire tokens
  _ <- forkIO $ forever $ do
      now <- getMonotonicTime
      expired <- atomicModifyIORef' vTokens $ M.partition ((now<) . (+timeout) . snd)
      unless (null expired) $ logger $ show (M.keys expired) <> " expired"
      threadDelay $ 10 * 1000 * 1000
  let onAttestation user acd _ _ = do
        logger $ show user <> " registered"
        pure $ responseJSON acd
  let onAssertion name _ = do
        tokenRaw <- getRandomBytes 16
        let token = B.encode tokenRaw
        now <- getMonotonicTime
        atomicModifyIORef' vTokens $ \m -> (M.insert token (name, now) m, ())
        logger $ show name <> " logged in"
        pure $ responseLBS status200 [] $ BL.fromStrict token

  let mid app req sendResp = case req of
        _ | (xs, (_, token) : ys) <- break ((=="Authorization") . fst) $ requestHeaders req -> do
          m <- readIORef vTokens
          case M.lookup token m of
            Nothing -> sendResp unauthorised
            Just (Identifier name, _) -> app (req
              { requestHeaders = ("Authorization", T.encodeUtf8 name) : xs ++ ys }) sendResp
        _ -> app req sendResp

  pure (\h -> h { onAttestation, onAssertion }, mid)

-- | Create a web authentication middleware.
--
-- * @GET /webauthn/lib.js@ returns a JavaScript library containing helper functions.
--
-- If it receives a request containing an Authorization: TOKEN header, it checks
-- if TOKEN is valid. If so, replaces TOKEN by the corresponding 'Identifier'.
-- Otherwise, returns 403.
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

unauthorised :: Response
unauthorised = responseBuilder status403 headers "Unauthorised"
