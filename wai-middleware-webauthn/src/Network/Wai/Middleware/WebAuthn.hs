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
  )
  where

import Control.Concurrent
import Control.Monad (forever)
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
import Network.Wai
import qualified Data.HashMap.Strict as HM
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
  , registerKey :: User -> AttestedCredentialData -> IO ()
  }

type StaticKeys = HM.HashMap Identifier [AttestedCredentialData]

staticKeys :: StaticKeys -> Handler
staticKeys authorisedKeys = Handler
  { findCredentials = \ident -> pure
    $ maybe [] Prelude.id
    $ HM.lookup ident authorisedKeys
  , findPublicKey = \cid -> pure $ HM.lookup cid authorisedMap
  , registerKey = \_ _ -> pure ()
  }
  where
    authorisedMap = HM.fromList
      [(cid, (name, pub)) | (name, ks) <- HM.toList authorisedKeys, AttestedCredentialData _ cid pub <- ks]

data Config a = Config
  { handler :: !a
  , endpoint :: !Text
  , origin :: !Origin
  , timeout :: !Double
  , certStore :: !FilePath
  } deriving (Functor, Generic)
instance J.FromJSON a => J.FromJSON (Config a)

defaultConfig :: a -> Config a
defaultConfig a = Config
  { handler = a
  , endpoint = "webauthn"
  , origin = Origin "https" "localhost" (Just 8080)
  , timeout = 86400
  , certStore = "cacert.pem"
  }

requestIdentifier :: Request -> Maybe Identifier
requestIdentifier = fmap (Identifier . T.decodeUtf8) . lookup "Authorization" . requestHeaders

headers :: [Header]
headers = [("Access-Control-Allow-Origin", "*")]

responseJSON :: J.ToJSON a => a -> Response
responseJSON val = responseLBS status200 ((hContentType, "application/json") : headers) $ J.encode val

data RegisterRequest = RegisterRequest
  { response :: AuthenticatorAttestationResponse
  , challenge :: Challenge
  , user :: User
  }
  deriving Generic
instance J.FromJSON RegisterRequest

data VerifyRequest = VerifyRequest
  { credential :: PublicKeyCredential AuthenticatorAssertionResponse
  , challenge :: Challenge
  }
  deriving Generic
instance J.FromJSON VerifyRequest

jsonBody :: J.FromJSON a => (Response -> IO ResponseReceived) -> Request -> ContT ResponseReceived IO a
jsonBody sendResp req = do
  body <- liftIO $ lazyRequestBody req
  ContT $ \k -> case J.eitherDecode body of
    Left err -> sendResp $ responseBuilder status400 headers $ fromString err
    Right a -> k a

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
  vTokens <- newIORef HM.empty
  libJSPath <- getDataFileName "lib.js"
  certificateStore <- X509.readCertificateStore certStore >>= \case
    Nothing -> fail $ "Failed to obtain certification store from " <> certStore
    Just a -> pure a

  _ <- forkIO $ forever $ do
      now <- getMonotonicTime
      atomicModifyIORef' vTokens $ \m -> (HM.filter ((now<) . (+timeout) . snd) m, ())
      threadDelay 10000000

  return $ \app req sendResp -> case pathInfo req of
    x : xs | x == endpoint -> case xs of
      ["lib.js"] -> sendResp $ responseFile status200 headers libJSPath Nothing
      ["challenge"] -> do
        challenge <- generateChallenge 16
        sendResp $ responseJSON challenge
      ["lookup", name] -> findCredentials handler (Identifier name)
        >>= sendResp . responseJSON
      ["register"] -> evalContT $ do
        RegisterRequest{..} <- jsonBody sendResp req
        
        liftIO $ do
          rg <- W.verifyRegistration
            def
              { certificateStore
              , options = def
                { rp = originToRelyingParty origin
                , challenge = challenge
                , user
                }
              , response
              }

          case rg of
            Left e -> sendResp $ responseBuilder status403 headers $ fromString $ show e
            Right (cd, _, _) -> do
              registerKey handler user cd
              sendResp $ responseJSON cd
      ["verify"] -> evalContT $ do
        VerifyRequest{..} <- jsonBody sendResp req
        (name, pub) <- ContT $ \k -> findPublicKey handler credential.id
          >>= maybe (sendResp unauthorised) k
        
        ContT $ \k -> case verifyAssertion def
          { options = def { challenge }
          , relyingParty = originToRelyingParty origin
          , credential
          , credentialPublicKey = pub
          } of
          Left e -> sendResp $ responseBuilder status403 headers $ fromString $ show e
          Right _ -> k ()

        liftIO $ do
          tokenRaw <- getRandomBytes 16
          let token = B.encode tokenRaw
          now <- getMonotonicTime
          atomicModifyIORef' vTokens $ \m -> (HM.insert token (name, now) m, ())
          sendResp $ responseJSON $ T.decodeUtf8 token

      _ -> sendResp $ responseBuilder status404 headers "Not Found"
    _ | (xs, (_, token) : ys) <- break ((=="Authorization") . fst) $ requestHeaders req -> do
      m <- readIORef vTokens
      case HM.lookup token m of
        Nothing -> sendResp unauthorised
        Just (Identifier name, _) -> app (req
          { requestHeaders = ("Authorization", T.encodeUtf8 name) : xs ++ ys }) sendResp
    _ -> app req sendResp
  where
    unauthorised = responseBuilder status403 headers "Unauthorised"
