{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Network.Wai.Middleware.WebAuthn where

import Control.Concurrent
import Control.Monad (forever)
import Crypto.Random (getRandomBytes)
import Web.WebAuthn as W
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
import qualified Codec.Serialise as CBOR

data AuthorisedKey = AuthorisedKey
  { credentialId :: CredentialId
  , publicKey :: CredentialPublicKey
  } deriving Generic
instance J.FromJSON AuthorisedKey
instance J.ToJSON AuthorisedKey

newtype Identifier = Identifier { unIdentifier :: Text }
  deriving (Show, Eq, Ord, J.FromJSON, J.ToJSON, J.FromJSONKey, J.ToJSONKey, Hashable)

data Config = Config
  { authorisedKeys :: HM.HashMap Identifier AuthorisedKey
  , endpoint :: Text
  , origin :: Origin
  , timeout :: Double
  } deriving Generic
instance J.FromJSON Config

defaultConfig :: Config
defaultConfig = Config
  { authorisedKeys = mempty
  , endpoint = "webauthn"
  , origin = Origin "https" "localhost" 8080
  , timeout = 86400
  }

requestIdentifier :: Request -> Maybe Identifier
requestIdentifier = fmap (Identifier . T.decodeUtf8) . lookup "Authorization" . requestHeaders

-- | Create a web authentication middleware.
--
-- * @GET /webauthn/lib.js@ returns a JavaScript library containing helper functions.
--
-- If it receives a request containing an Authorization: TOKEN header, it checks
-- if TOKEN is valid. If so, replaces TOKEN by the corresponding 'Identifier'.
-- Otherwise, returns 403.
mkMiddleware :: Config -> IO Middleware
mkMiddleware Config{..} = do
  vTokens <- newIORef HM.empty
  libJSPath <- getDataFileName "lib.js"
  let authorisedMap = HM.fromList
        [(cid, (name, pub)) | (name, AuthorisedKey cid pub) <- HM.toList authorisedKeys]
  let theRelyingParty = W.defaultRelyingParty origin

  _ <- forkIO $ forever $ do
      now <- getMonotonicTime
      atomicModifyIORef' vTokens $ \m -> (HM.filter ((<now) . (+timeout) . snd) m, ())
      threadDelay 10000000

  return $ \app req sendResp -> case pathInfo req of
    x : xs | x == endpoint -> case xs of
      ["lib.js"] -> sendResp $ responseFile status200 [] libJSPath Nothing -- TODO data-files
      ["challenge"] -> do
        challenge <- generateChallenge 16
        sendResp $ responseLBS status200 [] $ J.encode challenge
      ["lookup", name] -> do
        sendResp $ case HM.lookup (Identifier name) authorisedKeys of
          Nothing -> responseBuilder status404 [] "Not found"
          Just (AuthorisedKey cid _) -> responseLBS status200 [] $ J.encode cid
      ["register"] -> do
        body <- lazyRequestBody req
        let (cdj, att, challenge) = CBOR.deserialise body
        case registerCredential challenge theRelyingParty Nothing False cdj att of
          Left e -> sendResp $ responseBuilder status403 [] $ fromString $ show e
          Right (cid, pub) -> sendResp $ responseLBS status200 [] $ J.encode $ AuthorisedKey cid pub
      ["verify"] -> do
        body <- lazyRequestBody req
        let (cid, cdj, ad, sig, challenge) = CBOR.deserialise body
        case HM.lookup cid authorisedMap of
          Just (name, pub) -> case verify challenge theRelyingParty Nothing False cdj ad sig pub of
            Left e -> sendResp $ responseBuilder status403 [] $ fromString $ show e
            Right _ -> do
              tokenRaw <- getRandomBytes 16
              let token = B.encode tokenRaw
              now <- getMonotonicTime
              atomicModifyIORef' vTokens $ \m -> (HM.insert token (name, now) m, ())
              sendResp $ responseLBS status200 [] $ J.encode $ T.decodeUtf8 token
          Nothing -> sendResp unauthorised
      _ -> sendResp $ responseBuilder status404 [] "Not Found"
    _ | (xs, (_, token) : ys) <- break ((=="Authorization") . fst) $ requestHeaders req -> do
      m <- readIORef vTokens
      case HM.lookup token m of
        Nothing -> sendResp unauthorised
        Just (Identifier name, _) -> app (req
          { requestHeaders = ("Authorization", T.encodeUtf8 name) : xs ++ ys }) sendResp
    _ -> app req sendResp
  where
    unauthorised = responseBuilder status403 [] "Unauthorised"
