{-# LANGUAGE OverloadedStrings, TypeApplications #-}
module Main where
import Network.Wai.Handler.Warp
import Network.Wai.Handler.WarpTLS
import Network.Wai
import Web.WebAuthn as W
import Network.HTTP.Types
import qualified Data.Aeson as J
import qualified Network.Wai.Middleware.Static as S
import Data.Text (Text)
import Control.Concurrent.STM
import qualified Data.HashMap.Strict as HM
import qualified Codec.Serialise as CBOR

theRelyingParty :: RelyingParty
theRelyingParty = defaultRelyingParty (Origin "https" "localhost" 8080)

main = do
  vChallenges <- newTVarIO HM.empty
  runTLS (tlsSettings "certificate.pem" "key.pem") (setPort 8080 defaultSettings)
    $ S.staticPolicy (S.addBase "app/static")
      $ \req sendResp -> case pathInfo req of
      ["challenge"] -> do
        challenge <- generateChallenge 16
        atomically $ modifyTVar' vChallenges $ HM.insert challenge ()
        sendResp $ responseLBS status200 [] $ J.encode challenge
      ["verify"] -> do
        body <- lazyRequestBody req
        case CBOR.deserialiseOrFail body of
          Left e -> sendResp $ responseLBS status400 [] "Bad request"
          Right (challenge, att, cdj) -> do
            challenge' <- atomically $ do
              m <- readTVar vChallenges
              writeTVar vChallenges $! HM.delete challenge m
              return $! HM.lookup challenge m
            case challenge' of
              Nothing -> sendResp $ responseLBS status403 [] "Access denied"
              Just _ -> case registerCredential challenge theRelyingParty Nothing False (AuthenticatorAttestationResponse att cdj) of
                Left e -> sendResp $ responseLBS status403 [] $ J.encode $ show e
                Right _ -> sendResp $ responseLBS status200 [] "Success"
      [] -> sendResp $ responseFile status200 [] "app/demo.html" Nothing
      e -> do
        sendResp $ responseLBS status404 [] "Not found"
