{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
module Main where

import WebAuthn.Types (Origin(..))
import qualified Network.Wai.Middleware.WebAuthn.Token as WebAuthn
import Network.Wai.Handler.Warp
import Network.Wai.Handler.Warp.Internal
import Network.Wai.Handler.WarpTLS
import Network.Wai
import Network.HTTP.Types
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import qualified Data.Yaml as Yaml
import qualified Data.Aeson as J
import Paths_demo
import System.Environment

main :: IO ()
main = do
  config <- getDataFileName "config.yaml" >>= Yaml.decodeFileThrow

  -- Initialise the authorisation logic. Creates a function that updates the handler
  middleware <- WebAuthn.volatileTokenAuthorisation putStrLn 60
    $ WebAuthn.staticKeys <$> config

  path <- getDataFileName "index.html"
  -- dead simple application which returns the user name
  let application req sendResp = case pathInfo req of
        [] -> sendResp $ responseFile status200 [] path Nothing
        ["api"] -> case WebAuthn.requestIdentifier req of
          Nothing -> sendResp $ responseLBS status401 [] "Authorisation required"
          Just name -> sendResp $ responseLBS status200 [] $ J.encode name
        _ -> sendResp $ responseLBS status404 [] "Not found"

  pathCert <- getDataFileName "certificate.pem"
  pathKey <- getDataFileName "key.pem"
  port <- maybe 8080 read <$> lookupEnv "PORT"
  putStrLn $ "Listening on port " <> show port
  let cfg = setPort port defaultSettings
  runTLS (tlsSettings pathCert pathKey) cfg { settingsHTTP2Enabled = False }
    $ middleware application