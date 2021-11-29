{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
module Main where

import Data.Aeson qualified as J
import Data.Yaml qualified as Yaml
import Network.HTTP.Types
import Network.Wai
import Network.Wai.Handler.Warp
import Network.Wai.Handler.Warp.Internal
import Network.Wai.Handler.WarpTLS
import Network.Wai.Middleware.WebAuthn.Token qualified as WebAuthn
import Paths_demo
import System.Environment

main :: IO ()
main = do
  config <- getDataFileName "config.yaml" >>= Yaml.decodeFileThrow

  middleware <- WebAuthn.volatileTokenAuthorisation
    putStrLn -- logger function
    60 -- lifetime of tokens in seconds
    $ WebAuthn.staticKeys -- convert a list of public keys to a Handler
      <$> config

  application <- mkApplication

  startServer $ middleware application

-- | dead simple application which returns the user name
mkApplication :: IO Application
mkApplication = do
  path <- getDataFileName "index.html"
  pure $ \req sendResp -> case pathInfo req of
    [] -> sendResp $ responseFile status200 [] path Nothing
    -- Obtain the user name using requestIdentifier
    ["api"] -> case WebAuthn.requestIdentifier req of
      Nothing -> sendResp $ responseLBS status401 [] "Authorisation required"
      Just name -> sendResp $ responseLBS status200 [] $ J.encode name
    _ -> sendResp $ responseLBS status404 [] "Not found"

startServer :: Application -> IO ()
startServer app = do
  pathCert <- getDataFileName "certificate.pem"
  pathKey <- getDataFileName "key.pem"
  port <- maybe 8080 read <$> lookupEnv "PORT"
  putStrLn $ "Listening on port " <> show port
  let cfg = setPort port defaultSettings
  runTLS (tlsSettings pathCert pathKey) cfg { settingsHTTP2Enabled = False } app
