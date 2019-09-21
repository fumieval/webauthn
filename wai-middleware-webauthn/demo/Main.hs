{-# LANGUAGE OverloadedStrings #-}
module Main where

import qualified Network.Wai.Middleware.WebAuthn as WebAuthn
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

main :: IO ()
main = do
  config <- getDataFileName "config.yaml" >>= Yaml.decodeFileThrow
  mid <- WebAuthn.mkMiddleware config
  path <- getDataFileName "index.html"
  pathCert <- getDataFileName "certificate.pem"
  pathKey <- getDataFileName "key.pem"
  runTLS (tlsSettings pathCert pathKey) (setPort 8080 defaultSettings) { settingsHTTP2Enabled = False }
    $ mid $ \req sendResp -> case pathInfo req of
      [] -> sendResp $ responseFile status200 [] path Nothing
      ["api"] -> case WebAuthn.requestIdentifier req of
        Nothing -> sendResp $ responseLBS status401 [] "Authorisation required"
        Just name -> sendResp $ responseLBS status200 [] $ J.encode name
      _ -> sendResp $ responseLBS status404 [] "Not found"
