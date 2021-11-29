{-# LANGUAGE NamedFieldPuns #-}
module Network.Wai.Middleware.WebAuthn.Token
  ( StaticKeys
  , staticKeys
  , requestIdentifier
  , volatileTokenAuthorisation
  ) where

import Control.Concurrent
import Control.Monad (forever, unless)
import Crypto.Random (getRandomBytes)
import WebAuthn as W
import Data.IORef
import qualified Data.Text.Encoding as T
import qualified Data.ByteString.Base64 as B
import qualified Data.ByteString.Lazy as BL
import Network.Wai
import qualified Data.Map.Strict as M
import GHC.Clock
import Network.HTTP.Types
import Network.Wai.Middleware.WebAuthn
import Network.Wai.Middleware.WebAuthn.Utils

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

requestIdentifier :: Request -> Maybe Identifier
requestIdentifier = fmap (Identifier . T.decodeUtf8) . lookup "Authorization" . requestHeaders

-- | An opinionated authorisation mechanism for demo
-- On verified attestation, it returns AttestedCredentialData in JSON.
-- On verified assertion, it returns a token as plain text and stores it in memory.
-- As long as the token is available, the middleware replaces the `Authorization: [token]` header with `Authorization: [Identifier]`.
volatileTokenAuthorisation :: (String -> IO ()) -- ^ logger
  -> Double -- timeout in seconds
  -> Config Handler
  -> IO Middleware
volatileTokenAuthorisation logger timeout config = do
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

  auth <- mkMiddleware $ (\h -> h { onAttestation, onAssertion }) <$> config

  pure (mid . auth)
