{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
module WebAuthn.AndroidSafetyNet (
  decode,
  verify
) where

import qualified Data.Aeson as J
import Data.ByteString (ByteString)
import Data.Text (pack)
import Data.Text.Encoding (encodeUtf8)
import WebAuthn.Types
import qualified Codec.CBOR.Term as CBOR
import qualified Codec.CBOR.Decoding as CBOR
import qualified Data.Map as Map
import Data.Maybe (fromMaybe)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Lazy as BL hiding (pack)
import qualified Data.ByteArray as BA
import qualified Data.ByteString.Base64 as Base64
import qualified Data.ByteString.Base64.URL as Base64URL
import qualified Data.X509 as X509
import qualified Data.X509.Validation as X509
import qualified Data.X509.CertificateStore as X509
import Crypto.Hash (Digest, hash)
import Crypto.Hash.Algorithms (SHA256(..))
import Control.Monad.IO.Class (MonadIO, liftIO)
import Control.Monad.Trans.Except (ExceptT(..), throwE)
import Data.Char (ord)
import Data.Bifunctor (first)
import WebAuthn.Signature (verifyX509Sig)
import Control.Error.Util (hoistEither, failWith)
import Time.Types (DateTime)

decode :: CBOR.Term -> CBOR.Decoder s StmtSafetyNet
decode (CBOR.TMap xs) = do
  let m = Map.fromList xs
  let CBOR.TBytes response = fromMaybe (CBOR.TString "response") (Map.lookup (CBOR.TString "response") m)
  case B.split (fromIntegral . ord $ '.') response of
    (h : p : s : _) -> StmtSafetyNet (Base64ByteString h) (Base64ByteString p) (Base64URL.decodeLenient s) <$> getCertificateChain h
    _ -> fail "decodeSafetyNet: response was not a JWT"
decode _ = fail "decodeSafetyNet: expected a Map"

getCertificateChain :: MonadFail m => ByteString -> m X509.CertificateChain
getCertificateChain h = do
  let bs = BL.fromStrict $ Base64URL.decodeLenient h
  case J.eitherDecode bs of
    Left e -> fail ("android-safetynet: Response header decode failed: " <> show e)
    Right (jth :: JWTHeader) -> do
      if jth.alg /= "RS256" then fail ("android-safetynet: Unknown signature alg " <> show jth.alg) else do
        let x5cbs = Base64.decodeLenient . encodeUtf8 <$> jth.x5c
        case X509.decodeCertificateChain (X509.CertificateChainRaw x5cbs) of
          Left e -> fail ("Certificate chain decode failed: " <> show e)
          Right cc -> pure cc

verify :: MonadIO m => X509.CertificateStore
  -> StmtSafetyNet
  -> B.ByteString
  -> Digest SHA256
  -> Maybe DateTime
  -> ExceptT VerificationFailure m ()
verify cs sf authDataRaw clientDataHash maybeNow = do
  verifyJWS
  let dat = authDataRaw <> BA.convert clientDataHash
  as :: AndroidSafetyNet <- extractAndroidSafetyNet
  let nonceCheck = Base64.encode (BA.convert (hash dat :: Digest SHA256))
  if nonceCheck /= B8.pack as.nonce then throwE NonceCheckFailure else pure ()
  where
    extractAndroidSafetyNet = ExceptT $ pure $ first JSONDecodeError
      $ J.eitherDecode (BL.fromStrict . Base64URL.decodeLenient $ unBase64ByteString sf.payload)
    verifyJWS = do
      let dat = unBase64ByteString sf.header <> "." <> unBase64ByteString sf.payload
      res <- liftIO $ validateCert cs (X509.exceptionValidationCache []) ("attest.android.com", "") sf.certificates
      case res of
        [] -> pure ()
        es -> throwE (MalformedX509Certificate (pack $ show es))
      cert <- failWith MalformedPublicKey $ signCert sf.certificates
      let pub = X509.certPubKey $ X509.getCertificate cert
      hoistEither $ verifyX509Sig rs256 pub dat sf.signature_ "AndroidSafetyNet"
    signCert (X509.CertificateChain cschain) = headMay cschain
    validateCert = X509.validate X509.HashSHA256 X509.defaultHooks (X509.defaultChecks { X509.checkAtTime = maybeNow})

rs256 :: X509.SignatureALG
rs256 = X509.SignatureALG X509.HashSHA256 X509.PubKeyALG_RSA

headMay :: [a] -> Maybe a
headMay [] = Nothing
headMay (x : _) = Just x