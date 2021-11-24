{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
module WebAuthn.Attestation.Statement.AndroidSafetyNet (
  Stmt,
  decode,
  verify
) where

import Codec.CBOR.Decoding qualified as CBOR
import Codec.CBOR.Term qualified as CBOR
import Control.Error.Util (failWith)
import Control.Monad.IO.Class (MonadIO, liftIO)
import Control.Monad.Trans.Except (ExceptT(..), except, throwE)
import Crypto.Hash (Digest, hash)
import Crypto.Hash.Algorithms (SHA256(..))
import Data.Aeson (FromJSON)
import Data.Aeson qualified as AE
import Data.Bifunctor (first)
import Data.ByteArray qualified as BA
import Data.ByteString (ByteString)
import Data.ByteString qualified as B
import Data.ByteString.Base64 qualified as B64
import Data.ByteString.Base64.URL qualified as B64URL
import Data.ByteString.Char8 qualified as B8
import Data.ByteString.Lazy qualified as BL hiding (pack)
import Data.Char (ord)
import Data.Map qualified as Map
import Data.Text (Text, pack)
import Data.Text.Encoding (encodeUtf8)
import Data.X509 qualified as X509
import Data.X509.CertificateStore qualified as X509
import Data.X509.Validation qualified as X509
import GHC.Generics (Generic)
import Time.Types (DateTime)
import WebAuthn.Signature (verifyX509Sig)
import WebAuthn.Types

data AndroidSafetyNet = AndroidSafetyNet
  { timestampMs :: Integer
  , nonce :: [Char]
  , apkPackageName :: Text
  , apkCertificateDigestSha256 :: [Text]
  , ctsProfileMatch :: Bool
  , basicIntegrity :: Bool
  } deriving stock (Show, Generic)
    deriving anyclass (FromJSON)

data Stmt = Stmt
  { header :: Base64UrlByteString
  , payload :: Base64UrlByteString
  , signature :: ByteString
  , certificates :: X509.CertificateChain
  } deriving stock (Show)

data JWTHeader = JWTHeader
  { alg :: Text
  , x5c :: [Text]
  } deriving stock (Show, Generic)
    deriving anyclass (FromJSON)

decode :: CBOR.Term -> CBOR.Decoder s Stmt
decode (CBOR.TMap xs) = do
  let m = Map.fromList xs
  response <- case Map.lookup (CBOR.TString "response") m of
    Nothing -> fail "StmySafetyNet: Missing response"
    Just (CBOR.TBytes bs) -> pure bs
    Just term -> fail $ "StmySafetyNet: Expecting TBytes but got " <> show term
  case B.split (fromIntegral . ord $ '.') response of
    (h : p : s : _) -> Stmt (Base64UrlByteString h) (Base64UrlByteString p) (B64URL.decodeLenient s) <$> getCertificateChain h
    _ -> fail "decodeSafetyNet: response was not a JWT"
decode _ = fail "decodeSafetyNet: expected a Map"

getCertificateChain :: MonadFail m => ByteString -> m X509.CertificateChain
getCertificateChain h = do
  let bs = BL.fromStrict $ B64URL.decodeLenient h
  case AE.eitherDecode bs of
    Left e -> fail ("android-safetynet: Response header decode failed: " <> show e)
    Right (jth :: JWTHeader) -> do
      if jth.alg /= "RS256" then fail ("android-safetynet: Unknown signature alg " <> show jth.alg) else do
        let x5cbs = B64.decodeLenient . encodeUtf8 <$> jth.x5c
        case X509.decodeCertificateChain (X509.CertificateChainRaw x5cbs) of
          Left e -> fail ("Certificate chain decode failed: " <> show e)
          Right cc -> pure cc

verify :: forall m. MonadIO m
  => X509.CertificateStore 
  -> Stmt 
  -> B.ByteString
  -> Digest SHA256
  -> Maybe DateTime
  -> ExceptT VerificationFailure m ()
verify trustAnchors sf@Stmt{signature = sig} authDataRaw clientDataHash maybeNow = do
  verifyJWS
  let dat = authDataRaw <> BA.convert clientDataHash
  as :: AndroidSafetyNet <- extractAndroidSafetyNet
  let nonceCheck = B64.encode (BA.convert (hash dat :: Digest SHA256))
  if nonceCheck /= B8.pack as.nonce then throwE NonceCheckFailure else pure ()
  where
    extractAndroidSafetyNet = ExceptT $ pure $ first JSONDecodeError 
      $ AE.eitherDecode $ BL.fromStrict $ B64URL.decodeLenient $ unBase64UrlByteString sf.payload

    verifyJWS :: ExceptT VerificationFailure m ()
    verifyJWS = do
      let dat = unBase64UrlByteString sf.header <> "." <> unBase64UrlByteString sf.payload
      res <- liftIO $ validateCert trustAnchors (X509.exceptionValidationCache []) ("attest.android.com", "") sf.certificates
      case res of
        [] -> pure ()
        es -> throwE (MalformedX509Certificate (pack $ show es))
      cert <- failWith MalformedPublicKey $ signCert sf.certificates
      let pub = X509.certPubKey $ X509.getCertificate cert
      except $ verifyX509Sig rs256 pub dat sig "AndroidSafetyNet"

    signCert (X509.CertificateChain cschain) = headMay cschain
    validateCert = X509.validate X509.HashSHA256 X509.defaultHooks (X509.defaultChecks { X509.checkAtTime = maybeNow})

rs256 :: X509.SignatureALG
rs256 = X509.SignatureALG X509.HashSHA256 X509.PubKeyALG_RSA

headMay :: [a] -> Maybe a
headMay [] = Nothing
headMay (x : _) = Just x
