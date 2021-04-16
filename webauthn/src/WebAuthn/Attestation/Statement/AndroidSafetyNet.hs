module WebAuthn.Attestation.Statement.AndroidSafetyNet where

import qualified Data.Aeson as AE
import Data.ByteString (ByteString)
import Data.Text (pack)
import Data.Text.Encoding (encodeUtf8)
import qualified Codec.CBOR.Term as CBOR
import qualified Codec.CBOR.Decoding as CBOR
import qualified Data.Map as Map
import Data.Maybe (fromMaybe)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL hiding (pack)
import qualified Data.ByteString.Lazy.Char8 as BL
import qualified Data.ByteArray as BA
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Base64.URL as B64URL
import qualified Data.X509 as X509
import qualified Data.X509.Validation as X509
import qualified Data.X509.CertificateStore as X509
import Crypto.Hash (Digest, hash)
import Crypto.Hash.Algorithms (SHA256(..))
import Control.Monad.IO.Class (MonadIO, liftIO)
import Control.Monad.Trans.Except (ExceptT(..), except, throwE)
import Data.Char (ord)
import Data.Bifunctor (first)
import Control.Error.Util (failWith)

import WebAuthn.Signature (verifyX509Sig)
import WebAuthn.Types


decode :: CBOR.Term -> CBOR.Decoder s StmtSafetyNet
decode (CBOR.TMap xs) = do
  let m = Map.fromList xs
      CBOR.TBytes response = fromMaybe (CBOR.TString "response") (Map.lookup (CBOR.TString "response") m)
  case B.split (fromIntegral . ord $ '.') response of 
    (h : p : s : _) -> StmtSafetyNet (Base64UrlByteString h) (Base64UrlByteString p) (B64URL.decodeBase64Lenient s) <$> getCertificateChain h
    _ -> fail "decodeSafetyNet: response was not a JWT"
decode _ = fail "decodeSafetyNet: expected a Map"

getCertificateChain :: MonadFail m => ByteString -> m X509.CertificateChain
getCertificateChain h = do
  let bs = BL.fromStrict $ B64URL.decodeBase64Lenient h
  case AE.eitherDecode bs of
    Left e -> fail ("android-safetynet: Response header decode failed: " <> show e)
    Right jth -> do
      if alg (jth ::JWTHeader) /= "RS256" then fail ("android-safetynet: Unknown signature alg " <> show (alg (jth :: JWTHeader))) else do
        let x5cbs = B64.decodeBase64Lenient . encodeUtf8 <$> x5c jth
        case X509.decodeCertificateChain (X509.CertificateChainRaw x5cbs) of
          Left e -> fail ("Certificate chain decode failed: " <> show e)
          Right cc -> pure cc

verify :: forall m. MonadIO m
  => X509.CertificateStore 
  -> StmtSafetyNet 
  -> B.ByteString
  -> Digest SHA256
  -> ExceptT VerificationFailure m ()
verify trustAnchors sf authDataRaw clientDataHash = do
  verifyJWS
  let dat = authDataRaw <> BA.convert clientDataHash
  as <- extractAndroidSafetyNet
  let nonceCheck = B64.encodeBase64' (BA.convert (hash dat :: Digest SHA256))
  if nonceCheck /= BL.toStrict (BL.pack (nonce as)) then throwE NonceCheckFailure else pure ()
  where
    extractAndroidSafetyNet = ExceptT $ pure $ first JSONDecodeError 
      $ AE.eitherDecode (BL.fromStrict . B64URL.decodeBase64Lenient . unBase64UrlByteString $ payload sf)

    verifyJWS :: ExceptT VerificationFailure m ()
    verifyJWS = do
      let dat = unBase64UrlByteString (header sf) <> "." <> unBase64UrlByteString (payload sf)
      res <- liftIO $ X509.validateDefault trustAnchors (X509.exceptionValidationCache []) ("attest.android.com", "") (certificates sf)
      case res of
        [] -> pure ()
        es -> throwE (MalformedX509Certificate (pack $ show es))
      cert <- failWith MalformedPublicKey (signCert $ certificates sf)
      let pub = X509.certPubKey $ X509.getCertificate cert
      except $ verifyX509Sig rs256 pub dat (signature (sf :: StmtSafetyNet)) "AndroidSafetyNet"

    signCert (X509.CertificateChain cschain) = headMay cschain

rs256 :: X509.SignatureALG
rs256 = X509.SignatureALG X509.HashSHA256 X509.PubKeyALG_RSA  

headMay :: [a] -> Maybe a
headMay [] = Nothing
headMay (x : _) = Just x
