{-# LANGUAGE OverloadedStrings #-}
module WebAuthn.Packed where

import Control.Monad (when)
import Crypto.Hash
import Data.ByteString (ByteString)
import qualified Data.ByteArray as BA
import qualified Data.X509 as X509
import qualified Codec.CBOR.Term as CBOR
import qualified Codec.CBOR.Decoding as CBOR
import qualified Data.Map as Map
import WebAuthn.Signature
import WebAuthn.Types

data Stmt = Stmt PubKeyCredAlg ByteString (Maybe (X509.SignedExact X509.Certificate))
  deriving Show

decode :: CBOR.Term -> CBOR.Decoder s Stmt
decode (CBOR.TMap xs) = do
  let m = Map.fromList xs
  CBOR.TInt algc <- Map.lookup (CBOR.TString "alg") m ??? "alg"
  algo <- maybe (fail $ "Packed.decode: alg not supported " <> show algc) return $ pubKeyCredAlgFromInt algc
  CBOR.TBytes sig <- Map.lookup (CBOR.TString "sig") m ??? "sig"
  cert <- case Map.lookup (CBOR.TString "x5c") m of
    Just (CBOR.TList (CBOR.TBytes certBS : _)) ->
      either fail (pure . Just) $ X509.decodeSignedCertificate certBS
    _ -> pure Nothing
  return $ Stmt algo sig cert
  where
    Nothing ??? e = fail e
    Just a ??? _ = pure a
decode _ = fail "Packed.decode: expected a Map"

verify :: Stmt
  -> Maybe PublicKey
  -> ByteString
  -> Digest SHA256
  -> Either VerificationFailure ()
verify (Stmt algo sig cert) mAdPubKey adRaw clientDataHash = do
  let dat = adRaw <> BA.convert clientDataHash
  case cert of
    Just x509 -> do
      let pub = X509.certPubKey $ X509.getCertificate x509
      verifyX509Sig (X509.SignatureALG X509.HashSHA256 X509.PubKeyALG_EC) pub dat sig "Packed"
    Nothing -> do
      adPubKey <- maybe (Left MalformedAuthenticatorData) return mAdPubKey
      when (not $ hasMatchingAlg adPubKey algo) $ Left MalformedAuthenticatorData
      verifySig adPubKey sig dat
