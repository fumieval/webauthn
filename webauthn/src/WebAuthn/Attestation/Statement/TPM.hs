{-# LANGUAGE OverloadedStrings #-}
module WebAuthn.Attestation.Statement.TPM where

import Data.ByteString (ByteString)
import Crypto.Hash (Digest, SHA256)
import qualified Data.X509 as X509
import qualified Codec.CBOR.Term as CBOR
import qualified Codec.CBOR.Decoding as CBOR
import qualified Data.Map as Map
import WebAuthn.Types (VerificationFailure(..), AuthenticatorData)
import WebAuthn.Signature (verifyX509Sig)

data Stmt = Stmt Int ByteString (X509.SignedExact X509.Certificate) ByteString deriving Show

decode :: CBOR.Term -> CBOR.Decoder s Stmt
decode (CBOR.TMap xs) = do
  let m = Map.fromList xs
  CBOR.TInt alg <- Map.lookup (CBOR.TString "alg") m ??? "alg"
  CBOR.TBytes sig <- Map.lookup (CBOR.TString "sig") m ??? "sig"
  CBOR.TList (CBOR.TBytes certBS : _) <- Map.lookup (CBOR.TString "x5c") m ??? "x5c"
  aikCert <- either fail pure $ X509.decodeSignedCertificate certBS
  CBOR.TBytes certInfo <- Map.lookup (CBOR.TString "certInfo") m ??? "certInfo"
  -- pubArea <- Map.lookup (CBOR.TString "pubArea") ?? "pubArea"
  return $ Stmt alg sig aikCert certInfo
  where
    Nothing ??? e = fail e
    Just a ??? _ = pure a
decode _ = fail "TPM.decode: expected a Map"

verify :: Stmt
  -> AuthenticatorData
  -> ByteString
  -> Digest SHA256
  -> Either VerificationFailure ()
verify (Stmt alg sig x509 certInfo) _ad _adRaw _clientDataHash = do
  -- TODO Verify that the public key specified by the parameters and unique fields of pubArea is identical to the credentialPublicKey in the attestedCredentialData in authenticatorData.
  let pub = X509.certPubKey $ X509.getCertificate x509
  -- let attToBeSigned = adRaw <> BA.convert clientDataHash
  -- https://www.iana.org/assignments/cose/cose.xhtml#algorithms
  case alg of
    -65535 -> verifyX509Sig (X509.SignatureALG X509.HashSHA1 X509.PubKeyALG_RSA) pub certInfo sig "TPM"
    _ -> Left $ UnsupportedAlgorithm alg
