{-# LANGUAGE OverloadedStrings #-}
-- | 8.3. TPM Attestation Statement Format
--
-- Work in progress. Do not use.
module WebAuthn.Attestation.Statement.TPM where

import Data.ByteString (ByteString)
import Crypto.Hash (Digest, SHA256)
import qualified Data.X509 as X509
import qualified Codec.CBOR.Term as CBOR
import qualified Codec.CBOR.Decoding as CBOR
import qualified Data.Map as Map

import WebAuthn.Types (VerificationFailure(..), AuthenticatorData)
import WebAuthn.Signature (verifyX509Sig)


data Stmt = Stmt
  { alg :: Int
  , x5c :: X509.SignedExact X509.Certificate
  , sig :: ByteString
  , certInfo :: ByteString
  , pubArea :: ByteString
  } deriving stock (Show)

decode :: CBOR.Term -> CBOR.Decoder s Stmt
decode (CBOR.TMap xs) = do
  let m = Map.fromList xs
  CBOR.TInt alg <- Map.lookup (CBOR.TString "alg") m ??? "alg"
  CBOR.TBytes sig <- Map.lookup (CBOR.TString "sig") m ??? "sig"
  CBOR.TList (CBOR.TBytes certBS : _) <- Map.lookup (CBOR.TString "x5c") m ??? "x5c"
  x5c <- either fail pure $ X509.decodeSignedCertificate certBS
  CBOR.TBytes certInfo <- Map.lookup (CBOR.TString "certInfo") m ??? "certInfo"
  CBOR.TBytes pubArea <- Map.lookup (CBOR.TString "pubArea") m ??? "pubArea"
  pure $ Stmt {..}
  where
    Nothing ??? e = fail e
    Just a ??? _ = pure a
decode _ = fail "TPM.decode: expected a Map"

verify
  :: Stmt
  -> AuthenticatorData
  -> ByteString
  -> Digest SHA256
  -> Either VerificationFailure ()
verify Stmt{..} _ad _adRaw _clientDataHash = do
  -- TODO Verify that the public key specified by the parameters and unique fields of pubArea is identical to the credentialPublicKey in the attestedCredentialData in authenticatorData.
  let pub = X509.certPubKey $ X509.getCertificate x5c
  -- let attToBeSigned = adRaw <> BA.convert clientDataHash
  -- https://www.iana.org/assignments/cose/cose.xhtml#algorithms
  case alg of
    -65535 -> verifyX509Sig (X509.SignatureALG X509.HashSHA1 X509.PubKeyALG_RSA) pub certInfo sig "TPM"
    _ -> Left $ UnsupportedAlgorithm alg
