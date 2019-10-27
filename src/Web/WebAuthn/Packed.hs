{-# LANGUAGE OverloadedStrings #-}
module Web.WebAuthn.Packed where

import Crypto.Hash
import Data.ByteString (ByteString)
import qualified Data.ByteArray as BA
import qualified Data.X509 as X509
import qualified Data.X509.Validation as X509
import qualified Codec.CBOR.Term as CBOR
import qualified Codec.CBOR.Decoding as CBOR
import qualified Data.Map as Map
import Web.WebAuthn.Signature
import Web.WebAuthn.Types

data Stmt = Stmt Int ByteString (Maybe (X509.SignedExact X509.Certificate))
  deriving Show

decode :: CBOR.Term -> CBOR.Decoder s Stmt
decode (CBOR.TMap xs) = do
  let m = Map.fromList xs
  CBOR.TInt alg <- Map.lookup (CBOR.TString "alg") m ??? "alg"
  CBOR.TBytes sig <- Map.lookup (CBOR.TString "sig") m ??? "sig"
  cert <- case Map.lookup (CBOR.TString "x5c") m of
    Just (CBOR.TList (CBOR.TBytes certBS : _)) ->
      either fail (pure . Just) $ X509.decodeSignedCertificate certBS
    _ -> pure Nothing
  return $ Stmt alg sig cert
  where
    Nothing ??? e = fail e
    Just a ??? _ = pure a
decode _ = fail "Packed.decode: expected a Map"

verify :: Stmt
  -> AuthenticatorData
  -> ByteString
  -> Digest SHA256
  -> Either VerificationFailure ()
verify (Stmt _ sig cert) ad adRaw clientDataHash = do
  let dat = adRaw <> BA.convert clientDataHash
  case cert of
    Just x509 -> do
      let pub = X509.certPubKey $ X509.getCertificate x509
      case X509.verifySignature (X509.SignatureALG X509.HashSHA256 X509.PubKeyALG_EC) pub dat sig of
        X509.SignaturePass -> return ()
        X509.SignatureFailed _ -> Left $ SignatureFailure "Packed"
    Nothing -> do
      pub <- case attestedCredentialData ad of
          Nothing -> Left MalformedAuthenticatorData
          Just c -> parsePublicKey $ credentialPublicKey c
      verifySig pub sig dat
