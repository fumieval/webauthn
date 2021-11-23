{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
module WebAuthn.Attestation.Statement.FIDOU2F where

import Crypto.Hash
import Data.ByteString (ByteString)
import qualified Data.ByteString.Builder as BB
import qualified Data.ByteString.Lazy as BL
import qualified Codec.CBOR.Term as CBOR
import qualified Codec.Serialise as CBOR
import qualified Data.ByteArray as BA
import qualified Data.Map as Map
import qualified Data.X509 as X509
import WebAuthn.Types
import WebAuthn.Signature (verifyX509Sig)

data Stmt = Stmt (X509.SignedExact X509.Certificate) ByteString
  deriving Show

decode :: CBOR.Term -> Maybe Stmt
decode (CBOR.TMap xs) = do
  let m = Map.fromList xs
  CBOR.TBytes sig <- Map.lookup (CBOR.TString "sig") m
  CBOR.TList [CBOR.TBytes certBS] <- Map.lookup (CBOR.TString "x5c") m
  cert <- either fail pure $ X509.decodeSignedCertificate certBS
  return (Stmt cert sig)
decode _ = Nothing

verify :: Stmt
  -> AuthenticatorData
  -> Digest SHA256
  -> Either VerificationFailure ()
verify (Stmt cert sig) AuthenticatorData{..} clientDataHash = do
  AttestedCredentialData{..} <- maybe (Left $ MalformedAuthenticatorData "FIDOU2F") pure attestedCredentialData
  m <- either (Left . CBORDecodeError "FIDOU2F.verify") pure
    $ CBOR.deserialiseOrFail $ BL.fromStrict $ unCredentialPublicKey credentialPublicKey
  pubU2F <- maybe (Left MalformedPublicKey) pure $ do
      CBOR.TBytes x <- Map.lookup (-2 :: Int) m
      CBOR.TBytes y <- Map.lookup (-3) m
      return $ BB.word8 0x04 <> BB.byteString x <> BB.byteString y
  let dat = BL.toStrict $ BB.toLazyByteString $ mconcat
        [ BB.word8 0x00
        , BB.byteString $ BA.convert rpIdHash
        , BB.byteString $ BA.convert clientDataHash
        , BB.byteString $ unCredentialId credentialId
        , pubU2F]
  let pub = X509.certPubKey $ X509.getCertificate cert
  verifyX509Sig (X509.SignatureALG X509.HashSHA256 X509.PubKeyALG_EC) pub dat sig "FIDOU2F"
