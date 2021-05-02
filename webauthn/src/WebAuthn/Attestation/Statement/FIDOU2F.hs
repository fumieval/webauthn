-- | 8.6. FIDO U2F Attestation Statement Format
module WebAuthn.Attestation.Statement.FIDOU2F where

import Crypto.Hash ( SHA256, Digest )
import Data.Bifunctor (first)
import Data.ByteString (ByteString)

import Control.Monad ( unless )
import qualified Data.ByteString.Builder as BB
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import Data.Map (Map)
import qualified Codec.Serialise as CBOR
import qualified Codec.CBOR.Term as CBOR
import qualified Codec.CBOR.Decoding as CBOR
import qualified Data.ByteArray as BA
import qualified Data.Map as Map
import qualified Data.X509 as X509

import WebAuthn.Types
import WebAuthn.Signature (verifyX509Sig)


data Stmt = Stmt
  { x5c :: X509.SignedExact X509.Certificate
  , sig :: ByteString
  } deriving stock (Show)

decode :: CBOR.Term -> CBOR.Decoder s Stmt
decode (CBOR.TMap xs) = do
  let m = Map.fromList xs
  CBOR.TBytes sig <- Map.lookup (CBOR.TString "sig") m ??? "sig"
  CBOR.TList [CBOR.TBytes certBS] <- Map.lookup (CBOR.TString "x5c") m ??? "x5c"
  cert <- either fail pure (X509.decodeSignedCertificate certBS) ??? "decodedSignedCertificate"
  pure $ Stmt cert sig
  where
    Nothing ??? e = fail e
    Just a ??? _ = pure a
decode _ = fail "FIDOU2F.decode: expected a Map"

verify
  :: Stmt
  -> AuthenticatorData
  -> Digest SHA256
  -> Either VerificationFailure ()
verify (Stmt cert sig) AuthenticatorData{..} clientDataHash = do
  AttestedCredentialData{..} <- maybe (Left $ MalformedAuthenticatorData "AttestedCredentialData missing") pure attestedCredentialData
  m :: Map Int CBOR.Term <- first (CBORDecodeError "verifyFIDOU2F") $ CBOR.deserialiseOrFail $ BL.fromStrict $ unCredentialPublicKey credentialPublicKey
  publicKeyU2F <- maybe (Left MalformedPublicKey) pure $ do
      CBOR.TBytes x <- Map.lookup (-2) m
      unless (B.length x == 32) Nothing
      CBOR.TBytes y <- Map.lookup (-3) m
      unless (B.length y == 32) Nothing
      pure $ BB.word8 0x04 <> BB.byteString x <> BB.byteString y
  let dat = BL.toStrict $ BB.toLazyByteString $ mconcat
        [ BB.word8 0x00
        , BB.byteString $ BA.convert rpIdHash
        , BB.byteString $ BA.convert clientDataHash
        , BB.byteString $ unCredentialId credentialId
        , publicKeyU2F
        ]
  let pub = X509.certPubKey $ X509.getCertificate cert
  verifyX509Sig (X509.SignatureALG X509.HashSHA256 X509.PubKeyALG_EC) pub dat sig "FIDOU2F"
