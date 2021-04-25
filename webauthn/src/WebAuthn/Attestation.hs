module WebAuthn.Attestation where

import Control.Monad (when, unless)
import Data.Bifunctor (bimap, first)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as BL
import qualified Data.List.NonEmpty as NE
import Data.Map (Map)
import qualified Data.Map as Map
import Data.Text (Text)
import qualified Data.Text.Encoding as TE
import Data.List.NonEmpty (NonEmpty)
import qualified Crypto.Hash as H

import qualified Codec.CBOR.Term as CBOR
import qualified Codec.CBOR.Read as CBOR
import qualified Codec.CBOR.Decoding as CBOR
import qualified Codec.Serialise as CBOR

import qualified WebAuthn.Attestation.Statement.AndroidSafetyNet as AndroidSafetyNet
import qualified WebAuthn.Attestation.Statement.FIDOU2F as FIDOU2F
import qualified WebAuthn.Attestation.Statement.Packed as Packed
import qualified WebAuthn.Attestation.Statement.TPM as TPM
import WebAuthn.AuthenticatorData
import qualified WebAuthn.Common as Common
import WebAuthn.Signature ( hasMatchingAlg, parsePublicKey, PublicKey )
import WebAuthn.Types


-- | 6.5 Attestation Object - intermediate version with raw authData
data AttestationObjectRaw = AttestationObjectRaw
  { fmt :: Text
  , attStmt :: AttestationStatement
  , authDataRaw :: ByteString
  }

-- | 6.5 Attestation Object 
data AttestationObject = AttestationObject
  { fmt :: Text
  , attStmt :: AttestationStatement
  , authData :: AuthenticatorData
  }

-- Attestation Statement Formats must be registered through IANA:
-- https://www.iana.org/assignments/webauthn/webauthn.xhtml
data AttestationStatement
  = ASPacked Packed.Stmt
  | ASTpm TPM.Stmt
  | ASAndroidKey
  | ASAndroidSafetyNet AndroidSafetyNet.StmtSafetyNet
  | ASFidou2f FIDOU2F.Stmt
  -- 8.7. None Attestation Statement Format (defined in the spec, not in the IANA registry)
  | ASNone
  | ASApple
  deriving Show

-- | 7.1 steps 7. to 10.
verifyCollectedClientData :: Origin -> Challenge -> Maybe Text -> CollectedClientData -> Either VerificationFailure ()
verifyCollectedClientData = Common.verifyCollectedClientData WebAuthnCreate

-- | 7.1 steps 13. to 15.
verifyAttestationObject :: RpId -> Bool -> AttestationObject -> Either VerificationFailure ()
verifyAttestationObject rpId uvRequired AttestationObject{..} = do
  -- 13.
  unless (H.hash (TE.encodeUtf8 $ unRpId rpId) == rpIdHash authData) $ Left MismatchedRPID
  -- 14.
  unless (userPresent authData) $ Left UserNotPresent
  -- 15.
  when (uvRequired && not (userVerified authData)) $ Left UserUnverified

verifyPubKey :: NonEmpty PublicKeyCredentialParameters -> AuthenticatorData -> Either VerificationFailure (Maybe PublicKey)
verifyPubKey params ad = do
  let pubKey = credentialPublicKey <$> attestedCredentialData ad
  case pubKey of
    Just k -> do
      parsedPubKey <- parsePublicKey k
      unless (any (hasMatchingAlg parsedPubKey) (NE.map (alg :: PublicKeyCredentialParameters -> COSEAlgorithmIdentifier) params)) $ Left MalformedAuthenticatorData
      pure $ Just parsedPubKey
    -- non present public key will fail anyway or the fmt == 'none'
    Nothing -> pure Nothing

attestationObjectDecode :: CBOR.Decoder s AttestationObjectRaw
attestationObjectDecode = do
  m :: Map Text CBOR.Term <- CBOR.decode
  CBOR.TString fmt <- maybe (fail "fmt") pure $ Map.lookup "fmt" m
  stmtTerm <- maybe (fail "stmt") pure $ Map.lookup "attStmt" m
  stmt <- case fmt of
    "fido-u2f" -> ASFidou2f <$> FIDOU2F.decode stmtTerm
    "packed" -> ASPacked <$> Packed.decode stmtTerm
    "tpm" -> ASTpm <$> TPM.decode stmtTerm
    "android-safetynet" -> ASAndroidSafetyNet <$> AndroidSafetyNet.decode stmtTerm
    "none" -> pure ASNone
    _ -> fail $ "decodeAttestation: Unsupported format: " ++ show fmt
  CBOR.TBytes adRaw <- maybe (fail "authData") pure $ Map.lookup "authData" m
  pure $ AttestationObjectRaw fmt stmt adRaw

-- | Parse AttestationObject
--
-- On success returns AttestationObject and raw AuthenticatorData.
parseAttestationObject :: ByteString -> Either VerificationFailure (AttestationObject, ByteString)
parseAttestationObject bs = do
  AttestationObjectRaw{..} <- bimap (CBORDecodeError "AttestationObject") snd $ CBOR.deserialiseFromBytes attestationObjectDecode $ BL.fromStrict bs
  authData <- first (const MalformedAuthenticatorData) $ parseAuthenticatorData authDataRaw
  pure (AttestationObject{..}, authDataRaw)
