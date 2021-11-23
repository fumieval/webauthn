{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NoFieldSelectors #-}
{-# LANGUAGE DuplicateRecordFields #-}
module WebAuthn.Attestation where

import Control.Monad (unless, when)
import Crypto.Hash as H
import Data.Bifunctor (first)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as BL
import qualified Data.Map as Map
import Data.String
import Data.Text (Text)
import Data.Text.Encoding (encodeUtf8)
import Data.List.NonEmpty (NonEmpty)

import qualified Codec.CBOR.Term as CBOR
import qualified Codec.CBOR.Encoding as CBOR
import qualified Codec.Serialise as CBOR

import qualified WebAuthn.Attestation.Statement.AndroidSafetyNet as AndroidSafetyNet
import qualified WebAuthn.Attestation.Statement.FIDOU2F as FIDOU2F
import qualified WebAuthn.Attestation.Statement.Packed as Packed
import qualified WebAuthn.Attestation.Statement.TPM as TPM
import WebAuthn.AuthenticatorData
import WebAuthn.Common
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
  | ASAndroidSafetyNet AndroidSafetyNet.Stmt
  | ASFidou2f FIDOU2F.Stmt
  -- 8.7. None Attestation Statement Format (not in the IANA registry)
  | ASNone
  deriving Show

-- 7.1 steps 7. to 10.
verifyCollectedClientData :: PublicKeyCredentialRpEntity -> Challenge -> Maybe Text -> CollectedClientData -> Either VerificationFailure ()
verifyCollectedClientData rpOrigin rpChallenge rpTokenBinding CollectedClientData{..} = do
  -- 7.
  unless (_type == WebAuthnCreate) $ Left InvalidType
  -- 8.
  unless (challenge == rpChallenge) $ Left $ MismatchedChallenge rpChallenge challenge
  -- 9.
  unless (isRegistrableDomainSuffixOfOrIsEqualTo rpOrigin origin) $ Left $ MismatchedOrigin rpOrigin origin
  -- 10.
  verifyTokenBinding rpTokenBinding tokenBinding
  case rpTokenBinding of
    Just rpTb ->
      case tokenBinding of
        Just TokenBindingSupported ->
          -- RP provided a TB, client claims support but also claims that it was not negotiated.
          -- Either something went wrong or the client is lying.
          Left MismatchedTokenBinding
        Just (TokenBindingPresent clientTb) ->
          -- Both RP and client provided TB, values must match
          unless (clientTb == rpTb) $ Left MismatchedTokenBinding
        Nothing ->
          -- RP provided a TB but client claims no support.
          -- Either something went wrong or the client is lying.
          Left MismatchedTokenBinding
    Nothing ->
      -- RP did not provide TB, nothing to check
      pure ()

-- | 7.1 steps 13. to 15.
verifyAttestationObject :: PublicKeyCredentialRpEntity -> Bool -> AttestationObject -> Either VerificationFailure ()
verifyAttestationObject rpId uvRequired AttestationObject{..} = do
  -- 13.
  unless (H.hash (encodeUtf8 rpId.id) == authData.rpIdHash) $ Left MismatchedRPID
  -- 14.
  unless authData.userPresent $ Left UserNotPresent
  -- 15.
  when (uvRequired && not authData.userVerified) $ Left UserUnverified

verifyPubKey :: NonEmpty PubKeyCredAlg -> AuthenticatorData -> Either VerificationFailure (Maybe PublicKey)
verifyPubKey pubKeyCredParams AuthenticatorData{..} = do
  case attestedCredentialData of
    Just k -> do
      parsedPubKey <- parsePublicKey k.credentialPublicKey
      unless (any (hasMatchingAlg parsedPubKey) pubKeyCredParams) $ Left $ MalformedAuthenticatorData "No matching algo"
      pure $ Just parsedPubKey
    -- non present public key will fail anyway or the fmt == 'none'
    Nothing -> pure Nothing

instance CBOR.Serialise AttestationObjectRaw where
  decode = do
    m :: Map.Map Text CBOR.Term <- CBOR.decode
    CBOR.TString fmt <- maybe (fail "fmt") pure $ Map.lookup "fmt" m
    stmtTerm <- maybe (fail "stmt") pure $ Map.lookup "attStmt" m
    stmt <- case fmt of
      "fido-u2f" -> maybe (fail "fido-u2f") (pure . ASFidou2f) $ FIDOU2F.decode stmtTerm
      "packed" -> ASPacked <$> Packed.decode stmtTerm
      "tpm" -> ASTpm <$> TPM.decode stmtTerm
      "android-safetynet" -> ASAndroidSafetyNet <$> AndroidSafetyNet.decode stmtTerm
      "none" -> pure ASNone
      _ -> fail $ "AttestationObject.decode: Unsupported format: " ++ show fmt
    CBOR.TBytes adRaw <- maybe (fail "authData") pure $ Map.lookup "authData" m
    return (AttestationObjectRaw fmt stmt adRaw)

  encode AttestationObjectRaw{..} = CBOR.encodeMapLen 3
    <> CBOR.encodeString "fmt"
    <> encodeAttestationFmt
    <> CBOR.encodeString "attStmt"
    where
      encodeAttestationFmt :: CBOR.Encoding
      encodeAttestationFmt = case attStmt of
        ASFidou2f _ -> CBOR.encodeString "fido-u2f"
        ASPacked _ -> CBOR.encodeString "packed"
        ASTpm _ -> CBOR.encodeString "tpm"
        ASAndroidKey -> CBOR.encodeString "android-key"
        ASAndroidSafetyNet _ -> CBOR.encodeString "android-safetynet"
        ASNone -> CBOR.encodeString "none"
  
-- | Parse AttestationObject
--
-- On success returns AttestationObject and raw AuthenticatorData.
parseAttestationObject :: ByteString -> Either VerificationFailure (AttestationObject, ByteString)
parseAttestationObject bs = do
  AttestationObjectRaw{..} <- first (CBORDecodeError "AttestationObject") $ CBOR.deserialiseOrFail $ BL.fromStrict bs
  authData <- first (MalformedAuthenticatorData . fromString) $ parseAuthenticatorData authDataRaw
  pure (AttestationObject{..}, authDataRaw)
