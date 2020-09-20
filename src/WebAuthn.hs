{-# LANGUAGE RecordWildCards, NamedFieldPuns #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
-----------------------------------------------------------------------
-- |
-- Module      :  WebAuthn
-- License     :  BSD3
--
-- Maintainer  :  Fumiaki Kinoshita <fumiexcel@gmail.com>
--
-- <https://www.w3.org/TR/webauthn/ Web Authentication API> Verification library
-----------------------------------------------------------------------

module WebAuthn (
  -- * Basic
  TokenBinding(..)
  , Origin(..)
  , RelyingParty(..)
  , defaultRelyingParty
  , User(..)
  -- Challenge
  , Challenge(..)
  , generateChallenge
  , WebAuthnType(..)
  , CollectedClientData(..)
  , AuthenticatorData(..)
  , AttestedCredentialData(..)
  , AAGUID(..)
  , CredentialPublicKey(..)
  , CredentialId(..)
  -- * verfication
  , VerificationFailure(..)
  , registerCredential
  , verify
  ) where

import Prelude hiding (fail)
import Data.Aeson as J
import Data.Bits
import Data.ByteString (ByteString)
import qualified Data.Serialize as C
import qualified Data.ByteArray as BA
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import qualified Data.Map as Map
import Data.Text (Text)
import Crypto.Random
import Crypto.Hash
import qualified Codec.CBOR.Term as CBOR
import qualified Codec.CBOR.Read as CBOR
import qualified Codec.CBOR.Decoding as CBOR
import qualified Codec.Serialise as CBOR
import Control.Monad.Fail

import WebAuthn.Signature
import WebAuthn.Types
import qualified WebAuthn.TPM as TPM
import qualified WebAuthn.FIDOU2F as U2F
import qualified WebAuthn.Packed as Packed

-- | Generate a cryptographic challenge (13.1).
generateChallenge :: Int -> IO Challenge
generateChallenge len = Challenge <$> getRandomBytes len

parseAuthenticatorData :: C.Get AuthenticatorData
parseAuthenticatorData = do
  rpIdHash' <- C.getBytes 32
  rpIdHash <- maybe (fail "impossible") pure $ digestFromByteString rpIdHash'
  flags <- C.getWord8
  _counter <- C.getBytes 4
  attestedCredentialData <- if testBit flags 6
    then do
      aaguid <- AAGUID <$> C.getBytes 16
      len <- C.getWord16be
      credentialId <- CredentialId <$> C.getBytes (fromIntegral len)
      n <- C.remaining
      credentialPublicKey <- CredentialPublicKey <$> C.getBytes n
      pure $ Just AttestedCredentialData{..}
    else pure Nothing
  let authenticatorDataExtension = B.empty --FIXME
  let userPresent = testBit flags 0
  let userVerified = testBit flags 2
  return AuthenticatorData{..}

-- | Attestation (6.4) provided by authenticators
data AttestationStatement = AF_Packed Packed.Stmt
  | AF_TPM TPM.Stmt
  | AF_AndroidKey
  | AF_AndroidSafetyNet
  | AF_FIDO_U2F U2F.Stmt
  | AF_None
  deriving Show

decodeAttestation :: CBOR.Decoder s (ByteString, AttestationStatement)
decodeAttestation = do
  m :: Map.Map Text CBOR.Term <- CBOR.decode
  CBOR.TString fmt <- maybe (fail "fmt") pure $ Map.lookup "fmt" m
  stmtTerm <- maybe (fail "stmt") pure $ Map.lookup "attStmt" m
  stmt <- case fmt of
    "fido-u2f" -> maybe (fail "fido-u2f") (pure . AF_FIDO_U2F) $ U2F.decode stmtTerm
    "packed" -> AF_Packed <$> Packed.decode stmtTerm
    "tpm" -> AF_TPM <$> TPM.decode stmtTerm
    _ -> fail $ "decodeAttestation: Unsupported format: " ++ show fmt
  CBOR.TBytes adRaw <- maybe (fail "authData") pure $ Map.lookup "authData" m
  return (adRaw, stmt)

-- | 7.1. Registering a New Credential
registerCredential :: Challenge
  -> RelyingParty
  -> Maybe Text -- ^ Token Binding ID in base64
  -> Bool -- ^ require user verification?
  -> ByteString -- ^ clientDataJSON
  -> ByteString -- ^ attestationObject
  -> Either VerificationFailure AttestedCredentialData
registerCredential challenge RelyingParty{..} tbi verificationRequired clientDataJSON attestationObject = do
  CollectedClientData{..} <- either
    (Left . JSONDecodeError) Right $ J.eitherDecode $ BL.fromStrict clientDataJSON
  clientType == Create ?? InvalidType
  challenge == clientChallenge ?? MismatchedChallenge
  rpOrigin == clientOrigin ?? MismatchedOrigin
  case clientTokenBinding of
    TokenBindingUnsupported -> pure ()
    TokenBindingSupported -> pure ()
    TokenBindingPresent t -> case tbi of
      Nothing -> Left UnexpectedPresenceOfTokenBinding
      Just t'
        | t == t' -> pure ()
        | otherwise -> Left MismatchedTokenBinding
  (adRaw, stmt) <- either (Left . CBORDecodeError "registerCredential") (pure . snd)
    $ CBOR.deserialiseFromBytes decodeAttestation
    $ BL.fromStrict $ attestationObject
  ad <- either (const $ Left MalformedAuthenticatorData) pure $ C.runGet parseAuthenticatorData adRaw
  let clientDataHash = hash clientDataJSON :: Digest SHA256
  hash rpId == rpIdHash ad ?? MismatchedRPID
  userPresent ad ?? UserNotPresent
  not verificationRequired || userVerified ad ?? UserUnverified

  -- TODO: extensions here

  case stmt of
    AF_FIDO_U2F s -> U2F.verify s ad clientDataHash
    AF_Packed s -> Packed.verify s ad adRaw clientDataHash
    AF_TPM s -> TPM.verify s ad adRaw clientDataHash
    AF_None -> pure ()
    _ -> error $ "registerCredential: unsupported format: " ++ show stmt

  case attestedCredentialData ad of
    Nothing -> Left MalformedAuthenticatorData
    Just c -> pure c

-- | 7.2. Verifying an Authentication Assertion
verify :: Challenge
  -> RelyingParty
  -> Maybe Text -- ^ Token Binding ID in base64
  -> Bool -- ^ require user verification?
  -> ByteString -- ^ clientDataJSON
  -> ByteString -- ^ authenticatorData
  -> ByteString -- ^ signature
  -> CredentialPublicKey -- ^ public key
  -> Either VerificationFailure ()
verify challenge RelyingParty{..} tbi verificationRequired clientDataJSON adRaw sig pub = do
  CollectedClientData{..} <- either
    (Left . JSONDecodeError) Right $ J.eitherDecode $ BL.fromStrict clientDataJSON
  clientType == Get ?? InvalidType
  challenge == clientChallenge ?? MismatchedChallenge
  rpOrigin == clientOrigin ?? MismatchedOrigin
  case clientTokenBinding of
    TokenBindingUnsupported -> pure ()
    TokenBindingSupported -> pure ()
    TokenBindingPresent t -> case tbi of
      Nothing -> Left UnexpectedPresenceOfTokenBinding
      Just t'
        | t == t' -> pure ()
        | otherwise -> Left MismatchedTokenBinding

  ad <- either (const $ Left MalformedAuthenticatorData) pure
    $ C.runGet parseAuthenticatorData adRaw

  let clientDataHash = hash clientDataJSON :: Digest SHA256
  hash rpId == rpIdHash ad ?? MismatchedRPID
  userPresent ad ?? UserNotPresent
  not verificationRequired || userVerified ad ?? UserUnverified

  let dat = adRaw <> BA.convert clientDataHash

  pub' <- parsePublicKey pub
  verifySig pub' sig dat

(??) :: Bool -> e -> Either e ()
False ?? e = Left e
True ?? _ = Right ()
infix 1 ??
