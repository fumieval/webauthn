{-# LANGUAGE DataKinds #-}
{-# LANGUAGE RecordWildCards, NamedFieldPuns #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NoFieldSelectors #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE DuplicateRecordFields #-}
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
  , User(..)
  -- Challenge
  , Challenge(..)
  , generateChallenge
  , WebAuthnType(..)
  , CollectedClientData(..)
  , AuthenticatorData(..)
  , AttestedCredentialData(..)
  , AttestationObject(..)
  , AAGUID(..)
  , CredentialPublicKey(..)
  , CredentialId(..)
  , PublicKeyCredentialRpEntity(..)
  , originToRelyingParty
  -- * verfication
  , VerificationFailure(..)
  , RegisterCredentialArgs(..)
  , registerCredential
  , defaultRegisterCredentialArgs
  , CredentialCreationOptions(..)
  , defaultCredentialCreationOptions
  , VerifyArgs(..)
  , verify
  ) where

import Codec.CBOR.Encoding qualified as CBOR
import Codec.CBOR.Term qualified as CBOR
import Codec.Serialise qualified as CBOR
import Control.Monad (unless)
import Control.Monad.Fail
import Control.Monad.IO.Class (MonadIO)
import Control.Monad.Trans.Except (runExceptT, ExceptT(..), throwE)
import Crypto.Hash
import Crypto.Random
import Data.Aeson as J
import Data.Bifunctor (first)
import Data.Bits
import Data.ByteArray qualified as BA
import Data.ByteString (ByteString)
import Data.ByteString qualified as B
import Data.ByteString.Lazy qualified as BL
import Data.Hourglass (DateTime)
import Data.Map qualified as Map
import Data.Serialize qualified as C
import Data.Text (pack, Text)
import Data.Text.Encoding (encodeUtf8)
import Data.X509.CertificateStore qualified as X509
import GHC.Records
import Prelude hiding (fail)
import WebAuthn.AndroidSafetyNet qualified as Android
import WebAuthn.Base
import WebAuthn.FIDOU2F qualified as U2F
import WebAuthn.Packed qualified as Packed
import WebAuthn.Signature
import WebAuthn.TPM qualified as TPM
import WebAuthn.Types

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

data AttestationObject = AttestationObject {
  fmt :: Text
  , attStmt :: AttestationStatement
  , authData :: ByteString
}

data AttestationStatement = AF_Packed Packed.Stmt
  | AF_TPM TPM.Stmt
  | AF_AndroidKey
  | AF_AndroidSafetyNet StmtSafetyNet
  | AF_FIDO_U2F U2F.Stmt
  | AF_None
  deriving Show

instance CBOR.Serialise AttestationObject where
  decode = do
    m :: Map.Map Text CBOR.Term <- CBOR.decode
    CBOR.TString fmt <- maybe (fail "fmt") pure $ Map.lookup "fmt" m
    stmtTerm <- maybe (fail "stmt") pure $ Map.lookup "attStmt" m
    stmt <- case fmt of
      "fido-u2f" -> maybe (fail "fido-u2f") (pure . AF_FIDO_U2F) $ U2F.decode stmtTerm
      "packed" -> AF_Packed <$> Packed.decode stmtTerm
      "tpm" -> AF_TPM <$> TPM.decode stmtTerm
      "android-safetynet" -> AF_AndroidSafetyNet <$> Android.decode stmtTerm
      "none" -> pure AF_None
      _ -> fail $ "AttestationObject.decode: Unsupported format: " ++ show fmt
    CBOR.TBytes adRaw <- maybe (fail "authData") pure $ Map.lookup "authData" m
    return (AttestationObject fmt stmt adRaw)

  encode AttestationObject{..} = CBOR.encodeMapLen 3
    <> CBOR.encodeString "fmt"
    <> encodeAttestationFmt
    <> CBOR.encodeString  "attStmt"
    where
      encodeAttestationFmt :: CBOR.Encoding
      encodeAttestationFmt = case attStmt of
        AF_FIDO_U2F _ -> CBOR.encodeString "fido-u2f"
        AF_Packed _ -> CBOR.encodeString "packed"
        AF_TPM _ -> CBOR.encodeString "tpm"
        AF_AndroidKey -> CBOR.encodeString "android-key"
        AF_AndroidSafetyNet _ -> CBOR.encodeString "android-safetynet"
        AF_None -> CBOR.encodeString "none"

data RegisterCredentialArgs t = RegisterCredentialArgs
  { certificateStore :: X509.CertificateStore
  , options :: CredentialCreationOptions t
  , clientDataJSON :: Required t ByteString
  , attestationObject :: Required t ByteString
  , now :: Maybe DateTime
  , tokenBindingID :: Maybe Text
  }

defaultRegisterCredentialArgs :: RegisterCredentialArgs Incomplete
defaultRegisterCredentialArgs = RegisterCredentialArgs
  { certificateStore = mempty
  , options = defaultCredentialCreationOptions
  , clientDataJSON = ()
  , attestationObject = ()
  , now = Nothing
  , tokenBindingID = Nothing
  }

instance t ~ Complete => HasField "run" (RegisterCredentialArgs t) (IO (Either VerificationFailure AttestedCredentialData)) where
  getField = registerCredential

-- | 7.1. Registering a New Credential
registerCredential :: forall m. MonadIO m
  => RegisterCredentialArgs Complete
  -> m (Either VerificationFailure AttestedCredentialData)
registerCredential RegisterCredentialArgs{attestationObject = rawAttObj, ..} = runExceptT $ do
  _ <- hoistEither runAttestationCheck
  attestationObject@AttestationObject{..} <- hoistEither
    $ first (CBORDecodeError "registerCredential")
    $ CBOR.deserialiseOrFail
    $ BL.fromStrict rawAttObj
  ad@AuthenticatorData{..} <- hoistEither $ extractAuthData attestationObject
  mAdPubKey <- verifyPubKey ad
  -- TODO: extensions here
  case attStmt of
    AF_FIDO_U2F s -> hoistEither $ U2F.verify s ad clientDataHash
    AF_Packed s -> hoistEither $ Packed.verify s mAdPubKey ad authData clientDataHash
    AF_TPM s -> hoistEither $ TPM.verify s ad authData clientDataHash
    AF_AndroidSafetyNet s -> Android.verify certificateStore s authData clientDataHash now
    AF_None -> pure ()
    _ -> throwE $ UnsupportedAttestationFormat $ pack $ show attStmt

  case attestedCredentialData of
    Nothing -> throwE $ MalformedAuthenticatorData "missing attestedCredentialData"
    Just c -> pure c
  where
    CredentialCreationOptions{..} = options
    clientDataHash = hash clientDataJSON :: Digest SHA256
    runAttestationCheck = do
      ccd :: CollectedClientData <- either
        (Left . JSONDecodeError) Right $ J.eitherDecode $ BL.fromStrict clientDataJSON
      ccd._type == Create ?? InvalidType
      challenge == ccd.challenge ?? MismatchedChallenge challenge ccd.challenge
      isRegistrableDomainSuffixOfOrIsEqualTo rp ccd.origin ?? MismatchedOrigin rp ccd.origin
      case ccd.tokenBinding of
        TokenBindingUnsupported -> pure ()
        TokenBindingSupported -> pure ()
        TokenBindingPresent t -> case tokenBindingID of
          Nothing -> Left UnexpectedPresenceOfTokenBinding
          Just t'
            | t == t' -> pure ()
            | otherwise -> Left MismatchedTokenBinding
    extractAuthData AttestationObject{..} = do
      ad <- either (Left . MalformedAuthenticatorData . pack) pure
        $ C.runGet parseAuthenticatorData authData
      hash (encodeUtf8 rp.id) == ad.rpIdHash ?? MismatchedRPID
      ad.userPresent ?? UserNotPresent
      not options.requireUserVerification || ad.userVerified ?? UserUnverified
      pure ad
    verifyPubKey :: AuthenticatorData -> ExceptT VerificationFailure m (Maybe PublicKey)
    verifyPubKey ad = do
      case ad.attestedCredentialData of
        Just k -> do
          parsedPubKey <- either throwE return $ parsePublicKey k.credentialPublicKey
          unless (any (hasMatchingAlg parsedPubKey) pubKeyCredParams) $ throwE $ MalformedAuthenticatorData
            $ "does not match " <> pack (show pubKeyCredParams)
          return $ Just parsedPubKey
        -- non present public key will fail anyway or the fmt == 'none'
        Nothing -> return Nothing

data VerifyArgs = VerifyArgs
  { challenge :: Challenge
  , relyingParty :: PublicKeyCredentialRpEntity
  , tokenBindingID :: Maybe Text
  , requireVerification :: Bool
  , clientDataJSON :: ByteString
  , authenticatorData :: ByteString
  , signature :: ByteString
  , credentialPublicKey :: CredentialPublicKey
  }

instance HasField "run" VerifyArgs (Either VerificationFailure ()) where
  getField = verify

-- | 7.2. Verifying an Authentication Assertion
verify :: VerifyArgs
  -> Either VerificationFailure ()
verify VerifyArgs{..} = do
  clientDataCheck Get challenge clientDataJSON relyingParty tokenBindingID
  let clientDataHash = hash clientDataJSON :: Digest SHA256
  _ <- verifyAuthenticatorData relyingParty authenticatorData requireVerification
  let dat = authenticatorData <> BA.convert clientDataHash
  pub' <- parsePublicKey credentialPublicKey
  verifySig pub' signature dat

clientDataCheck :: WebAuthnType -> Challenge -> ByteString -> PublicKeyCredentialRpEntity -> Maybe Text -> Either VerificationFailure ()
clientDataCheck ctype challenge clientDataJSON rp tbi = do
  ccd :: CollectedClientData <- first JSONDecodeError (J.eitherDecode $ BL.fromStrict clientDataJSON)
  ccd._type == ctype ?? InvalidType
  challenge == ccd.challenge ?? MismatchedChallenge challenge ccd.challenge
  isRegistrableDomainSuffixOfOrIsEqualTo rp ccd.origin ?? MismatchedOrigin rp ccd.origin
  verifyClientTokenBinding tbi ccd.tokenBinding

verifyClientTokenBinding :: Maybe Text -> TokenBinding -> Either VerificationFailure ()
verifyClientTokenBinding tbi (TokenBindingPresent t) = case tbi of
      Nothing -> Left UnexpectedPresenceOfTokenBinding
      Just t'
        | t == t' -> pure ()
        | otherwise -> Left MismatchedTokenBinding
verifyClientTokenBinding _ _ = pure ()

verifyAuthenticatorData :: PublicKeyCredentialRpEntity -> ByteString -> Bool -> Either VerificationFailure AuthenticatorData
verifyAuthenticatorData (PublicKeyCredentialRpEntity rpId) adRaw verificationRequired = do
  ad@AuthenticatorData{..} <- first (MalformedAuthenticatorData . pack) (C.runGet parseAuthenticatorData adRaw)
  hash (encodeUtf8 rpId) == rpIdHash ?? MismatchedRPID
  userPresent ?? UserNotPresent
  not verificationRequired || userVerified ?? UserUnverified
  pure ad

(??) :: Bool -> e -> Either e ()
False ?? e = Left e
True ?? _ = Right ()
infix 1 ??

hoistEither :: Monad m => Either e a -> ExceptT e m a
hoistEither = ExceptT . pure
