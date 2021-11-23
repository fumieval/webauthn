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
-- <https://www.w3.org/TR/webauthn-2/ Web Authentication API> Verification library
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
  , VerifyRegistrationArgs(..)
  , verifyRegistration
  , defaultVerifyRegistrationArgs
  , PublicKeyCredentialCreationOptions(..)
  , defaultPublicKeyCredentialCreationOptions
  , PublicKeyCredentialRequestOptions(..)
  , PublicKeyCredential(..)
  , AuthenticatorAttestationResponse(..)
  , VerifyAssertionArgs(..)
  , verifyAssertion
  ) where

import Control.Monad (when, unless)
import Control.Monad.IO.Class (MonadIO)
import Control.Monad.Trans.Except (runExceptT, throwE, except)
import qualified Crypto.Hash as H
import Crypto.Random
import Data.Aeson as AE
import Data.Bifunctor (first)
import Data.ByteArray qualified as BA
import Data.ByteString (ByteString)
import Data.ByteString.Lazy qualified as BL
import Data.Hourglass (DateTime)
import qualified Data.Text as T
import Data.Text (Text)
import Data.Text.Encoding (encodeUtf8)
import Data.X509.CertificateStore qualified as X509
import GHC.Records
import Prelude hiding (fail)
import WebAuthn.Assertion as Assertion
import WebAuthn.AuthenticatorData
import WebAuthn.Base
import WebAuthn.Signature
import WebAuthn.Attestation as Attestation
import WebAuthn.Attestation.Statement.AndroidSafetyNet qualified as AndroidSafetyNet
import WebAuthn.Attestation.Statement.FIDOU2F qualified as FIDOU2F
import WebAuthn.Attestation.Statement.Packed qualified as Packed
import WebAuthn.Attestation.Statement.TPM qualified as TPM
import WebAuthn.Types

-- | Generate a cryptographic challenge (13.1).
generateChallenge :: Int -> IO Challenge
generateChallenge len = Challenge <$> getRandomBytes len

data VerifyRegistrationArgs t = VerifyRegistrationArgs
  { certificateStore :: X509.CertificateStore
  , options :: PublicKeyCredentialCreationOptions t
  , clientDataJSON :: Required t ByteString
  , attestationObject :: Required t ByteString
  , now :: Maybe DateTime
  , tokenBindingID :: Maybe Text
  }

defaultVerifyRegistrationArgs :: VerifyRegistrationArgs Incomplete
defaultVerifyRegistrationArgs = VerifyRegistrationArgs
  { certificateStore = mempty
  , options = defaultPublicKeyCredentialCreationOptions
  , clientDataJSON = ()
  , attestationObject = ()
  , now = Nothing
  , tokenBindingID = Nothing
  }

instance t ~ Complete => HasField "run" (VerifyRegistrationArgs t) (IO (Either VerificationFailure (AttestedCredentialData, AttestationStatement, SignCount))) where
  getField = verifyRegistration

-- | 7.1. Registering a New Credential (Attestation)
--
-- Registration ceremony (partial, read carefully).
--
-- Following steps of the algorithm described in 7.1 are NOT implemented here and are out of scope
-- for this library:
--
-- 20. If validation is successful, obtain a list of acceptable trust anchors (i.e. attestation root
--     certificates) for that attestation type and attestation statement format fmt, from a trusted
--     source or from policy. For example, the FIDO Metadata Service [FIDOMetadataService] provides
--     one way to obtain such information, using the aaguid in the attestedCredentialData in
--     authData.
--
--     (partially handled)
--
-- 21. ...
--
-- 22. Check that the credentialId is not yet registered to any other user. If registration is requested
--     for a credential that is already registered to a different user, the Relying Party SHOULD fail this
--     registration ceremony, or it MAY decide to accept the registration, e.g. while deleting the older
--     registration.
--
-- 23. If the attestation statement attStmt verified successfully and is found to be trustworthy, then
--     register the new credential with the account that was denoted in options.user:
--
--       o Associate the user’s account with the credentialId and credentialPublicKey in
--         authData.attestedCredentialData, as appropriate for the Relying Party's system.
--
--       o Associate the credentialId with a new stored signature counter value initialized to the
--         value of authData.signCount.
--
--     It is RECOMMENDED to also:
--
--       o Associate the credentialId with the transport hints returned by calling
--         credential.response.getTransports(). This value SHOULD NOT be modified before or after
--         storing it. It is RECOMMENDED to use this value to populate the transports of the
--         allowCredentials option in future get() calls to help the client know how to find a
--         suitable authenticator.
--
-- 24. If the attestation statement attStmt successfully verified but is not trustworthy per step 21
--     above, the Relying Party SHOULD fail the registration ceremony.
--
-- TODO: This seems to need IO only because of AndroidSafetyNet.verify. Can we make it pure?
--
verifyRegistration :: MonadIO m
  => VerifyRegistrationArgs Complete
  -> m (Either VerificationFailure (AttestedCredentialData, AttestationStatement, SignCount))
verifyRegistration VerifyRegistrationArgs{..} = runExceptT $ do
  let PublicKeyCredentialCreationOptions{..} = options
  -- 1. Let options be a new PublicKeyCredentialCreationOptions structure configured to the Relying Party's needs for the ceremony.
  -- options passed as argument
  --
  -- 2. Call navigator.credentials.create() and pass options as the publicKey option. Let credential be the result of the
  --    successfully resolved promise.
  -- credential passed as argument
  --
  -- 3. Let response be credential.response...
  -- Should be done on the client. Data from response object is required as arguments here.
  --
  -- 4. Let clientExtensionResults be the result of calling credential.getClientExtensionResults()
  -- We currently do not support any extensions. Skip ahead.
  --
  -- 5. to 10.
  c :: CollectedClientData <- except $ first JSONDecodeError $ AE.eitherDecode $ BL.fromStrict clientDataJSON
  let PublicKeyCredentialCreationOptions{ challenge } = options
  except $ Attestation.verifyCollectedClientData rp challenge tokenBindingID c
  -- 11.
  let hash = H.hash clientDataJSON :: H.Digest H.SHA256
  -- 12.
  (AttestationObject{ attStmt, authData }, authDataRaw) <- except $ Attestation.parseAttestationObject attestationObject
  -- 13.
  except $ unless (H.hash (encodeUtf8 rp.id) == authData.rpIdHash) $ Left MismatchedRPID
  -- 14.
  except $ unless authData.userPresent $ Left UserNotPresent
  -- 15.
  let uvRequired = options.requireUserVerification
  except $ when (uvRequired && not authData.userVerified) $ Left UserUnverified
  -- 16.
  let PublicKeyCredentialCreationOptions{ pubKeyCredParams } = options
  mAdPubKey <- except $ Attestation.verifyPubKey pubKeyCredParams authData
  -- 17.
  -- We currently do not support any extensions. Skip forward.
  -- 18. to 19.
  case attStmt of
    ASFidou2f s -> except $ FIDOU2F.verify s authData hash
    ASPacked s -> except $ Packed.verify s mAdPubKey authData authDataRaw hash
    ASTpm s -> except $ TPM.verify s authData authDataRaw hash
    ASAndroidSafetyNet s -> AndroidSafetyNet.verify certificateStore s authDataRaw hash now
    ASNone -> pure ()
    _ -> throwE $ UnsupportedAttestationFormat $ T.pack $ show attStmt
  -- 20. to 24.
  -- Not implemented here. Out of scope.
  case authData.attestedCredentialData of
    Nothing -> throwE $ MalformedAuthenticatorData "No attestedCredentialData"
    Just x -> pure (x, attStmt, authData.signCount)

data VerifyAssertionArgs = VerifyAssertionArgs
  { relyingParty :: PublicKeyCredentialRpEntity
  , origin :: Origin
  , options :: PublicKeyCredentialRequestOptions
  , credential :: PublicKeyCredential AuthenticatorAssertionResponse
  , tokenBindingID :: Maybe Text
  , credentialPublicKey :: CredentialPublicKey
  , requireVerification :: Bool
  , storedSignCount :: SignCount
  }

instance HasField "run" VerifyAssertionArgs (Either VerificationFailure (Maybe SignCount)) where
  getField = verifyAssertion

-- | 7.2. Verifying an Authentication Assertion
--
-- Authentication ceremony (partial, read carefully).
--
-- Following steps of the algorithm described in 7.2 are NOT implemented here and are out of scope
-- for this library:
--
-- 6. Identify the user being authenticated and verify that this user is the owner of the public key
--    credential source credentialSource identified by credential.id:
--
--    If the user was identified before the authentication ceremony was initiated, e.g.,
--    via a username or cookie,
--        verify that the identified user is the owner of credentialSource. If response.userHandle
--        is present, let userHandle be its value. Verify that userHandle also maps to the same user.
--
--    If the user was not identified before the authentication ceremony was initiated,
--        verify that response.userHandle is present, and that the user identified by this value is
--        the owner of credentialSource.
--
-- 7. Using credential.id (or credential.rawId, if base64url encoding is inappropriate for your use
--    case), look up the corresponding credential public key and let credentialPublicKey be that
--    credential public key.
--
-- These steps are caller's responsibility.
--
-- Addionally, following steps require the caller to lookup user-associated data:
--
-- 21. Let storedSignCount be the stored signature counter value associated with credential.id (...)
--
-- The result of verifyAssertion is either an error, in which case authentication should fail, or a
-- value that should be saved as the new storedSignCount.
--
verifyAssertion
  :: VerifyAssertionArgs
  -> Either VerificationFailure (Maybe SignCount)
verifyAssertion VerifyAssertionArgs{..} = do
  -- 1. Let options be a new PublicKeyCredentialRequestOptions structure configured to the Relying Party's needs for the ceremony.
  -- options passed as argument
  -- 
  -- 2. Call navigator.credentials.get() and pass options as the publicKey option. Let credential be the result...
  -- credential passed as argument
  --
  -- 3. Let response be credential.response...
  let PublicKeyCredential{ response } = credential
  -- 4. Let clientExtensionResults be the result of calling credential.getClientExtensionResults().
  -- We currently do not support any extensions. Skip ahead.
  --
  -- 5.
  Assertion.verifyCredentialAllowed options credential
  -- 6. to 7.
  -- Not implemented here. Caller MUST perform both prior to executing verify.
  --
  -- 8. to 14.
  let PublicKeyCredentialRequestOptions{ challenge } = options
      AuthenticatorAssertionResponse{ clientDataJSON } = response
  collectedClientData <- first JSONDecodeError $ AE.eitherDecode $ BL.fromStrict clientDataJSON
  Assertion.verifyCollectedClientData relyingParty challenge tokenBindingID collectedClientData
  -- 15. to 18.
  let PublicKeyCredentialRequestOptions{ userVerification } = options
      AuthenticatorAssertionResponse{ authenticatorData, signature } = response
  authData <- first (MalformedAuthenticatorData . T.pack) (parseAuthenticatorData authenticatorData)
  Assertion.verifyAuthenticatorData relyingParty (userVerification == Just Required) authData
  -- 19. to 20.
  let hash = H.hash clientDataJSON :: H.Digest H.SHA256
      dat = authenticatorData <> BA.convert hash
  pubKey <- parsePublicKey credentialPublicKey
  verifySig pubKey signature dat
  -- 21.
  let AuthenticatorData{ signCount } = authData
  if signCount /= 0 || storedSignCount /= 0
    then
      if signCount > storedSignCount
      then pure $ Just signCount
      else
        -- This is a signal that the authenticator may be cloned, i.e. at least two copies of the
        -- credential private key may exist and are being used in parallel. Relying Parties
        -- should incorporate this information into their risk scoring. Whether the Relying
        -- Party updates storedSignCount in this case, or not, or fails the authentication
        -- ceremony or not, is Relying Party-specific.
        --
        -- TODO: should be configurable
        Left InvalidSignCount
    else pure Nothing
