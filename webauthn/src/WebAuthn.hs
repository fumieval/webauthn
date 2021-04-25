-----------------------------------------------------------------------
-- |
-- Module      :  WebAuthn
-- License     :  BSD3
--
-- Maintainer  :  Fumiaki Kinoshita <fumiexcel@gmail.com>
--
-- <https://www.w3.org/TR/webauthn-2/ Web Authentication API> Verification library
-----------------------------------------------------------------------

module WebAuthn where

import Prelude hiding (fail)
import qualified Data.ByteArray as BA
import Data.Text (Text)
import qualified Data.Text as T
import qualified Crypto.Hash as H
import Control.Monad.IO.Class (MonadIO)
import Control.Monad.Trans.Except (runExceptT, except, throwE)
import qualified Data.X509.CertificateStore as X509
import Data.Bifunctor (first)

import WebAuthn.AuthenticatorData ( parseAuthenticatorData )
import qualified WebAuthn.Assertion as Assertion
import WebAuthn.Attestation (AttestationObject(..), AttestationStatement(..))
import qualified WebAuthn.Attestation as Attestation
import qualified WebAuthn.Attestation.Statement.AndroidSafetyNet as AndroidSafetyNet
import qualified WebAuthn.Attestation.Statement.FIDOU2F as FIDOU2F
import qualified WebAuthn.Attestation.Statement.Packed as Packed
import qualified WebAuthn.Attestation.Statement.TPM as TPM
import WebAuthn.Common ( parseCollectedClientData )
import WebAuthn.Signature ( parsePublicKey, verifySig )
import WebAuthn.Types


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
  => RpId                                                 -- ^ Relying Party's ID
  -> Origin                                               -- ^ Relying Party's origin
  -> Maybe Text                                           -- ^ TLS connection token binding in base64
  -> PublicKeyCredentialCreationOptions                   -- ^ options as sent to the client earlier
  -> PublicKeyCredential AuthenticatorAttestationResponse -- ^ credential from navigator.credential.create()
  -> X509.CertificateStore                                -- ^ trust anchors
  -> m (Either VerificationFailure (AttestedCredentialData, AttestationStatement, SignCount))
verifyRegistration rpId rpOrigin rpTokenBinding options credential trustAnchors = runExceptT $ do
  -- 1. Let options be a new PublicKeyCredentialCreationOptions structure configured to the Relying Party's needs for the ceremony.
  -- Passed as argument.
  --
  -- 2. Call navigator.credentials.create() and pass options as the publicKey option. Let credential be the result of the
  --    successfully resolved promise.
  -- Passed as argument.
  --
  -- 3. Let response be credential.response...
  let PublicKeyCredential { response } = credential
      AuthenticatorAttestationResponse{..} = response
  --
  -- 4. Let clientExtensionResults be the result of calling credential.getClientExtensionResults()
  -- We currently do not support any extensions. Skip ahead.
  --
  -- 5. to 10.
  c <- except $ parseCollectedClientData clientDataJSON
  let PublicKeyCredentialCreationOptions{ challenge } = options
  except $ Attestation.verifyCollectedClientData rpOrigin challenge rpTokenBinding c
  -- 11.
  let hash = H.hash clientDataJSON :: H.Digest H.SHA256
  -- 12.
  (attObj@AttestationObject{ attStmt, authData }, authDataRaw) <- except $ Attestation.parseAttestationObject attestationObject
  -- 13. to 15.
  let uvRequired = (authenticatorSelection options >>= (userVerification :: AuthenticatorSelection -> Maybe UserVerificationRequirement)) == Just Required
  except $ Attestation.verifyAttestationObject rpId uvRequired attObj
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
    ASAndroidSafetyNet s -> AndroidSafetyNet.verify trustAnchors s authDataRaw hash
    ASNone -> pure ()
    x -> throwE $ UnsupportedAttestationFormat $ T.pack $ show x
  -- 20. to 24.
  -- Not implemented here. Out of scope.
  case attestedCredentialData authData of
    Nothing -> throwE MalformedAuthenticatorData
    Just x -> pure (x, attStmt, signCount authData)

 

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
  :: RpId                                               -- ^ Relying Party's ID
  -> Origin                                             -- ^ Relying Party's origin
  -> Maybe Text                                         -- ^ Token Binding ID in base64
  -> PublicKeyCredentialRequestOptions                  -- ^ Options for Assertion Generation as sent to the client earlier
  -> PublicKeyCredential AuthenticatorAssertionResponse -- ^ credential from navigator.credential.get()
  -> CredentialPublicKey                                -- ^ stored credentialPublicKey
  -> SignCount                                          -- ^ stored signCount
  -> Either VerificationFailure (Maybe SignCount)
verifyAssertion rpId rpOrigin rpTokenBinding options credential credentialPublicKey storedSignCount = do
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
  c <- parseCollectedClientData clientDataJSON
  Assertion.verifyCollectedClientData rpOrigin challenge rpTokenBinding c
  -- 15. to 18.
  let PublicKeyCredentialRequestOptions{ userVerification } = options
      AuthenticatorAssertionResponse{ authenticatorData, signature } = response
  authData <- first (const MalformedAuthenticatorData) (parseAuthenticatorData authenticatorData)
  Assertion.verifyAuthenticatorData rpId (userVerification == Just Required) authData
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
