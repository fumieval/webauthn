{-# LANGUAGE OverloadedRecordDot #-}
module WebAuthn.Assertion where

import Control.Monad ( when, unless )
import qualified Crypto.Hash as H
import qualified Data.List.NonEmpty as NE
import Data.Text (Text)
import qualified Data.Text.Encoding as TE

import WebAuthn.Base
import WebAuthn.Types

-- | Check if credential.id is allowed by options.allowCredentials (7.2 step 5)
verifyCredentialAllowed
  :: PublicKeyCredentialRequestOptions Complete
  -> PublicKeyCredential a
  -> Either VerificationFailure ()
verifyCredentialAllowed options PublicKeyCredential{ id = pkid } =
  case options.allowCredentials of
    Just xs -> do
      let notFound = null $ NE.filter (\PublicKeyCredentialDescriptor{ id = pkcdId } -> pkid == pkcdId) xs
      when notFound $ Left CredentialNotAllowed
    Nothing -> pure ()

-- | Perform checks against CollectedClientData (7.2 steps 8-14)
verifyCollectedClientData
  :: PublicKeyCredentialRpEntity
  -> Challenge
  -> Maybe Text -- ^ Token Binding
  -> CollectedClientData -- ^ parsed clientDataJSON
  -> Either VerificationFailure ()
verifyCollectedClientData rpOrigin rpChallenge tbi CollectedClientData{ typ = clientType, challenge = clientChallenge, origin = clientOrigin, tokenBinding = clientTokenBinding } = do
  unless (clientType == WebAuthnGet) $ Left InvalidType
  unless (clientChallenge == rpChallenge) $ Left $ MismatchedChallenge rpChallenge clientChallenge
  unless (isRegistrableDomainSuffixOfOrIsEqualTo rpOrigin clientOrigin) $ Left $ MismatchedOrigin rpOrigin clientOrigin
  -- 14. TODO: ???
  case clientTokenBinding of
    Just ctbi -> verifyClientTokenBinding tbi ctbi
    Nothing -> pure ()

verifyClientTokenBinding
  :: Maybe Text
  -> TokenBinding
  -> Either VerificationFailure ()
verifyClientTokenBinding tbi (TokenBindingPresent t) = case tbi of
      Nothing -> Left UnexpectedPresenceOfTokenBinding
      Just t'
        | t == t' -> pure ()
        | otherwise -> Left MismatchedTokenBinding 
verifyClientTokenBinding _ _ = pure ()

-- | Perform checks against authenticator data (7.2 steps 15-18)
verifyAuthenticatorData
  :: PublicKeyCredentialRpEntity -- ^ Relying Party's ID
  -> Bool -- ^ is user verification required
  -> AuthenticatorData
  -> Either VerificationFailure ()
verifyAuthenticatorData rpId verificationRequired ad = do
  unless (H.hash (TE.encodeUtf8 rpId.id) == ad.rpIdHash) $ Left MismatchedRPID
  unless ad.userPresent $ Left UserNotPresent
  when (verificationRequired && not ad.userVerified) $ Left UserUnverified
  -- 18.
  -- We currently do not support any extensions. Skip ahead.
