{-# language DeriveAnyClass #-}

module Types where

import GHC.Generics (Generic)
import Data.Aeson
import qualified Data.Aeson as AE
import Data.Text (Text)
import WebAuthn.Types as WA

data TestAttestationOptionsRequest = TestAttestationOptionsRequest
  { username :: Text
  , displayName :: Text
  , authenticatorSelection :: Maybe WA.AuthenticatorSelection
  , attestation :: WA.AttestationConveyancePreference
  , extensions :: Maybe AE.Value
  } deriving stock (Eq, Show, Generic)
    deriving anyclass (FromJSON)

data TestAssertionOptionsRequest = TestAssertionOptionsRequest
  { username :: Text
  , userVerification :: Maybe WA.UserVerificationRequirement
  , extensions :: Maybe AE.Value
  } deriving stock (Eq, Show, Generic)
    deriving anyclass (FromJSON)
