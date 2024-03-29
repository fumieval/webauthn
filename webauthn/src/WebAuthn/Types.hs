{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NoFieldSelectors #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE StrictData #-}
{-# LANGUAGE TypeFamilies #-}
module WebAuthn.Types
  ( AAGUID(..)
  , AttestationConveyancePreference(..)
  , AttestedCredentialData(..)
  , AuthenticatorAssertionResponse(..)
  , AuthenticatorAttachment(..)
  , AuthenticatorAttestationResponse(..)
  , AuthenticatorData(..)
  , AuthenticatorSelection (..)
  , AuthenticatorTransport(..)
  , Base64UrlByteString(..)
  , Challenge(..)
  , CollectedClientData(..)
  , CredentialId(..)
  , CredentialPublicKey(..)
  , Extensions
  , COSEAlgorithmIdentifier (..), pubKeyCredAlgFromInt32
  , PublicKeyCredential(..)
  , PublicKeyCredentialCreationOptions(..), defaultPublicKeyCredentialCreationOptions
  , PublicKeyCredentialDescriptor(..)
  , PublicKeyCredentialRequestOptions(..), defaultPublicKeyCredentialRequestOptions
  , PublicKeyCredentialRpEntity(..), originToRelyingParty, isRegistrableDomainSuffixOfOrIsEqualTo
  , PublicKeyCredentialParameters(..)
  , PublicKeyCredentialType(..)
  , SignCount(..)
  , TokenBinding(..)
  , User(..)
  , UserVerificationRequirement(..)
  , VerificationFailure(..)
  , WebAuthnType(..)
  , Origin(..), displayOrigin, parseOrigin
  ) where

import Prelude hiding (fail)
import Data.Aeson as J
    (Value(..),
      (.:),
      (.:?),
      object,
      genericParseJSON,
      (.=),
      withObject,
      withText,
      constructorTagModifier,
      FromJSON(..),
      ToJSON(..),
      Options(..)
      , genericToEncoding
      , defaultOptions
      , genericToJSON
    )

import Codec.CBOR.Read qualified as CBOR
import Codec.CBOR.Term qualified as CBOR
import Codec.Serialise qualified as CBOR
import Control.Monad.Fail ( MonadFail(fail) )
import Crypto.Hash ( SHA256, Digest )
import Data.Aeson (SumEncoding(UntaggedValue))
import Data.ByteString (ByteString)
import Data.Char ( toLower )
import Data.List (isSuffixOf)
import Data.List.NonEmpty as NE
import Data.Int (Int32)
import Data.Map qualified as Map
import Data.Maybe
import Data.String
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.Read qualified as T
import Data.Word (Word32)
import Data.Void
import Data.Default.Class
import GHC.Generics (Generic)
import GHC.Records
import WebAuthn.Base

-- | 5.4.5. Authenticator Attachment Enumeration (enum AuthenticatorAttachment)
data AuthenticatorAttachment = Platform | CrossPlatform
  deriving stock (Eq, Show)

instance ToJSON AuthenticatorAttachment where
  toJSON Platform = String "platform"
  toJSON CrossPlatform = String "cross-platform"

-- | 5.4.6. Resident Key Requirement Enumeration (enum ResidentKeyRequirement)
data ResidentKeyRequirement
  = ResidentKeyDiscouraged
  | ResidentKeyPreferred
  | ResidentKeyRequired
  deriving stock (Eq, Show)

instance ToJSON ResidentKeyRequirement where
  toJSON = \case
    ResidentKeyDiscouraged -> String "discouraged"
    ResidentKeyPreferred -> String "preferred"
    ResidentKeyRequired -> String "required"

-- | 5.4.7. Attestation Conveyance Preference Enumeration (enum AttestationConveyancePreference)
data AttestationConveyancePreference = None | Direct | Indirect | Enterprise
  deriving stock (Eq, Show, Generic)

instance ToJSON AttestationConveyancePreference where
  toJSON = J.String . \case
    None -> "none"
    Direct -> "direct"
    Indirect -> "indirect"
    Enterprise -> "enterprise"

-- | 5.5. Options for Assertion Generation (dictionary PublicKeyCredentialRequestOptions)
--
-- extensions omitted as support is minimal:
-- https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialRequestOptions/extensions
data PublicKeyCredentialRequestOptions t = PublicKeyCredentialRequestOptions
  { challenge :: Required t Challenge
  , timeout :: Maybe Word32
  , rpId :: Maybe Text
  , allowCredentials :: Maybe (NonEmpty PublicKeyCredentialDescriptor)
  , userVerification :: Maybe UserVerificationRequirement
  } deriving stock (Generic)

deriving instance Eq (PublicKeyCredentialRequestOptions Complete)
deriving instance Show (PublicKeyCredentialRequestOptions Complete)

instance t ~ Incomplete => Default (PublicKeyCredentialRequestOptions t) where
  def = defaultPublicKeyCredentialRequestOptions

defaultPublicKeyCredentialRequestOptions :: PublicKeyCredentialRequestOptions Incomplete
defaultPublicKeyCredentialRequestOptions = PublicKeyCredentialRequestOptions
  { challenge = ()
  , timeout = Nothing
  , rpId = Nothing
  , allowCredentials = Nothing
  , userVerification = Nothing
  }

instance t ~ Complete => ToJSON (PublicKeyCredentialRequestOptions t) where
  toEncoding = J.genericToEncoding defaultOptions { omitNothingFields = True}
  toJSON = J.genericToJSON defaultOptions { omitNothingFields = True}

data COSEAlgorithmIdentifier
  = ES256 -- (-7)
  | RS256 -- (-257)
  | PS256 -- (-37)
  deriving stock (Show, Eq)

instance ToJSON COSEAlgorithmIdentifier where
  toJSON ES256 = Number (-7)
  toJSON RS256 = Number (-257)
  toJSON PS256 = Number (-37)

pubKeyCredAlgFromInt32 :: Int32 -> Maybe COSEAlgorithmIdentifier
pubKeyCredAlgFromInt32 = \case
  -7   -> Just ES256
  -257 -> Just RS256
  -37  -> Just PS256
  _    -> Nothing

-- | 5.8.1. Client Data Used in WebAuthn Signatures (dictionary CollectedClientData)
data CollectedClientData = CollectedClientData
  { typ :: WebAuthnType
  , challenge :: Challenge
  , origin :: Origin
  , tokenBinding :: Maybe TokenBinding
  }

instance FromJSON CollectedClientData where
  parseJSON = withObject "CollectedClientData" $ \obj -> CollectedClientData
    <$> obj .: "type"
    <*> obj .: "challenge"
    <*> obj .: "origin"
    <*> (obj .:? "tokenBinding") -- state of the Token Binding protocol (unsupported)


data TokenBinding = TokenBindingSupported
  | TokenBindingPresent !Text
  deriving (Eq, Show)

instance FromJSON TokenBinding where
  parseJSON = withText "TokenBinding" $ \case
    "supported" -> pure TokenBindingSupported -- TODO: FIXME
    _ -> fail "unknown TokenBinding"

data WebAuthnType = WebAuthnCreate | WebAuthnGet
  deriving (Show, Eq, Ord)

instance FromJSON WebAuthnType where
  parseJSON = withText "WebAuthnType" $ \case
    "webauthn.create" -> pure WebAuthnCreate
    "webauthn.get" -> pure WebAuthnGet
    _ -> fail "unknown WebAuthnType"

-- | Origin as described in 5.8.1.
--
-- See RFC6454
--
-- https://www.w3.org/TR/webauthn-2/#dom-collectedclientdata-origin
--
-- TODO: this should probably network-uri or so
data Origin = Origin
  { scheme :: Text
  , host :: Text
  , port :: Maybe Int
  }
  deriving (Show, Eq, Ord, Generic)

displayOrigin :: Origin -> Text
displayOrigin Origin{..} = scheme <> "://" <> host <> mkPort port
  where
    mkPort (Just int) = ":" <> T.pack (show int)
    mkPort Nothing = ""

parseOrigin :: MonadFail m => Text -> m Origin
parseOrigin str = case T.break (==':') str of
  (sch, url) -> case T.break (==':') $ T.drop 3 url of
    (host, portStr)
      | T.null portStr -> pure $ Origin sch host Nothing
      | otherwise -> case T.decimal $ T.drop 1 portStr of
        Left e -> fail e
        Right (port, _) -> pure $ Origin sch host $ Just port

instance ToJSON Origin where
  toJSON = String . displayOrigin

instance FromJSON Origin where
  parseJSON = withText "Origin" parseOrigin

-- | 5.8.6. User Verification Requirement Enumeration (enum UserVerificationRequirement)
data UserVerificationRequirement = Required | Preferred | Discouraged
  deriving stock (Show, Eq, Generic)

instance ToJSON UserVerificationRequirement where
  toJSON = String . \case
    Required -> "required"
    Preferred -> "preferred"
    Discouraged -> "discouraged"

-- | 6.1. Authenticator Data
data AuthenticatorData = AuthenticatorData
  { rpIdHash :: Digest SHA256
  , userPresent :: Bool
  , userVerified :: Bool
  , signCount :: SignCount
  , attestedCredentialData :: Maybe AttestedCredentialData
  , extensions :: Maybe ByteString
  }

newtype SignCount = SignCount { unSignCount :: Word32 }
  deriving newtype (Eq, Ord, Show, Num)

-- | 6.4.1. Attested Credential Data
data AttestedCredentialData = AttestedCredentialData
  { aaguid :: AAGUID
  , credentialId :: CredentialId
  , credentialPublicKey :: CredentialPublicKey
  } deriving (Show, Eq, Generic)

instance J.FromJSON AttestedCredentialData
instance J.ToJSON AttestedCredentialData

-- | 5.4.3. User Account Parameters for Credential Generation
data User = User
  { id :: Base64UrlByteString
  , displayName :: Text
  } deriving (Generic, Show, Eq)
  deriving anyclass (FromJSON, ToJSON)

instance CBOR.Serialise User where
  encode (User i d) = CBOR.encode $ Map.fromList
    ([("id" :: Text, CBOR.TBytes (unBase64UrlByteString i))]
      <> [("displayName" :: Text, CBOR.TString d)])
  decode = do
    m <- CBOR.decode
    CBOR.TBytes i <- maybe (fail "id") pure $ Map.lookup ("id" :: Text) m
    CBOR.TString d <-  maybe (fail "name") pure $ Map.lookup "displayName" m
    return $ User (Base64UrlByteString i) d

data VerificationFailure
  = InvalidType
  | MismatchedChallenge Challenge Challenge
  | MismatchedOrigin PublicKeyCredentialRpEntity Origin
  | UnexpectedPresenceOfTokenBinding
  | MismatchedTokenBinding
  | JSONDecodeError String
  | CBORDecodeError String CBOR.DeserialiseFailure
  | MismatchedRPID
  | UserNotPresent
  | UserUnverified
  | UnsupportedAttestationFormat Text
  | UnsupportedAlgorithm Int
  | MalformedPublicKey
  | MalformedAuthenticatorData Text
  | MalformedX509Certificate Text
  | MalformedSignature
  | SignatureFailure String
  | NonceCheckFailure
  | CredentialNotAllowed
  | InvalidSignCount
  deriving Show

-- | 5.1. PublicKeyCredential Interface
--
-- Extensions are not implemented.
data PublicKeyCredential response = PublicKeyCredential
  { id :: CredentialId
  , rawId :: Base64UrlByteString
  , response :: response
  , typ :: PublicKeyCredentialType
  } deriving stock (Show, Generic)

instance FromJSON response => FromJSON (PublicKeyCredential response) where
  parseJSON = withObject "PublicKeyCredential" $ \o ->
    PublicKeyCredential
      <$> o .: "id"
      <*> o .: "rawId"
      <*> o .: "response"
      <*> o .: "type"

-- | 5.2.1. Information About Public Key Credential (interface AuthenticatorAttestationResponse)
data AuthenticatorAttestationResponse = AuthenticatorAttestationResponse
  { clientDataJSON :: ByteString
  , attestationObject :: ByteString
  -- , transports :: [AuthenticatorTransport] -- TODO: should be a set?
  --, authenticatorData - omitted, stored inside attestationObject
  --, publicKey
  --, publicKeyAlgorithm
  }

instance FromJSON AuthenticatorAttestationResponse where
  parseJSON = withObject "AuthenticatorAttestationResponse" $ \o ->
    AuthenticatorAttestationResponse
      <$> fmap unBase64UrlByteString (o .: "clientDataJSON")
      <*> fmap unBase64UrlByteString (o .: "attestationObject")
--      <*> o .: "transports"

data PublicKeyCredentialType = PublicKey deriving (Eq, Show, Generic)

instance FromJSON PublicKeyCredentialType where
  parseJSON = J.withText "PublicKeyCredentialType" $ \case
    "public-key" -> pure PublicKey
    x -> fail $ "PublicKeyCredentialType: unsuppored type: " <> show x

instance ToJSON PublicKeyCredentialType where
  toJSON PublicKey = String "public-key"

data AuthenticatorTransport = USB -- usb
    | NFC -- nfc
    | BLE -- ble
    | Internal -- internal
  deriving (Eq, Show, Generic)

instance FromJSON AuthenticatorTransport where
  parseJSON = genericParseJSON defaultOptions { sumEncoding = UntaggedValue, constructorTagModifier = fmap toLower }

instance ToJSON AuthenticatorTransport where
  toEncoding = genericToEncoding defaultOptions { sumEncoding = UntaggedValue, constructorTagModifier = fmap toLower }
  toJSON = genericToJSON defaultOptions { sumEncoding = UntaggedValue, constructorTagModifier = fmap toLower }

data PublicKeyCredentialDescriptor = PublicKeyCredentialDescriptor
  { typ :: PublicKeyCredentialType
  , id :: CredentialId
  , transports :: Maybe (NonEmpty AuthenticatorTransport)
  } deriving (Eq, Show, Generic)

instance ToJSON PublicKeyCredentialDescriptor where
  toJSON PublicKeyCredentialDescriptor{ typ, id = credId, transports } = object $
    [ "type" .= toJSON typ
    , "id" .= toJSON credId
    ] ++ mtransports
    where
      mtransports = maybe [] (\x -> [ "transports" .= toJSON x ]) transports

type Extensions = Void

data AuthenticatorSelection = AuthenticatorSelection {
  authenticatorAttachment :: Maybe AuthenticatorAttachment
  , requireResidentKey :: Maybe Bool
  , requireUserVerification :: Maybe UserVerificationRequirement
} deriving (Show, Eq, Generic)

instance ToJSON AuthenticatorSelection where
  toEncoding = genericToEncoding defaultOptions { omitNothingFields = True }
  toJSON = genericToJSON defaultOptions { omitNothingFields = True }

-- | https://www.w3.org/TR/webauthn-1/#sctn-rp-credential-params
newtype PublicKeyCredentialRpEntity = PublicKeyCredentialRpEntity { id :: Text }
  deriving (Show, Eq, Generic)
  deriving newtype (FromJSON, ToJSON)
  deriving newtype IsString

originToRelyingParty :: Origin -> PublicKeyCredentialRpEntity
originToRelyingParty Origin{host} = PublicKeyCredentialRpEntity host

-- | https://html.spec.whatwg.org/multipage/origin.html#is-a-registrable-domain-suffix-of-or-is-equal-to
isRegistrableDomainSuffixOfOrIsEqualTo :: PublicKeyCredentialRpEntity -> Origin -> Bool
isRegistrableDomainSuffixOfOrIsEqualTo (PublicKeyCredentialRpEntity hostSuffixString) Origin{host = originalHost}
  = not (T.null hostSuffixString)
  && isSuffixOf (T.splitOn "." hostSuffixString) (T.splitOn "." originalHost)

-- | 5.2.2. Web Authentication Assertion (interface AuthenticatorAssertionResponse)
--
-- This is raw, no fields are parsed.
data AuthenticatorAssertionResponse = AuthenticatorAssertionResponse
  { clientDataJSON :: ByteString
  , authenticatorData :: ByteString
  , signature :: ByteString
  , userHandler :: Maybe ByteString
  } deriving stock (Eq, Show, Generic)

instance FromJSON AuthenticatorAssertionResponse where
  parseJSON = withObject "AuthenticatorAssertionResponse" $ \o ->
    AuthenticatorAssertionResponse
      <$> fmap unBase64UrlByteString (o .: "clientDataJSON")
      <*> fmap unBase64UrlByteString (o .: "authenticatorData")
      <*> fmap unBase64UrlByteString (o .: "signature")
      <*> fmap (fmap unBase64UrlByteString) (o .:? "userHandler")

-- | 5.3. Parameters for Credential Generation (dictionary PublicKeyCredentialParameters)
data PublicKeyCredentialParameters = PublicKeyCredentialParameters
  { typ :: PublicKeyCredentialType
  , alg :: COSEAlgorithmIdentifier
  } deriving stock (Eq, Show, Generic)

instance ToJSON PublicKeyCredentialParameters where
  toJSON PublicKeyCredentialParameters{..} = object
    [ "type" .= toJSON typ
    , "alg" .= toJSON alg
    ]

data PublicKeyCredentialCreationOptions t = PublicKeyCredentialCreationOptions
  { rp :: Required t PublicKeyCredentialRpEntity
  , user :: Required t User
  , challenge :: Required t Challenge
  , pubKeyCredParams :: NonEmpty PublicKeyCredentialParameters
  , timeout :: Maybe Integer
  , excludeCredentials :: Maybe [PublicKeyCredentialDescriptor]
  , authenticatorSelection :: Maybe AuthenticatorSelection
  , attestation :: Maybe AttestationConveyancePreference
  , extensions :: Maybe Extensions
  } deriving Generic

deriving instance Show (PublicKeyCredentialCreationOptions Complete)
deriving instance Eq (PublicKeyCredentialCreationOptions Complete)

instance t ~ Complete => ToJSON (PublicKeyCredentialCreationOptions t) where
  toEncoding = genericToEncoding defaultOptions { omitNothingFields = True }
  toJSON = genericToJSON defaultOptions { omitNothingFields = True }

instance t ~ Incomplete => Default (PublicKeyCredentialCreationOptions t) where
  def = defaultPublicKeyCredentialCreationOptions

defaultPublicKeyCredentialCreationOptions
  :: PublicKeyCredentialCreationOptions Incomplete
defaultPublicKeyCredentialCreationOptions = PublicKeyCredentialCreationOptions
  { rp = ()
  , challenge = ()
  , user = ()
  , timeout = Nothing
  , pubKeyCredParams = PublicKeyCredentialParameters PublicKey <$> NE.fromList [ES256, RS256]
  , attestation = Nothing
  , extensions = Nothing
  , authenticatorSelection = Nothing
  , excludeCredentials = Nothing
  }

instance HasField "requireUserVerification" (PublicKeyCredentialCreationOptions t) Bool where
  getField PublicKeyCredentialCreationOptions{..} = fromMaybe False $ do
    AuthenticatorSelection{..} <- authenticatorSelection
    uv <- requireUserVerification
    pure $ case uv of
      Discouraged -> False
      _ -> True
