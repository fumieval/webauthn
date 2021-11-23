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
module WebAuthn.Types (
  -- * Relying party
  Origin(..)
  , displayOrigin
  , parseOrigin
  , TokenBinding(..)
  -- Challenge
  , Challenge(..)
  , WebAuthnType(..)
  , CollectedClientData(..)
  , UserVerificationRequirement(..)
  , AuthenticatorData(..)
  -- * Credential
  , AttestedCredentialData(..)
  , AAGUID(..)
  , CredentialPublicKey(..)
  , CredentialId(..)
  , User(..)
  , PublicKeyCredential(..)
  -- * Exception
  , VerificationFailure(..)
  -- * Types
  , AuthenticatorAttestationResponse(..)
  , AndroidSafetyNet(..)
  , StmtSafetyNet(..)
  , JWTHeader(..)
  , Base64UrlByteString(..)
  , PublicKeyCredentialRequestOptions(..)
  , PublicKeyCredentialDescriptor(..)
  , AuthenticatorTransport(..)
  , PublicKeyCredentialType(..)
  , PublicKeyCredentialRpEntity(..)
  , originToRelyingParty
  , isRegistrableDomainSuffixOfOrIsEqualTo
  , PublicKeyCredentialCreationOptions(..)
  , defaultPublicKeyCredentialCreationOptions
  , Attestation (..)
  , Extensions (..)
  , AuthenticatorSelection (..)
  , PubKeyCredAlg (..)
  , pubKeyCredAlgFromInt32
  , AuthnSel(..)
  , BiometricPerfBounds(..)
  , AuthenticatorAttachment(..)
  , SignCount(..)
  , AuthenticatorAssertionResponse(..)
  ) where

import Prelude hiding (fail)
import Data.Aeson as J
    (Value(..),
      (.:),
      (.:?),
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
import Data.Char ( toLower, toUpper )
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
import Data.X509 qualified as X509
import Deriving.Aeson
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
data Attestation = None | Direct | Indirect | Enterprise
  deriving stock (Eq, Show, Generic)

instance ToJSON Attestation where
  toJSON = J.String . \case
    None -> "none"
    Direct -> "direct"
    Indirect -> "indirect"
    Enterprise -> "enterprise"

-- | 5.5. Options for Assertion Generation (dictionary PublicKeyCredentialRequestOptions)
--
-- extensions omitted as support is minimal:
-- https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialRequestOptions/extensions
data PublicKeyCredentialRequestOptions = PublicKeyCredentialRequestOptions
  { challenge :: Challenge
  , timeout :: Maybe Word32
  , rpId :: Maybe Text
  , allowCredentials :: Maybe (NonEmpty PublicKeyCredentialDescriptor)
  , userVerification :: Maybe UserVerificationRequirement
  } deriving stock (Eq, Show, Generic)

instance ToJSON PublicKeyCredentialRequestOptions where
  toEncoding = J.genericToEncoding defaultOptions { omitNothingFields = True}
  toJSON = J.genericToJSON defaultOptions { omitNothingFields = True}

data PubKeyCredAlg
  = ES256 -- (-7)
  | RS256 -- (-257)
  | PS256 -- (-37)
  deriving stock (Show, Eq)

instance ToJSON PubKeyCredAlg where
  toJSON ES256 = Number (-7)
  toJSON RS256 = Number (-257)
  toJSON PS256 = Number (-37)

pubKeyCredAlgFromInt32 :: Int32 -> Maybe PubKeyCredAlg
pubKeyCredAlgFromInt32 = \case
  -7   -> Just ES256
  -257 -> Just RS256
  -37  -> Just PS256
  _    -> Nothing

-- | 5.8.1. Client Data Used in WebAuthn Signatures (dictionary CollectedClientData)
data CollectedClientData = CollectedClientData
  { _type :: WebAuthnType
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
  { id :: Text
  , rawId :: Base64UrlByteString
  , response :: response
  , typ :: PublicKeyCredentialType
  } deriving stock (Show, Generic)


-- | 5.2.1. Information About Public Key Credential (interface AuthenticatorAttestationResponse)
data AuthenticatorAttestationResponse = AuthenticatorAttestationResponse
  { clientDataJSON :: ByteString
  , attestationObject :: ByteString
  , transports :: [ByteString] -- TODO: should be a set?
  --, authenticatorData - omitted, stored inside attestationObject
  --, publicKey 
  --, publicKeyAlgorithm 
  }

data AndroidSafetyNet = AndroidSafetyNet
  { timestampMs :: Integer
  , nonce :: [Char]
  , apkPackageName :: Text
  , apkCertificateDigestSha256 :: [Text]
  , ctsProfileMatch :: Bool
  , basicIntegrity :: Bool
  } deriving stock (Show, Generic)
    deriving anyclass (FromJSON)

data StmtSafetyNet = StmtSafetyNet
  { header :: Base64UrlByteString
  , payload :: Base64UrlByteString
  , signature_ :: ByteString
  , certificates :: X509.CertificateChain
  } deriving stock Show

data JWTHeader = JWTHeader
  { alg :: Text
  , x5c :: [Text]
  } deriving (Show, Generic)

instance FromJSON JWTHeader

data PublicKeyCredentialType = PublicKey deriving (Eq, Show, Generic)

instance ToJSON PublicKeyCredentialType where
  toJSON PublicKey = String "public-key"

data AuthenticatorTransport = USB -- usb
    | NFC -- nfc
    | BLE -- ble
    | Internal -- internal
  deriving (Eq, Show, Generic)

instance ToJSON AuthenticatorTransport where
  toEncoding = genericToEncoding defaultOptions { sumEncoding = UntaggedValue, constructorTagModifier = fmap toLower }
  toJSON = genericToJSON defaultOptions { sumEncoding = UntaggedValue, constructorTagModifier = fmap toLower }

data PublicKeyCredentialDescriptor = PublicKeyCredentialDescriptor
  { _type :: PublicKeyCredentialType
  , id :: CredentialId
  , transports :: Maybe (NonEmpty AuthenticatorTransport)
  } deriving (Eq, Show, Generic)
  deriving ToJSON via CustomJSON '[FieldLabelModifier (StripPrefix "_", CamelToSnake), OmitNothingFields] PublicKeyCredentialDescriptor

newtype AuthnSel = AuthnSel [Base64UrlByteString] deriving (Show, Eq, Generic)

instance ToJSON AuthnSel where
  toEncoding = J.genericToEncoding defaultOptions { unwrapUnaryRecords = True }
  toJSON = J.genericToJSON defaultOptions { unwrapUnaryRecords = True }

data BiometricPerfBounds = BiometricPerfBounds
  { far :: Double
  , frr :: Double
  } deriving stock (Show, Eq, Generic)

instance ToJSON BiometricPerfBounds where
  toEncoding = J.genericToEncoding defaultOptions { fieldLabelModifier = fmap toUpper }
  toJSON = J.genericToJSON defaultOptions { fieldLabelModifier = fmap toUpper }

data Extensions = Extensions
  { uvi :: Bool
  , loc :: Bool
  , uvm :: Bool
  , exts :: Bool
  , authnSel :: Maybe AuthnSel
  , biometricPerfBounds :: Maybe BiometricPerfBounds
  } deriving stock (Show, Eq, Generic)

instance ToJSON Extensions where
  toEncoding = genericToEncoding defaultOptions { omitNothingFields = True }
  toJSON = genericToJSON defaultOptions { omitNothingFields = True }

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
  deriving anyclass (FromJSON, ToJSON)
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
      <*> fmap (fmap unBase64UrlByteString) (o .: "userHandler")

data PublicKeyCredentialCreationOptions t = PublicKeyCredentialCreationOptions
  { rp :: Required t PublicKeyCredentialRpEntity
  , user :: Required t User
  , challenge :: Required t Challenge
  , pubKeyCredParams :: NonEmpty PubKeyCredAlg
  , timeout :: Maybe Integer
  , excludeCredentials :: Maybe [PublicKeyCredentialDescriptor]
  , authenticatorSelection :: Maybe AuthenticatorSelection
  , attestation :: Maybe Attestation
  , extensions :: Maybe Extensions
  } deriving Generic

deriving instance Show (PublicKeyCredentialCreationOptions Complete)
deriving instance Eq (PublicKeyCredentialCreationOptions Complete)
deriving via CustomJSON '[OmitNothingFields] (PublicKeyCredentialCreationOptions t)
  instance t ~ Complete => ToJSON (PublicKeyCredentialCreationOptions t)

defaultPublicKeyCredentialCreationOptions
  :: PublicKeyCredentialCreationOptions Incomplete
defaultPublicKeyCredentialCreationOptions = PublicKeyCredentialCreationOptions
  { rp = ()
  , challenge = ()
  , user = ()
  , timeout = Nothing
  , pubKeyCredParams = NE.fromList [ES256, RS256]
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
