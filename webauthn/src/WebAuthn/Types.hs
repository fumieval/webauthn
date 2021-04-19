{-# LANGUAGE StrictData #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingVia #-}

module WebAuthn.Types where

import Prelude hiding (fail)
import Data.Aeson
    ( (.:)
    , (.:?)
    , withObject
    , withText
    , FromJSON(..)
    , ToJSON(..)
    , Options(..)
    , defaultOptions
    , object
    , (.=)
    )
import qualified Data.Aeson as AE
import Data.ByteString (ByteString)
import qualified Data.ByteString.Base64.URL as B64URL
import qualified Data.Hashable as H
import Data.Text (Text)
import Data.Text.Encoding (decodeUtf8, encodeUtf8)
import qualified Data.Text as T
import qualified Data.Text.Read as T
import Crypto.Hash (SHA256, Digest)
import qualified Codec.CBOR.Read as CBOR
import qualified Codec.Serialise as CBOR
import Control.Monad.Fail ( MonadFail(fail) )
import Data.ByteArray (ByteArrayAccess)
import Data.List.NonEmpty (NonEmpty)
import qualified Data.List.NonEmpty as NE
import GHC.Generics (Generic)
import Data.Word (Word16, Word32)
import Data.Int (Int32)
import Data.Void ( Void )


-- | RFC4648, Secion 5 with all trailing '=' characters omitted (as permitted by 3.2)
--
-- https://www.w3.org/TR/webauthn-2/#base64url-encoding
newtype Base64UrlByteString = Base64UrlByteString { unBase64UrlByteString :: ByteString }
  deriving stock (Eq, Generic)
  deriving newtype (ByteArrayAccess)

instance Show Base64UrlByteString where
  show = show . B64URL.encodeBase64Unpadded . unBase64UrlByteString

instance ToJSON Base64UrlByteString where
  toJSON = AE.String . decodeUtf8 . B64URL.encodeBase64Unpadded' . unBase64UrlByteString

instance FromJSON Base64UrlByteString where
  parseJSON = withText "Base64UrlByteString" $ \v ->
    case B64URL.decodeBase64Unpadded (encodeUtf8 v) of
      Left err -> fail $ T.unpack $ "Base64UrlByteString: " <> err
      Right s -> pure (Base64UrlByteString s)

data VerificationFailure
  = InvalidType
  | MismatchedChallenge Challenge Challenge
  | MismatchedOrigin Origin Origin
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
  | MalformedAuthenticatorData
  | MalformedX509Certificate Text
  | MalformedSignature
  | SignatureFailure String
  | NonceCheckFailure
  -- 7.2 step 21. Relying Party may decide to fail authentication if signCount > storedSignCount
  | InvalidSignCount
  -- 7.2 step 5. credential.id is not present in options.allowCredentials
  | CredentialNotAllowed
  deriving stock (Show, Eq)

-- | 5.1. PublicKeyCredential Interface
--
-- Extensions are not implemented.
-- Use with AuthenticatorAttestationResponse or AuthenticatorAssertionResponse.
data PublicKeyCredential response = PublicKeyCredential
  { id :: Text
  , rawId :: Base64UrlByteString
  , response :: response
  , typ :: PublicKeyCredentialType
  } deriving stock (Show)

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
  --, transports :: [ByteString] -- TODO: should be a set?
  --, authenticatorData - omitted, stored inside attestationObject
  --, publicKey 
  --, publicKeyAlgorithm 
  } deriving (Eq, Show)

instance FromJSON AuthenticatorAttestationResponse where
  parseJSON = withObject "AuthenticatorAttestationResponse" $ \o ->
    AuthenticatorAttestationResponse
      <$> fmap unBase64UrlByteString (o .: "clientDataJSON")
      <*> fmap unBase64UrlByteString (o .: "attestationObject")

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

-- | 5.3. Parameters for Credential Generation (dictionary PublicKeyCredentialParameters)
data PublicKeyCredentialParameters = PublicKeyCredentialParameters
  { typ :: PublicKeyCredentialType
  , alg :: COSEAlgorithmIdentifier
  } deriving stock (Eq, Show, Generic)

instance ToJSON PublicKeyCredentialParameters where
  toJSON PublicKeyCredentialParameters{..} = AE.object
    [ "type" .= toJSON typ
    , "alg" .= toJSON alg
    ]

-- | 5.4. Options for Credential Creation (dictionary PublicKeyCredentialCreationOptions)
data PublicKeyCredentialCreationOptions = PublicKeyCredentialCreationOptions
  { rp :: PublicKeyCredentialRpEntity
  , user :: PublicKeyCredentialUserEntity
  , challenge :: Challenge
  , pubKeyCredParams :: NonEmpty PublicKeyCredentialParameters
  , timeout :: Maybe Word32
  , excludeCredentials :: Maybe (NonEmpty PublicKeyCredentialDescriptor)
  , authenticatorSelection :: Maybe AuthenticatorSelection
  , attestation :: Maybe AttestationConveyancePreference 
  , extensions :: Maybe Extensions
  } deriving stock (Eq, Show, Generic)

instance ToJSON PublicKeyCredentialCreationOptions where
  toEncoding = AE.genericToEncoding AE.defaultOptions { omitNothingFields = True }
  toJSON = AE.genericToJSON AE.defaultOptions { omitNothingFields = True }

defaultCredentialCreationOptions
  :: PublicKeyCredentialRpEntity
  -> PublicKeyCredentialUserEntity
  -> Challenge
  -> PublicKeyCredentialCreationOptions
defaultCredentialCreationOptions rp user challenge =
  PublicKeyCredentialCreationOptions
    { pubKeyCredParams = PublicKeyCredentialParameters PublicKey ES256 NE.:| []
    , timeout = Just 60000
    , excludeCredentials = Nothing
    , authenticatorSelection = Nothing
    , attestation = Nothing
    , extensions = Nothing
    , ..
    }

-- | 5.4.2. Relying Party Parameters for Credential Generation (dictionary PublicKeyCredentialRpEntity)
data PublicKeyCredentialRpEntity = PublicKeyCredentialRpEntity
  { id :: Maybe RpId
  , name :: Text
  } deriving stock (Show, Eq, Generic)

instance ToJSON PublicKeyCredentialRpEntity where
  toJSON (PublicKeyCredentialRpEntity rpid name) = object $
    ("name" .= toJSON name) : maybe [] (\x -> ["id" .= toJSON x]) rpid

newtype RpId = RpId { unRpId :: Text }
  deriving newtype (Eq, Show, ToJSON, FromJSON)

-- | 5.4.3. User Account Parameters for Credential Generation (dictionary PublicKeyCredentialUserEntity)
data PublicKeyCredentialUserEntity = PublicKeyCredentialUserEntity
  { id :: UserId
  , name :: Text
  , displayName :: Text
  } deriving stock (Show, Eq, Generic)
    deriving anyclass (ToJSON)

newtype UserId = UserId { unUserId :: ByteString }
  deriving newtype (Eq, Show)
  deriving (ToJSON) via Base64UrlByteString

-- | 5.4.4. Authenticator Selection Criteria (dictionary AuthenticatorSelectionCriteria)
data AuthenticatorSelection = AuthenticatorSelection
  { authenticatorAttachment :: Maybe AuthenticatorAttachment
  , residentKey :: Maybe ResidentKeyRequirement
  -- | This member is retained for backwards compatibility with WebAuthn Level 1 and, for historical reasons, its naming
  -- retains the deprecated “resident” terminology for discoverable credentials. Relying Parties SHOULD set it to true
  -- if, and only if, residentKey is set to required.
  , requireResidentKey :: Maybe Bool
  , userVerification :: Maybe UserVerificationRequirement
  } deriving stock (Show, Eq, Generic)

instance ToJSON AuthenticatorSelection where
  toEncoding = AE.genericToEncoding defaultOptions { omitNothingFields = True }
  toJSON = AE.genericToJSON defaultOptions { omitNothingFields = True }

-- | 5.4.5. Authenticator Attachment Enumeration (enum AuthenticatorAttachment)
data AuthenticatorAttachment = Platform | CrossPlatform
  deriving stock (Eq, Show)

instance ToJSON AuthenticatorAttachment where
  toJSON = AE.String . \case
    Platform -> "platform"
    CrossPlatform -> "cross-platform"

-- | 5.4.6. Resident Key Requirement Enumeration (enum ResidentKeyRequirement)
data ResidentKeyRequirement
  = ResidentKeyDiscouraged
  | ResidentKeyPreferred
  | ResidentKeyRequired
  deriving stock (Eq, Show)

instance ToJSON ResidentKeyRequirement where
  toJSON = AE.String . \case
    ResidentKeyDiscouraged -> "discouraged"
    ResidentKeyPreferred -> "preferred"
    ResidentKeyRequired -> "required"

-- | 5.4.7. Attestation Conveyance Preference Enumeration (enum AttestationConveyancePreference)
data AttestationConveyancePreference = None | Direct | Indirect | Enterprise
  deriving stock (Eq, Show, Generic)

instance ToJSON AttestationConveyancePreference where
  toJSON = AE.String . \case
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
  , rpId :: Maybe RpId
  , allowCredentials :: Maybe (NonEmpty PublicKeyCredentialDescriptor)
  , userVerification :: Maybe UserVerificationRequirement
  } deriving stock (Eq, Show, Generic)

instance ToJSON PublicKeyCredentialRequestOptions where
  toEncoding = AE.genericToEncoding defaultOptions { omitNothingFields = True}
  toJSON = AE.genericToJSON defaultOptions { omitNothingFields = True}

-- | 5.8.5. Cryptographic Algorithm Identifier (typedef COSEAlgorithmIdentifier)
data COSEAlgorithmIdentifier
  = ES256 -- (-7)
  | RS256 -- (-257)
  | PS256 -- (-37)
  deriving stock (Show, Eq)

instance ToJSON COSEAlgorithmIdentifier where
  toJSON = AE.Number . \case
    ES256 -> (-7)
    RS256 -> (-257)
    PS256 -> (-37)

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
  , crossOrigin :: Maybe Bool
  , tokenBinding :: Maybe TokenBinding -- Nothing == no client support
  } deriving (Eq, Show)

instance FromJSON CollectedClientData where
  parseJSON = withObject "CollectedClientData" $ \o -> CollectedClientData
    <$> o .: "type"
    <*> o .: "challenge"
    <*> o .: "origin"
    <*> o .:? "crossOrigin"
    <*> o .:? "tokenBinding"

-- | 5.8.1 TokenBinding
--
-- https://www.w3.org/TR/webauthn-2/#dom-collectedclientdata-tokenbinding
data TokenBinding
  -- | Indicates the client supports token binding, but it was not negotiated when communicating with the Relying Party.
  = TokenBindingSupported
  -- | Indicates token binding was used when communicating with the Relying Party. In this case, the id member MUST be present.
  | TokenBindingPresent !Text
  deriving (Eq, Show)

instance FromJSON TokenBinding where
  parseJSON = withText "TokenBinding" $ \case
    "supported" -> pure TokenBindingSupported -- TODO: FIXME
    _ -> fail "unknown TokenBinding"

-- | Type as described in 5.8.1.
--
-- https://www.w3.org/TR/webauthn-2/#dom-collectedclientdata-type
data WebAuthnType = WebAuthnCreate | WebAuthnGet
  deriving stock (Show, Eq, Ord)

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
-- TODO: this should probably use network-uri or so
data Origin = Origin
  { originScheme :: Text
  , originHost :: Text
  , originPort :: Maybe Word16 -- TODO: port is only optional in text notation, should lookup default port for scheme if not present
  } deriving stock (Show, Eq, Ord, Generic)

-- RFC6454 Section 6.1
instance ToJSON Origin where
  toJSON Origin{..} = AE.String $ originScheme <> "://" <> originHost <> port originPort
    where
      port (Just x) = ":" <> T.pack (show x)
      port Nothing = ""

-- RFC6454 Section 4
instance FromJSON Origin where
  parseJSON = withText "Origin" $ \str -> case T.break (==':') str of
    (sch, url) -> case T.break (==':') $ T.drop 3 url of
      (host, portStr) -> do
        let lsch = T.toLower sch
            lhost = T.toLower host
        if T.null portStr
        then pure $ Origin lsch lhost Nothing
        else case T.decimal $ T.drop 1 portStr of
               Left e -> fail e
               Right (port, _) -> pure $ Origin lsch lhost $ Just port

-- | 5.8.2. Credential Type Enumeration (enum PublicKeyCredentialType)
data PublicKeyCredentialType = PublicKey
  deriving stock (Eq, Show)

instance ToJSON PublicKeyCredentialType where
  toJSON PublicKey = AE.String "public-key"

instance FromJSON PublicKeyCredentialType where
  parseJSON = AE.withText "PublicKeyCredentialType" $ \case
    "public-key" -> pure PublicKey
    x -> fail $ "PublicKeyCredentialType: unsuppored type: " <> show x

-- | 5.8.3. Credential Descriptor (dictionary PublicKeyCredentialDescriptor)
data PublicKeyCredentialDescriptor = PublicKeyCredentialDescriptor
  { typ :: PublicKeyCredentialType
  , id :: CredentialId
  , transports :: Maybe (NonEmpty AuthenticatorTransport)
  } deriving stock (Eq, Show, Generic)

instance ToJSON PublicKeyCredentialDescriptor where
  toJSON PublicKeyCredentialDescriptor{ typ, id = credId, transports } = AE.object $
    [ "type" .= toJSON typ
    , "id" .= toJSON credId
    ] ++ mtransports
    where
      mtransports = maybe [] (\x -> [ "transports" .= toJSON x ]) transports

-- | 5.8.4. Authenticator Transport Enumeration (enum AuthenticatorTransport)
data AuthenticatorTransport = Usb | Nfc | Ble | Internal
  deriving stock (Eq, Show)

instance ToJSON AuthenticatorTransport where
  toJSON = AE.String . \case
    Usb -> "usb"
    Nfc -> "nfc"
    Ble -> "ble"
    Internal -> "internal"

-- | 5.8.6. User Verification Requirement Enumeration (enum UserVerificationRequirement)
data UserVerificationRequirement = Required | Preferred | Discouraged
  deriving stock (Show, Eq, Generic)

instance ToJSON UserVerificationRequirement where
  toJSON = AE.String . \case
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
  } deriving stock (Eq, Show)

newtype SignCount = SignCount { unSignCount :: Word32 }
  deriving newtype (Eq, Ord, Show, Num)

-- | 6.5.1. Attested Credential Data
data AttestedCredentialData = AttestedCredentialData
  { aaguid :: AAGUID
  , credentialId :: CredentialId
  , credentialPublicKey :: CredentialPublicKey
  } deriving stock (Show, Eq, Generic)
    deriving anyclass (FromJSON, ToJSON)

-- | Credential ID as described in 6.5.1.
--
-- https://www.w3.org/TR/webauthn-2/#credential-id
newtype CredentialId = CredentialId { unCredentialId :: ByteString }
  deriving stock (Eq)
  deriving newtype (H.Hashable, CBOR.Serialise)
  deriving (Show, ToJSON, FromJSON) via Base64UrlByteString

-- | Credential public key encoded in COSE_Key format as described in 6.5.1.
--
-- https://www.w3.org/TR/webauthn-2/#credentialpublickey
newtype CredentialPublicKey = CredentialPublicKey { unCredentialPublicKey :: ByteString }
  deriving stock (Show, Eq)
  deriving newtype (H.Hashable, CBOR.Serialise)
  deriving (FromJSON, ToJSON) via Base64UrlByteString

-- | AAGUID of the authenticator as described in 6.5.1.
--
-- https://www.w3.org/TR/webauthn-2/#aaguid
--
-- TODO: confirm this *has* to be base16 encoded
newtype AAGUID = AAGUID { unAAGUID :: ByteString }
  deriving stock (Show, Eq)
  deriving (FromJSON, ToJSON) via Base64UrlByteString

-- | 13.4.3. Cryptographic Challenges
newtype Challenge = Challenge { unChallenge :: ByteString }
  deriving stock (Eq, Show, Generic)
  deriving newtype (H.Hashable, CBOR.Serialise)
  deriving (ToJSON, FromJSON) via Base64UrlByteString


-----------------------------------------------------------------------------
-- Everything below needs review
--
-- Some extensions described in Level 1 seem to be removed and new ones
-- appeared in Level 2

-- placeholder
type Extensions = Void

-- newtype AuthnSel = AuthnSel [Base64UrlByteString]
--   deriving stock (Show, Eq, Generic)
--
-- instance ToJSON AuthnSel where
--   toEncoding = AE.genericToEncoding defaultOptions { unwrapUnaryRecords = True }
--   toJSON = AE.genericToJSON defaultOptions { unwrapUnaryRecords = True }
--
-- data BiometricPerfBounds = BiometricPerfBounds
--   { far :: Double
--   , frr :: Double
--   } deriving stock (Show, Eq, Generic)
--
-- instance ToJSON BiometricPerfBounds where
--   toEncoding = AE.genericToEncoding defaultOptions { fieldLabelModifier = fmap toUpper }
--   toJSON = AE.genericToJSON defaultOptions { fieldLabelModifier = fmap toUpper }
--
-- data Extensions = Extensions
--   { uvi :: Bool
--   , loc :: Bool
--   , uvm :: Bool
--   , exts :: Bool
--   , authnSel :: Maybe AuthnSel
--   , biometricPerfBounds :: Maybe BiometricPerfBounds
--   } deriving stock (Show, Eq, Generic)
--
-- instance ToJSON Extensions where
--   toEncoding = AE.genericToEncoding defaultOptions { omitNothingFields = True }
--   toJSON = AE.genericToJSON defaultOptions { omitNothingFields = True }
