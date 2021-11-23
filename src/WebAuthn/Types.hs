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
  , AuthenticatorData(..)
  -- * Credential
  , AttestedCredentialData(..)
  , AAGUID(..)
  , CredentialPublicKey(..)
  , CredentialId(..)
  , User(..)
  -- * Exception
  , VerificationFailure(..)
  , AndroidSafetyNet(..)
  , StmtSafetyNet(..)
  , JWTHeader(..)
  , Base64ByteString(..)
  , PublicKeyCredentialDescriptor(..)
  , AuthenticatorTransport(..)
  , PublicKeyCredentialType(..)
  , PublicKeyCredentialRpEntity(..)
  , originToRelyingParty
  , isRegistrableDomainSuffixOfOrIsEqualTo
  , CredentialCreationOptions(..)
  , defaultCredentialCreationOptions
  , Attestation (..)
  , Extensions (..)
  , AuthenticatorSelection (..)
  , UserVerification (..)
  , PubKeyCredAlg (..)
  , pubKeyCredAlgFromInt
  , AuthnSel(..)
  , BiometricPerfBounds(..)
  , AuthenticatorAttachment(..)
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
    )

import Codec.CBOR.Read qualified as CBOR
import Codec.CBOR.Term qualified as CBOR
import Codec.Serialise qualified as CBOR
import Control.Monad.Fail ( MonadFail(fail) )
import Crypto.Hash ( SHA256, Digest )
import Data.Aeson (SumEncoding(UntaggedValue))
import Data.Aeson (genericToJSON)
import Data.ByteString (ByteString)
import Data.Char ( toLower, toUpper )
import Data.List (isSuffixOf)
import Data.List.NonEmpty as NE
import Data.Map qualified as Map
import Data.Maybe
import Data.String
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.Read qualified as T
import Data.X509 qualified as X509
import Deriving.Aeson
import GHC.Records
import WebAuthn.Base

-- | 5.10.1. Client Data Used in WebAuthn Signatures (dictionary CollectedClientData)
data CollectedClientData = CollectedClientData
  { _type :: WebAuthnType
  , challenge :: Challenge
  , origin :: Origin
  , tokenBinding :: TokenBinding
  }

instance FromJSON CollectedClientData where
  parseJSON = withObject "CollectedClientData" $ \obj -> CollectedClientData
    <$> obj .: "type"
    <*> obj .: "challenge"
    <*> obj .: "origin"
    <*> fmap (fromMaybe TokenBindingUnsupported) (obj .:? "tokenBinding") -- state of the Token Binding protocol (unsupported)


data TokenBinding = TokenBindingUnsupported
  | TokenBindingSupported
  | TokenBindingPresent !Text

instance FromJSON TokenBinding where
  parseJSON = withText "TokenBinding" $ \case
    "supported" -> pure TokenBindingSupported -- FIXME
    _ -> fail "unknown TokenBinding"

data WebAuthnType = Create | Get
  deriving (Show, Eq, Ord)

instance FromJSON WebAuthnType where
  parseJSON = withText "WebAuthnType" $ \case
    "webauthn.create" -> pure Create
    "webauthn.get" -> pure Get
    _ -> fail "unknown WebAuthnType"

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

-- | 6.1. Authenticator Data
data AuthenticatorData = AuthenticatorData
  { rpIdHash :: Digest SHA256
  , userPresent :: Bool
  , userVerified :: Bool
  , attestedCredentialData :: Maybe AttestedCredentialData
  , authenticatorDataExtension :: ByteString
  }

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
  { id :: Base64ByteString
  , displayName :: Text
  } deriving (Generic, Show, Eq)
  deriving anyclass (FromJSON, ToJSON)

instance CBOR.Serialise User where
  encode (User i d) = CBOR.encode $ Map.fromList
    ([("id" :: Text, CBOR.TBytes (unBase64ByteString i))]
      <> [("displayName" :: Text, CBOR.TString d)])
  decode = do
    m <- CBOR.decode
    CBOR.TBytes i <- maybe (fail "id") pure $ Map.lookup ("id" :: Text) m
    CBOR.TString d <-  maybe (fail "name") pure $ Map.lookup "displayName" m
    return $ User (Base64ByteString i) d

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
  deriving Show

data AndroidSafetyNet = AndroidSafetyNet
  { timestampMs :: Integer
  , nonce :: [Char]
  , apkPackageName :: Text
  , apkCertificateDigestSha256 :: [Text]
  , ctsProfileMatch :: Bool
  , basicIntegrity :: Bool
  } deriving (Show, Generic)

instance  FromJSON AndroidSafetyNet

data StmtSafetyNet = StmtSafetyNet
  { header :: Base64ByteString
  , payload :: Base64ByteString
  , signature_ :: ByteString
  , certificates :: X509.CertificateChain
  } deriving Show

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
  , id :: Base64ByteString
  , transports :: Maybe (NonEmpty AuthenticatorTransport)
  } deriving (Eq, Show, Generic)
  deriving ToJSON via CustomJSON '[FieldLabelModifier (StripPrefix "_", CamelToSnake), OmitNothingFields] PublicKeyCredentialDescriptor

data UserVerification = Required | Preferred | Discouraged deriving (Show, Eq, Generic)

instance ToJSON UserVerification where
  toEncoding = genericToEncoding defaultOptions { sumEncoding = UntaggedValue, constructorTagModifier = fmap toLower }
  toJSON = genericToJSON defaultOptions { sumEncoding = UntaggedValue, constructorTagModifier = fmap toLower }

data PubKeyCredAlg = ES256 -- -7
  | RS256 -- (-257)
  | PS256 -- (-37)
  deriving (Show, Eq, Generic)

instance ToJSON PubKeyCredAlg where
  toJSON ES256 = Number (-7)
  toJSON RS256 = Number (-257)
  toJSON PS256 = Number (-37)

pubKeyCredAlgFromInt :: Int -> Maybe PubKeyCredAlg
pubKeyCredAlgFromInt = \case -7 -> Just ES256
                             -257 -> Just RS256
                             -37 -> Just PS256
                             _ -> Nothing

data Attestation = None | Direct | Indirect deriving (Eq, Show, Generic)

instance ToJSON Attestation where
  toEncoding = genericToEncoding defaultOptions { sumEncoding = UntaggedValue, constructorTagModifier = fmap  toLower }
  toJSON = genericToJSON defaultOptions { sumEncoding = UntaggedValue, constructorTagModifier = fmap  toLower }

newtype AuthnSel = AuthnSel [Base64ByteString] deriving (Show, Eq, Generic)

instance ToJSON AuthnSel where
  toEncoding = genericToEncoding defaultOptions { unwrapUnaryRecords = True }
  toJSON = genericToJSON defaultOptions { unwrapUnaryRecords = True }

data BiometricPerfBounds = BiometricPerfBounds {
  far :: Double
  , frr :: Double
} deriving (Show, Eq, Generic)

instance ToJSON BiometricPerfBounds where
  toEncoding = genericToEncoding defaultOptions { fieldLabelModifier = fmap toUpper }
  toJSON = genericToJSON defaultOptions { fieldLabelModifier = fmap toUpper }

data Extensions = Extensions {
  uvi :: Bool
  , loc :: Bool
  , uvm :: Bool
  , exts :: Bool
  , authnSel :: Maybe AuthnSel
  , biometricPerfBounds :: Maybe BiometricPerfBounds
} deriving (Show, Eq, Generic)

instance ToJSON Extensions where
  toEncoding = genericToEncoding defaultOptions { omitNothingFields = True }
  toJSON = genericToJSON defaultOptions { omitNothingFields = True }

data AuthenticatorAttachment = Platform | CrossPlatform deriving (Eq, Show, Generic)

instance ToJSON AuthenticatorAttachment where
  toJSON Platform = String "platform"
  toJSON CrossPlatform = String "cross-platform"

data AuthenticatorSelection = AuthenticatorSelection {
  authenticatorAttachment :: Maybe AuthenticatorAttachment
  , requireResidentKey :: Maybe Bool
  , requireUserVerification :: Maybe UserVerification
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

data CredentialCreationOptions t = CredentialCreationOptions
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

deriving instance Show (CredentialCreationOptions Complete)
deriving instance Eq (CredentialCreationOptions Complete)
deriving via CustomJSON '[OmitNothingFields] (CredentialCreationOptions t)
  instance t ~ Complete => ToJSON (CredentialCreationOptions t)

defaultCredentialCreationOptions
  :: CredentialCreationOptions Incomplete
defaultCredentialCreationOptions = CredentialCreationOptions
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

instance HasField "requireUserVerification" (CredentialCreationOptions t) Bool where
  getField CredentialCreationOptions{..} = fromMaybe False $ do
    AuthenticatorSelection{..} <- authenticatorSelection
    uv <- requireUserVerification
    pure $ case uv of
      Discouraged -> False
      _ -> True
