{-# LANGUAGE StrictData #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}
module WebAuthn.Types (
  -- * Relying party
  RelyingParty(..)
  , Origin(..)
  , defaultRelyingParty
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
  , PublicKeyCredentialRequestOptions(..)
  , PublicKeyCredentialDescriptor(..)
  , AuthenticatorTransport(..)
  , PublicKeyCredentialType(..)
  , PublicKeyCredentialCreationOptions(..)
  , PubKeyCredParam (..)
  , Attestation (..)
  , Extensions (..)
  , AuthenticatorSelection (..)
  , UserVerification (..)
  , PubKeyCredAlg (..)
  , AuthnSel
  , BiometricPerfBounds
  , AuthenticatorAttachment (..)
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
      , object
      , (.=)
    )
import Data.ByteString (ByteString)
import qualified Data.ByteString.Base64.URL as Base64
import Data.ByteString.Base16 as Base16 (decodeLenient, encode )
import qualified Data.Hashable as H
import qualified Data.Map as Map
import Data.Text (Text)
import Data.Text.Encoding ( decodeUtf8, encodeUtf8 )
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import qualified Data.Text.Read as T
import Crypto.Hash ( SHA256, Digest )
import qualified Codec.CBOR.Term as CBOR
import qualified Codec.CBOR.Read as CBOR
import qualified Codec.Serialise as CBOR
import Control.Monad.Fail ( MonadFail(fail) )
import GHC.Generics (Generic)
import qualified Data.X509 as X509
import Data.Aeson.Types (Pair, typeMismatch)
import Data.Char ( toLower, toUpper )
import Data.ByteArray (ByteArrayAccess)
import Data.Aeson (SumEncoding(UntaggedValue))
import Data.List.NonEmpty
import Data.Aeson (genericToJSON)
import Data.Aeson (genericParseJSON)

newtype Base64ByteString = Base64ByteString { unBase64ByteString :: ByteString } deriving (Generic, Show, Eq, ByteArrayAccess)

instance ToJSON Base64ByteString where
  toJSON (Base64ByteString bs) = String $ decodeUtf8 $ Base64.encode bs

instance FromJSON Base64ByteString where
  parseJSON s@(String v) = do
    let eth = Base64.decode (encodeUtf8 v)
    case eth of
      Left err -> typeMismatch ("Base64: " <> err) s
      Right str -> pure (Base64ByteString str)
  parseJSON oth = typeMismatch "Expecting String" oth

-- | 13.1. Cryptographic Challenges
newtype Challenge = Challenge { rawChallenge :: ByteString }
  deriving (Show, Eq, Ord, Generic, H.Hashable, CBOR.Serialise)

instance ToJSON Challenge where
  toJSON = toJSON . decodeUtf8 . Base64.encode . rawChallenge

instance FromJSON Challenge where
  parseJSON (String s) = (pure . Challenge . Base64.decodeLenient . encodeUtf8) s
  parseJSON oth = typeMismatch "Expecting String of Base64" oth


-- | 5.10.1. Client Data Used in WebAuthn Signatures (dictionary CollectedClientData)
data CollectedClientData = CollectedClientData
  { clientType :: WebAuthnType
  , clientChallenge :: Challenge
  , clientOrigin :: Origin
  , clientTokenBinding :: TokenBinding
  }

instance FromJSON CollectedClientData where
  parseJSON = withObject "CollectedClientData" $ \obj -> CollectedClientData
    <$> obj .: "type"
    <*> obj .: "challenge"
    <*> obj .: "origin"
-- | state of the Token Binding protocol (unsupported)
    <*> fmap (maybe TokenBindingUnsupported Prelude.id) (obj .:? "tokenBinding")

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
  { originScheme :: Text
  , originHost :: Text
  , originPort :: Maybe Int
  }
  deriving (Show, Eq, Ord, Generic)

instance ToJSON Origin where
  toJSON origin = String (originScheme origin <> "://" <> originHost origin <> port (originPort origin))
    where
      port (Just int) = ":" <> T.pack (show int)
      port Nothing = ""

-- | WebAuthn Relying Party
data RelyingParty = RelyingParty
  { rpOrigin :: Origin
  , rpId :: Text
  , icon :: Maybe Base64ByteString
  , name :: Text
  }
  deriving (Show, Eq, Generic)

instance ToJSON RelyingParty where
  toJSON rpo = object (["id" .= toJSON (rpId (rpo :: RelyingParty))] 
    <> maybeToPair "icon" (icon rpo)
    <> [ "name" .= name (rpo :: RelyingParty)])

maybeToPair :: Text -> Maybe Base64ByteString -> [Pair]
maybeToPair _ Nothing = []
maybeToPair lbl (Just bs) = [lbl .= toJSON bs]


defaultRelyingParty :: Origin -> Text -> RelyingParty
defaultRelyingParty orig = RelyingParty orig (originHost orig) Nothing

instance FromJSON Origin where
  parseJSON = withText "Origin" $ \str -> case T.break (==':') str of
    (sch, url) -> case T.break (==':') $ T.drop 3 url of
      (host, portStr)
        | T.null portStr -> pure $ Origin sch host Nothing
        | otherwise -> case T.decimal $ T.drop 1 portStr of
          Left e -> fail e
          Right (port, _) -> pure $ Origin sch host $ Just port

-- | 6.1. Authenticator Data
data AuthenticatorData = AuthenticatorData
  { rpIdHash :: Digest SHA256
  , userPresent :: Bool
  , userVerified :: Bool
  , attestedCredentialData :: Maybe AttestedCredentialData
  , authenticatorDataExtension :: ByteString
  }

-- | A probabilistically-unique byte sequence identifying a public key credential source and its authentication assertions.
newtype CredentialId = CredentialId { unCredentialId :: ByteString }
  deriving (Show, Eq, Generic, H.Hashable, CBOR.Serialise)

instance FromJSON CredentialId where
  parseJSON = fmap (CredentialId . Base64.decodeLenient . T.encodeUtf8) . parseJSON

instance ToJSON CredentialId where
  toJSON = toJSON . T.decodeUtf8 . Base64.encode  . unCredentialId

-- | credential public key encoded in COSE_Key format
newtype CredentialPublicKey = CredentialPublicKey { unCredentialPublicKey :: ByteString }
  deriving (Show, Eq, H.Hashable, CBOR.Serialise)

instance FromJSON CredentialPublicKey where
  parseJSON v = parseJSON v
    >>= either (const $ fail "failed to decode a public key") (pure . CredentialPublicKey)
    . Base64.decode . T.encodeUtf8

instance ToJSON CredentialPublicKey where
  toJSON = toJSON . T.decodeUtf8 . Base64.encode  . unCredentialPublicKey

-- | AAGUID of the authenticator
newtype AAGUID = AAGUID { unAAGUID :: ByteString } deriving (Show, Eq)

instance FromJSON AAGUID where
  parseJSON v = AAGUID . Base16.decodeLenient . T.encodeUtf8 <$> parseJSON v

instance ToJSON AAGUID where
  toJSON = toJSON . T.decodeUtf8 . Base16.encode . unAAGUID

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
  { id :: Text
  , name :: T.Text
  , displayName ::  T.Text
  } deriving (Generic, Show, Eq)

instance ToJSON User where
  toJSON = genericToJSON defaultOptions { omitNothingFields = True}
  toEncoding = genericToEncoding defaultOptions { omitNothingFields = True}

instance CBOR.Serialise User where
  encode (User i n d) = CBOR.encode $ Map.fromList
    ([("id" :: Text, CBOR.TBytes (encodeUtf8 i))] 
      <> [("name" :: Text, CBOR.TString n)]
      <> [("displayName" :: Text, CBOR.TString d)])
  decode = do
    m <- CBOR.decode
    CBOR.TBytes i <- maybe (fail "id") pure $ Map.lookup ("id" :: Text) m
    CBOR.TString n <-  maybe (fail "name") pure $ Map.lookup "name" m
    CBOR.TString d <-  maybe (fail "name") pure $ Map.lookup "displayName" m
    return $ User (decodeUtf8 i) n d

data VerificationFailure
  = InvalidType
  | MismatchedChallenge
  | MismatchedOrigin
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
  deriving Show

data AndroidSafetyNet = AndroidSafetyNet {
  timestampMs :: Integer
  , nonce :: [Char]
  , apkPackageName :: Text
  , apkCertificateDigestSha256 :: [Text]
  , ctsProfileMatch :: Bool
  , basicIntegrity :: Bool
} deriving (Show, Generic)

instance  FromJSON AndroidSafetyNet

data StmtSafetyNet = StmtSafetyNet {
  header :: Base64ByteString
  , payload :: Base64ByteString
  , signature :: ByteString
  , certificates :: X509.CertificateChain
} deriving Show

data JWTHeader = JWTHeader {
  alg :: Text
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

instance FromJSON AuthenticatorTransport where
  parseJSON = genericParseJSON defaultOptions { sumEncoding = UntaggedValue, constructorTagModifier = fmap toLower }

data PublicKeyCredentialDescriptor = PublicKeyCredentialDescriptor {
  tipe :: PublicKeyCredentialType
  , id :: Base64ByteString
  , transports :: Maybe (NonEmpty AuthenticatorTransport)
} deriving (Eq, Show, Generic)

instance ToJSON PublicKeyCredentialDescriptor where
  toEncoding = genericToEncoding defaultOptions { omitNothingFields = True, fieldLabelModifier = mapTipe}
  toJSON = genericToJSON defaultOptions { omitNothingFields = True, fieldLabelModifier = mapTipe}

mapTipe :: String -> String
mapTipe str = if str == "tipe" then "type" else str

data UserVerification = Required | Preferred | Discouraged deriving (Show, Eq, Generic)

instance ToJSON UserVerification where
  toEncoding = genericToEncoding defaultOptions { sumEncoding = UntaggedValue, constructorTagModifier = fmap toLower }
  toJSON = genericToJSON defaultOptions { sumEncoding = UntaggedValue, constructorTagModifier = fmap toLower }

data PublicKeyCredentialRequestOptions =  PublicKeyCredentialRequestOptions {
  challenge :: Challenge
  , timeout :: Maybe Integer
  , rpId :: Maybe Text
  , allowCredentials ::Maybe (NonEmpty PublicKeyCredentialDescriptor)
  , userVerification :: Maybe UserVerification
  -- extensions omitted as support is minimal https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialRequestOptions/extensions
} deriving (Eq, Show, Generic)

instance ToJSON PublicKeyCredentialRequestOptions where
  toEncoding = genericToEncoding defaultOptions { omitNothingFields = True}
  toJSON = genericToJSON defaultOptions { omitNothingFields = True}

data PubKeyCredAlg = ES256 -- -7 
  | RS256 -- (-257) 
  | PS256 -- (-37)
  deriving (Show, Eq, Generic)

instance ToJSON PubKeyCredAlg where
  toJSON ES256 = Number (-7)
  toJSON RS256 = Number (-257)
  toJSON PS256 = Number (-37)
  
data PubKeyCredParam = PubKeyCredParam {
  tipe :: PublicKeyCredentialType
  , alg :: PubKeyCredAlg
} deriving (Show, Eq, Generic)

instance ToJSON PubKeyCredParam where
  toEncoding = genericToEncoding defaultOptions { omitNothingFields = True, fieldLabelModifier = mapTipe}
  toJSON = genericToJSON defaultOptions { omitNothingFields = True, fieldLabelModifier = mapTipe}

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
  , userVerification :: Maybe UserVerification
} deriving (Show, Eq, Generic)

instance ToJSON AuthenticatorSelection where
  toEncoding = genericToEncoding defaultOptions { omitNothingFields = True }
  toJSON = genericToJSON defaultOptions { omitNothingFields = True }

data PublicKeyCredentialCreationOptions = PublicKeyCredentialCreationOptions {
  rp :: RelyingParty
  , challenge :: Challenge
  , user :: User
  , pubKeyCredParams :: NonEmpty PubKeyCredParam
  , timeout :: Maybe Integer
  , attestation :: Maybe Attestation
  , extensions :: Maybe Extensions
  , authenticatorSelection :: Maybe AuthenticatorSelection
  , excludeCredentials :: Maybe (NonEmpty PublicKeyCredentialDescriptor)
} deriving (Eq, Show, Generic)

instance ToJSON PublicKeyCredentialCreationOptions where
  toEncoding = genericToEncoding defaultOptions { omitNothingFields = True }
  toJSON = genericToJSON defaultOptions { omitNothingFields = True }

