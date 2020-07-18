{-# LANGUAGE StrictData #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}
module Web.WebAuthn.Types (
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
  , CredentialData(..)
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
      Options(..) )
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
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
import Data.Aeson.Types (typeMismatch)
import Data.Aeson (genericToEncoding)
import Data.Aeson (defaultOptions)
import Data.Char ( toLower )

newtype Base64ByteString = Base64ByteString { unBase64ByteString :: ByteString } deriving (Generic, Show, Eq)

instance ToJSON Base64ByteString where
  toJSON (Base64ByteString bs) = String $ decodeUtf8 $ Base64.encode bs

instance FromJSON Base64ByteString where
  parseJSON s@(String v) = do
    eth <- pure $ Base64.decode (encodeUtf8 v)
    case eth of
      Left err -> typeMismatch ("Base64: " <> err) s
      Right str -> pure (Base64ByteString str)
  parseJSON oth = typeMismatch "Expecting String" oth

newtype Challenge = Challenge { rawChallenge :: ByteString }
  deriving (Show, Eq, Ord, H.Hashable, CBOR.Serialise)

instance ToJSON Challenge where
  toJSON = toJSON . decodeUtf8 . Base64.encode . rawChallenge

instance FromJSON Challenge where
  parseJSON = withText "Challenge" $ pure . Challenge
    . Base64.decodeLenient . encodeUtf8

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
  deriving (Show, Eq, Ord)

data RelyingParty = RelyingParty
  { rpOrigin :: Origin
  , rpId :: ByteString
  , rpAllowSelfAttestation :: Bool
  , rpAllowNoAttestation :: Bool
  }
  deriving (Show, Eq, Ord)

defaultRelyingParty :: Origin -> RelyingParty
defaultRelyingParty orig = RelyingParty orig (encodeUtf8 $ originHost orig) False False

instance FromJSON Origin where
  parseJSON = withText "Origin" $ \str -> case T.break (==':') str of
    (sch, url) -> case T.break (==':') $ T.drop 3 url of
      (host, portStr)
        | T.null portStr -> pure $ Origin sch host Nothing
        | otherwise -> case T.decimal $ T.drop 1 portStr of
          Left e -> fail e
          Right (port, _) -> pure $ Origin sch host $ Just port

data AuthenticatorData = AuthenticatorData
  { rpIdHash :: Digest SHA256
  , userPresent :: Bool
  , userVerified :: Bool
  , attestedCredentialData :: Maybe CredentialData
  , authenticatorDataExtension :: ByteString
  }

newtype CredentialId = CredentialId { unCredentialId :: ByteString }
  deriving (Show, Eq, H.Hashable, CBOR.Serialise)

instance FromJSON CredentialId where
  parseJSON = fmap (CredentialId . Base64.decodeLenient . T.encodeUtf8) . parseJSON

instance ToJSON CredentialId where
  toJSON = toJSON . T.decodeUtf8 . Base64.encode  . unCredentialId

newtype CredentialPublicKey = CredentialPublicKey { unCredentialPublicKey :: ByteString }
  deriving (Show, Eq, H.Hashable, CBOR.Serialise)

instance FromJSON CredentialPublicKey where
  parseJSON v = parseJSON v
    >>= either (const $ fail "failed to decode a public key") (pure . CredentialPublicKey)
    . Base64.decode . T.encodeUtf8

instance ToJSON CredentialPublicKey where
  toJSON = toJSON . T.decodeUtf8 . Base64.encode  . unCredentialPublicKey

newtype AAGUID = AAGUID { unAAGUID :: ByteString } deriving (Show, Eq)

instance FromJSON AAGUID where
  parseJSON v = AAGUID . Base16.decodeLenient . T.encodeUtf8 <$> parseJSON v

instance ToJSON AAGUID where
  toJSON = toJSON . T.decodeUtf8 . Base16.encode . unAAGUID

data CredentialData = CredentialData
  { aaguid :: AAGUID
  , credentialId :: CredentialId
  , credentialPublicKey :: CredentialPublicKey
  } deriving (Show, Eq, Generic)

instance J.FromJSON CredentialData
instance J.ToJSON CredentialData

data User = User
  { userId :: B.ByteString
  , userName :: T.Text
  , userDisplayName :: T.Text
  } deriving (Generic, Show, Eq)

instance CBOR.Serialise User where
  encode (User i n d) = CBOR.encode $ Map.fromList
    [("id" :: Text, CBOR.TBytes i), ("name", CBOR.TString n), ("displayName", CBOR.TString d)]
  decode = do
    m <- CBOR.decode
    CBOR.TBytes i <- maybe (fail "id") pure $ Map.lookup ("id" :: Text) m
    CBOR.TString n <- maybe (fail "name") pure $ Map.lookup "name" m
    CBOR.TString d <- maybe (fail "displayName") pure $ Map.lookup "displayName" m
    return $ User i n d

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


data PublicKeyCredentialType = PublicKey deriving (Eq, Show)

instance ToJSON PublicKeyCredentialType where
  toJSON PublicKey = String "public-key"

data AuthenticatorTransport = USB -- usb
    | NFC -- nfc
    | BLE -- ble
    | Internal -- internal
  deriving (Eq, Show, Generic)

instance ToJSON AuthenticatorTransport where
  toEncoding = genericToEncoding defaultOptions { constructorTagModifier = fmap toLower }

data PublicKeyCredentialDescriptor = PublicKeyCredentialDescriptor {
  tipe :: PublicKeyCredentialType
  , id :: Base64ByteString
  , transports :: [AuthenticatorTransport]
} deriving (Eq, Show, Generic)

instance ToJSON PublicKeyCredentialDescriptor where
  toEncoding = genericToEncoding defaultOptions { omitNothingFields = True}

data PublicKeyCredentialRequestOptions =  PublicKeyCredentialRequestOptions {
  challenge :: Base64ByteString
  , timeout :: Maybe Integer
  , rpId :: Maybe Text
  , allowCredentials :: Maybe PublicKeyCredentialDescriptor
} deriving (Eq, Show, Generic)

instance ToJSON PublicKeyCredentialRequestOptions where
  toEncoding = genericToEncoding defaultOptions { omitNothingFields = True}