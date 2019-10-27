{-# LANGUAGE RecordWildCards, NamedFieldPuns #-}
{-# LANGUAGE StrictData #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE ScopedTypeVariables #-}
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
  , CredentialPublicKey(..)
  , CredentialId(..)
  , User(..)
  -- * Exception
  , VerificationFailure(..)
  ) where

import Prelude hiding (fail)
import Data.Aeson as J
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Base64 as Base64
import qualified Data.Hashable as H
import qualified Data.Map as Map
import Data.Text (Text)
import Data.Text.Encoding
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import qualified Data.Text.Read as T
import Crypto.Hash
import Crypto.Hash.Algorithms (SHA256(..))
import qualified Codec.CBOR.Term as CBOR
import qualified Codec.CBOR.Read as CBOR
import qualified Codec.Serialise as CBOR
import Control.Monad.Fail
import GHC.Generics (Generic)

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
    <*> fmap (maybe TokenBindingUnsupported id) (obj .:? "tokenBinding")

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
  , originPort :: Int
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
      (host, portPath) -> case T.decimal $ T.drop 1 portPath of
        Left e -> fail e
        Right (port, _) -> pure $ Origin sch host port

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

data CredentialData = CredentialData
  { aaguid :: ByteString
  , credentialId :: CredentialId
  , credentialPublicKey :: CredentialPublicKey
  } deriving (Show, Eq)

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
  | UnsupportedAttestationFormat
  | UnsupportedAlgorithm Int
  | MalformedPublicKey
  | MalformedAuthenticatorData
  | MalformedX509Certificate
  | MalformedSignature
  | SignatureFailure String
  deriving Show
