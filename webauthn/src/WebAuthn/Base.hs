{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE TypeFamilies #-}
module WebAuthn.Base
  ( Base64UrlByteString(..)
  , Challenge(..)
  , AAGUID(..)
  , CredentialId(..)
  , CredentialPublicKey(..)
  , Required
  , Complete
  , Incomplete
  ) where

import Codec.Serialise qualified as CBOR
import Data.Aeson
import Data.Aeson.Types
import Data.ByteArray (ByteArrayAccess)
import Data.ByteString (ByteString)
import Data.ByteString.Base16 qualified as Base16
import Data.ByteString.Base64.URL qualified as Base64
import Data.ByteString.Char8 qualified as B8
import Data.Hashable
import Data.String
import Data.Text.Encoding ( decodeUtf8, encodeUtf8 )
import Data.Kind (Type)
import GHC.Generics (Generic)

-- | A wrapper of 'ByteString' where its contents is Base64-encoded in JSON
newtype Base64UrlByteString = Base64UrlByteString { unBase64UrlByteString :: ByteString } deriving (Generic, Eq, ByteArrayAccess)

instance Show Base64UrlByteString where
  show = show . Base64.encode . unBase64UrlByteString

-- | Expects Base64
instance IsString Base64UrlByteString where
  fromString = Base64UrlByteString . Base64.decodeLenient . B8.pack

instance ToJSON Base64UrlByteString where
  toJSON (Base64UrlByteString bs) = String $ decodeUtf8 $ Base64.encode bs

instance FromJSON Base64UrlByteString where
  parseJSON = withText "Base64UrlByteString" $ \v -> do
    let eth = Base64.decode (encodeUtf8 v)
    case eth of
      Left err -> typeMismatch ("Base64: " <> err) (String v)
      Right str -> pure (Base64UrlByteString str)

-- | 13.1. Cryptographic Challenges
newtype Challenge = Challenge { rawChallenge :: ByteString }
  deriving (Eq, Ord, Generic, Hashable, CBOR.Serialise)
  deriving (FromJSON, ToJSON, Show, IsString) via Base64UrlByteString

-- | AAGUID of the authenticator
newtype AAGUID = AAGUID { unAAGUID :: ByteString } deriving (Show, Eq)

instance FromJSON AAGUID where
  parseJSON v = AAGUID . Base16.decodeLenient . encodeUtf8 <$> parseJSON v

instance ToJSON AAGUID where
  toJSON = toJSON . decodeUtf8 . Base16.encode . unAAGUID

-- | A probabilistically-unique byte sequence identifying a public key credential source and its authentication assertions.
newtype CredentialId = CredentialId { unCredentialId :: ByteString }
  deriving (Eq, Generic, Hashable, CBOR.Serialise)
  deriving (FromJSON, ToJSON, Show, IsString) via Base64UrlByteString

-- | credential public key encoded in COSE_Key format
newtype CredentialPublicKey = CredentialPublicKey { unCredentialPublicKey :: ByteString }
  deriving (Eq, Hashable, CBOR.Serialise)
  deriving (FromJSON, ToJSON, Show, IsString) via Base64UrlByteString

data Complete
data Incomplete

type family Required a b :: Type where
  Required Incomplete _ = ()
  Required Complete t = t