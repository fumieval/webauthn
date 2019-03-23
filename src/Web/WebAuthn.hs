{-# LANGUAGE RecordWildCards, NamedFieldPuns #-}
{-# LANGUAGE StrictData #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
module Web.WebAuthn where

import Prelude hiding (fail)
import Data.Aeson as J
import Data.Bits
import Data.ByteString (ByteString)
import qualified Data.Serialize as C
import qualified Data.ByteArray as BA
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Base64 as Base64
import Data.Int
import qualified Data.Map as Map
import Data.Text (Text)
import Data.Text.Encoding
import qualified Data.Text as T
import qualified Data.Text.Read as T
import Crypto.Random
import Crypto.Hash
import Crypto.Hash.Algorithms (SHA256(..))
import qualified Data.X509 as X509
import qualified Data.X509.Validation as X509
import qualified Codec.CBOR.Read as CBOR
import qualified Codec.CBOR.Decoding as CBOR
import qualified Codec.Serialise as CBOR
import Control.Monad.Fail
import Control.Monad hiding (fail)

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
    _ -> fail "unknown type"

data WebAuthnType = Create | Get
  deriving (Show, Eq, Ord)

instance FromJSON WebAuthnType where
  parseJSON = withText "WebAuthnType" $ \case
    "webauthn.create" -> pure Create
    _ -> fail "unknown type"

newtype Challenge = Challenge { rawChallenge :: ByteString }
  deriving (Show, Eq, Ord)

instance FromJSON Challenge where
  parseJSON = withText "Challenge" $ either fail (pure . Challenge)
    . Base64.decode . encodeUtf8

instance FromJSON Origin where
  parseJSON = withText "Origin" $ \str -> case T.break (==':') str of
    (sch, url) -> case T.break (==':') $ T.drop 3 url of
      (host, portPath) -> case T.decimal portPath of
        Left str -> fail str
        Right (port, _) -> pure $ Origin sch host port

data VerificationFailure
  = InvalidType
  | MismatchedChallenge
  | MismatchedOrigin
  | UnexpectedPresenceOfTokenBinding
  | MismatchedTokenBinding
  | JSONDecodeError String
  | CBORDecodeError CBOR.DeserialiseFailure
  | MismatchedRPID
  | UserNotPresent
  | UserUnverified
  | UnsupportedAttestationFormat
  | MalformedU2FPublicKey
  | SignatureFailure X509.SignatureFailure

data AuthenticatorAttestationResponse = AuthenticatorAttestationResponse
  { clientDataJSON :: ByteString
  , attestationObject :: ByteString
  }

data Attestation = Attestation
  { attestationAuthData :: AuthenticatorData
  , attestationStatement :: AttestationStatement
  }

data StmtFIDOU2F = StmtFIDOU2F (X509.SignedExact X509.Certificate) ByteString

decodeFIDOU2F = do
  _ <- CBOR.decodeMapLen
  assertKey "x5c"
  _ <- CBOR.decodeListLen
  assertKey "attestnCert"
  certBS <- CBOR.decodeBytes
  cert <- either fail pure $ X509.decodeSignedCertificate certBS
  assertKey "sig"
  sig <- CBOR.decodeBytes
  return (StmtFIDOU2F cert sig)

assertKey k = do
  k' <- CBOR.decodeString
  unless (k == k') $ fail $ "assertKey: " ++ show (k, k')

parseAuthenticatorData :: C.Get AuthenticatorData
parseAuthenticatorData = do
  rpIdHash' <- C.getBytes 32
  rpIdHash <- maybe (fail "impossible") pure $ digestFromByteString rpIdHash'
  flags <- C.getWord8
  counter <- C.getBytes 4
  aaguid <- C.getBytes 16
  len <- C.getWord16be
  credentialId <- C.getBytes (fromIntegral len)
  n <- C.remaining
  credentialPublicKey <- C.getBytes n
  let authenticatorDataExtension = B.empty --FIXME
  let userPresent = testBit flags 0
  let userVerified = testBit flags 2
  let attestedCredentialData = CredentialData{..}
  return AuthenticatorData{..}

data AttestationStatement = AF_Packed
  | AF_TPM
  | AF_AndroidKey
  | AF_AndroidSafetyNet
  | AF_FIDO_U2F StmtFIDOU2F
  | AF_None

verifyFIDOU2F :: StmtFIDOU2F -> AuthenticatorData -> Digest SHA256 -> Either VerificationFailure ()
verifyFIDOU2F (StmtFIDOU2F cert sig) AuthenticatorData{..} clientDataHash = do
  let CredentialData{..} = attestedCredentialData
  m <- either (Left . CBORDecodeError) pure
    $ CBOR.deserialiseOrFail $ BL.fromStrict credentialPublicKey
  pubU2F <- maybe (Left MalformedU2FPublicKey) pure $ do
      x <- Map.lookup ("-2" :: Text) m
      y <- Map.lookup "-3" m
      return $ B.concat [B.singleton 0x04, x, y]
  let dat = B.concat [B.singleton 0x00
        , BA.convert rpIdHash
        , BA.convert clientDataHash
        , credentialId
        , pubU2F]
  case X509.verifySignature (X509.SignatureALG X509.HashSHA256 X509.PubKeyALG_EC)
    (X509.certPubKey $ X509.getCertificate cert) dat sig of
      X509.SignaturePass -> return ()
      X509.SignatureFailed f -> Left $ SignatureFailure f

decodeAttestation :: CBOR.Decoder s Attestation
decodeAttestation = do
  _ <- CBOR.decodeMapLen
  assertKey "authData"
  ad <- CBOR.decodeBytes
    >>= either fail pure . C.runGet parseAuthenticatorData
  assertKey "fmt"
  fmt <- CBOR.decodeString
  stmt <- case fmt of
    "fido-u2f" -> AF_FIDO_U2F <$> decodeFIDOU2F
    _ -> error "decodeAttestation: Unsupported format"
  return (Attestation ad stmt)

lookupM :: (Ord k, MonadFail m) => k -> Map.Map k a -> m a
lookupM k = maybe (fail "not found") pure . Map.lookup k

data AuthenticatorData = AuthenticatorData
  { rpIdHash :: Digest SHA256
  , userPresent :: Bool
  , userVerified :: Bool
  , attestedCredentialData :: CredentialData
  , authenticatorDataExtension :: ByteString
  }

data CredentialData = CredentialData
  { aaguid :: ByteString
  , credentialId :: ByteString
  , credentialPublicKey :: ByteString
  }

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

data TrustPath = TrustEmpty
  | TrustX509 [X509.PubKey]

data TrustAnchors = TrustAnchors
  { trusedX509PubKeys :: [X509.PubKey]
  }

(??) :: Bool -> e -> Either e ()
False ?? e = Left e
True ?? _ = Right ()
infix 1 ??

registerCredential :: Challenge
  -> RelyingParty
  -> Maybe Text -- ^ Token Binding ID in base64
  -> Bool -- ^ require user verification?
  -> TrustAnchors
  -> AuthenticatorAttestationResponse
  -> Either VerificationFailure CredentialData
registerCredential ch RelyingParty{..} tbi verificationRequired anchors
  AuthenticatorAttestationResponse{..} = do
  CollectedClientData{..} <- either
    (Left . JSONDecodeError) Right $ J.eitherDecode $ BL.fromStrict clientDataJSON
  clientType == Create ?? InvalidType
  ch == clientChallenge ?? MismatchedChallenge
  rpOrigin == clientOrigin ?? MismatchedOrigin
  case clientTokenBinding of
    TokenBindingUnsupported -> pure ()
    TokenBindingSupported -> pure ()
    TokenBindingPresent t -> case tbi of
      Nothing -> Left UnexpectedPresenceOfTokenBinding
      Just t'
        | t == t' -> pure ()
        | otherwise -> Left MismatchedTokenBinding
  Attestation{ attestationAuthData = ad, attestationStatement = stmt }
    <- either (Left . CBORDecodeError) (pure . snd)
    $ CBOR.deserialiseFromBytes decodeAttestation
    $ BL.fromStrict $ attestationObject
  let clientDataHash = hash clientDataJSON :: Digest SHA256
  hash rpId == rpIdHash ad ?? MismatchedRPID
  userPresent ad ?? UserNotPresent
  not verificationRequired || userVerified ad ?? UserUnverified

  -- TODO: extensions here

  case stmt of
    AF_FIDO_U2F s -> verifyFIDOU2F s ad clientDataHash
    _ -> error "registerCredential: unsupported format"
  return $ attestedCredentialData ad
