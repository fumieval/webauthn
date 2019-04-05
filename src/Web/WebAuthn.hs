{-# LANGUAGE RecordWildCards, NamedFieldPuns #-}
{-# LANGUAGE StrictData #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
module Web.WebAuthn (
  -- * Basic
  TokenBinding(..)
  , Origin(..)
  , RelyingParty(..)
  , defaultRelyingParty
  -- Challenge
  , Challenge(..)
  , generateChallenge
  , WebAuthnType(..)
  , AuthenticatorAttestationResponse(..)
  , Attestation(..)
  , CollectedClientData(..)
  , AuthenticatorData(..)
  , CredentialData(..)
  -- * verfication
  , VerificationFailure(..)
  , registerCredential
  ) where

import Prelude hiding (fail)
import Data.Aeson as J
import Data.Bits
import Data.ByteString (ByteString)
import qualified Data.Serialize as C
import qualified Data.ByteArray as BA
import qualified Data.ByteString as B
import qualified Data.ByteString.Builder as BB
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Base64 as Base64
import qualified Data.Hashable as H
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
import qualified Codec.CBOR.Term as CBOR
import qualified Codec.CBOR.Read as CBOR
import qualified Codec.CBOR.Decoding as CBOR
import qualified Codec.Serialise as CBOR
import Control.Monad.Fail
import Control.Monad hiding (fail)

import Debug.Trace

generateChallenge :: Int -> IO Challenge
generateChallenge len = Challenge <$> getRandomBytes len

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
    _ -> fail "unknown type"

data WebAuthnType = Create | Get
  deriving (Show, Eq, Ord)

instance FromJSON WebAuthnType where
  parseJSON = withText "WebAuthnType" $ \case
    "webauthn.create" -> pure Create
    _ -> fail "unknown type"

instance FromJSON Origin where
  parseJSON = withText "Origin" $ \str -> case T.break (==':') str of
    (sch, url) -> case T.break (==':') $ T.drop 3 url of
      (host, portPath) -> case T.decimal $ T.drop 1 portPath of
        Left str -> fail str
        Right (port, _) -> pure $ Origin sch host port

data VerificationFailure
  = InvalidType
  | MismatchedChallenge
  | MismatchedOrigin
  | UnexpectedPresenceOfTokenBinding
  | MismatchedTokenBinding
  | JSONDecodeError String
  | CBORDecodeError String CBOR.DeserialiseFailure
  | MismatchedRPID
  | MismatchedPublicKey
  | UserNotPresent
  | UserUnverified
  | UnsupportedAttestationFormat
  | MalformedU2FPublicKey
  | SignatureFailure X509.SignatureFailure
  deriving Show

data AuthenticatorAttestationResponse = AuthenticatorAttestationResponse
  { attestationObject :: ByteString
  , clientDataJSON :: ByteString
  }

data Attestation = Attestation
  { attestationAuthData :: AuthenticatorData
  , attestationStatement :: AttestationStatement
  }

data StmtFIDOU2F = StmtFIDOU2F (X509.SignedExact X509.Certificate) ByteString

decodeFIDOU2F :: CBOR.Decoder s StmtFIDOU2F
decodeFIDOU2F = do
  _ <- CBOR.decodeMapLen
  assertKey "sig"
  sig <- CBOR.decodeBytes
  assertKey "x5c"
  _ <- CBOR.decodeListLen
  certBS <- CBOR.decodeBytes
  cert <- either fail pure $ X509.decodeSignedCertificate certBS
  return (StmtFIDOU2F cert sig)

data StmtTPMCert = StmtTPMX5C [X509.SignedExact X509.Certificate]
  | StmtTPMECDAA ByteString

data StmtTPM = StmtTPM
  { stmtTPM'alg :: COSEAlgorithmIdentifier
  , stmtTPM'cert :: StmtTPMCert
  , stmtTPM'sig :: ByteString
  , stmtTPM'certInfo :: ByteString
  , stmtTPM'pubArea :: ByteString
  }

decodeTPM :: CBOR.Decoder s StmtTPM
decodeTPM = do
  m <- CBOR.decode
  stmtTPM'alg <- case Map.lookup "alg" m of
    Just (CBOR.TInt i) -> pure $ COSEAlgorithmIdentifier i
    Nothing -> fail "decodeTPM: alg is missing"
  stmtTPM'cert <- case Map.lookup "x5c" m of
    Just (CBOR.TList ts) -> StmtTPMX5C
      <$> sequence [either fail pure $ X509.decodeSignedCertificate bs | CBOR.TBytes bs <- ts]
    _ -> fail "decodeTPM: x5c is missing"
  let fetchB :: Text -> CBOR.Decoder s ByteString
      fetchB k = case Map.lookup k m of
        Just (CBOR.TBytes b) -> pure b
        _ -> fail $ "decodeTPM: " ++ show k ++ " is missing"
  stmtTPM'sig <- fetchB "sig"
  stmtTPM'certInfo <- fetchB "certInfo"
  stmtTPM'pubArea <- fetchB "pubArea"
  return StmtTPM{..}

newtype COSEAlgorithmIdentifier = COSEAlgorithmIdentifier { getCOSEAlgorithmIdentifier :: Int }
  deriving (Show, Eq, Ord, CBOR.Serialise)

verifyTPM :: StmtTPM -> AuthenticatorData -> Digest SHA256 -> Either VerificationFailure ()
verifyTPM StmtTPM{..} AuthenticatorData{..} clientDataHash = case stmtTPM'cert of
  StmtTPMECDAA _ -> error "verifyTPM: ECDAA is not supported"
  StmtTPMX5C (aikCert : _) -> do
    -- TODO: verify certInfo
    -- XXX and so on
    let alg = case getCOSEAlgorithmIdentifier stmtTPM'alg of
          -257 -> X509.SignatureALG X509.HashSHA256 X509.PubKeyALG_RSA
          -7 -> X509.SignatureALG X509.HashSHA256 X509.PubKeyALG_EC
    credentialPublicKey attestedCredentialData == stmtTPM'pubArea ?? MismatchedPublicKey
    case X509.verifySignature alg
      (X509.certPubKey $ X509.getCertificate aikCert) stmtTPM'certInfo stmtTPM'sig of
        X509.SignaturePass -> return ()
        X509.SignatureFailed f -> Left $ SignatureFailure f

assertKey :: Text -> CBOR.Decoder s ()
assertKey k = do
  k' <- CBOR.decodeString
  unless (k == k') $ fail $ "assertKey: " ++ T.unpack k ++ " /= " ++ T.unpack k'

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
  | AF_TPM StmtTPM
  | AF_AndroidKey
  | AF_AndroidSafetyNet
  | AF_FIDO_U2F StmtFIDOU2F
  | AF_None

verifyFIDOU2F :: StmtFIDOU2F -> AuthenticatorData -> Digest SHA256 -> Either VerificationFailure ()
verifyFIDOU2F (StmtFIDOU2F cert sig) AuthenticatorData{..} clientDataHash = do
  let CredentialData{..} = attestedCredentialData
  m <- either (Left . CBORDecodeError "verifyFIDOU2F") pure
    $ CBOR.deserialiseOrFail $ BL.fromStrict credentialPublicKey
  pubU2F <- maybe (Left MalformedU2FPublicKey) pure $ do
      CBOR.TBytes x <- Map.lookup (-2 :: Int) m
      CBOR.TBytes y <- Map.lookup (-3) m
      return $ BB.word8 0x04 <> BB.byteString x <> BB.byteString y
  let dat = BL.toStrict $ BB.toLazyByteString $ mconcat
        [ BB.word8 0x00
        , BB.byteString $ BA.convert rpIdHash
        , BB.byteString $ BA.convert clientDataHash
        , BB.byteString credentialId
        , pubU2F]
  case X509.verifySignature (X509.SignatureALG X509.HashSHA256 X509.PubKeyALG_EC)
    (X509.certPubKey $ X509.getCertificate cert) dat sig of
      X509.SignaturePass -> return ()
      X509.SignatureFailed f -> Left $ SignatureFailure f

decodeAttestation :: CBOR.Decoder s Attestation
decodeAttestation = do
  _ <- CBOR.decodeMapLen
  assertKey "fmt"
  fmt <- CBOR.decodeString
  assertKey "attStmt"
  stmt <- case fmt of
    "fido-u2f" -> AF_FIDO_U2F <$> decodeFIDOU2F
    "tpm" -> AF_TPM <$> decodeTPM
    _ -> error "decodeAttestation: Unsupported format"
  assertKey "authData"
  ad <- CBOR.decodeBytes
    >>= either fail pure . C.runGet parseAuthenticatorData
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
  -> AuthenticatorAttestationResponse
  -> Either VerificationFailure CredentialData
registerCredential challenge RelyingParty{..} tbi verificationRequired
  AuthenticatorAttestationResponse{..} = do
  CollectedClientData{..} <- either
    (Left . JSONDecodeError) Right $ J.eitherDecode $ BL.fromStrict clientDataJSON
  clientType == Create ?? InvalidType
  challenge == clientChallenge ?? MismatchedChallenge
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
    <- either (Left . CBORDecodeError "registerCredential") (pure . snd)
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
