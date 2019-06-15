{-# LANGUAGE RecordWildCards, NamedFieldPuns #-}
{-# LANGUAGE StrictData #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Web.WebAuthn (
  -- * Basic
  TokenBinding(..)
  , Origin(..)
  , RelyingParty(..)
  , defaultRelyingParty
  , User(..)
  -- Challenge
  , Challenge(..)
  , generateChallenge
  , WebAuthnType(..)
  , Attestation(..)
  , CollectedClientData(..)
  , AuthenticatorData(..)
  , CredentialData(..)
  , CredentialPublicKey(..)
  , CredentialId(..)
  -- * verfication
  , VerificationFailure(..)
  , registerCredential
  , verify
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
import qualified Crypto.PubKey.ECC.ECDSA as EC
import qualified Crypto.PubKey.ECC.Types as EC
import Data.ASN1.BinaryEncoding
import Data.ASN1.Encoding
import Data.ASN1.Types
import GHC.Generics (Generic)

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
    _ -> fail "unknown TokenBinding"

data WebAuthnType = Create | Get
  deriving (Show, Eq, Ord)

instance FromJSON WebAuthnType where
  parseJSON = withText "WebAuthnType" $ \case
    "webauthn.create" -> pure Create
    "webauthn.get" -> pure Get
    _ -> fail "unknown WebAuthnType"

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
  | UserNotPresent
  | UserUnverified
  | UnsupportedAttestationFormat
  | MalformedPublicKey
  | MalformedAuthenticatorData
  | MalformedX509Certificate
  | MalformedSignature
  | SignatureFailure
  deriving Show

data Attestation = Attestation
  { attestationAuthData :: AuthenticatorData
  , attestationAuthDataRaw :: ByteString
  , attestationStatement :: AttestationStatement
  }

data StmtFIDOU2F = StmtFIDOU2F (X509.SignedExact X509.Certificate) ByteString
  deriving Show

decodeFIDOU2F :: CBOR.Term -> Maybe StmtFIDOU2F
decodeFIDOU2F (CBOR.TMap xs) = do
  let m = Map.fromList xs
  CBOR.TBytes sig <- Map.lookup (CBOR.TString "sig") m
  CBOR.TList [CBOR.TBytes certBS] <- Map.lookup (CBOR.TString "x5c") m
  cert <- either fail pure $ X509.decodeSignedCertificate certBS
  return (StmtFIDOU2F cert sig)
decodeFIDOU2F _ = Nothing

data StmtPacked = StmtPacked Int ByteString (X509.SignedExact X509.Certificate)
  deriving Show

decodePacked :: CBOR.Term -> CBOR.Decoder s StmtPacked
decodePacked (CBOR.TMap xs) = do
  let m = Map.fromList xs
  CBOR.TInt alg <- Map.lookup (CBOR.TString "alg") m ??? "alg"
  CBOR.TList (CBOR.TBytes certBS : _) <- Map.lookup (CBOR.TString "x5c") m ??? "x5c"
  CBOR.TBytes sig <- Map.lookup (CBOR.TString "sig") m ??? "sig"
  cert <- either fail pure $ X509.decodeSignedCertificate certBS
  return $ StmtPacked alg sig cert
  where
    Nothing ??? e = fail e
    Just a ??? _ = pure a
decodePacked _ = fail "decodePacked: expected a Map"

verifyPacked :: StmtPacked -> B.ByteString
  -> Digest SHA256
  -> Either VerificationFailure ()
verifyPacked (StmtPacked _ sig cert) ad clientDataHash = do
  let pub = X509.certPubKey $ X509.getCertificate cert
  case X509.verifySignature ec256 pub (ad <> BA.convert clientDataHash) sig of
    X509.SignaturePass -> return ()
    X509.SignatureFailed _ -> Left SignatureFailure

parseAuthenticatorData :: C.Get AuthenticatorData
parseAuthenticatorData = do
  rpIdHash' <- C.getBytes 32
  rpIdHash <- maybe (fail "impossible") pure $ digestFromByteString rpIdHash'
  flags <- C.getWord8
  counter <- C.getBytes 4
  attestedCredentialData <- if testBit flags 6
    then do
      aaguid <- C.getBytes 16
      len <- C.getWord16be
      credentialId <- CredentialId <$> C.getBytes (fromIntegral len)
      n <- C.remaining
      credentialPublicKey <- CredentialPublicKey <$> C.getBytes n
      pure $ Just CredentialData{..}
    else pure Nothing
  let authenticatorDataExtension = B.empty --FIXME
  let userPresent = testBit flags 0
  let userVerified = testBit flags 2
  return AuthenticatorData{..}

data AttestationStatement = AF_Packed StmtPacked
  | AF_TPM
  | AF_AndroidKey
  | AF_AndroidSafetyNet
  | AF_FIDO_U2F StmtFIDOU2F
  | AF_None
  deriving Show

verifyFIDOU2F :: StmtFIDOU2F -> AuthenticatorData
  -> Digest SHA256
  -> Either VerificationFailure ()
verifyFIDOU2F (StmtFIDOU2F cert sig) AuthenticatorData{..} clientDataHash = do
  CredentialData{..} <- maybe (Left MalformedAuthenticatorData) pure attestedCredentialData
  m <- either (Left . CBORDecodeError "verifyFIDOU2F") pure
    $ CBOR.deserialiseOrFail $ BL.fromStrict $ unCredentialPublicKey credentialPublicKey
  pubU2F <- maybe (Left MalformedPublicKey) pure $ do
      CBOR.TBytes x <- Map.lookup (-2 :: Int) m
      CBOR.TBytes y <- Map.lookup (-3) m
      return $ BB.word8 0x04 <> BB.byteString x <> BB.byteString y
  let dat = BL.toStrict $ BB.toLazyByteString $ mconcat
        [ BB.word8 0x00
        , BB.byteString $ BA.convert rpIdHash
        , BB.byteString $ BA.convert clientDataHash
        , BB.byteString $ unCredentialId credentialId
        , pubU2F]
  let pub = X509.certPubKey $ X509.getCertificate cert
  case X509.verifySignature ec256 pub dat sig of
    X509.SignaturePass -> return ()
    X509.SignatureFailed _ -> Left SignatureFailure

decodeAttestation :: CBOR.Decoder s Attestation
decodeAttestation = do
  m :: Map.Map Text CBOR.Term <- CBOR.decode
  CBOR.TString fmt <- maybe (fail "fmt") pure $ Map.lookup "fmt" m
  stmtTerm <- maybe (fail "stmt") pure $ Map.lookup "attStmt" m
  stmt <- case fmt of
    "fido-u2f" -> maybe (fail "fido-u2f") (pure . AF_FIDO_U2F) $ decodeFIDOU2F stmtTerm
    "packed" -> AF_Packed <$> decodePacked stmtTerm
    _ -> error $ "decodeAttestation: Unsupported format: " ++ show fmt
  CBOR.TBytes adRaw <- maybe (fail "authData") pure $ Map.lookup "authData" m
  ad <- either fail pure $ C.runGet parseAuthenticatorData adRaw
  return (Attestation ad adRaw stmt)

lookupM :: (Ord k, MonadFail m) => k -> Map.Map k a -> m a
lookupM k = maybe (fail "not found") pure . Map.lookup k

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

data AuthenticatorData = AuthenticatorData
  { rpIdHash :: Digest SHA256
  , userPresent :: Bool
  , userVerified :: Bool
  , attestedCredentialData :: Maybe CredentialData
  , authenticatorDataExtension :: ByteString
  }

newtype CredentialId = CredentialId { unCredentialId :: ByteString }
  deriving (Show, Eq, H.Hashable, CBOR.Serialise)

newtype CredentialPublicKey = CredentialPublicKey { unCredentialPublicKey :: ByteString }
  deriving (Show, Eq, H.Hashable, CBOR.Serialise)

data CredentialData = CredentialData
  { aaguid :: ByteString
  , credentialId :: CredentialId
  , credentialPublicKey :: CredentialPublicKey
  } deriving (Show, Eq)

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
  -> ByteString -- ^ clientDataJSON
  -> ByteString -- ^ attestationObject
  -> Either VerificationFailure (CredentialId, CredentialPublicKey)
registerCredential challenge RelyingParty{..} tbi verificationRequired clientDataJSON attestationObject = do
  CollectedClientData{..} <- either
    (Left . JSONDecodeError) Right $ J.eitherDecode $ BL.fromStrict clientDataJSON
  clientType == Create ?? InvalidType
  -- challenge == clientChallenge ?? MismatchedChallenge
  rpOrigin == clientOrigin ?? MismatchedOrigin
  case clientTokenBinding of
    TokenBindingUnsupported -> pure ()
    TokenBindingSupported -> pure ()
    TokenBindingPresent t -> case tbi of
      Nothing -> Left UnexpectedPresenceOfTokenBinding
      Just t'
        | t == t' -> pure ()
        | otherwise -> Left MismatchedTokenBinding
  Attestation{ attestationAuthData = ad
    , attestationAuthDataRaw = adRaw
    , attestationStatement = stmt }
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
    AF_Packed s -> verifyPacked s adRaw clientDataHash
    stmt -> error $ "registerCredential: unsupported format: " ++ show stmt

  case attestedCredentialData ad of
    Nothing -> Left MalformedAuthenticatorData
    Just c -> pure (credentialId c, credentialPublicKey c)

ec256 :: X509.SignatureALG
ec256 = X509.SignatureALG X509.HashSHA256 X509.PubKeyALG_EC

verify :: Challenge
  -> RelyingParty
  -> Maybe Text -- ^ Token Binding ID in base64
  -> Bool -- ^ require user verification?
  -> ByteString -- ^ clientDataJSON
  -> ByteString -- ^ authenticatorData
  -> ByteString -- ^ signature
  -> CredentialPublicKey -- ^ public key
  -> Either VerificationFailure ()
verify challenge RelyingParty{..} tbi verificationRequired clientDataJSON adRaw sig pub = do
  CollectedClientData{..} <- either
    (Left . JSONDecodeError) Right $ J.eitherDecode $ BL.fromStrict clientDataJSON
  clientType == Get ?? InvalidType
  -- challenge == clientChallenge ?? MismatchedChallenge
  rpOrigin == clientOrigin ?? MismatchedOrigin
  case clientTokenBinding of
    TokenBindingUnsupported -> pure ()
    TokenBindingSupported -> pure ()
    TokenBindingPresent t -> case tbi of
      Nothing -> Left UnexpectedPresenceOfTokenBinding
      Just t'
        | t == t' -> pure ()
        | otherwise -> Left MismatchedTokenBinding

  ad <- either (const $ Left MalformedAuthenticatorData) pure
    $ C.runGet parseAuthenticatorData adRaw

  let clientDataHash = hash clientDataJSON :: Digest SHA256
  hash rpId == rpIdHash ad ?? MismatchedRPID
  userPresent ad ?? UserNotPresent
  not verificationRequired || userVerified ad ?? UserUnverified

  let dat = adRaw <> BA.convert clientDataHash

  pub' <- parsePublicKey pub

  sig' <- maybe (Left MalformedSignature) pure $ parseSignature sig
  case EC.verify SHA256 pub' sig' dat of
    True  -> return ()
    False -> Left SignatureFailure

parsePublicKey :: CredentialPublicKey -> Either VerificationFailure EC.PublicKey
parsePublicKey pub = do
  m <- either (Left . CBORDecodeError "parsePublicKey") pure
    $ CBOR.deserialiseOrFail $ BL.fromStrict $ unCredentialPublicKey pub
  maybe (Left MalformedPublicKey) pure $ do
      CBOR.TInt crv <- Map.lookup (-1) m
      CBOR.TBytes x <- Map.lookup (-2 :: Int) m
      CBOR.TBytes y <- Map.lookup (-3) m
      c <- case crv of
        1 -> pure EC.SEC_p256r1
        _ -> fail $ "parsePublicKey: unknown curve: " ++ show crv
      return $ EC.PublicKey (EC.getCurveByName c) (EC.Point (fromOctet x) (fromOctet y))

fromOctet :: B.ByteString -> Integer
fromOctet = B.foldl' (\r x -> r `unsafeShiftL` 8 .|. fromIntegral x) 0

parseSignature :: ByteString -> Maybe EC.Signature
parseSignature b = case decodeASN1' BER b of
  Left _ -> Nothing
  Right asn1 -> case asn1 of
    Start Sequence:IntVal r:IntVal s:End Sequence:_ -> Just $ EC.Signature r s
    _ -> Nothing
