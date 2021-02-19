{-# LANGUAGE RecordWildCards, NamedFieldPuns #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE DuplicateRecordFields #-}
-----------------------------------------------------------------------
-- |
-- Module      :  WebAuthn
-- License     :  BSD3
--
-- Maintainer  :  Fumiaki Kinoshita <fumiexcel@gmail.com>
--
-- <https://www.w3.org/TR/webauthn/ Web Authentication API> Verification library
-----------------------------------------------------------------------

module WebAuthn (
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
  , CollectedClientData(..)
  , AuthenticatorData(..)
  , AttestedCredentialData(..)
  , AAGUID(..)
  , CredentialPublicKey(..)
  , CredentialId(..)
  -- * verfication
  , VerificationFailure(..)
  , registerCredential
  , verify
  , encodeAttestation
  ) where

import Prelude hiding (fail)
import Data.Aeson as J
import Data.Bits
import Data.ByteString (ByteString)
import qualified Data.Serialize as C
import qualified Data.ByteArray as BA
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import qualified Data.Map as Map
import Data.Text (Text)
import Crypto.Random
import Crypto.Hash
import qualified Codec.CBOR.Term as CBOR
import qualified Codec.CBOR.Read as CBOR
import qualified Codec.CBOR.Decoding as CBOR
import qualified Codec.CBOR.Encoding as CBOR
import qualified Codec.Serialise as CBOR
import Control.Monad.Fail
import WebAuthn.Signature
import WebAuthn.Types
import qualified WebAuthn.TPM as TPM
import qualified WebAuthn.FIDOU2F as U2F
import qualified WebAuthn.Packed as Packed
import qualified WebAuthn.AndroidSafetyNet as Android
import Control.Monad (when)
import Control.Monad.IO.Class (MonadIO)
import Control.Monad.Trans.Except (runExceptT, ExceptT(..), throwE)
import Data.Text (pack)
import qualified Data.X509.CertificateStore as X509
import Data.Bifunctor (first)
import Data.Text.Encoding (encodeUtf8)

-- | Generate a cryptographic challenge (13.1).
generateChallenge :: Int -> IO Challenge
generateChallenge len = Challenge <$> getRandomBytes len

parseAuthenticatorData :: C.Get AuthenticatorData
parseAuthenticatorData = do
  rpIdHash' <- C.getBytes 32
  rpIdHash <- maybe (fail "impossible") pure $ digestFromByteString rpIdHash'
  flags <- C.getWord8
  _counter <- C.getBytes 4
  attestedCredentialData <- if testBit flags 6
    then do
      aaguid <- AAGUID <$> C.getBytes 16
      len <- C.getWord16be
      credentialId <- CredentialId <$> C.getBytes (fromIntegral len)
      n <- C.remaining
      credentialPublicKey <- CredentialPublicKey <$> C.getBytes n
      pure $ Just AttestedCredentialData{..}
    else pure Nothing
  let authenticatorDataExtension = B.empty --FIXME
  let userPresent = testBit flags 0
  let userVerified = testBit flags 2
  return AuthenticatorData{..}

-- | Attestation (6.4) provided by authenticators

data AttestationObject = AttestationObject {
  fmt :: Text
  , attStmt :: AttestationStatement
  , authData :: ByteString
}

data AttestationStatement = AF_Packed Packed.Stmt
  | AF_TPM TPM.Stmt
  | AF_AndroidKey
  | AF_AndroidSafetyNet StmtSafetyNet
  | AF_FIDO_U2F U2F.Stmt
  | AF_None
  deriving Show

decodeAttestation :: CBOR.Decoder s AttestationObject
decodeAttestation = do
  m :: Map.Map Text CBOR.Term <- CBOR.decode
  CBOR.TString fmt <- maybe (fail "fmt") pure $ Map.lookup "fmt" m
  stmtTerm <- maybe (fail "stmt") pure $ Map.lookup "attStmt" m
  stmt <- case fmt of
    "fido-u2f" -> maybe (fail "fido-u2f") (pure . AF_FIDO_U2F) $ U2F.decode stmtTerm
    "packed" -> AF_Packed <$> Packed.decode stmtTerm
    "tpm" -> AF_TPM <$> TPM.decode stmtTerm
    "android-safetynet" -> AF_AndroidSafetyNet <$> Android.decode stmtTerm
    "none" -> pure AF_None
    _ -> fail $ "decodeAttestation: Unsupported format: " ++ show fmt
  CBOR.TBytes adRaw <- maybe (fail "authData") pure $ Map.lookup "authData" m
  return (AttestationObject fmt stmt adRaw)

encodeAttestation :: AttestationObject -> CBOR.Encoding 
encodeAttestation attestationObject = CBOR.encodeMapLen 3 
  <> CBOR.encodeString "fmt"
  <> encodeAttestationFmt
  <> CBOR.encodeString  "attStmt"
  where
    encodeAttestationFmt :: CBOR.Encoding
    encodeAttestationFmt =  case (attStmt attestationObject) of
      AF_FIDO_U2F _ -> CBOR.encodeString "fido-u2f"
      AF_Packed _ -> CBOR.encodeString "packed"
      AF_TPM _ -> CBOR.encodeString "tpm"
      AF_AndroidKey -> CBOR.encodeString "android-key"
      AF_AndroidSafetyNet _ -> CBOR.encodeString "android-safetynet"
      AF_None -> CBOR.encodeString "none"

-- | 7.1. Registering a New Credential
registerCredential :: MonadIO m => PublicKeyCredentialCreationOptions
  -> X509.CertificateStore
  -> Challenge
  -> RelyingParty
  -> Maybe Text -- ^ Token Binding ID in base64
  -> Bool -- ^ require user verification?
  -> ByteString -- ^ clientDataJSON
  -> ByteString -- ^ attestationObject
  -> m (Either VerificationFailure AttestedCredentialData)
registerCredential opts cs challenge (RelyingParty rpOrigin rpId _ _) tbi verificationRequired clientDataJSON attestationObjectBS = runExceptT $ do
  _ <- hoistEither runAttestationCheck
  attestationObject <- hoistEither $ either (Left . CBORDecodeError "registerCredential") (pure . snd)
        $ CBOR.deserialiseFromBytes decodeAttestation
        $ BL.fromStrict 
        $ attestationObjectBS
  ad <- hoistEither $ extractAuthData attestationObject
  mAdPubKey <- verifyPubKey ad
  -- TODO: extensions here
  case (attStmt attestationObject) of
    AF_FIDO_U2F s -> hoistEither $ U2F.verify s ad clientDataHash
    AF_Packed s -> hoistEither $ Packed.verify s mAdPubKey ad (authData attestationObject) clientDataHash
    AF_TPM s -> hoistEither $ TPM.verify s ad (authData attestationObject) clientDataHash
    AF_AndroidSafetyNet s -> Android.verify cs s (authData attestationObject) clientDataHash
    AF_None -> pure ()
    _ -> throwE (UnsupportedAttestationFormat (pack $ show (attStmt attestationObject)))

  case attestedCredentialData ad of
    Nothing -> throwE MalformedAuthenticatorData
    Just c -> pure c
  where
    clientDataHash = hash clientDataJSON :: Digest SHA256
    runAttestationCheck = do 
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
    extractAuthData attestationObject = do
      ad <- either (const $ Left MalformedAuthenticatorData) pure $ C.runGet parseAuthenticatorData (authData attestationObject)
      hash (encodeUtf8 rpId) == rpIdHash ad ?? MismatchedRPID
      userPresent ad ?? UserNotPresent
      not verificationRequired || userVerified ad ?? UserUnverified
      pure ad
    verifyPubKey ad = do
      let pubKey = credentialPublicKey <$> attestedCredentialData ad
      case pubKey of
        Just k -> do
          parsedPubKey <- either throwE return $ parsePublicKey k
          let hasProperAlg pubKeyParam = hasMatchingAlg parsedPubKey $ alg (pubKeyParam :: PubKeyCredParam)
          when (not . any hasProperAlg $ pubKeyCredParams opts) $ throwE MalformedAuthenticatorData
          return $ Just parsedPubKey
        -- non present public key will fail anyway or the fmt == 'none'
        Nothing -> return Nothing

-- | 7.2. Verifying an Authentication Assertion
verify :: Challenge
  -> RelyingParty
  -> Maybe Text -- ^ Token Binding ID in base64
  -> Bool -- ^ require user verification?
  -> ByteString -- ^ clientDataJSON
  -> ByteString -- ^ authenticatorData
  -> ByteString -- ^ signature
  -> CredentialPublicKey -- ^ public key
  -> Either VerificationFailure ()
verify challenge rp tbi verificationRequired clientDataJSON adRaw sig pub = do
  clientDataCheck Get challenge clientDataJSON rp tbi
  let clientDataHash = hash clientDataJSON :: Digest SHA256
  _ <- verifyAuthenticatorData rp adRaw verificationRequired
  let dat = adRaw <> BA.convert clientDataHash
  pub' <- parsePublicKey pub
  verifySig pub' sig dat

clientDataCheck :: WebAuthnType -> Challenge -> ByteString -> RelyingParty -> Maybe Text -> Either VerificationFailure ()
clientDataCheck ctype challenge clientDataJSON rp tbi = do 
  ccd <-  first JSONDecodeError (J.eitherDecode $ BL.fromStrict clientDataJSON)
  clientType ccd == ctype ?? InvalidType
  challenge == clientChallenge ccd ?? MismatchedChallenge
  rpOrigin rp == clientOrigin ccd ?? MismatchedOrigin
  verifyClientTokenBinding tbi (clientTokenBinding ccd)

verifyClientTokenBinding :: Maybe Text -> TokenBinding -> Either VerificationFailure ()
verifyClientTokenBinding tbi (TokenBindingPresent t) = case tbi of
      Nothing -> Left UnexpectedPresenceOfTokenBinding
      Just t'
        | t == t' -> pure ()
        | otherwise -> Left MismatchedTokenBinding 
verifyClientTokenBinding _ _ = pure ()

verifyAuthenticatorData :: RelyingParty -> ByteString -> Bool -> Either VerificationFailure AuthenticatorData
verifyAuthenticatorData rp adRaw verificationRequired = do
  ad <- first (const MalformedAuthenticatorData) (C.runGet parseAuthenticatorData adRaw)
  hash (encodeUtf8 $ rpId (rp :: RelyingParty)) == rpIdHash ad ?? MismatchedRPID
  userPresent ad ?? UserNotPresent
  not verificationRequired || userVerified ad ?? UserUnverified
  pure ad

(??) :: Bool -> e -> Either e ()
False ?? e = Left e
True ?? _ = Right ()
infix 1 ??

hoistEither :: Monad m => Either e a -> ExceptT e m a
hoistEither = ExceptT . pure
