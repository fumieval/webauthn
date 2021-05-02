{-# LANGUAGE OverloadedStrings #-}
module WebAuthn.Signature
  ( PublicKey(..)
  , parsePublicKey
  , parsePublicKeyTerm
  , verifySig
  , verifyX509Sig
  , encodeECSSignature
  , hasMatchingAlg
  ) where

import Control.Monad ((>=>))
import Data.Bits (unsafeShiftL, (.|.))
import qualified Data.ByteArray as BA
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import Crypto.Hash (SHA256(..), hashWith)
import qualified Crypto.PubKey.ECC.ECDSA as EC
import qualified Crypto.PubKey.ECC.Types as EC
import qualified Crypto.PubKey.RSA.Types as RSA
import qualified Crypto.PubKey.RSA.Prim as RSA
import qualified Codec.CBOR.Term as CBOR
import qualified Codec.Serialise as CBOR
import qualified Data.Map as Map
import Data.ASN1.BinaryEncoding
import Data.ASN1.Encoding
import Data.ASN1.Types
import WebAuthn.Types
import qualified Data.X509 as X509
import qualified Data.X509.Validation as X509

data PublicKey
  = PubEC EC.PublicKey
  | PubRSA RSA.PublicKey
  deriving (Show, Eq)

verifySig :: PublicKey
  -> B.ByteString -- ^ signature
  -> B.ByteString -- ^ data
  -> Either VerificationFailure ()
verifySig (PubEC pub) sig dat = do
  sig' <- maybe (Left MalformedSignature) pure $ parseECSignature sig
  case EC.verify SHA256 pub sig' dat of
    True  -> pure ()
    False -> Left $ SignatureFailure "EC256"
verifySig (PubRSA pub) sig dat
  | Just dat' <- parseRS256Signature (RSA.ep pub sig), dat' == BA.convert (hashWith SHA256 dat) = pure ()
  | otherwise = Left $ SignatureFailure "RS256"

hasMatchingAlg :: PublicKey -> COSEAlgorithmIdentifier -> Bool
hasMatchingAlg key algo =
    case key of
      PubEC (EC.PublicKey curve _) -> algo == ES256 && curve == EC.getCurveByName EC.SEC_p256r1
      PubRSA (RSA.PublicKey size _ _) -> algo == RS256 && size == 256

parsePublicKey :: CredentialPublicKey -> Either VerificationFailure PublicKey
parsePublicKey pub = do
  m <- either (Left . CBORDecodeError "parsePublicKey") pure
    $ CBOR.deserialiseOrFail $ BL.fromStrict $ unCredentialPublicKey pub
  maybe (Left MalformedPublicKey) pure $ do
      CBOR.TInt ty <- Map.lookup 3 m
      case ty of
        -7 -> do
          CBOR.TInt crv <- Map.lookup (-1) m
          CBOR.TBytes x <- Map.lookup (-2 :: Int) m
          CBOR.TBytes y <- Map.lookup (-3) m
          c <- case crv of
            1 -> pure EC.SEC_p256r1
            _ -> fail $ "parsePublicKey: unknown curve: " ++ show crv
          pure $ PubEC $ EC.PublicKey (EC.getCurveByName c) (EC.Point (fromOctet x) (fromOctet y))
        -257 -> do
          CBOR.TBytes n <- Map.lookup (-1) m
          CBOR.TBytes e <- Map.lookup (-2) m
          pure $ PubRSA $ RSA.PublicKey 256 (fromOctet n) (fromOctet e)
        _ -> fail $ "parsePublicKey: unknown algorithm"

parsePublicKeyTerm :: CBOR.Term -> Either String PublicKey
parsePublicKeyTerm = \case
  CBOR.TMap xs ->
    let m = Map.fromList xs
    in maybe (Left "parsePublicKeyTerm: failure") pure $ do
      CBOR.TInt ty <- Map.lookup (CBOR.TInt 3) m
      case ty of
        -7 -> do
          CBOR.TInt crv <- Map.lookup (CBOR.TInt (-1)) m
          CBOR.TBytes x <- Map.lookup (CBOR.TInt (-2)) m
          CBOR.TBytes y <- Map.lookup (CBOR.TInt (-3)) m
          c <- case crv of
            1 -> pure EC.SEC_p256r1
            _ -> fail $ "parsePublicKeyTerm: unknown curve: " ++ show crv
          pure $ PubEC $ EC.PublicKey (EC.getCurveByName c) (EC.Point (fromOctet x) (fromOctet y))
        -257 -> do
          CBOR.TBytes n <- Map.lookup (CBOR.TInt (-1)) m
          CBOR.TBytes e <- Map.lookup (CBOR.TInt (-2)) m
          pure $ PubRSA $ RSA.PublicKey 256 (fromOctet n) (fromOctet e)
        _ -> fail $ "parsePublicKeyTerm: unknown algorithm"
  _ -> Left "parsePublicKeyTerm: failure"

fromOctet :: B.ByteString -> Integer
fromOctet = B.foldl' (\r x -> r `unsafeShiftL` 8 .|. fromIntegral x) 0

parseECSignature :: B.ByteString -> Maybe EC.Signature
parseECSignature b = case decodeASN1' BER b of
  Left _ -> Nothing
  Right asn1 -> case asn1 of
    Start Sequence:IntVal r:IntVal s:End Sequence:_ -> Just $ EC.Signature r s
    _ -> Nothing

encodeECSSignature :: EC.Signature -> B.ByteString
encodeECSSignature (EC.Signature r s) = encodeASN1' DER (Start Sequence:IntVal r:IntVal s:End Sequence:[])

parseRS256Signature :: B.ByteString -> Maybe B.ByteString
parseRS256Signature = unpad >=> \b -> case decodeASN1' BER b of
  Left _ -> Nothing
  Right asn1 -> case asn1 of
    Start Sequence:Start Sequence:_:_:End Sequence:OctetString sig:_ -> Just sig
    _ -> Nothing

unpad :: B.ByteString -> Maybe B.ByteString
unpad packed
    | paddingSuccess = Just m
    | otherwise      = Nothing
  where
        (zt, ps0m)   = B.splitAt 2 packed
        (ps, zm)     = B.span (/= 0) ps0m
        (z, m)       = B.splitAt 1 zm
        paddingSuccess = and [ zt == "\NUL\SOH"
                              , z == "\NUL"
                              , B.length ps >= 8
                              ]

verifyX509Sig :: X509.SignatureALG -> X509.PubKey -> B.ByteString -> B.ByteString -> [Char] -> Either VerificationFailure ()
verifyX509Sig sigType pub dat sig msg = case X509.verifySignature sigType pub dat sig of
  X509.SignaturePass -> pure ()
  X509.SignatureFailed e -> Left (SignatureFailure (msg <> " " <> show e))
