module WebAuthn.AuthenticatorData where

import Control.Monad (unless)
import qualified Crypto.Hash as H
import Data.Bits (testBit)
import Data.Maybe (fromMaybe)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import qualified Data.Serialize as C
import qualified Codec.CBOR.Read as CBOR
import qualified Codec.CBOR.Term as CBOR
import Data.Word (Word8)
import Data.Int (Int64)
import Crypto.Hash ( SHA256, Digest )

import WebAuthn.Types


-- attestedCredentialData and extensions are variable length CBOR encoded fields so we have to track where we are in the input or rather
-- what is left to be parsed after each step
parseAuthenticatorData :: B.ByteString -> Either String AuthenticatorData
parseAuthenticatorData bs = do
  ((rpIdHash, flags, signCount), rest1) <- C.runGetState adFixedFields bs 0
  
  (attestedCredentialData, rest2) <- if flags `testBit` 6
    then parseAttestedCredentialData rest1
    else pure (Nothing, rest1)
  
  (extensions, _, rest3) <- if flags `testBit` 7
    then do
      (e, n, r) <- parseCborTerm rest2
      pure (Just e, n, r)
    else pure (Nothing, 0, rest2)
  
  unless (B.null rest3) $ Left "AuthenticatorData: decoding failed: leftover bytes"

  let userPresent = flags `testBit` 0
      userVerified = flags `testBit` 2
  pure AuthenticatorData{..}

adFixedFields :: C.Get (Digest SHA256, Word8, SignCount)
adFixedFields = do
  rpIdHashBytes <- C.getBytes 32
  -- digestFromByteString only fails if input is wrong size but we know we have 32 bytes
  let rpIdHash = fromMaybe (error "impossible") $ H.digestFromByteString rpIdHashBytes
  flags <- C.getWord8
  signCount <- SignCount <$> C.getWord32be
  pure (rpIdHash, flags, signCount)

parseAttestedCredentialData :: B.ByteString -> Either String (Maybe AttestedCredentialData, B.ByteString)
parseAttestedCredentialData bs = do
  ((aaguid, credentialId), rest1) <- C.runGetState f bs 0
  (_, siz, rest2) <- parseCborTerm rest1
  let credentialPublicKey = CredentialPublicKey $ B.take (fromIntegral siz) rest1
  pure (Just AttestedCredentialData{..}, rest2)
  where
    f = do
      aaguid <- AAGUID <$> C.getBytes 16
      len <- C.getWord16be
      credentialId <- CredentialId <$> C.getBytes (fromIntegral len)
      pure (aaguid, credentialId)

parseCborTerm :: B.ByteString -> Either String (CBOR.Term, Int64, B.ByteString)
parseCborTerm bs =
  case CBOR.deserialiseFromBytesWithSize CBOR.decodeTerm (BL.fromStrict bs) of
    Right (rest, siz, term) -> pure (term, siz, BL.toStrict rest)
    Left err -> Left (show err)
