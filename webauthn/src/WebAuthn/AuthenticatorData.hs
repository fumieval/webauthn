module WebAuthn.AuthenticatorData where

import qualified Crypto.Hash as H
import Data.Bits (testBit)
import Data.Maybe (fromMaybe)
import qualified Data.ByteString as B
import qualified Data.Serialize as C

import WebAuthn.Types


parseAuthenticatorData :: B.ByteString -> Either String AuthenticatorData
parseAuthenticatorData = C.runGet authenticatorDataParser

authenticatorDataParser :: C.Get AuthenticatorData
authenticatorDataParser = do
  rpIdHashBytes <- C.getBytes 32
  -- digestFromByteString only fails if input is wrong size but we know we have 32 bytes and the hash is SHA-256
  let rpIdHash = fromMaybe (error "impossible") $ H.digestFromByteString rpIdHashBytes
  flags <- C.getWord8
  signCount <- SignCount <$> C.getWord32be
  attestedCredentialData <- if flags `testBit` 6
    then do
      aaguid <- AAGUID <$> C.getBytes 16
      len <- C.getWord16be
      credentialId <- CredentialId <$> C.getBytes (fromIntegral len)
      n <- C.remaining
      credentialPublicKey <- CredentialPublicKey <$> C.getBytes n
      pure $ Just AttestedCredentialData{..}
    else pure Nothing
  extensions <- if flags `testBit` 7
    then do
      pure $ Just B.empty -- TODO: parse extensions
    else pure Nothing
  let userPresent = flags `testBit` 0
      userVerified = flags `testBit` 2
  pure AuthenticatorData{..}
