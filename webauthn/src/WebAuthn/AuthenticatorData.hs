
module WebAuthn.AuthenticatorData where

import qualified Crypto.Hash as H
import Data.Bits (testBit)
import qualified Data.ByteString as B
import qualified Data.Serialize as C

import WebAuthn.Types

parseAuthenticatorData :: B.ByteString -> Either String AuthenticatorData
parseAuthenticatorData = C.runGet authenticatorDataParser

authenticatorDataParser :: C.Get AuthenticatorData
authenticatorDataParser = do
  rpIdHash' <- C.getBytes 32
  rpIdHash <- maybe (fail "impossible") pure $ H.digestFromByteString rpIdHash'
  flags <- C.getWord8
  signCount <- SignCount <$> C.getWord32be
  attestedCredentialData <- if testBit flags 6
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
  let userPresent = testBit flags 0
  let userVerified = testBit flags 2
  return AuthenticatorData{..}
