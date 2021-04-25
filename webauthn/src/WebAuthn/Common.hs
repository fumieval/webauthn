module WebAuthn.Common where

import Control.Monad (unless)
import Crypto.Random ( MonadRandom(..) )
import qualified Crypto.Random as Random
import qualified Data.Aeson as AE
import Data.Bifunctor (first)
import Data.Text (Text)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as BL
import Data.Word (Word16)

import WebAuthn.Types


-- In order to prevent replay attacks, the challenges MUST contain enough entropy to make guessing them infeasible.
-- Challenges SHOULD therefore be at least 16 bytes long.
--
-- https://www.w3.org/TR/webauthn-2/#sctn-cryptographic-challenges
newChallengeDef :: MonadRandom m => m Challenge
newChallengeDef = newChallenge 16

newChallenge :: MonadRandom m => Word16 -> m Challenge
newChallenge len = Challenge <$> Random.getRandomBytes (fromIntegral len)

-- It is RECOMMENDED to let the user handle be 64 random bytes, and store this value in the user’s account.
--
-- https://www.w3.org/TR/webauthn-2/#sctn-user-handle-privacy
newUserId :: MonadRandom m => m UserId
newUserId = UserId <$> Random.getRandomBytes 64

parseCollectedClientData :: ByteString -> Either VerificationFailure CollectedClientData
parseCollectedClientData = 
  first JSONDecodeError . AE.eitherDecode . BL.fromStrict

-- | 7.1 steps 7-10 and 7.2 steps 11-14
verifyCollectedClientData
  :: WebAuthnType -- ^ Expected operation type
  -> Origin -- ^ Relying Party's origin
  -> Challenge
  -> Maybe Text -- ^ Relying Party's declared token binding
  -> CollectedClientData -- ^ parsed clientDataJSON
  -> Either VerificationFailure ()
verifyCollectedClientData rpTy rpOrigin rpChallenge rpTokenBinding CollectedClientData{..} = do
  unless (typ == rpTy) $ Left InvalidType
  unless (challenge == rpChallenge) $ Left $ MismatchedChallenge rpChallenge challenge
  unless (origin == rpOrigin) $ Left $ MismatchedOrigin rpOrigin origin
  verifyTokenBinding rpTokenBinding tokenBinding

-- | 7.1. step 10 and 7.2 step 14.
verifyTokenBinding
  :: Maybe Text         -- ^ Relying Party's declared token binding
  -> Maybe TokenBinding -- ^ Client token binding from CollectedClientData
  -> Either VerificationFailure ()
verifyTokenBinding = f
  where
    f Nothing   Nothing                             = pure ()
    f Nothing   (Just (TokenBindingPresent _))      = Left UnexpectedPresenceOfTokenBinding
    f (Just rp) (Just (TokenBindingPresent client)) = unless (rp == client) $ Left MismatchedTokenBinding
    f _         _                                   = Left MismatchedTokenBinding
