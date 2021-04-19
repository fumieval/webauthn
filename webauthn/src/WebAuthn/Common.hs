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
newChallengeDef :: MonadRandom m => m Challenge
newChallengeDef = newChallenge 16

newChallenge :: MonadRandom m => Word16 -> m Challenge
newChallenge len = Challenge <$> Random.getRandomBytes (fromIntegral len)

parseCollectedClientData :: ByteString -> Either VerificationFailure CollectedClientData
parseCollectedClientData = 
  first JSONDecodeError . AE.eitherDecode . BL.fromStrict

-- | 7.1. step 10.
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
