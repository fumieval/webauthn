module Network.Wai.Middleware.WebAuthn.Utils where

import Control.Monad.IO.Class
import Control.Monad.Trans.Cont
import qualified Data.Aeson as J
import Data.String
import Network.Wai
import Network.HTTP.Types

headers :: [Header]
headers = [("Access-Control-Allow-Origin", "*")]

responseJSON :: J.ToJSON a => a -> Response
responseJSON val = responseLBS status200 ((hContentType, "application/json") : headers) $ J.encode val

unauthorised :: Response
unauthorised = responseBuilder status403 headers "Unauthorised"

jsonBody :: J.FromJSON a => (Response -> IO ResponseReceived) -> Request -> ContT ResponseReceived IO a
jsonBody sendResp req = do
  body <- liftIO $ lazyRequestBody req
  ContT $ \k -> case J.eitherDecode body of
    Left err -> sendResp $ responseBuilder status400 headers $ fromString err
    Right a -> k a
