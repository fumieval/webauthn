module Lib where

import Data.Aeson ((.=))
import qualified Data.Aeson as AE
import Control.Concurrent.STM (atomically)
import Control.Concurrent.STM.TVar
import Control.Monad.IO.Class
import Control.Monad.Reader
import Data.ByteString (ByteString)
import qualified Data.Map as Map
import Data.Maybe (catMaybes, listToMaybe)
import Data.List.NonEmpty (NonEmpty)
import qualified Data.List.NonEmpty as NE
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.Text.Lazy as TL
import qualified Data.List.NonEmpty as NE
import Web.Scotty.Trans
import Data.X509.CertificateStore as X509
import Data.Int (Int64)
import Data.Word (Word16, Word32)
import Network.HTTP.Types.Status
import qualified Database.SQLite.Simple as SQL
import qualified Database.SQLite.Simple.FromField as SQL
import qualified Database.SQLite.Simple.ToField as SQL

import qualified WebAuthn as WA
import qualified WebAuthn.Common as WA
import qualified WebAuthn.Types as WA

--
-- Configuration
--

port :: Word16
port = 9000

rpId :: WA.RpId
rpId = WA.RpId "localhost"

rpOrigin :: WA.Origin
rpOrigin = WA.Origin "http" "localhost" (Just port)

rp :: WA.PublicKeyCredentialRpEntity
rp = WA.PublicKeyCredentialRpEntity (Just rpId) "ACME Inc."


main :: IO ()
main = do
  env <- initEnv
  scottyT (fromIntegral port) (`unApp` env) routes

type CredentialId = Int64
type UserId = Int64
type Username = Text

data Env = Env
  { dbconn :: SQL.Connection
  , sessionStore :: TVar (Map.Map Username SessionData)
  }


data SessionData = SessionData
  { waUserId :: WA.UserId
  , waChallenge :: WA.Challenge
  } deriving stock (Eq, Show)

saveSessionData :: (MonadIO m, MonadReader Env m) => Username -> SessionData -> m ()
saveSessionData k d = do
  s <- asks sessionStore
  liftIO $ atomically $ do
    m <- readTVar s
    writeTVar s $ Map.insert k d m

lookupSessionData :: (MonadIO m, MonadReader Env m) => Username -> m (Maybe SessionData)
lookupSessionData k = do
  s <- asks sessionStore
  m <- liftIO $ atomically $ readTVar s
  pure $ Map.lookup k m

initEnv :: IO Env
initEnv = do
  sessionStore <- atomically $ newTVar Map.empty
  dbconn <- SQL.open ":memory:"
  initSchema dbconn
  pure $ Env{..}


-- orphans
deriving via ByteString instance SQL.FromField WA.CredentialPublicKey
deriving via ByteString instance SQL.ToField WA.CredentialPublicKey
deriving via ByteString instance SQL.FromField WA.CredentialId
deriving via ByteString instance SQL.ToField WA.CredentialId
deriving via ByteString instance SQL.FromField WA.UserId
deriving via ByteString instance SQL.ToField WA.UserId
deriving via Word32 instance SQL.FromField WA.SignCount
deriving via Word32 instance SQL.ToField WA.SignCount

data User = User
  { id :: UserId
  , username :: Text
  , webauthnUserId :: WA.UserId
  } deriving stock (Eq, Show)

instance SQL.FromRow User where
  fromRow = User <$> SQL.field <*> SQL.field <*> SQL.field

data Credential = Credential
  { id :: CredentialId
  , userId :: UserId
  , credentialId :: WA.CredentialId
  , publicKey :: WA.CredentialPublicKey
  , signCount :: WA.SignCount
  } deriving stock (Eq, Show)

instance SQL.FromRow Credential where
  fromRow = Credential <$> SQL.field <*> SQL.field <*> SQL.field <*> SQL.field <*> SQL.field

initSchema :: SQL.Connection -> IO ()
initSchema conn = do
  SQL.execute_ conn "create table users (id integer primary key, username text unique not null, webauthn_user_id blob not null)"
  SQL.execute_ conn "create table creds (id integer primary key, user_id integer not null, credential_id blob not null, pubkey blob not null, sign_count integer not null)"

insertUser :: (MonadReader Env m, MonadIO m) => User -> m UserId
insertUser User{..} = do
  conn <- asks dbconn
  liftIO $ do
    SQL.execute conn "insert into users (username, webauthn_user_id) values (?, ?)" (username, webauthnUserId)
    SQL.lastInsertRowId conn

insertCredential :: (MonadReader Env m, MonadIO m) => Credential -> m ()
insertCredential c = do
  conn <- asks dbconn
  liftIO $ SQL.execute conn "insert into creds (user_id, credential_id, pubkey, sign_count) values (?, ?, ?, ?)" (userId c, credentialId c, publicKey c, signCount c)

fetchUser :: (MonadReader Env m, MonadIO m) => Username -> m (Maybe User)
fetchUser uname = do
  conn <- asks dbconn
  fmap listToMaybe $ liftIO $ SQL.query conn "select u.id, u.username, u.webauthn_user_id from users u where u.username = (?)" (SQL.Only uname)

fetchCredentials :: (MonadReader Env m, MonadIO m) => Username -> m [Credential]
fetchCredentials uname = do
  conn <- asks dbconn
  liftIO $ SQL.query conn "select c.id, c.user_id, c.credential_id, c.pubkey, c.sign_count from users u join creds c on (c.user_id = u.id) where u.username = (?)" (SQL.Only uname)

fetchCredentialsDescriptors :: (MonadReader Env m, MonadIO m) => Username -> m (Maybe (NonEmpty WA.PublicKeyCredentialDescriptor))
fetchCredentialsDescriptors uname =
  credsToAllowCreds <$> fetchCredentials uname

credsToAllowCreds :: [Credential] -> Maybe (NonEmpty WA.PublicKeyCredentialDescriptor)
credsToAllowCreds = \case
    []   -> Nothing
    x:xs -> Just $ flip fmap (x NE.:| xs) $ \c -> WA.PublicKeyCredentialDescriptor WA.PublicKey (credentialId c) Nothing

updateSignCount :: (MonadReader Env m, MonadIO m) => Int64 -> WA.SignCount -> m ()
updateSignCount cid signCount = do
  conn <- asks dbconn
  liftIO $ SQL.execute conn "update creds set sign_count = (?) where id = (?)" (signCount, cid)

fetchCredentialForAssertion :: (MonadReader Env m, MonadIO m) => Username -> WA.CredentialId -> m (Maybe Credential)
fetchCredentialForAssertion uname credid = do
  conn <- asks dbconn
  fmap listToMaybe $ liftIO $ SQL.query conn "select c.id, c.user_id, c.credential_id, c.pubkey, c.sign_count from users u join creds c on (c.user_id = u.id) where u.username = (?) and c.credential_id = (?)" (uname, credid)



newtype App a = App { unApp :: Env -> IO a }
  deriving ( Functor
           , Applicative
           , Monad
           , MonadIO
           , MonadReader Env
           ) via ReaderT Env IO

routes :: ScottyT TL.Text App ()
routes = do
  get "/" $ do
    setHeader "content-type" "text/html"
    file "../frontend/index.html"

  get (regex "^/dist/(.*)") $ do
    path <- param "1"
    setHeader "content-type" $ guessContentType path
    file $ "../frontend/dist/" <> T.unpack path

  post "/webauthn/credentialCreationOptions" $ do
    username <- param "username"
    Env{..} <- ask
    excludedCreds <- fetchCredentialsDescriptors username
    ch <- liftIO WA.newChallengeDef
    mu <- fetchUser username
    uid <- case mu of
      Just u -> pure $ webauthnUserId u
      Nothing -> liftIO WA.newUserId
    let u = WA.PublicKeyCredentialUserEntity uid username username
    saveSessionData username $ SessionData uid ch
    json $ mkCredentialCreationOptions rp u ch excludedCreds

  post "/webauthn/registerCredential" $ do
    username <- param "username"
    env <- ask
    SessionData{..} <- lookupSessionData username >>= maybe fail400 pure
    excludedCreds <- fetchCredentialsDescriptors username
    credential :: WA.PublicKeyCredential WA.AuthenticatorAttestationResponse <- jsonData
    let u = WA.PublicKeyCredentialUserEntity waUserId username username
        options = mkCredentialCreationOptions rp u waChallenge excludedCreds
        trustAnchors = X509.makeCertificateStore []
    res <- WA.verifyRegistration rpId rpOrigin Nothing options credential trustAnchors
    case res of
      Left err -> do
        json $ AE.object
          [ "status" .= ("failure" :: Text)
          , "message" .= T.pack (show err)
          ]
        fail400
      Right (attCredData, attStmt, signCount) -> do
        mu <- fetchUser username
        uid <- case mu of
          Nothing -> insertUser (User 0 username waUserId)
          Just u -> do
            let User{id = uid} = u
            pure uid
        insertCredential $ Credential 0 uid (WA.credentialId attCredData) (WA.credentialPublicKey attCredData) signCount
        json $ AE.object [ "status" .= ("success" :: Text) ]

  post "/webauthn/credentialRequestOptions" $ do
    username <- param "username"
    creds <- fetchCredentialsDescriptors username
    case creds of
      Nothing -> do
        json $ AE.object
          [ "status" .= ("failure" :: Text)
          , "message" .= ("No credentials registered for this user" :: Text)
          ]
        fail400
      Just allowCreds -> do
        ch <- liftIO WA.newChallengeDef
        saveSessionData username $ SessionData (WA.UserId "") ch
        json $ mkCredentialRequestOptions ch allowCreds

  post "/webauthn/verifyCredential" $ do
    username <- param "username"
    creds <- fetchCredentials username
    case credsToAllowCreds creds of
      Nothing ->  do
        json $ AE.object
          [ "status" .= ("failure" :: Text)
          , "message" .= ("No credentials registered for this user" :: Text)
          ]
        fail400
      Just allowCreds -> do
        SessionData{..} <- lookupSessionData username `orFinish` status400
        let options = mkCredentialRequestOptions waChallenge allowCreds
        credential@WA.PublicKeyCredential{rawId = credId} <- jsonData
        storedCred <- fetchCredentialForAssertion username credId `orFinish` status400
        case WA.verifyAssertion rpId rpOrigin Nothing options credential (publicKey storedCred) (signCount storedCred) of
          Left err -> do
            json $ AE.object
              [ "status" .= ("failure" :: Text)
              , "message" .= T.pack (show err)
              ]
            fail400
          Right mnewSignCount -> do
            let Credential{ id = cid } = storedCred
            forM_ mnewSignCount $ \newSignCount -> updateSignCount cid newSignCount
            json $ AE.object [ "status" .= ("success" :: Text) ]

  where
    fail400 = status status400 >> finish
    f `orFinish` s = f >>= maybe (status s >> finish) pure

guessContentType :: Text -> TL.Text
guessContentType path =
  case ext of
    "css" -> "text/css"
    "html" -> "text/html"
    "js" -> "text/javascript"
    _ -> "text/plain"
  where
    ext = case T.split (=='.') path of
            [] -> error "impossibe"
            xs -> last xs

mkCredentialCreationOptions
  :: WA.PublicKeyCredentialRpEntity
  -> WA.PublicKeyCredentialUserEntity
  -> WA.Challenge
  -> Maybe (NonEmpty WA.PublicKeyCredentialDescriptor)
  -> WA.PublicKeyCredentialCreationOptions
mkCredentialCreationOptions rp user challenge excluded = WA.PublicKeyCredentialCreationOptions
  { rp = rp
  , user = user
  , challenge = challenge
  , pubKeyCredParams = WA.PublicKeyCredentialParameters WA.PublicKey WA.ES256 NE.:| []
  , timeout = Just 60000
  , excludeCredentials = excluded
  , authenticatorSelection = Just $ WA.AuthenticatorSelection
    { authenticatorAttachment = Just WA.CrossPlatform 
    , residentKey = Nothing
    , requireResidentKey = Nothing
    , userVerification = Nothing
    }
  , attestation = Just WA.Direct
  , extensions = Nothing
  }

mkCredentialRequestOptions
  :: WA.Challenge
  -> NonEmpty WA.PublicKeyCredentialDescriptor
  -> WA.PublicKeyCredentialRequestOptions
mkCredentialRequestOptions challenge allowed =
  WA.PublicKeyCredentialRequestOptions
    { challenge = challenge
    , timeout = Just 60000 -- 60s
    , rpId = Nothing
    , allowCredentials = Just allowed
    , userVerification = Just WA.Discouraged
    }
