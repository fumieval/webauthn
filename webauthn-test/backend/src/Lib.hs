module Lib where

import Data.Aeson ((.=))
import qualified Data.Aeson as AE
import Control.Concurrent.STM (atomically)
import Control.Concurrent.STM.TVar
import Control.Monad.IO.Class
import Control.Monad.Reader
import qualified Data.ByteString.Base64.URL as B64URL
import Data.ByteString (ByteString)
import qualified Data.Map as Map
import Data.Maybe (listToMaybe)
import Data.List.NonEmpty (NonEmpty)
import qualified Data.List.NonEmpty as NE
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.Text.Lazy as TL
import Web.Scotty.Trans
import Data.X509.CertificateStore as X509
import Data.Int (Int64)
import Data.Word (Word16, Word32)
import Network.HTTP.Types.Status
import qualified Database.SQLite.Simple as SQL
import qualified Database.SQLite.Simple.FromField as SQL
import qualified Database.SQLite.Simple.ToField as SQL
import Web.Cookie
import Web.Scotty.Cookie

import qualified WebAuthn as WA
import qualified WebAuthn.Common as WA
import qualified WebAuthn.Types as WA

import qualified Types

--
-- Configuration
--

data RpConf = RpConf
  { rpPort :: Word16
  , rpId :: WA.RpId
  , rpOrigin :: WA.Origin
  , rpEntity :: WA.PublicKeyCredentialRpEntity
  }

conf :: RpConf
conf = RpConf
  { rpPort = port
  , rpId = rpId
  , rpOrigin =  WA.Origin "http" "192.168.122.1" (Just port)
  , rpEntity = WA.PublicKeyCredentialRpEntity (Just rpId) "ACME Inc."
  }
  where
    port = 9000
    rpId = WA.RpId "192.168.122.1"

main :: IO ()
main = do
  env <- initEnv
  scottyT (fromIntegral (rpPort conf)) (`unApp` env) routes

type CredentialId = Int64
type UserId = Int64
type Username = Text

data Env = Env
  { dbconn :: SQL.Connection
  , sessionStore :: TVar (Map.Map SessionId SessionData)
  }

newtype SessionId = SessionId { unSessionId :: ByteString } deriving stock (Eq, Show, Ord)

data SessionData = SessionData
  { creationOptions :: Maybe WA.PublicKeyCredentialCreationOptions
  , requestOptions :: Maybe WA.PublicKeyCredentialRequestOptions
  } deriving stock (Eq, Show)

newSessionId :: (MonadIO m) => m SessionId
newSessionId =
  SessionId . WA.unChallenge <$> liftIO WA.newChallengeDef

saveSessionData :: (MonadIO m, MonadReader Env m) => SessionId -> SessionData -> m ()
saveSessionData k d = do
  s <- asks sessionStore
  liftIO $ atomically $ do
    m <- readTVar s
    writeTVar s $ Map.insert k d m

lookupSessionData :: (MonadIO m, MonadReader Env m) => SessionId -> m (Maybe SessionData)
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

fetchCredentialForAssertion :: (MonadReader Env m, MonadIO m) => WA.CredentialId -> m (Maybe Credential)
fetchCredentialForAssertion credid = do
  conn <- asks dbconn
  fmap listToMaybe $ liftIO $ SQL.query conn "select c.id, c.user_id, c.credential_id, c.pubkey, c.sign_count from creds c where c.credential_id = (?)" (SQL.Only credid)


newtype App a = App { unApp :: Env -> IO a }
  deriving ( Functor
           , Applicative
           , Monad
           , MonadIO
           , MonadReader Env
           ) via ReaderT Env IO

authCookieName :: Text
authCookieName = "sessid"

authCookie :: SetCookie
authCookie = def
  { setCookieName = TE.encodeUtf8 authCookieName
  , setCookieValue = ""
  , setCookiePath = Just "/"
  , setCookieHttpOnly = True
  -- only for testing
  , setCookieSecure = False
  , setCookieSameSite = Nothing
  }

setSessionCookie :: (Monad m) => SessionId -> ActionT TL.Text m ()
setSessionCookie sessId =
  setCookie $ authCookie { setCookieValue = TE.encodeUtf8 $ B64URL.encodeBase64Unpadded $ unSessionId sessId }

getSessionId :: (Monad m) => ActionT TL.Text m (Maybe SessionId)
getSessionId = do
  mc <- getCookie authCookieName
  case mc of
    Just t ->
      case B64URL.decodeBase64Unpadded $ TE.encodeUtf8 t of
        Right x -> pure $ Just $ SessionId x
        Left _ -> pure Nothing
    Nothing -> pure Nothing

requireSessionId :: (Monad m) => ActionT TL.Text m SessionId
requireSessionId = getSessionId `orFinish` status400


routes :: ScottyT TL.Text App ()
routes = do
  
  post "/attestation/options" $ do
    sessId <- getSessionId >>= maybe newSessionId pure

    req :: Types.TestAttestationOptionsRequest <- jsonData
    let username = (Types.username :: Types.TestAttestationOptionsRequest -> Text) req
        displayName = Types.displayName req
        authSel = Types.authenticatorSelection req
        exts = (Types.extensions :: Types.TestAttestationOptionsRequest -> Maybe AE.Value) req

    Env{..} <- ask
    excludedCreds <- fetchCredentialsDescriptors username
    ch <- liftIO WA.newChallengeDef
    mu <- fetchUser username
    uid <- case mu of
      Just u -> pure $ webauthnUserId u
      Nothing -> liftIO WA.newUserId
    let u = WA.PublicKeyCredentialUserEntity uid username displayName
        opts = WA.PublicKeyCredentialCreationOptions
          { rp = rpEntity conf
          , user = u
          , challenge = ch
          , pubKeyCredParams = WA.PublicKeyCredentialParameters WA.PublicKey WA.ES256 NE.:| []
          , timeout = Just 60000
          , excludeCredentials = excludedCreds
          , authenticatorSelection = authSel
          , attestation = Just $ Types.attestation req
          , extensions = exts
          }
        AE.Object optsObj = AE.toJSON opts
        AE.Object statusProps = AE.object
          [ "status" .= AE.String "ok"
          , "errorMessage" .= AE.String ""
          , "extensions" .= exts
          ]
        res = AE.Object (statusProps <> optsObj)
    
    saveSessionData sessId $ SessionData (Just opts) Nothing
    
    setSessionCookie sessId
    json res

  post "/attestation/result" $ do
    sessId <- requireSessionId
    SessionData{..} <- lookupSessionData sessId >>= maybe fail400 pure
    savedOpts <- pure creationOptions `orFinish` status400
    
    let username = (WA.name :: WA.PublicKeyCredentialUserEntity -> Text) $ WA.user savedOpts
        wauid = (WA.id :: WA.PublicKeyCredentialUserEntity -> WA.UserId) $ WA.user savedOpts
        trustAnchors = X509.makeCertificateStore []
    
    excludedCreds <- fetchCredentialsDescriptors username

    credential :: WA.PublicKeyCredential WA.AuthenticatorAttestationResponse <- jsonData
    res <- WA.verifyRegistration (rpId conf) (rpOrigin conf) Nothing savedOpts credential trustAnchors
    case res of
      Left err -> do
        json $ AE.object
          [ "status" .= AE.String "failure"
          , "errorMessage" .= T.pack (show err)
          ]
        fail400
      Right (attCredData, attStmt, signCount) -> do
        mu <- fetchUser username
        uid <- case mu of
          Nothing -> insertUser (User 0 username wauid)
          Just u -> do
            let User{id = uid} = u
            pure uid
        insertCredential $ Credential 0 uid (WA.credentialId attCredData) (WA.credentialPublicKey attCredData) signCount
        json $ AE.object
          [ "status" .= AE.String "ok"
          , "errorMessage" .= AE.String ""
          ]

  post "/assertion/options" $ do
    sessId <- getSessionId >>= maybe newSessionId pure

    req :: Types.TestAssertionOptionsRequest <- jsonData
    let username = (Types.username :: Types.TestAssertionOptionsRequest -> Text) req
        uv = (Types.userVerification :: Types.TestAssertionOptionsRequest -> Maybe WA.UserVerificationRequirement) req
        exts = (Types.extensions :: Types.TestAssertionOptionsRequest -> Maybe AE.Value) req

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
        let opts = WA.PublicKeyCredentialRequestOptions
              { challenge = ch
              , timeout = Just 60000 -- 60s
              , rpId = Nothing
              , allowCredentials = creds
              , userVerification = uv
              }
            AE.Object optsObj = AE.toJSON opts
            AE.Object statusProps = AE.object
              [ "status" .= AE.String "ok"
              , "errorMessage" .= AE.String ""
              , "extensions" .= exts
              ]
            res = AE.Object (statusProps <> optsObj)
    
        saveSessionData sessId $ SessionData Nothing (Just opts)
        json res

  post "/assertion/result" $ do
    
    sessId <- requireSessionId
    SessionData{..} <- lookupSessionData sessId >>= maybe fail400 pure
    savedOpts <- pure requestOptions `orFinish` status400

    credential@WA.PublicKeyCredential{rawId = credId} <- jsonData
    storedCred <- fetchCredentialForAssertion credId `orFinish` status400
    case WA.verifyAssertion (rpId conf) (rpOrigin conf) Nothing savedOpts credential (publicKey storedCred) (signCount storedCred) of
      Left err -> do
        json $ AE.object
          [ "status" .= ("failure" :: Text)
          , "errorMessage" .= T.pack (show err)
          ]
        fail400
      Right mnewSignCount -> do
        let Credential{ id = cid } = storedCred
        forM_ mnewSignCount $ \newSignCount -> updateSignCount cid newSignCount
        json $ AE.object
          [ "status" .= AE.String "ok"
          ]
    
fail400 :: (Monad m) => ActionT TL.Text m a
fail400 = status status400 >> finish
    
orFinish :: (Monad m, ScottyError e) => ActionT e m (Maybe b) -> Status -> ActionT e m b
f `orFinish` s = f >>= maybe (status s >> finish) pure
