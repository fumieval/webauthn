
module WebAuthn.Packed where

import Data.Maybe (isJust)
import qualified Data.ASN1.OID as OID (OID, getObjectID)
import Data.List (find)
import Control.Monad (when)
import Crypto.Hash
import Data.ByteString (ByteString)
import qualified Data.ByteArray as BA
import qualified Data.X509 as X509
import qualified Codec.CBOR.Term as CBOR
import qualified Codec.CBOR.Decoding as CBOR
import qualified Data.Map as Map
import WebAuthn.Signature
import WebAuthn.Types

data Stmt = Stmt PubKeyCredAlg ByteString (Maybe (X509.SignedExact X509.Certificate))
  deriving Show

decode :: CBOR.Term -> CBOR.Decoder s Stmt
decode (CBOR.TMap xs) = do
  let m = Map.fromList xs
  CBOR.TInt algc <- Map.lookup (CBOR.TString "alg") m ??? "alg"
  algo <- maybe (fail $ "Packed.decode: alg not supported " <> show algc) return $ pubKeyCredAlgFromInt algc
  CBOR.TBytes sig <- Map.lookup (CBOR.TString "sig") m ??? "sig"
  cert <- case Map.lookup (CBOR.TString "x5c") m of
    Just (CBOR.TList (CBOR.TBytes certBS : _)) ->
      either fail (pure . Just) $ X509.decodeSignedCertificate certBS
    _ -> pure Nothing
  return $ Stmt algo sig cert
  where
    Nothing ??? e = fail e
    Just a ??? _ = pure a
decode _ = fail "Packed.decode: expected a Map"

verify :: Stmt
  -> Maybe PublicKey
  -> AuthenticatorData
  -> ByteString
  -> Digest SHA256
  -> Either VerificationFailure ()
verify (Stmt algo sig cert) mAdPubKey ad adRaw clientDataHash = do
  let dat = adRaw <> BA.convert clientDataHash
  case cert of
    Just x509 -> do
        let x509Cert = X509.getCertificate x509 
            pub = X509.certPubKey x509Cert
        verifyX509Sig (X509.SignatureALG X509.HashSHA256 X509.PubKeyALG_EC) pub dat sig "Packed"
        when (not (certMeetsCriteria x509Cert)) $ Left MalformedAuthenticatorData
    Nothing -> do
      adPubKey <- maybe (Left MalformedAuthenticatorData) return mAdPubKey
      when (not $ hasMatchingAlg adPubKey algo) $ Left MalformedAuthenticatorData
      verifySig adPubKey sig dat
    where
        certMeetsCriteria :: X509.Certificate -> Bool
        certMeetsCriteria c =
            let 
                maaguid = unAAGUID . aaguid <$> attestedCredentialData ad
                (X509.Extensions mX509Exts) = X509.certExtensions c
                mX509Ext = mX509Exts >>= findProperExtension [1,3,6,1,4,1,45724,1,1,4]
                dnElements = X509.getDistinguishedElements $ X509.certSubjectDN c
            in
                (maybe False ((==) maaguid . Just . X509.extRawContent) mX509Ext)
                &&
                (hasDnElement X509.DnCountry dnElements)
                &&
                (hasDnElement X509.DnOrganization dnElements)
                &&
                (hasDnElement X509.DnCommonName dnElements)
                &&
                (findDnElement X509.DnOrganizationUnit dnElements == Just "Authenticator Attestation")
        hasDnElement :: X509.DnElement -> [(OID.OID, X509.ASN1CharacterString)] -> Bool
        hasDnElement el = isJust . findDnElement el
        findDnElement :: X509.DnElement -> [(OID.OID, X509.ASN1CharacterString)] -> Maybe X509.ASN1CharacterString
        findDnElement dnElementName = fmap snd . find ((==) (OID.getObjectID dnElementName) . fst)
        findProperExtension :: OID.OID -> [X509.ExtensionRaw] -> Maybe X509.ExtensionRaw
        findProperExtension extensionOID = find ((==) extensionOID . X509.extRawOID)
