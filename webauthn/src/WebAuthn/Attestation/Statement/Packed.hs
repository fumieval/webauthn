-- | 8.2. Packed Attestation Statement Format
module WebAuthn.Attestation.Statement.Packed where

import Data.ByteString.Lazy (fromStrict)
import Data.ASN1.BinaryEncoding (DER(..))
import Data.ASN1.Prim (ASN1(..))
import Data.ASN1.Encoding (decodeASN1)
import Data.Maybe (isJust)
import qualified Data.ASN1.OID as OID (OID, getObjectID)
import Data.List (find)
import Control.Monad (unless)
import Crypto.Hash
import qualified Data.ByteString as BS
import qualified Data.ByteArray as BA
import qualified Data.X509 as X509
import qualified Codec.CBOR.Term as CBOR
import qualified Codec.CBOR.Decoding as CBOR
import qualified Data.Map as Map

import WebAuthn.Signature
import WebAuthn.Types

data Stmt = Stmt COSEAlgorithmIdentifier BS.ByteString (Maybe (X509.SignedExact X509.Certificate))
  deriving stock (Show)

decode :: CBOR.Term -> CBOR.Decoder s Stmt
decode (CBOR.TMap xs) = do
  let m = Map.fromList xs
  CBOR.TInt algc <- Map.lookup (CBOR.TString "alg") m ??? "alg"
  algo <- maybe (fail $ "Packed.decode: alg not supported " <> show algc) return $ pubKeyCredAlgFromInt32 $ fromIntegral algc
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

verify
  :: Stmt
  -> Maybe PublicKey
  -> AuthenticatorData
  -> BS.ByteString
  -> Digest SHA256
  -> Either VerificationFailure ()
verify (Stmt algo sig cert) mAdPubKey ad adRaw clientDataHash = do
  let dat = adRaw <> BA.convert clientDataHash
  case cert of
    Just x509 -> do
        let x509Cert = X509.getCertificate x509 
            pub = X509.certPubKey x509Cert
        verifyX509Sig (X509.SignatureALG X509.HashSHA256 X509.PubKeyALG_EC) pub dat sig "Packed"
        certMeetsCriteria x509Cert
    Nothing -> do
      adPubKey <- maybe (Left MalformedAuthenticatorData) return mAdPubKey
      unless (hasMatchingAlg adPubKey algo) $ Left MalformedAuthenticatorData
      verifySig adPubKey sig dat
    where
        certMeetsCriteria :: X509.Certificate -> Either VerificationFailure ()
        certMeetsCriteria c = do
            let (X509.Extensions mX509Exts) = X509.certExtensions c
                mX509Ext = mX509Exts >>= findProperExtension [1,3,6,1,4,1,45724,1,1,4]
                dnElements = X509.getDistinguishedElements $ X509.certSubjectDN c
            adAAGUID <- maybe (Left $ MalformedX509Certificate "No AAGUID provided in attested credential data") (return . unAAGUID . aaguid) $ attestedCredentialData ad
            certAAGUID <- maybe (Left $ MalformedX509Certificate "No AAGUID present in x509 extensions") (decodeAAGUID . X509.extRawContent) mX509Ext
            unless (certAAGUID == adAAGUID) . Left . MalformedX509Certificate $ "AAGUID in attested credential data doesn't match the one in x509 extensions"
            unless ( 
                (hasDnElement X509.DnCountry dnElements)
                &&
                (hasDnElement X509.DnOrganization dnElements)
                &&
                (hasDnElement X509.DnCommonName dnElements)
                &&
                (findDnElement X509.DnOrganizationUnit dnElements == Just "Authenticator Attestation")) . Left $ MalformedX509Certificate "Certificate SubjectDN doesn't meet crtieria"
        hasDnElement :: X509.DnElement -> [(OID.OID, X509.ASN1CharacterString)] -> Bool
        hasDnElement el = isJust . findDnElement el
        findDnElement :: X509.DnElement -> [(OID.OID, X509.ASN1CharacterString)] -> Maybe X509.ASN1CharacterString
        findDnElement dnElementName = lookup (OID.getObjectID dnElementName)
        findProperExtension :: OID.OID -> [X509.ExtensionRaw] -> Maybe X509.ExtensionRaw
        findProperExtension extensionOID = find ((==) extensionOID . X509.extRawOID)
        decodeAAGUID :: BS.ByteString -> Either VerificationFailure BS.ByteString
        decodeAAGUID bs = do
            asn1 <- either (const . Left $ MalformedX509Certificate "AAGUID decoding failed") return . decodeASN1 DER $ fromStrict bs
            case asn1 of
              [OctetString s] -> Right s
              _ -> Left $ MalformedX509Certificate "AAGUIID in wrong format - should be OctetString"
