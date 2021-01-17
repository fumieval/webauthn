{-# LANGUAGE RecordWildCards #-}
import WebAuthn
    ( registerCredential,
      verify )
import Test.Tasty ( defaultMain, testGroup, TestTree )
import Test.Tasty.HUnit (assertEqual,  assertBool, testCaseSteps )
import Data.String.Interpolate ()
import Data.ByteString.Base64.URL as BS (decodeLenient)
import Data.Aeson as A (toEncoding, toJSON, eitherDecode, FromJSON)
import URI.ByteString ()
import Data.X509.CertificateStore ( readCertificateStore )
import Data.ByteString ( ByteString )
import Data.Either ( isRight )
import qualified Data.ByteString.Lazy as BL
import WebAuthn.Types
    ( PublicKeyCredentialCreationOptions(PublicKeyCredentialCreationOptions),
      PubKeyCredParam(PubKeyCredParam),
      PubKeyCredAlg(ES256),
      PublicKeyCredentialDescriptor(PublicKeyCredentialDescriptor),
      AuthenticatorTransport(BLE),
      PublicKeyCredentialType(PublicKey),
      User(User),
      AttestedCredentialData(credentialPublicKey),
      RelyingParty,
      Origin(Origin),
      Challenge(Challenge),
      Base64ByteString(Base64ByteString),
      defaultRelyingParty )
import Data.Aeson.QQ.Simple ( aesonQQ )
import Data.List.NonEmpty ( NonEmpty((:|)) )
import Data.Aeson.Encoding (value)

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests = testGroup "Tests" [androidTests]

androidTests :: TestTree
androidTests = testGroup "WebAuthn Tests" 
  [
    -- See: https://github.com/fumieval/webauthn/issues/9
    -- androidCredentialTest
    packedSelfAttestedTest
    , packedNonSelfAttestedTest
    , fidoU2FAttestedTest
    , tpmTest
    , registrationTest
  ]

androidCredentialTest :: TestTree
androidCredentialTest = genericCredentialTest "Android test" androidPublicKeyCredential

registrationTest :: TestTree
registrationTest = testCaseSteps "Credentials Test" $ \step -> do
  step "Credential creation"
  let pkcco = PublicKeyCredentialCreationOptions (defaultRelyingParty (Origin "https" "webauthn.biz" Nothing)) (Base64ByteString "12343434") (User (Base64ByteString "id") Nothing Nothing) (PubKeyCredParam PublicKey ES256 :| []) Nothing Nothing Nothing Nothing (Just (PublicKeyCredentialDescriptor PublicKey (Base64ByteString "1234") (Just (BLE :| []))  :| []))
  let ref = [aesonQQ| {
    "rp":{"id":"webauthn.biz"},
    "challenge":"MTIzNDM0MzQ=",
    "user":{"id":"aWQ="},
    "pubKeyCredParams":[
      {
        "type":"public-key",
        "alg":-7
      }],
    "excludeCredentials":[
      {"type":"public-key", "id": "MTIzNA==", "transports":["ble"]}
      ]
    }
  |]
  assertEqual "TOJSON not equal" ref (toJSON pkcco)

defRp :: RelyingParty
defRp = defaultRelyingParty  (Origin "https" "psteniusubi.github.io" Nothing)

decodePanic :: FromJSON a => ByteString -> a
decodePanic s = either error Prelude.id (A.eitherDecode (BL.fromStrict s))

data TestPublicKeyCredential = TestPublicKeyCredential 
                                {
                                clientDataJSON :: ByteString
                                , attestationObject :: ByteString
                                , challenge :: Challenge
                                , getChallenge :: Challenge
                                , getClientDataJSON :: ByteString
                                , getAuthenticatorData :: ByteString
                                , getSignature :: ByteString
                                }


androidPublicKeyCredential = TestPublicKeyCredential 
                             {
                             clientDataJSON = androidClientDataJSON
                             , attestationObject = androidAttestationObject
                             , challenge = androidChallenge
                             , getChallenge = androidGetChallenge
                             , getClientDataJSON = androidGetClientDataJSON
                             , getAuthenticatorData = androidGetAuthenticatorData
                             , getSignature = androidGetSignature
                             }

packedSelfAttestedKeyCredential = TestPublicKeyCredential 
                              {
                              clientDataJSON = BS.decodeLenient "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiSkhxcVRQWF9oQkw1bHlDZE9DQzRMNTVzcm9LbXFMX0RDemlOeWx6MXF5dyIsIm9yaWdpbiI6Imh0dHBzOi8vcHN0ZW5pdXN1YmkuZ2l0aHViLmlvIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ"
                              , attestationObject = BS.decodeLenient "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEYwRAIgaAVCWvaUJo0NBq_c1yr7R9jXN-G8MqqIOVhswsTX4K0CIFZul9oOTdWwDx4WAb3cgPTTjWzXSSxcjseS33OVqhgWaGF1dGhEYXRhWNUs15PPoLQYy78OqFIihgfZ6XszPU2wpBAXdmr2u4x1UUVgAZ6yrc4AAjW8xgpkiwsl8fBVAwBRAft9ACeHPR6QCu6Clp5otBmdIyMGV6w1emT--vpR_JpIKPJdIkNLOjzoLqd-z_j3vKvLCB4pQAwccqPF56HKs4h8DsrEuG0mMx5jJz_9ndh1pQECAyYgASFYIFgD8QsPYGMaq49F7-JWJowfVaxeiFzJUXp2k8nvrRpUIlggyGWqdGOBLZgO61mPMEncHjTmBxFPWzqKbUlBvT1fhRg"
                              , challenge = Challenge (BS.decodeLenient "JHqqTPX_hBL5lyCdOCC4L55sroKmqL_DCziNylz1qyw")
                              , getChallenge = Challenge (BS.decodeLenient "VXrK0ywwsYO2k6c52md-Lg2JDOmxrkGMli_4MHJcKaM")
                              , getClientDataJSON = BS.decodeLenient "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiVlhySzB5d3dzWU8yazZjNTJtZC1MZzJKRE9teHJrR01saV80TUhKY0thTSIsIm9yaWdpbiI6Imh0dHBzOi8vcHN0ZW5pdXN1YmkuZ2l0aHViLmlvIiwiY3Jvc3NPcmlnaW4iOmZhbHNlLCJvdGhlcl9rZXlzX2Nhbl9iZV9hZGRlZF9oZXJlIjoiZG8gbm90IGNvbXBhcmUgY2xpZW50RGF0YUpTT04gYWdhaW5zdCBhIHRlbXBsYXRlLiBTZWUgaHR0cHM6Ly9nb28uZ2wveWFiUGV4In0"
                              , getAuthenticatorData = BS.decodeLenient "LNeTz6C0GMu_DqhSIoYH2el7Mz1NsKQQF3Zq9ruMdVEFYAGfAg"
                              , getSignature = BS.decodeLenient "MEYCIQDteZqnEublzIw5AgnOzu5sd7b387GitIHbjNSXFFoFxgIhAP4IFIiyweG__D3VOBSnvneuK794RuGoUNasXhQNe0gk"
                              }

packedSelfAttestedTest = genericCredentialTest "Packed self attested test" packedSelfAttestedKeyCredential

packedNonSelfAttestedKeyCredential = TestPublicKeyCredential 
                              {
                              clientDataJSON = BS.decodeLenient "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiTU1jVUFkWkJ2STRENktNYldjZW44bTNNRElCRWVWQWxkalBwcjYzZWFJbyIsIm9yaWdpbiI6Imh0dHBzOi8vcHN0ZW5pdXN1YmkuZ2l0aHViLmlvIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ"
                              , attestationObject = BS.decodeLenient "o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIge9MVIqCg80CbXoD2m6Hu4J6EKztfia76dtOoAeDUejQCIQCQwLbwVYoiYsAcOf8iigzbixDBiUAYJpUCIoa-XXvuYmN4NWOBWQLBMIICvTCCAaWgAwIBAgIEGKxGwDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbjELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEnMCUGA1UEAwweWXViaWNvIFUyRiBFRSBTZXJpYWwgNDEzOTQzNDg4MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeeo7LHxJcBBiIwzSP-tg5SkxcdSD8QC-hZ1rD4OXAwG1Rs3Ubs_K4-PzD4Hp7WK9Jo1MHr03s7y-kqjCrutOOqNsMGowIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjcwEwYLKwYBBAGC5RwCAQEEBAMCBSAwIQYLKwYBBAGC5RwBAQQEEgQQy2lIHo_3QDmT7AonKaFUqDAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQCXnQOX2GD4LuFdMRx5brr7Ivqn4ITZurTGG7tX8-a0wYpIN7hcPE7b5IND9Nal2bHO2orh_tSRKSFzBY5e4cvda9rAdVfGoOjTaCW6FZ5_ta2M2vgEhoz5Do8fiuoXwBa1XCp61JfIlPtx11PXm5pIS2w3bXI7mY0uHUMGvxAzta74zKXLslaLaSQibSKjWKt9h-SsXy4JGqcVefOlaQlJfXL1Tga6wcO0QTu6Xq-Uw7ZPNPnrpBrLauKDd202RlN4SP7ohL3d9bG6V5hUz_3OusNEBZUn5W3VmPj1ZnFavkMB3RkRMOa58MZAORJT4imAPzrvJ0vtv94_y71C6tZ5aGF1dGhEYXRhWMQs15PPoLQYy78OqFIihgfZ6XszPU2wpBAXdmr2u4x1UUUAAAAuy2lIHo_3QDmT7AonKaFUqABAPjPqie67O5ZBLiBEWi1uF8ueqxifIu5txG8qQ82HiribGY2F99HPJ_ZTgRbEZCVySxy0Xbd-tiUzyEwmJQsiNqUBAgMmIAEhWCAiZN75DKsRFIWYKExiHA_ZpKIJGbRlL2JYE6iw9x1OGSJYILwa9HpPBuZ4S4BfT4wigrSzs_V6m47z0A1wsetLUwl1"
                              , challenge = Challenge (BS.decodeLenient "MMcUAdZBvI4D6KMbWcen8m3MDIBEeVAldjPpr63eaIo")
                              , getChallenge = Challenge (BS.decodeLenient "Yb5eG9OA4jPLlrkGIMhedXD76XHqJhddTAdeHXHBRl8")
                              , getClientDataJSON = BS.decodeLenient "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiWWI1ZUc5T0E0alBMbHJrR0lNaGVkWEQ3NlhIcUpoZGRUQWRlSFhIQlJsOCIsIm9yaWdpbiI6Imh0dHBzOi8vcHN0ZW5pdXN1YmkuZ2l0aHViLmlvIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ"
                              , getAuthenticatorData = BS.decodeLenient "LNeTz6C0GMu_DqhSIoYH2el7Mz1NsKQQF3Zq9ruMdVEFAAAALw"
                              , getSignature = BS.decodeLenient "MEUCIAUiSZx7SeFuqLS7nCtfEwgHM7zfhJQTx2AUf6qW0P0TAiEAh-UwgffnlRaz5cjYeGirABt2FTcgyiuLuv-NOpdJQf8"
                              }

packedNonSelfAttestedTest = genericCredentialTest "Packed non-self attested test" packedNonSelfAttestedKeyCredential

fidoU2FAttestedKeyCredential = TestPublicKeyCredential 
                              {
                                  clientDataJSON = BS.decodeLenient "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiVHF5dWZTNmJCam5obk5sT09BcWN3X2tfcW9DZVhrdy1VbkQ2X1QxTEZ6WSIsIm9yaWdpbiI6Imh0dHBzOi8vcHN0ZW5pdXN1YmkuZ2l0aHViLmlvIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ"
                                , attestationObject = BS.decodeLenient "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgLalQZ_wPQbHRQJWvkSb9pMwykJTIglVyO9tQqJBdWeACIQDW9PpXo-7gcl8f8MOvcQZ2a-BV0NDtsKysznwF17hTmmN4NWOBWQHiMIIB3jCCAYCgAwIBAgIBATANBgkqhkiG9w0BAQsFADBgMQswCQYDVQQGEwJVUzERMA8GA1UECgwIQ2hyb21pdW0xIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xGjAYBgNVBAMMEUJhdGNoIENlcnRpZmljYXRlMB4XDTE3MDcxNDAyNDAwMFoXDTQxMDExMDE1MDgwNVowYDELMAkGA1UEBhMCVVMxETAPBgNVBAoMCENocm9taXVtMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMRowGAYDVQQDDBFCYXRjaCBDZXJ0aWZpY2F0ZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABI1hfmXJUI5kvMVnOsgqZ5naPBRGaCwljEY__99Y39L6Pmw3i1PXlcSk3_tBme3Xhi8jq68CA7S4kRugVpmU4QGjKDAmMBMGCysGAQQBguUcAgEBBAQDAgUgMA8GA1UdEwEB_wQFMAMBAQAwDQYJKoZIhvcNAQELBQADSQAwRgIhALzf9AI7ncZCUGONkRJg1j0giitNVEtql2-DNLkUcAKNAiEAl2FZKfyv8wP6gq8a15Zwvb0IuqhbW6Oa3ChynC2bc-JoYXV0aERhdGFYpCzXk8-gtBjLvw6oUiKGB9npezM9TbCkEBd2ava7jHVRQQAAAAAAAAAAAAAAAAAAAAAAAAAAACAeEV8OookaEAnZsZ6sTBQd34n7FG-UChiAg_h4Wds73qUBAgMmIAEhWCAxZCF_UplKr9yfSrWtQbCeHBu8kmi9wJpIldWlT3fFMiJYIMHLS8tIUgpZgxb706EC_Hx6P6qoeBZHKVhOtc80uLbz"
                                , challenge = Challenge (BS.decodeLenient "TqyufS6bBjnhnNlOOAqcw_k_qoCeXkw-UnD6_T1LFzY")
                                , getChallenge = Challenge (BS.decodeLenient "FKo-YOqdA16wn5PtyGCF5kcW5Cbq-kdJH47vhEYVEHA")
                                , getClientDataJSON = BS.decodeLenient "FKo-YOqdA16wn5PtyGCF5kcW5Cbq-kdJH47vhEYVEHA"
                                , getAuthenticatorData = BS.decodeLenient "LNeTz6C0GMu_DqhSIoYH2el7Mz1NsKQQF3Zq9ruMdVEBAAAAAg"
                                , getSignature = BS.decodeLenient "MEYCIQDhsVWAb0QLCdfLpjfWSv1jDQXTlL-eR0jqxpY09UsO7QIhALG5c5ORMNAyRR2R7NcOWDLHKKmV9KZM5S1miiVhYmZ5"
                              }

fidoU2FAttestedTest = genericCredentialTest "FIDOU2F test" packedNonSelfAttestedKeyCredential

tpmKeyCredential = TestPublicKeyCredential 
                              {
                                  clientDataJSON = BS.decodeLenient "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiRmdxRWd5cTZ6V2FrNlUzR1ZuX2EyTkZqVkhKd0dZOHNvTEZFUGpWS3duMCIsIm9yaWdpbiI6Imh0dHBzOi8vcHN0ZW5pdXN1YmkuZ2l0aHViLmlvIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ"
                                , attestationObject = BS.decodeLenient "o2NmbXRjdHBtZ2F0dFN0bXSmY2FsZzn__mNzaWdZAQCuCTo7b0ADqzr-SaGuG2KdCJcwba6StqS8v3bWbVdVbXwWvhRLWM6ELgkuNy4EVexlvbS6iYYNLoEZYNAcMdd8-wkSnptS9V9bGj8ZUqYAz2UyXWqtzK2Y-rp0T-j2jcnefXSXQvsZgDtdULM5IW0VMfaptPPRlM9nSUJouhL5xCuOvGnteP1gfgXuh5fQ1tbBWgsZ18c4ghJysmJQAEQW-TITeaRRT5zj1zLCUCttDbUMPoBHCbAbrNoxDBfPPIrGRNWU4RrxX1UVMo2ZGpwpPcJgWIf7VdNsb08O70i4B_4_lu0T62bRGQJ6e0ARuCS-ol0LJkz_8l4jRj6e7f13Y3ZlcmMyLjBjeDVjglkFwzCCBb8wggOnoAMCAQICEB5DwniKUUIQluhCgj8ldj0wDQYJKoZIhvcNAQELBQAwQTE_MD0GA1UEAxM2RVVTLUlGWC1LRVlJRC0zN0FFMzQ2QkFBNTRDNTEzQ0ZGMDI5MEJCMzIxQTIyQTM0QTRBOEM0MB4XDTE4MTAxNTE1MjkwNFoXDTI0MDkyMDIwMDk1NFowADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANnZQQ6CmX5pJiCmhbY1WK8DCe9eb7er13-ojljpxmI7B1ir2m_8CBHOg_oSRl9XbKx41gu0P0xZNDDXEHBBhZYhK4o1SIrySEH_WSpKW_GM0zaxdIoGpQbRDKDMN2Dxku2aHJTDAJXc0HRZHVRuvD4dWYdLjdpQGldzR39Znhw57vWN034PB6L_H_XZBJ_hLQd8g1Lba8gSqv2EsJMGh1c9rrbkYTM_HpQ1_9Y_yI0xHhsrWY5hLre3vHAc8tWpa-jF4X5dJQt0kE4SYNsvQPqd7jplL1NX16JrSZWCl-k-5o14r18ZJpeEm99_Wovz02z3XnGzJ3-_jOryBHmVPTcCAwEAAaOCAfIwggHuMA4GA1UdDwEB_wQEAwIHgDAMBgNVHRMBAf8EAjAAMG0GA1UdIAEB_wRjMGEwXwYJKwYBBAGCNxUfMFIwUAYIKwYBBQUHAgIwRB5CAFQAQwBQAEEAIAAgAFQAcgB1AHMAdABlAGQAIAAgAFAAbABhAHQAZgBvAHIAbQAgACAASQBkAGUAbgB0AGkAdAB5MBAGA1UdJQQJMAcGBWeBBQgDMFgGA1UdEQEB_wROMEykSjBIMRYwFAYFZ4EFAgEMC2lkOjQ5NDY1ODAwMRowGAYFZ4EFAgIMD1NMQiA5NjcwIFRQTTIuMDESMBAGBWeBBQIDDAdpZDowNzNFMB8GA1UdIwQYMBaAFGhTrcDZxsjgTl8J19XWRrR0_PlSMB0GA1UdDgQWBBQXbsRhpmWiAUdcPCuHhQTD9weR8TCBsgYIKwYBBQUHAQEEgaUwgaIwgZ8GCCsGAQUFBzAChoGSaHR0cDovL2F6Y3Nwcm9kZXVzYWlrcHVibGlzaC5ibG9iLmNvcmUud2luZG93cy5uZXQvZXVzLWlmeC1rZXlpZC0zN2FlMzQ2YmFhNTRjNTEzY2ZmMDI5MGJiMzIxYTIyYTM0YTRhOGM0L2IwZTIzYmMzLWU3YzMtNGJmMy05MGE5LTdhNzYzYmNhYWVhMS5jZXIwDQYJKoZIhvcNAQELBQADggIBAEOYvGzlzMZ9d86sQp2sUGeL2w0RAk9K1rFcrZDwdLPog1J7JISWxC7vdGksvPaHNsNGEbzt3s3mN07VxHBRCHu5HaQtZJw7td7BDynq9eMp_aIu1UafNVXI5HYiW4tfCichZ9Xbc-alK5tDb4Vf_AGdLAG0Z8WHnuBjhqdGTgWLwtmDKLbeUU8uJdu0Wm4CmHLJswah97XruNMjKtaRDtSAu60lyl16i9KSPta_jscoAXIRfD_rPJrho2Sb7dSQhNrW-EEWuC2Yprb2dqWLw1Mcy0kT5GIcv9ZuA_kRyZYYprm5DWV4TKqcoMuYjzy-UvlZ6Iat41WzdiKX8s0YeS5Kis_r79Uupc3YpoZEWFzS1gCBgH2k_0dxzR0GVs65D-K34GkAnKzXFu59lTdzQjPeJ_7gfTHNmg4y8WknoGSIudpkJ-hARnwcGW5GOWzQFEOwfN5bS3GE79xX__3WJfYLzBo5WHiajnpW63_biYnZGdJvozvr1EU3iiLnQIimMhNb4KRF5n-RS6cGQ4ed_JFEcdrFoSt5pKJvenNjv1hsxlr3zqJlDwEL6Ohk6DksyqP694v5LnutJSOxj908BN8rBbzo4TSbBAqtrfB8zKNXkKztGD-_diKqWKQ5jDFPvAw0I2YMQHKDSHfcQEYfo0UXNZulbMvEMJ5pp6_70VwuWQbvMIIG6zCCBNOgAwIBAgITMwAAAYGJIvhGas10mQAAAAABgTANBgkqhkiG9w0BAQsFADCBjDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjE2MDQGA1UEAxMtTWljcm9zb2Z0IFRQTSBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDE0MB4XDTE4MDkyMDIwMDk1NFoXDTI0MDkyMDIwMDk1NFowQTE_MD0GA1UEAxM2RVVTLUlGWC1LRVlJRC0zN0FFMzQ2QkFBNTRDNTEzQ0ZGMDI5MEJCMzIxQTIyQTM0QTRBOEM0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAqIal0K5MaeUAE2aK0mSzLmLeEFRKc8JfmYi8YzWtNHZbCVdAV_ec0rDg1i6cKB2ONgQ1lEuHsqEzh8saEjdj-gTABJRoAEweOXVXyCzDyJcjkXSi4VnJ9p0nk12An5EO-xIkrDzQKI2fWQ-Pdot4m7eCo1MClN_r7uHh8XP_EQtjMLAkyk6tnhvGX7CBkoq9MukPcpd9MjmwtAaGkQ08JIpkTblajRx_VAFdE2xT0JZq8Q6VDsG5dO0FRAajOVY8LujyuQSrjcg_L4WMrHz7MJfOfUjWwDMSas0cUzxAfQIORVUf4T17thb2t_wWVNDxvpWkUvGGp59oNdY29XhryZzYgyhkui_Hi1q83LEz2hb3Vi9pJ2lE4r04fHyRIioFVNT6CvKfPQTWvbNXcnFlZAg3j0HYC7lbDBhEFpb_WLHsrjRRz4Sf3qms_1jDSwhuNKAFg7T2wHu_sy4s2StXD6EkpLYRSgSHwxjdyaRldv7NCrqCW3gx8cE1sviT2S4TCLpPavkg68pgg8mSSYGXKo_v1dBq_hDbs19JlSAJy7MrgAzvyL3U_RzpiPEv7w1SNGcU8H_4tzW42e-J0gk4c73YCTG6jXDpl-XGzTr9DsjefIw-V1v-p-w4RhcX1e8pWYg1Sz0aBsOOXHo2Uy4wbqoKx3zsOy9NWP4R6zNvqrkCAwEAAaOCAY4wggGKMA4GA1UdDwEB_wQEAwIChDAbBgNVHSUEFDASBgkrBgEEAYI3FSQGBWeBBQgDMBYGA1UdIAQPMA0wCwYJKwYBBAGCNxUfMBIGA1UdEwEB_wQIMAYBAf8CAQAwHQYDVR0OBBYEFGhTrcDZxsjgTl8J19XWRrR0_PlSMB8GA1UdIwQYMBaAFHqMCs4vSGIX4pTRrlXBUuxxdKRWMHAGA1UdHwRpMGcwZaBjoGGGX2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMFRQTSUyMFJvb3QlMjBDZXJ0aWZpY2F0ZSUyMEF1dGhvcml0eSUyMDIwMTQuY3JsMH0GCCsGAQUFBwEBBHEwbzBtBggrBgEFBQcwAoZhaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUUE0lMjBSb290JTIwQ2VydGlmaWNhdGUlMjBBdXRob3JpdHklMjAyMDE0LmNydDANBgkqhkiG9w0BAQsFAAOCAgEAFudveZB4eDO3imhTcehiHt2zar2jkzS3i1byHQte06gzsqpDbNdogo_7NsQA9btrUQ68WH6lRo2MoXpNVSCNji4DsHoudcwaACwQOYgCJ4ngrbU6ZHpJEZkWCp44S5nK9J5atyoNynzyy_8G8Lb7MwmpFyN-p5kOvb_qsibJ7Vui5P7ncEHzYhdHy99pfSlGkkJ-Tay73uuXAZ7lwC-LCzY1RdQM_8Pr4uwkkyYtXSGh24aLjxQgVzGb1rtcvw5oRHY3f8UBMRhaoqYC6zw4tbp1dWrPz_AYmxoHIWCuF_SfEWvhzoRzu-6DZHaqtaOmqh8JG1sMLj9-cYihzW24GmeZFhduAN2gHp_0pkxZHN8HbTJWXrH5cb-HIvxP240gXADNFNiOqZnSeqoecuWoNS3WBc3JKixyC1G57lPtttQYxrV_dVwIQ1oyM0aeKtf8Q82sFq3VAmaOGjG7SCHkTYo9BhuNlcEDcsGK6_T0LUGlSbkf3JcNpkbhnW6SxTzAlHv7MAlU4CBvxRWUGzD7ExADGTkEW_eZh2qomxw0gGZR9wA29xRu3ds_CBWOXLvHhFDIvRZkiiLUEO1Tstu8puCIwtcjJGlDZL95HmeB8sEQFBlLNq4ph9nfX7EBrrF4LXyryGHK5pPiWcUK5X1favk4uwSCYCYZ8cBc0Q3b_SFncHViQXJlYVkBNgABAAsABgRyACCd_8vzbDg65pn7mGjcbcuJ1xU4hL4oA5IsEkFYv60irgAQABAIAAAAAAABALMuxTiloaNKfLUgHEunKECoQ4A7gq_9s1VTYMbAYIEFRFsqAXVAk2-CcMBPPrm7xuTzGmmmSYVLZVZSl6xrXPnUEhtYaqHbVWPJsDlTw5gq52qU8vqOXG-P37l-LVa2SR_IEok4i7XwTfFHp-NJJyKMllJIphtEyImC8sh1KgKxKwvlOHHyy7AYncsJIkHedP0chtmf-KoZNTZVl328gSi7KPZVMOeFf-gzQlqkFK5MrpnodiY5SsEJ02SliFZcq-04LhGh871VjKiaL5Jj3pIlhd9cNBwuc9ZlnnIKz9pg7WMfK3IvskKjf1KFAAPUKqvv1MU-XvyR9MA7GHhfgetoY2VydEluZm9Yof9UQ0eAFwAiAAv-USqFxz3CWSkZjq_MSXLd0vOillQ-wVQaZgymCVAovAAUSZLX2UHxhl94npSBSphDM7eA560AAAACv8O-zmGa86AEy1zLARIuZv9Lvo0GACIAC6AukP5lvf3jVL5klLOnAjoucxso5w3x6KmKXyjX4IltACIAC4jkCgohidE5QhXXlNbCctpPBhKCosSb2FhWiSC9VMU-aGF1dGhEYXRhWQFnLNeTz6C0GMu_DqhSIoYH2el7Mz1NsKQQF3Zq9ruMdVFFAAAAAAiYcFjK3EuBtuEw3lDcvpYAIM9gBal1ZTRde_rDB90BsJ0_2Fg7oTkMwVPL5_SsnhzapAEDAzkBACBZAQCzLsU4paGjSny1IBxLpyhAqEOAO4Kv_bNVU2DGwGCBBURbKgF1QJNvgnDATz65u8bk8xpppkmFS2VWUpesa1z51BIbWGqh21VjybA5U8OYKudqlPL6jlxvj9-5fi1WtkkfyBKJOIu18E3xR6fjSScijJZSSKYbRMiJgvLIdSoCsSsL5Thx8suwGJ3LCSJB3nT9HIbZn_iqGTU2VZd9vIEouyj2VTDnhX_oM0JapBSuTK6Z6HYmOUrBCdNkpYhWXKvtOC4RofO9VYyomi-SY96SJYXfXDQcLnPWZZ5yCs_aYO1jHytyL7JCo39ShQAD1Cqr79TFPl78kfTAOxh4X4HrIUMBAAE"
                                , challenge = Challenge (BS.decodeLenient "FgqEgyq6zWak6U3GVn_a2NFjVHJwGY8soLFEPjVKwn0")
                                , getChallenge = Challenge (BS.decodeLenient "pzjuAQFE7ILMiDjEVexOXyVF_IjM__7SbCWXNoi60g0")
                                , getClientDataJSON = BS.decodeLenient "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoicHpqdUFRRkU3SUxNaURqRVZleE9YeVZGX0lqTV9fN1NiQ1dYTm9pNjBnMCIsIm9yaWdpbiI6Imh0dHBzOi8vcHN0ZW5pdXN1YmkuZ2l0aHViLmlvIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ"
                                , getAuthenticatorData = BS.decodeLenient "LNeTz6C0GMu_DqhSIoYH2el7Mz1NsKQQF3Zq9ruMdVEFAAAAAQ"
                                , getSignature = BS.decodeLenient "BTwSmCmXFy3nsDFG3snW9-BV9unHMbY8J5INTVsrWv21_F6RfjLv2asDvpye56FPPeEgttliviry89bx7lSXqFRd8wMTxFncGJI2_PgusGeOGUeTNTW-NF2dVZG7fetVMajoSGjNw71DB8NBaXd6s-N638-12X7IDmpFLsqduMFD3Xrs3m34EnnFW4x4cyGSP1wwDU0nuew_umDwQ-ylE2J25KVF4tKRzQO_XosFhIlO1wFNDzwA6ZY7Ci4R271a4aZw1j-cvnDiaetf8w9fFFsHr_1kkytSK4lLuBx_4aDm03gQh8Kj7yDYFZtCaozHJU_yer1ILSfyNHWev0-_OA"
                              }

tpmTest = genericCredentialTest "TPM test" tpmKeyCredential

genericCredentialTest :: String -> TestPublicKeyCredential -> TestTree
genericCredentialTest name TestPublicKeyCredential{..} = testCaseSteps name $ \step -> do
  step "Registeration check..."
  Just k <- readCertificateStore "test/cacert.pem"
  let pkcco = PublicKeyCredentialCreationOptions (defaultRelyingParty (Origin "https" "webauthn.biz" Nothing)) (Base64ByteString "12343434") (User (Base64ByteString "id") Nothing Nothing) (PubKeyCredParam PublicKey ES256 :| []) Nothing Nothing Nothing Nothing (Just (PublicKeyCredentialDescriptor PublicKey (Base64ByteString "1234") (Just (BLE :| []))  :| []))
  eth <- registerCredential pkcco k challenge defRp Nothing False clientDataJSON attestationObject
  assertBool (show eth) (isRight eth)
  let Right cdata = eth
  step "Verification check..."
  let eth = verify getChallenge defRp Nothing False getClientDataJSON getAuthenticatorData getSignature (credentialPublicKey cdata)
  assertBool (show eth) (isRight eth)  


androidClientDataJSON :: ByteString
androidClientDataJSON = BS.decodeLenient "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiWkIyQVJraDZ3RVBoZkdjSFBRWWpWNXNidmxoa3liVlN1ZFQ4Q0VzNTBsNCIsIm9yaWdpbiI6Imh0dHBzOlwvXC9wc3Rlbml1c3ViaS5naXRodWIuaW8iLCJhbmRyb2lkUGFja2FnZU5hbWUiOiJjb20uYW5kcm9pZC5jaHJvbWUifQ"

androidAttestationObject :: ByteString
androidAttestationObject = BS.decodeLenient "o2NmbXRxYW5kcm9pZC1zYWZldHluZXRnYXR0U3RtdKJjdmVyaTIwMTIxNjAzMGhyZXNwb25zZVkU3mV5SmhiR2NpT2lKU1V6STFOaUlzSW5nMVl5STZXeUpOU1VsR2EzcERRMEpJZFdkQmQwbENRV2RKVWtGT1kxTnJhbVJ6Tlc0MkswTkJRVUZCUVVGd1lUQmpkMFJSV1VwTGIxcEphSFpqVGtGUlJVeENVVUYzVVdwRlRFMUJhMGRCTVZWRlFtaE5RMVpXVFhoSWFrRmpRbWRPVmtKQmIxUkdWV1IyWWpKa2MxcFRRbFZqYmxaNlpFTkNWRnBZU2pKaFYwNXNZM3BGVkUxQ1JVZEJNVlZGUVhoTlMxSXhVbFJKUlU1Q1NVUkdVRTFVUVdWR2R6QjVUVVJCZUUxVVRYaE5WRkY0VGtSc1lVWjNNSGxOVkVGNFRWUkZlRTFVVVhoT1JHeGhUVWQzZUVONlFVcENaMDVXUWtGWlZFRnNWbFJOVWsxM1JWRlpSRlpSVVVsRmQzQkVXVmQ0Y0ZwdE9YbGliV3hvVFZKWmQwWkJXVVJXVVZGSVJYY3hUbUl6Vm5Wa1IwWndZbWxDVjJGWFZqTk5VazEzUlZGWlJGWlJVVXRGZDNCSVlqSTVibUpIVldkVVJYaEVUVkp6ZDBkUldVUldVVkZFUlhoS2FHUklVbXhqTTFGMVdWYzFhMk50T1hCYVF6VnFZakl3ZDJkblJXbE5RVEJIUTFOeFIxTkpZak5FVVVWQ1FWRlZRVUUwU1VKRWQwRjNaMmRGUzBGdlNVSkJVVU5YUlhKQ1VWUkhXa2RPTVdsYVlrNDVaV2hTWjJsbVYwSjRjV2t5VUdSbmVIY3dNMUEzVkhsS1dtWk5lR3B3TlV3M2FqRkhUbVZRU3pWSWVtUnlWVzlKWkRGNVEwbDVRazE1ZUhGbllYcHhaM1J3V0RWWGNITllWelJXWmsxb1NtSk9NVmt3T1hGNmNYQTJTa1FyTWxCYVpHOVVWVEZyUmxKQlRWZG1UQzlWZFZwMGF6ZHdiVkpZWjBkdE5XcExSSEphT1U1NFpUQTBkazFaVVhJNE9FNXhkMWN2YTJaYU1XZFVUMDVKVlZRd1YzTk1WQzgwTlRJeVFsSlhlR1ozZUdNelVVVXhLMVJMVjJ0TVEzSjJaV3MyVjJ4SmNYbGhRelV5VnpkTlJGSTRUWEJHWldKNWJWTkxWSFozWmsxU2QzbExVVXhVTUROVlREUjJkRFE0ZVVWak9ITndOM2RVUVVoTkwxZEVaemhSYjNSaGNtWTRUMEpJYTI1dldqa3lXR2wyYVdGV05uUlJjV2hTVDBoRFptZHRia05ZYVhobVZ6QjNSVmhEZG5GcFRGUmlVWFJWWWt4elV5ODRTVkowWkZocmNGRkNPVUZuVFVKQlFVZHFaMmRLV1UxSlNVTldSRUZQUW1kT1ZraFJPRUpCWmpoRlFrRk5RMEpoUVhkRmQxbEVWbEl3YkVKQmQzZERaMWxKUzNkWlFrSlJWVWhCZDBWM1JFRlpSRlpTTUZSQlVVZ3ZRa0ZKZDBGRVFXUkNaMDVXU0ZFMFJVWm5VVlUyUkVoQ2QzTkJkbUkxTTJjdlF6QTNjSEpVZG5aM1RsRlJURmwzU0hkWlJGWlNNR3BDUW1kM1JtOUJWVzFPU0RSaWFFUnllalYyYzFsS09GbHJRblZuTmpNd1NpOVRjM2RhUVZsSlMzZFpRa0pSVlVoQlVVVkZWMFJDVjAxRFkwZERRM05IUVZGVlJrSjZRVUpvYUhSdlpFaFNkMDlwT0haaU1rNTZZME0xZDJFeWEzVmFNamwyV25rNWJtUklUWGhpZWtWM1MzZFpTVXQzV1VKQ1VWVklUVUZMUjBneWFEQmtTRUUyVEhrNWQyRXlhM1ZhTWpsMlduazVibU16U1hsTU1HUlZWWHBHVUUxVE5XcGpibEYzU0ZGWlJGWlNNRkpDUWxsM1JrbEpVMWxZVWpCYVdFNHdURzFHZFZwSVNuWmhWMUYxV1RJNWRFMURSVWRCTVZWa1NVRlJZVTFDWjNkRFFWbEhXalJGVFVGUlNVTk5RWGRIUTJselIwRlJVVUl4Ym10RFFsRk5kMHgzV1VSV1VqQm1Ra05uZDBwcVFXdHZRMHRuU1VsWlpXRklVakJqUkc5MlRESk9lV0pETlhkaE1tdDFXakk1ZGxwNU9VaFdSazE0VkhwRmRWa3pTbk5OU1VsQ1FrRlpTMHQzV1VKQ1FVaFhaVkZKUlVGblUwSTVVVk5DT0dkRWQwRklZMEU1YkhsVlREbEdNMDFEU1ZWV1FtZEpUVXBTVjJwMVRrNUZlR3Q2ZGprNFRVeDVRVXg2UlRkNFdrOU5RVUZCUm5adWRYa3dXbmRCUVVKQlRVRlRSRUpIUVdsRlFUZGxMekJaVW5VemQwRkdiVmRJTWpkTk1uWmlWbU5hTDIxeWNDczBjbVpaWXk4MVNWQktNamxHTm1kRFNWRkRia3REUTBGaFkxWk9aVmxhT0VORFpsbGtSM0JDTWtkelNIaDFUVTlJYTJFdlR6UXhhbGRsUml0NlowSXhRVVZUVlZwVE5uYzNjeloyZUVWQlNESkxhaXRMVFVSaE5XOUxLekpOYzNoMFZDOVVUVFZoTVhSdlIyOUJRVUZDWWpVM2MzUktUVUZCUVZGRVFVVlpkMUpCU1dkRldHSnBiMUJpU25BNWNVTXdSR295TlRoRVJrZFRVazFCVlN0YVFqRkZhVlpGWW1KaUx6UlZkazVGUTBsQ2FFaHJRblF4T0haU2JqbDZSSFo1Y21aNGVYVmtZMGhVVDFOc00yZFVZVmxCTHpkNVZDOUNhVWcwVFVFd1IwTlRjVWRUU1dJelJGRkZRa04zVlVGQk5FbENRVkZFU1VGalVVSnNiV1E0VFVWblRHUnljbkpOWWtKVVEzWndUVmh6ZERVcmQzZ3lSR3htWVdwS1RrcFZVRFJxV1VacVdWVlJPVUl6V0RSRk1ucG1ORGx1V0ROQmVYVmFSbmhCY1U5U2JtSnFMelZxYTFrM1lUaHhUVW93YWpFNWVrWlBRaXR4WlhKNFpXTXdibWh0T0dkWmJFeGlVVzAyYzB0Wk4xQXdaWGhtY2pkSWRVc3pUV3RRTVhCbFl6RTBkMFpGVldGSGNVUjNWV0pIWjJ3dmIybDZNemhHV0VORkswTlhPRVV4VVVGRlZXWjJZbEZRVkZsaVMzaFphaXQwUTA1c2MzTXdZbFJUYjB3eVdqSmtMMm96UW5CTU0wMUdkekI1ZUZOTEwxVlVjWGxyVEhJeVFTOU5aR2hLVVcxNGFTdEhLMDFMVWxOelVYSTJNa0Z1V21GMU9YRTJXVVp2YVNzNVFVVklLMEUwT0ZoMFNYbHphRXg1UTFSVk0waDBLMkZMYjJoSGJuaEJOWFZzTVZoU2JYRndPRWgyWTBGME16bFFPVFZHV2tkR1NtVXdkWFpzZVdwUGQwRjZXSFZOZFRkTksxQlhVbU1pTENKTlNVbEZVMnBEUTBGNlMyZEJkMGxDUVdkSlRrRmxUekJ0Y1VkT2FYRnRRa3BYYkZGMVJFRk9RbWRyY1docmFVYzVkekJDUVZGelJrRkVRazFOVTBGM1NHZFpSRlpSVVV4RmVHUklZa2M1YVZsWGVGUmhWMlIxU1VaS2RtSXpVV2RSTUVWblRGTkNVMDFxUlZSTlFrVkhRVEZWUlVOb1RVdFNNbmgyV1cxR2MxVXliRzVpYWtWVVRVSkZSMEV4VlVWQmVFMUxVako0ZGxsdFJuTlZNbXh1WW1wQlpVWjNNSGhPZWtFeVRWUlZkMDFFUVhkT1JFcGhSbmN3ZVUxVVJYbE5WRlYzVFVSQmQwNUVTbUZOUlVsNFEzcEJTa0puVGxaQ1FWbFVRV3hXVkUxU05IZElRVmxFVmxGUlMwVjRWa2hpTWpsdVlrZFZaMVpJU2pGak0xRm5WVEpXZVdSdGJHcGFXRTE0UlhwQlVrSm5UbFpDUVUxVVEydGtWVlY1UWtSUlUwRjRWSHBGZDJkblJXbE5RVEJIUTFOeFIxTkpZak5FVVVWQ1FWRlZRVUUwU1VKRWQwRjNaMmRGUzBGdlNVSkJVVVJSUjAwNVJqRkpkazR3TlhwclVVODVLM1JPTVhCSlVuWktlbnA1VDFSSVZ6VkVla1ZhYUVReVpWQkRiblpWUVRCUmF6STRSbWRKUTJaTGNVTTVSV3R6UXpSVU1tWlhRbGxyTDJwRFprTXpVak5XV2sxa1V5OWtUalJhUzBORlVGcFNja0Y2UkhOcFMxVkVlbEp5YlVKQ1NqVjNkV1JuZW01a1NVMVpZMHhsTDFKSFIwWnNOWGxQUkVsTFoycEZkaTlUU2tndlZVd3JaRVZoYkhST01URkNiWE5MSzJWUmJVMUdLeXRCWTNoSFRtaHlOVGx4VFM4NWFXdzNNVWt5WkU0NFJrZG1ZMlJrZDNWaFpXbzBZbGhvY0RCTVkxRkNZbXA0VFdOSk4wcFFNR0ZOTTFRMFNTdEVjMkY0YlV0R2MySnFlbUZVVGtNNWRYcHdSbXhuVDBsbk4zSlNNalY0YjNsdVZYaDJPSFpPYld0eE4zcGtVRWRJV0d0NFYxazNiMGM1YWl0S2ExSjVRa0ZDYXpkWWNrcG1iM1ZqUWxwRmNVWktTbE5RYXpkWVFUQk1TMWN3V1RONk5XOTZNa1F3WXpGMFNrdDNTRUZuVFVKQlFVZHFaMmRGZWsxSlNVSk1la0ZQUW1kT1ZraFJPRUpCWmpoRlFrRk5RMEZaV1hkSVVWbEVWbEl3YkVKQ1dYZEdRVmxKUzNkWlFrSlJWVWhCZDBWSFEwTnpSMEZSVlVaQ2QwMURUVUpKUjBFeFZXUkZkMFZDTDNkUlNVMUJXVUpCWmpoRFFWRkJkMGhSV1VSV1VqQlBRa0paUlVaS2FsSXJSelJSTmpncllqZEhRMlpIU2tGaWIwOTBPVU5tTUhKTlFqaEhRVEZWWkVsM1VWbE5RbUZCUmtwMmFVSXhaRzVJUWpkQllXZGlaVmRpVTJGTVpDOWpSMWxaZFUxRVZVZERRM05IUVZGVlJrSjNSVUpDUTJ0M1NucEJiRUpuWjNKQ1owVkdRbEZqZDBGWldWcGhTRkl3WTBSdmRrd3lPV3BqTTBGMVkwZDBjRXh0WkhaaU1tTjJXak5PZVUxcVFYbENaMDVXU0ZJNFJVdDZRWEJOUTJWblNtRkJhbWhwUm05a1NGSjNUMms0ZGxrelNuTk1ia0p5WVZNMWJtSXlPVzVNTW1SNlkycEpkbG96VG5sTmFUVnFZMjEzZDFCM1dVUldVakJuUWtSbmQwNXFRVEJDWjFwdVoxRjNRa0ZuU1hkTGFrRnZRbWRuY2tKblJVWkNVV05EUVZKWlkyRklVakJqU0UwMlRIazVkMkV5YTNWYU1qbDJXbms1ZVZwWVFuWmpNbXd3WWpOS05VeDZRVTVDWjJ0eGFHdHBSemwzTUVKQlVYTkdRVUZQUTBGUlJVRkhiMEVyVG01dU56aDVObkJTYW1RNVdHeFJWMDVoTjBoVVoybGFMM0l6VWs1SGEyMVZiVmxJVUZGeE5sTmpkR2s1VUVWaGFuWjNVbFF5YVZkVVNGRnlNREptWlhOeFQzRkNXVEpGVkZWM1oxcFJLMnhzZEc5T1JuWm9jMDg1ZEhaQ1EwOUpZWHB3YzNkWFF6bGhTamw0YW5VMGRGZEVVVWc0VGxaVk5sbGFXaTlZZEdWRVUwZFZPVmw2U25GUWFsazRjVE5OUkhoeWVtMXhaWEJDUTJZMWJ6aHRkeTkzU2pSaE1rYzJlSHBWY2paR1lqWlVPRTFqUkU4eU1sQk1Va3cyZFROTk5GUjZjek5CTWsweGFqWmllV3RLV1drNGQxZEpVbVJCZGt0TVYxcDFMMkY0UWxaaWVsbHRjVzEzYTIwMWVreFRSRmMxYmtsQlNtSkZURU5SUTFwM1RVZzFOblF5UkhaeGIyWjRjelpDUW1ORFJrbGFWVk53ZUhVMmVEWjBaREJXTjFOMlNrTkRiM05wY2xOdFNXRjBhaTg1WkZOVFZrUlJhV0psZERoeEx6ZFZTelIyTkZwVlRqZ3dZWFJ1V25veGVXYzlQU0pkZlEuZXlKdWIyNWpaU0k2SW5KS1lXcExhM1pEUm01aE0yUlpXVzVVWTFSQ1FWRnNlbkE1WVhVemMwWXpZVzVxTjBaVWJFbHpSRlU5SWl3aWRHbHRaWE4wWVcxd1RYTWlPakUxT0RnM05UazFNRFEyTkRFc0ltRndhMUJoWTJ0aFoyVk9ZVzFsSWpvaVkyOXRMbWR2YjJkc1pTNWhibVJ5YjJsa0xtZHRjeUlzSW1Gd2EwUnBaMlZ6ZEZOb1lUSTFOaUk2SWtGMmJTOU1MMmxHU1hkcmNuaE5TakJJU1V4M2NqVjRTa2xoVFZWUlREWlFjMGhFWWtWa2NVMXJja0U5SWl3aVkzUnpVSEp2Wm1sc1pVMWhkR05vSWpwMGNuVmxMQ0poY0d0RFpYSjBhV1pwWTJGMFpVUnBaMlZ6ZEZOb1lUSTFOaUk2V3lJNFVERnpWekJGVUVwamMyeDNOMVY2VW5OcFdFdzJOSGNyVHpVd1JXUXJVa0pKUTNSaGVURm5NalJOUFNKZExDSmlZWE5wWTBsdWRHVm5jbWwwZVNJNmRISjFaU3dpWlhaaGJIVmhkR2x2YmxSNWNHVWlPaUpDUVZOSlF5SjkuWXZtN1ZGNmVpeUhYWEMyanprdjJ2QTdQNGRYd3NobkxvYlN1Q2NHbEtYRFkzeFhLVkxlUTdWalZ6QkpyU1J2ODROYlh0TzFqanZ6WVdQLTNJcDdEWktXc2dBeEpJSk1SeHhwQU44UUJiWUlPS2Yzamxxczd4VWtMM2pNdVl2bFVsbkNseUJuaEpvTm9tN3JWZE04SmdiajMtUVQxRGhSNUt0WEVUbV9HaFFEanJrdHBJd201N3RGRFYwOHRVVEtrTkpmNkNnNDV3Y0plbnJ2UlZTUXBseXh1cVY4al91QWl5SkxGdTV5dk1qZ0o3WkdkLXRZX1ZscS1zNXQ2NTVSTnYtaHNFQTZhdTdyTzNJYjFQQVh3X0xGVENveXdKLVhVd0xqRkpqZTdieGpnQUx2SWtrOE5BUGpXYXh2YWcyRzMyNGs4RWdjSzc3U0dxNHhES1Zfek5BaGF1dGhEYXRhWMUs15PPoLQYy78OqFIihgfZ6XszPU2wpBAXdmr2u4x1UUUAAAAAuT_ZYfLmRi-xIoIAIkfeeABBAQJBVPhy4yG7tNUTkedMIgadvfK55s6r3qX_V5jaBOfycETIQLr7zGs_GrMbXGrkJU2BTCDU_uuea4WwBffTv_GlAQIDJiABIVggca4oTyEumIkH8am4WBD7h90D_SSj6cRf7ksf3HhbefoiWCD6gxvdhHuqvBsamD01kD6pCiVWakup0S0BNRYj0U7hOg"

androidChallenge :: Challenge
androidChallenge = Challenge (BS.decodeLenient "ZB2ARkh6wEPhfGcHPQYjV5sbvlhkybVSudT8CEs50l4")

androidGetChallenge :: Challenge
androidGetChallenge = Challenge (BS.decodeLenient "dCCcJkllvbdd-LKDJrCQYbouMEY3FEsNljYis_temyA")

-- This contains the Get Challenge in it
androidGetClientDataJSON :: ByteString
androidGetClientDataJSON = BS.decodeLenient "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiZENDY0prbGx2YmRkLUxLREpyQ1FZYm91TUVZM0ZFc05sallpc190ZW15QSIsIm9yaWdpbiI6Imh0dHBzOlwvXC9wc3Rlbml1c3ViaS5naXRodWIuaW8iLCJhbmRyb2lkUGFja2FnZU5hbWUiOiJjb20uYW5kcm9pZC5jaHJvbWUifQ"

androidGetAuthenticatorData :: ByteString
androidGetAuthenticatorData = BS.decodeLenient "LNeTz6C0GMu_DqhSIoYH2el7Mz1NsKQQF3Zq9ruMdVEFAAAAAQ"

androidGetSignature :: ByteString
androidGetSignature = BS.decodeLenient "MEQCIFM6aZjT8CefzdAn-QNaa5OcPU24V1SERVocZlus1YT1AiAH_UqNj7xVOW1sDLKkpicTxIONpwfWrWNbo8KL4z5wcA"

errorOnLeft (Left e) = error e
errorOnLeft (Right r) = r
