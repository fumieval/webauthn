{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE NoFieldSelectors #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE RecordWildCards #-}

import Data.Aeson as A (toEncoding, toJSON, eitherDecode, FromJSON)
import Data.Aeson.Encoding (value)
import Data.Aeson.QQ.Simple ( aesonQQ )
import Data.ByteString ( ByteString )
import Data.ByteString.Base64.URL as BS (decodeLenient)
import qualified Data.ByteString.Base64.URL as B64URL
import Data.Either ( isRight )
import Data.Hourglass (DateTime, timeConvert, Date (Date), Month (June))
import Data.List.NonEmpty ( NonEmpty((:|)) )
import Data.String.Interpolate ()
import Data.X509.CertificateStore ( readCertificateStore )
import Test.Tasty ( defaultMain, testGroup, TestTree )
import Test.Tasty.HUnit (assertEqual,  assertBool, testCaseSteps )
import URI.ByteString ()
import WebAuthn
import WebAuthn.Types (SignCount(..), AuthenticatorAssertionResponse(..), PublicKeyCredentialType(..), PubKeyCredAlg(..), Base64UrlByteString(..), AuthenticatorTransport(..), PublicKeyCredentialDescriptor(..))
import qualified Data.ByteString.Lazy as BL

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests = testGroup "Tests" [androidTests]

androidTests :: TestTree
androidTests = testGroup "WebAuthn Tests"
  [
    -- See: https://github.com/fumieval/webauthn/issues/9
    androidCredentialTest
    , packedSelfAttestedTest
    , packedNonSelfAttestedTest
    , fidoU2FAttestedTest
  ]

androidCredentialTest :: TestTree
androidCredentialTest = genericCredentialTest "Android test" androidPublicKeyCredential (Just $ timeConvert (Date 2020 June 1))

defRp :: PublicKeyCredentialRpEntity
defRp = "psteniusubi.github.io"

decodePanic :: FromJSON a => ByteString -> a
decodePanic s = either error Prelude.id (A.eitherDecode (BL.fromStrict s))

data TestPublicKeyCredential = TestPublicKeyCredential
  { clientDataJSON :: ByteString
  , attestationObject :: ByteString
  , challenge :: Challenge
  , getChallenge :: Challenge
  , getClientDataJSON :: ByteString
  , getAuthenticatorData :: ByteString
  , getSignature :: ByteString
  }

androidPublicKeyCredential = TestPublicKeyCredential
  { clientDataJSON = androidClientDataJSON
  , attestationObject = androidAttestationObject
  , challenge = androidChallenge
  , getChallenge = androidGetChallenge
  , getClientDataJSON = androidGetClientDataJSON
  , getAuthenticatorData = androidGetAuthenticatorData
  , getSignature = androidGetSignature
  }

packedSelfAttestedKeyCredential = TestPublicKeyCredential 
  { clientDataJSON = B64URL.decodeLenient "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiSkhxcVRQWF9oQkw1bHlDZE9DQzRMNTVzcm9LbXFMX0RDemlOeWx6MXF5dyIsIm9yaWdpbiI6Imh0dHBzOi8vcHN0ZW5pdXN1YmkuZ2l0aHViLmlvIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ"
  , attestationObject = B64URL.decodeLenient "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEYwRAIgaAVCWvaUJo0NBq_c1yr7R9jXN-G8MqqIOVhswsTX4K0CIFZul9oOTdWwDx4WAb3cgPTTjWzXSSxcjseS33OVqhgWaGF1dGhEYXRhWNUs15PPoLQYy78OqFIihgfZ6XszPU2wpBAXdmr2u4x1UUVgAZ6yrc4AAjW8xgpkiwsl8fBVAwBRAft9ACeHPR6QCu6Clp5otBmdIyMGV6w1emT--vpR_JpIKPJdIkNLOjzoLqd-z_j3vKvLCB4pQAwccqPF56HKs4h8DsrEuG0mMx5jJz_9ndh1pQECAyYgASFYIFgD8QsPYGMaq49F7-JWJowfVaxeiFzJUXp2k8nvrRpUIlggyGWqdGOBLZgO61mPMEncHjTmBxFPWzqKbUlBvT1fhRg"
  , challenge = Challenge $ B64URL.decodeLenient "JHqqTPX_hBL5lyCdOCC4L55sroKmqL_DCziNylz1qyw="
  , getChallenge = Challenge $ B64URL.decodeLenient "VXrK0ywwsYO2k6c52md-Lg2JDOmxrkGMli_4MHJcKaM="
  , getClientDataJSON = B64URL.decodeLenient "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiVlhySzB5d3dzWU8yazZjNTJtZC1MZzJKRE9teHJrR01saV80TUhKY0thTSIsIm9yaWdpbiI6Imh0dHBzOi8vcHN0ZW5pdXN1YmkuZ2l0aHViLmlvIiwiY3Jvc3NPcmlnaW4iOmZhbHNlLCJvdGhlcl9rZXlzX2Nhbl9iZV9hZGRlZF9oZXJlIjoiZG8gbm90IGNvbXBhcmUgY2xpZW50RGF0YUpTT04gYWdhaW5zdCBhIHRlbXBsYXRlLiBTZWUgaHR0cHM6Ly9nb28uZ2wveWFiUGV4In0"
  , getAuthenticatorData = B64URL.decodeLenient "LNeTz6C0GMu_DqhSIoYH2el7Mz1NsKQQF3Zq9ruMdVEFYAGfAg"
  , getSignature = B64URL.decodeLenient "MEYCIQDteZqnEublzIw5AgnOzu5sd7b387GitIHbjNSXFFoFxgIhAP4IFIiyweG__D3VOBSnvneuK794RuGoUNasXhQNe0gk"
  }

packedSelfAttestedTest = genericCredentialTest "Packed self attested test" packedSelfAttestedKeyCredential Nothing

packedNonSelfAttestedKeyCredential = TestPublicKeyCredential 
  { clientDataJSON = B64URL.decodeLenient "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiTU1jVUFkWkJ2STRENktNYldjZW44bTNNRElCRWVWQWxkalBwcjYzZWFJbyIsIm9yaWdpbiI6Imh0dHBzOi8vcHN0ZW5pdXN1YmkuZ2l0aHViLmlvIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ"
  , attestationObject = B64URL.decodeLenient "o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIge9MVIqCg80CbXoD2m6Hu4J6EKztfia76dtOoAeDUejQCIQCQwLbwVYoiYsAcOf8iigzbixDBiUAYJpUCIoa-XXvuYmN4NWOBWQLBMIICvTCCAaWgAwIBAgIEGKxGwDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbjELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEnMCUGA1UEAwweWXViaWNvIFUyRiBFRSBTZXJpYWwgNDEzOTQzNDg4MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeeo7LHxJcBBiIwzSP-tg5SkxcdSD8QC-hZ1rD4OXAwG1Rs3Ubs_K4-PzD4Hp7WK9Jo1MHr03s7y-kqjCrutOOqNsMGowIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjcwEwYLKwYBBAGC5RwCAQEEBAMCBSAwIQYLKwYBBAGC5RwBAQQEEgQQy2lIHo_3QDmT7AonKaFUqDAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQCXnQOX2GD4LuFdMRx5brr7Ivqn4ITZurTGG7tX8-a0wYpIN7hcPE7b5IND9Nal2bHO2orh_tSRKSFzBY5e4cvda9rAdVfGoOjTaCW6FZ5_ta2M2vgEhoz5Do8fiuoXwBa1XCp61JfIlPtx11PXm5pIS2w3bXI7mY0uHUMGvxAzta74zKXLslaLaSQibSKjWKt9h-SsXy4JGqcVefOlaQlJfXL1Tga6wcO0QTu6Xq-Uw7ZPNPnrpBrLauKDd202RlN4SP7ohL3d9bG6V5hUz_3OusNEBZUn5W3VmPj1ZnFavkMB3RkRMOa58MZAORJT4imAPzrvJ0vtv94_y71C6tZ5aGF1dGhEYXRhWMQs15PPoLQYy78OqFIihgfZ6XszPU2wpBAXdmr2u4x1UUUAAAAuy2lIHo_3QDmT7AonKaFUqABAPjPqie67O5ZBLiBEWi1uF8ueqxifIu5txG8qQ82HiribGY2F99HPJ_ZTgRbEZCVySxy0Xbd-tiUzyEwmJQsiNqUBAgMmIAEhWCAiZN75DKsRFIWYKExiHA_ZpKIJGbRlL2JYE6iw9x1OGSJYILwa9HpPBuZ4S4BfT4wigrSzs_V6m47z0A1wsetLUwl1"
  , challenge = Challenge (B64URL.decodeLenient "MMcUAdZBvI4D6KMbWcen8m3MDIBEeVAldjPpr63eaIo")
  , getChallenge = Challenge (B64URL.decodeLenient "Yb5eG9OA4jPLlrkGIMhedXD76XHqJhddTAdeHXHBRl8")
  , getClientDataJSON = B64URL.decodeLenient "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiWWI1ZUc5T0E0alBMbHJrR0lNaGVkWEQ3NlhIcUpoZGRUQWRlSFhIQlJsOCIsIm9yaWdpbiI6Imh0dHBzOi8vcHN0ZW5pdXN1YmkuZ2l0aHViLmlvIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ"
  , getAuthenticatorData = B64URL.decodeLenient "LNeTz6C0GMu_DqhSIoYH2el7Mz1NsKQQF3Zq9ruMdVEFAAAALw"
  , getSignature = B64URL.decodeLenient "MEUCIAUiSZx7SeFuqLS7nCtfEwgHM7zfhJQTx2AUf6qW0P0TAiEAh-UwgffnlRaz5cjYeGirABt2FTcgyiuLuv-NOpdJQf8"
  }

packedNonSelfAttestedTest = genericCredentialTest "Packed non-self attested test" packedNonSelfAttestedKeyCredential Nothing

fidoU2FAttestedKeyCredential = TestPublicKeyCredential 
  { clientDataJSON = B64URL.decodeLenient "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiVHF5dWZTNmJCam5obk5sT09BcWN3X2tfcW9DZVhrdy1VbkQ2X1QxTEZ6WSIsIm9yaWdpbiI6Imh0dHBzOi8vcHN0ZW5pdXN1YmkuZ2l0aHViLmlvIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ"
  , attestationObject = B64URL.decodeLenient "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgLalQZ_wPQbHRQJWvkSb9pMwykJTIglVyO9tQqJBdWeACIQDW9PpXo-7gcl8f8MOvcQZ2a-BV0NDtsKysznwF17hTmmN4NWOBWQHiMIIB3jCCAYCgAwIBAgIBATANBgkqhkiG9w0BAQsFADBgMQswCQYDVQQGEwJVUzERMA8GA1UECgwIQ2hyb21pdW0xIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xGjAYBgNVBAMMEUJhdGNoIENlcnRpZmljYXRlMB4XDTE3MDcxNDAyNDAwMFoXDTQxMDExMDE1MDgwNVowYDELMAkGA1UEBhMCVVMxETAPBgNVBAoMCENocm9taXVtMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMRowGAYDVQQDDBFCYXRjaCBDZXJ0aWZpY2F0ZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABI1hfmXJUI5kvMVnOsgqZ5naPBRGaCwljEY__99Y39L6Pmw3i1PXlcSk3_tBme3Xhi8jq68CA7S4kRugVpmU4QGjKDAmMBMGCysGAQQBguUcAgEBBAQDAgUgMA8GA1UdEwEB_wQFMAMBAQAwDQYJKoZIhvcNAQELBQADSQAwRgIhALzf9AI7ncZCUGONkRJg1j0giitNVEtql2-DNLkUcAKNAiEAl2FZKfyv8wP6gq8a15Zwvb0IuqhbW6Oa3ChynC2bc-JoYXV0aERhdGFYpCzXk8-gtBjLvw6oUiKGB9npezM9TbCkEBd2ava7jHVRQQAAAAAAAAAAAAAAAAAAAAAAAAAAACAeEV8OookaEAnZsZ6sTBQd34n7FG-UChiAg_h4Wds73qUBAgMmIAEhWCAxZCF_UplKr9yfSrWtQbCeHBu8kmi9wJpIldWlT3fFMiJYIMHLS8tIUgpZgxb706EC_Hx6P6qoeBZHKVhOtc80uLbz"
  , challenge = Challenge (B64URL.decodeLenient "TqyufS6bBjnhnNlOOAqcw_k_qoCeXkw-UnD6_T1LFzY")
  , getChallenge = Challenge (B64URL.decodeLenient "FKo-YOqdA16wn5PtyGCF5kcW5Cbq-kdJH47vhEYVEHA")
  , getClientDataJSON = B64URL.decodeLenient "FKo-YOqdA16wn5PtyGCF5kcW5Cbq-kdJH47vhEYVEHA"
  , getAuthenticatorData = B64URL.decodeLenient "LNeTz6C0GMu_DqhSIoYH2el7Mz1NsKQQF3Zq9ruMdVEBAAAAAg"
  , getSignature = B64URL.decodeLenient "MEYCIQDhsVWAb0QLCdfLpjfWSv1jDQXTlL-eR0jqxpY09UsO7QIhALG5c5ORMNAyRR2R7NcOWDLHKKmV9KZM5S1miiVhYmZ5"
  }

fidoU2FAttestedTest = genericCredentialTest "FIDOU2F test" packedNonSelfAttestedKeyCredential Nothing

genericCredentialTest :: String -> TestPublicKeyCredential -> Maybe DateTime -> TestTree
genericCredentialTest name TestPublicKeyCredential{..} now = testCaseSteps name $ \step -> do
  step "Registeration check..."
  Just certificateStore <- readCertificateStore "test/cacert.pem"
  eth <- VerifyRegistrationArgs
      { options = defaultPublicKeyCredentialCreationOptions
        { rp = defRp
        , challenge
        , user = User "id" "display name"
        }
      , tokenBindingID = Nothing
      , ..
      }.run
  assertBool (show eth) (isRight eth)
  let Right (cdata, _, count) = eth
  step "Verification check..."
  let eth = VerifyAssertionArgs
        { relyingParty = defRp
        , options = PublicKeyCredentialRequestOptions
          { challenge = getChallenge
          , timeout = Nothing
          , allowCredentials = Nothing
          , userVerification = Nothing
          , rpId = Just "psteniusubi.github.io"
          }
        , credential = PublicKeyCredential
          { typ = PublicKey
          , id = "id"
          , rawId = "id"
          , response = AuthenticatorAssertionResponse
            { clientDataJSON = getClientDataJSON
            , signature = getSignature
            , authenticatorData = getAuthenticatorData
            , userHandler = Nothing
            }
          }
        , origin = Origin "https" "psteniusubi.github.io" Nothing
        , requireVerification = False
        , credentialPublicKey = cdata.credentialPublicKey
        , tokenBindingID = Nothing
        , storedSignCount = count
        }.run
  assertBool (show eth) (isRight eth)

registrationTest :: TestTree
registrationTest = testCaseSteps "Credentials Test" $ \step -> do
  step "Credential creation"
  let pkcco = PublicKeyCredentialCreationOptions
        { rp = defRp
        , challenge = Challenge "12343434"
        , user = User (Base64UrlByteString "id") "display name"
        , pubKeyCredParams = ES256 :| []
        , timeout = Nothing
        , attestation = Nothing
        , authenticatorSelection = Nothing
        , extensions = Nothing
        , excludeCredentials = Just [PublicKeyCredentialDescriptor PublicKey "1234" (Just (BLE :| []))]
        }
  let ref = [aesonQQ| {
    "rp":{"id":"webauthn.biz", "name": "webauthn"},
    "challenge":"MTIzNDM0MzQ=",
    "user":{"id":"id", "name": "name", "displayName":"display name"},
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

androidClientDataJSON :: ByteString
androidClientDataJSON = B64URL.decodeLenient "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiWkIyQVJraDZ3RVBoZkdjSFBRWWpWNXNidmxoa3liVlN1ZFQ4Q0VzNTBsNCIsIm9yaWdpbiI6Imh0dHBzOlwvXC9wc3Rlbml1c3ViaS5naXRodWIuaW8iLCJhbmRyb2lkUGFja2FnZU5hbWUiOiJjb20uYW5kcm9pZC5jaHJvbWUifQ"

androidAttestationObject :: ByteString
androidAttestationObject = B64URL.decodeLenient "o2NmbXRxYW5kcm9pZC1zYWZldHluZXRnYXR0U3RtdKJjdmVyaTIwMTIxNjAzMGhyZXNwb25zZVkU3mV5SmhiR2NpT2lKU1V6STFOaUlzSW5nMVl5STZXeUpOU1VsR2EzcERRMEpJZFdkQmQwbENRV2RKVWtGT1kxTnJhbVJ6Tlc0MkswTkJRVUZCUVVGd1lUQmpkMFJSV1VwTGIxcEphSFpqVGtGUlJVeENVVUYzVVdwRlRFMUJhMGRCTVZWRlFtaE5RMVpXVFhoSWFrRmpRbWRPVmtKQmIxUkdWV1IyWWpKa2MxcFRRbFZqYmxaNlpFTkNWRnBZU2pKaFYwNXNZM3BGVkUxQ1JVZEJNVlZGUVhoTlMxSXhVbFJKUlU1Q1NVUkdVRTFVUVdWR2R6QjVUVVJCZUUxVVRYaE5WRkY0VGtSc1lVWjNNSGxOVkVGNFRWUkZlRTFVVVhoT1JHeGhUVWQzZUVONlFVcENaMDVXUWtGWlZFRnNWbFJOVWsxM1JWRlpSRlpSVVVsRmQzQkVXVmQ0Y0ZwdE9YbGliV3hvVFZKWmQwWkJXVVJXVVZGSVJYY3hUbUl6Vm5Wa1IwWndZbWxDVjJGWFZqTk5VazEzUlZGWlJGWlJVVXRGZDNCSVlqSTVibUpIVldkVVJYaEVUVkp6ZDBkUldVUldVVkZFUlhoS2FHUklVbXhqTTFGMVdWYzFhMk50T1hCYVF6VnFZakl3ZDJkblJXbE5RVEJIUTFOeFIxTkpZak5FVVVWQ1FWRlZRVUUwU1VKRWQwRjNaMmRGUzBGdlNVSkJVVU5YUlhKQ1VWUkhXa2RPTVdsYVlrNDVaV2hTWjJsbVYwSjRjV2t5VUdSbmVIY3dNMUEzVkhsS1dtWk5lR3B3TlV3M2FqRkhUbVZRU3pWSWVtUnlWVzlKWkRGNVEwbDVRazE1ZUhGbllYcHhaM1J3V0RWWGNITllWelJXWmsxb1NtSk9NVmt3T1hGNmNYQTJTa1FyTWxCYVpHOVVWVEZyUmxKQlRWZG1UQzlWZFZwMGF6ZHdiVkpZWjBkdE5XcExSSEphT1U1NFpUQTBkazFaVVhJNE9FNXhkMWN2YTJaYU1XZFVUMDVKVlZRd1YzTk1WQzgwTlRJeVFsSlhlR1ozZUdNelVVVXhLMVJMVjJ0TVEzSjJaV3MyVjJ4SmNYbGhRelV5VnpkTlJGSTRUWEJHWldKNWJWTkxWSFozWmsxU2QzbExVVXhVTUROVlREUjJkRFE0ZVVWak9ITndOM2RVUVVoTkwxZEVaemhSYjNSaGNtWTRUMEpJYTI1dldqa3lXR2wyYVdGV05uUlJjV2hTVDBoRFptZHRia05ZYVhobVZ6QjNSVmhEZG5GcFRGUmlVWFJWWWt4elV5ODRTVkowWkZocmNGRkNPVUZuVFVKQlFVZHFaMmRLV1UxSlNVTldSRUZQUW1kT1ZraFJPRUpCWmpoRlFrRk5RMEpoUVhkRmQxbEVWbEl3YkVKQmQzZERaMWxKUzNkWlFrSlJWVWhCZDBWM1JFRlpSRlpTTUZSQlVVZ3ZRa0ZKZDBGRVFXUkNaMDVXU0ZFMFJVWm5VVlUyUkVoQ2QzTkJkbUkxTTJjdlF6QTNjSEpVZG5aM1RsRlJURmwzU0hkWlJGWlNNR3BDUW1kM1JtOUJWVzFPU0RSaWFFUnllalYyYzFsS09GbHJRblZuTmpNd1NpOVRjM2RhUVZsSlMzZFpRa0pSVlVoQlVVVkZWMFJDVjAxRFkwZERRM05IUVZGVlJrSjZRVUpvYUhSdlpFaFNkMDlwT0haaU1rNTZZME0xZDJFeWEzVmFNamwyV25rNWJtUklUWGhpZWtWM1MzZFpTVXQzV1VKQ1VWVklUVUZMUjBneWFEQmtTRUUyVEhrNWQyRXlhM1ZhTWpsMlduazVibU16U1hsTU1HUlZWWHBHVUUxVE5XcGpibEYzU0ZGWlJGWlNNRkpDUWxsM1JrbEpVMWxZVWpCYVdFNHdURzFHZFZwSVNuWmhWMUYxV1RJNWRFMURSVWRCTVZWa1NVRlJZVTFDWjNkRFFWbEhXalJGVFVGUlNVTk5RWGRIUTJselIwRlJVVUl4Ym10RFFsRk5kMHgzV1VSV1VqQm1Ra05uZDBwcVFXdHZRMHRuU1VsWlpXRklVakJqUkc5MlRESk9lV0pETlhkaE1tdDFXakk1ZGxwNU9VaFdSazE0VkhwRmRWa3pTbk5OU1VsQ1FrRlpTMHQzV1VKQ1FVaFhaVkZKUlVGblUwSTVVVk5DT0dkRWQwRklZMEU1YkhsVlREbEdNMDFEU1ZWV1FtZEpUVXBTVjJwMVRrNUZlR3Q2ZGprNFRVeDVRVXg2UlRkNFdrOU5RVUZCUm5adWRYa3dXbmRCUVVKQlRVRlRSRUpIUVdsRlFUZGxMekJaVW5VemQwRkdiVmRJTWpkTk1uWmlWbU5hTDIxeWNDczBjbVpaWXk4MVNWQktNamxHTm1kRFNWRkRia3REUTBGaFkxWk9aVmxhT0VORFpsbGtSM0JDTWtkelNIaDFUVTlJYTJFdlR6UXhhbGRsUml0NlowSXhRVVZUVlZwVE5uYzNjeloyZUVWQlNESkxhaXRMVFVSaE5XOUxLekpOYzNoMFZDOVVUVFZoTVhSdlIyOUJRVUZDWWpVM2MzUktUVUZCUVZGRVFVVlpkMUpCU1dkRldHSnBiMUJpU25BNWNVTXdSR295TlRoRVJrZFRVazFCVlN0YVFqRkZhVlpGWW1KaUx6UlZkazVGUTBsQ2FFaHJRblF4T0haU2JqbDZSSFo1Y21aNGVYVmtZMGhVVDFOc00yZFVZVmxCTHpkNVZDOUNhVWcwVFVFd1IwTlRjVWRUU1dJelJGRkZRa04zVlVGQk5FbENRVkZFU1VGalVVSnNiV1E0VFVWblRHUnljbkpOWWtKVVEzWndUVmh6ZERVcmQzZ3lSR3htWVdwS1RrcFZVRFJxV1VacVdWVlJPVUl6V0RSRk1ucG1ORGx1V0ROQmVYVmFSbmhCY1U5U2JtSnFMelZxYTFrM1lUaHhUVW93YWpFNWVrWlBRaXR4WlhKNFpXTXdibWh0T0dkWmJFeGlVVzAyYzB0Wk4xQXdaWGhtY2pkSWRVc3pUV3RRTVhCbFl6RTBkMFpGVldGSGNVUjNWV0pIWjJ3dmIybDZNemhHV0VORkswTlhPRVV4VVVGRlZXWjJZbEZRVkZsaVMzaFphaXQwUTA1c2MzTXdZbFJUYjB3eVdqSmtMMm96UW5CTU0wMUdkekI1ZUZOTEwxVlVjWGxyVEhJeVFTOU5aR2hLVVcxNGFTdEhLMDFMVWxOelVYSTJNa0Z1V21GMU9YRTJXVVp2YVNzNVFVVklLMEUwT0ZoMFNYbHphRXg1UTFSVk0waDBLMkZMYjJoSGJuaEJOWFZzTVZoU2JYRndPRWgyWTBGME16bFFPVFZHV2tkR1NtVXdkWFpzZVdwUGQwRjZXSFZOZFRkTksxQlhVbU1pTENKTlNVbEZVMnBEUTBGNlMyZEJkMGxDUVdkSlRrRmxUekJ0Y1VkT2FYRnRRa3BYYkZGMVJFRk9RbWRyY1docmFVYzVkekJDUVZGelJrRkVRazFOVTBGM1NHZFpSRlpSVVV4RmVHUklZa2M1YVZsWGVGUmhWMlIxU1VaS2RtSXpVV2RSTUVWblRGTkNVMDFxUlZSTlFrVkhRVEZWUlVOb1RVdFNNbmgyV1cxR2MxVXliRzVpYWtWVVRVSkZSMEV4VlVWQmVFMUxVako0ZGxsdFJuTlZNbXh1WW1wQlpVWjNNSGhPZWtFeVRWUlZkMDFFUVhkT1JFcGhSbmN3ZVUxVVJYbE5WRlYzVFVSQmQwNUVTbUZOUlVsNFEzcEJTa0puVGxaQ1FWbFVRV3hXVkUxU05IZElRVmxFVmxGUlMwVjRWa2hpTWpsdVlrZFZaMVpJU2pGak0xRm5WVEpXZVdSdGJHcGFXRTE0UlhwQlVrSm5UbFpDUVUxVVEydGtWVlY1UWtSUlUwRjRWSHBGZDJkblJXbE5RVEJIUTFOeFIxTkpZak5FVVVWQ1FWRlZRVUUwU1VKRWQwRjNaMmRGUzBGdlNVSkJVVVJSUjAwNVJqRkpkazR3TlhwclVVODVLM1JPTVhCSlVuWktlbnA1VDFSSVZ6VkVla1ZhYUVReVpWQkRiblpWUVRCUmF6STRSbWRKUTJaTGNVTTVSV3R6UXpSVU1tWlhRbGxyTDJwRFprTXpVak5XV2sxa1V5OWtUalJhUzBORlVGcFNja0Y2UkhOcFMxVkVlbEp5YlVKQ1NqVjNkV1JuZW01a1NVMVpZMHhsTDFKSFIwWnNOWGxQUkVsTFoycEZkaTlUU2tndlZVd3JaRVZoYkhST01URkNiWE5MSzJWUmJVMUdLeXRCWTNoSFRtaHlOVGx4VFM4NWFXdzNNVWt5WkU0NFJrZG1ZMlJrZDNWaFpXbzBZbGhvY0RCTVkxRkNZbXA0VFdOSk4wcFFNR0ZOTTFRMFNTdEVjMkY0YlV0R2MySnFlbUZVVGtNNWRYcHdSbXhuVDBsbk4zSlNNalY0YjNsdVZYaDJPSFpPYld0eE4zcGtVRWRJV0d0NFYxazNiMGM1YWl0S2ExSjVRa0ZDYXpkWWNrcG1iM1ZqUWxwRmNVWktTbE5RYXpkWVFUQk1TMWN3V1RONk5XOTZNa1F3WXpGMFNrdDNTRUZuVFVKQlFVZHFaMmRGZWsxSlNVSk1la0ZQUW1kT1ZraFJPRUpCWmpoRlFrRk5RMEZaV1hkSVVWbEVWbEl3YkVKQ1dYZEdRVmxKUzNkWlFrSlJWVWhCZDBWSFEwTnpSMEZSVlVaQ2QwMURUVUpKUjBFeFZXUkZkMFZDTDNkUlNVMUJXVUpCWmpoRFFWRkJkMGhSV1VSV1VqQlBRa0paUlVaS2FsSXJSelJSTmpncllqZEhRMlpIU2tGaWIwOTBPVU5tTUhKTlFqaEhRVEZWWkVsM1VWbE5RbUZCUmtwMmFVSXhaRzVJUWpkQllXZGlaVmRpVTJGTVpDOWpSMWxaZFUxRVZVZERRM05IUVZGVlJrSjNSVUpDUTJ0M1NucEJiRUpuWjNKQ1owVkdRbEZqZDBGWldWcGhTRkl3WTBSdmRrd3lPV3BqTTBGMVkwZDBjRXh0WkhaaU1tTjJXak5PZVUxcVFYbENaMDVXU0ZJNFJVdDZRWEJOUTJWblNtRkJhbWhwUm05a1NGSjNUMms0ZGxrelNuTk1ia0p5WVZNMWJtSXlPVzVNTW1SNlkycEpkbG96VG5sTmFUVnFZMjEzZDFCM1dVUldVakJuUWtSbmQwNXFRVEJDWjFwdVoxRjNRa0ZuU1hkTGFrRnZRbWRuY2tKblJVWkNVV05EUVZKWlkyRklVakJqU0UwMlRIazVkMkV5YTNWYU1qbDJXbms1ZVZwWVFuWmpNbXd3WWpOS05VeDZRVTVDWjJ0eGFHdHBSemwzTUVKQlVYTkdRVUZQUTBGUlJVRkhiMEVyVG01dU56aDVObkJTYW1RNVdHeFJWMDVoTjBoVVoybGFMM0l6VWs1SGEyMVZiVmxJVUZGeE5sTmpkR2s1VUVWaGFuWjNVbFF5YVZkVVNGRnlNREptWlhOeFQzRkNXVEpGVkZWM1oxcFJLMnhzZEc5T1JuWm9jMDg1ZEhaQ1EwOUpZWHB3YzNkWFF6bGhTamw0YW5VMGRGZEVVVWc0VGxaVk5sbGFXaTlZZEdWRVUwZFZPVmw2U25GUWFsazRjVE5OUkhoeWVtMXhaWEJDUTJZMWJ6aHRkeTkzU2pSaE1rYzJlSHBWY2paR1lqWlVPRTFqUkU4eU1sQk1Va3cyZFROTk5GUjZjek5CTWsweGFqWmllV3RLV1drNGQxZEpVbVJCZGt0TVYxcDFMMkY0UWxaaWVsbHRjVzEzYTIwMWVreFRSRmMxYmtsQlNtSkZURU5SUTFwM1RVZzFOblF5UkhaeGIyWjRjelpDUW1ORFJrbGFWVk53ZUhVMmVEWjBaREJXTjFOMlNrTkRiM05wY2xOdFNXRjBhaTg1WkZOVFZrUlJhV0psZERoeEx6ZFZTelIyTkZwVlRqZ3dZWFJ1V25veGVXYzlQU0pkZlEuZXlKdWIyNWpaU0k2SW5KS1lXcExhM1pEUm01aE0yUlpXVzVVWTFSQ1FWRnNlbkE1WVhVemMwWXpZVzVxTjBaVWJFbHpSRlU5SWl3aWRHbHRaWE4wWVcxd1RYTWlPakUxT0RnM05UazFNRFEyTkRFc0ltRndhMUJoWTJ0aFoyVk9ZVzFsSWpvaVkyOXRMbWR2YjJkc1pTNWhibVJ5YjJsa0xtZHRjeUlzSW1Gd2EwUnBaMlZ6ZEZOb1lUSTFOaUk2SWtGMmJTOU1MMmxHU1hkcmNuaE5TakJJU1V4M2NqVjRTa2xoVFZWUlREWlFjMGhFWWtWa2NVMXJja0U5SWl3aVkzUnpVSEp2Wm1sc1pVMWhkR05vSWpwMGNuVmxMQ0poY0d0RFpYSjBhV1pwWTJGMFpVUnBaMlZ6ZEZOb1lUSTFOaUk2V3lJNFVERnpWekJGVUVwamMyeDNOMVY2VW5OcFdFdzJOSGNyVHpVd1JXUXJVa0pKUTNSaGVURm5NalJOUFNKZExDSmlZWE5wWTBsdWRHVm5jbWwwZVNJNmRISjFaU3dpWlhaaGJIVmhkR2x2YmxSNWNHVWlPaUpDUVZOSlF5SjkuWXZtN1ZGNmVpeUhYWEMyanprdjJ2QTdQNGRYd3NobkxvYlN1Q2NHbEtYRFkzeFhLVkxlUTdWalZ6QkpyU1J2ODROYlh0TzFqanZ6WVdQLTNJcDdEWktXc2dBeEpJSk1SeHhwQU44UUJiWUlPS2Yzamxxczd4VWtMM2pNdVl2bFVsbkNseUJuaEpvTm9tN3JWZE04SmdiajMtUVQxRGhSNUt0WEVUbV9HaFFEanJrdHBJd201N3RGRFYwOHRVVEtrTkpmNkNnNDV3Y0plbnJ2UlZTUXBseXh1cVY4al91QWl5SkxGdTV5dk1qZ0o3WkdkLXRZX1ZscS1zNXQ2NTVSTnYtaHNFQTZhdTdyTzNJYjFQQVh3X0xGVENveXdKLVhVd0xqRkpqZTdieGpnQUx2SWtrOE5BUGpXYXh2YWcyRzMyNGs4RWdjSzc3U0dxNHhES1Zfek5BaGF1dGhEYXRhWMUs15PPoLQYy78OqFIihgfZ6XszPU2wpBAXdmr2u4x1UUUAAAAAuT_ZYfLmRi-xIoIAIkfeeABBAQJBVPhy4yG7tNUTkedMIgadvfK55s6r3qX_V5jaBOfycETIQLr7zGs_GrMbXGrkJU2BTCDU_uuea4WwBffTv_GlAQIDJiABIVggca4oTyEumIkH8am4WBD7h90D_SSj6cRf7ksf3HhbefoiWCD6gxvdhHuqvBsamD01kD6pCiVWakup0S0BNRYj0U7hOg"

androidChallenge :: Challenge
androidChallenge = Challenge (B64URL.decodeLenient "ZB2ARkh6wEPhfGcHPQYjV5sbvlhkybVSudT8CEs50l4")

androidGetChallenge :: Challenge
androidGetChallenge = Challenge (B64URL.decodeLenient "dCCcJkllvbdd-LKDJrCQYbouMEY3FEsNljYis_temyA")

-- This contains the Get Challenge in it
androidGetClientDataJSON :: ByteString
androidGetClientDataJSON = B64URL.decodeLenient "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiZENDY0prbGx2YmRkLUxLREpyQ1FZYm91TUVZM0ZFc05sallpc190ZW15QSIsIm9yaWdpbiI6Imh0dHBzOlwvXC9wc3Rlbml1c3ViaS5naXRodWIuaW8iLCJhbmRyb2lkUGFja2FnZU5hbWUiOiJjb20uYW5kcm9pZC5jaHJvbWUifQ"

androidGetAuthenticatorData :: ByteString
androidGetAuthenticatorData = B64URL.decodeLenient "LNeTz6C0GMu_DqhSIoYH2el7Mz1NsKQQF3Zq9ruMdVEFAAAAAQ"

androidGetSignature :: ByteString
androidGetSignature = BS.decodeLenient "MEQCIFM6aZjT8CefzdAn-QNaa5OcPU24V1SERVocZlus1YT1AiAH_UqNj7xVOW1sDLKkpicTxIONpwfWrWNbo8KL4z5wcA"
