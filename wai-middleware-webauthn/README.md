wai-middleware-webauthn
====

This is a WAI middleware which introduces a simple authentication mechanism
based on [Web Authentication API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API) (WebAuthn).

Demo
----

```
cabal run demo
```

Starts a demo application. Open https://localhost:8080/ and click the Register button once you filled the display name.
If successful, it prints the credential in the top section. Copy the credential to `config.yaml` and restart the server.
If the credential is stored in the authenticator and `config.yaml` correctly, you should be able to `Login with WebAuthn` using the key of the credential in `config.yaml`.

Configuration
----

One easy way to configure the middleware is to use `staticKeys` with a YAML file.

```haskell
import qualified Network.Wai.Middleware.WebAuthn as WebAuthn
import qualified Data.Yaml as Yaml
main = do
  config <- Yaml.decodeFileThrow "config.yaml"
  mid <- WebAuthn.mkMiddleware $ staticKeys <$> config
  ...
```

```yaml
origin: "https://localhost:8080"
endpoint: "webauthn"
authorisedKeys:
  fumieval:
  - aaguid: '0000000000000000000000000000'
    credentialId: "0IMo2OFRmM903AGEP5/1u5eVGlcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
    publicKey: "pQECAyYgASFYICJwKPYkRYKWH6OIAjp+IDghFnl06S0iSGjxn/arBp0OIlggoJmTH1ZaVWCrn3A2b+wZx4/mVePRFowKujU5xXmafJY="
```

`authorisedKeys` is a map from identifiers to a list of public keys.

lib.js
----
This middleware exposes a JavaScript library in `/lib.js`:

You must import following scripts in order to make it work:

```
<script src="https://bundle.run/buffer@6.0.3"></script>
```

Here's the pseudo-code describing the content of the library.

```
CredentialId = String -- Credential Id
CredentialPublicKey = String -- Public key
Credential =
  { credentialId : CredentialId
  , publicKey : CredentialPublicKey
  }

Token = String -- Token for authorisation
Identifier = String -- Human-readable identifier for a Credential

HostName = String
Endpoint = String -- The prefix of the middleware API e.g. "webauthn"
User = -- Information stored in the authenticator
  { id : String
  , displayName : String
  }

WebAuthnProxy : HostName -> Endpoint ->
  { attest : User -> Promise Credential
  -- Register a user to the authenticator and returns a credential if it's valid.
  -- Once verified, insert the Credential to the list of authorisedKeys into the configuraion.
  , assert : CredentialId -> Promise Token
  -- Verify a credential using the public key stored in the server.
  -- Returns a token if succeeds.
  , lookup : Identifier -> Promise CredentialId
  -- Find a CredentialId associated to the Identifier (provisional).
  }
```

Whenever it receives a request containing `Authorization: XXX`, it checks if `XXX` is a valid token generated by `verify`.
It replaces `XXX` by the associated identifier which can be extracted by `requestIdentifier :: Request -> Maybe Identifier`.
