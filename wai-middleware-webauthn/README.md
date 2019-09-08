
You must import following scripts:

https://cdn.jsdelivr.net/npm/cbor-js@0.1.0/cbor.min.js
https://cdn.jsdelivr.net/npm/base64-js@1.3.0/base64js.min.js

```
WebAuthnProxy : Endpoint ->
  { register : User -> (Credential -> X) -> X
  , verify : CredentialId -> (Token -> X) -> X
  }

Endpoint = String
CredentialId = String
Token = String

User =
  {

  }
```
