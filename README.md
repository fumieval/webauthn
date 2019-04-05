Running the demo
----

Prepare certificate.pem and key.pem:

```
openssl genrsa -out key.pem 2048
openssl req -new -key key.pem -out certificate.csr
openssl x509 -req -in certificate.csr -signkey key.pem -out certificate.pem
```

Start the demo server:

```
$ cabal new-run webauthn-demo
```

Go to https://localhost:8080/ and click the "Login" button.

Support matrix
----

| OS  | Browser      | FIDO U2F |
| --- |------------- | -------- |
| Mac | Chrome 73    | Yes      |
| Mac | Firefox 66   | No       |

Links
----

* https://github.com/github/SoftU2F - Software U2F authenticator for macOS
