# WebAuthn demo

A simpliefied demo for registration and login using WebAuthn. You can find the original version at [webauthn.io](https://webauthn.io).

Please note this is not to be treated as a collection of best practices for implementing webauthn. Use your best judgement, read and follow the specification. PRs welcome!

## How to run

Instructions are for nix users but you are of course free to install necessary tools in your favourite way. You'll need GHC with libraries and node.

    nix-shell
    cd webauthn-demo/frontend
    npm ci
    npm run-script build
    cd ../backend
    cabal v2-run

Go to http://localhost:9000
