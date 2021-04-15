{ nixpkgs ? import ./nix/nixpkgs.nix {}, compiler ? "default" }:

let
  inherit (nixpkgs) pkgs;

  haskellPackages = if compiler == "default"
                       then pkgs.haskellPackages
                       else pkgs.haskell.packages.${compiler};

  webauthn = haskellPackages.callCabal2nix "webauthn" ./webauthn {};
  wai-middleware-webauthn = haskellPackages.callCabal2nix "wai-middleware-webauthn" ./wai-middleware-webauthn {
    webauthn = webauthn;
  };
  demo = haskellPackages.callCabal2nix "demo" ./wai-middleware-webauthn/demo {
    wai-middleware-webauthn = wai-middleware-webauthn;
  };

in
  if pkgs.lib.inNixShell
    then haskellPackages.shellFor {
           packages = ps: [ webauthn wai-middleware-webauthn demo ];
           buildInputs = with pkgs; [ cabal-install hlint haskellPackages.ghcid ];
         }
    else webauthn
