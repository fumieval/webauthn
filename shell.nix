{ nixpkgs ? import ./nix/nixpkgs.nix {}, compiler ? "ghc884" }:

let
  inherit (nixpkgs) pkgs;

  hlib = pkgs.haskell.lib;
  hpkgs0 = pkgs.haskell.packages.${compiler};

  # sources = {
  #   basement = pkgs.fetchFromGitHub {
  #     owner = "haskell-foundation";
  #     repo = "foundation";
  #     rev = "3c195907c7e7c41fa0888237b6e36cdbde67df59";
  #     sha256 = "0qyw0qpcqpkjihbpmwhw8ly5vcin85hfshhyyzck1w4zzgp14v17";
  #   };
  # };

  hpkgs = hpkgs0.override {
    overrides = self: super: {
      #basement = self.callCabal2nix "basement" "${sources.basement}/basement" {};

      webauthn = self.callCabal2nix "webauthn" ./webauthn {};
      webauthn-demo = self.callCabal2nix "webauthn-demo" ./webauthn-demo/backend { inherit (self) webauthn; };
      webauthn-test = self.callCabal2nix "webauthn-test" ./webauthn-test/backend { inherit (self) webauthn; };
      wai-middleware-webauthn = self.callCabal2nix "wai-middleware-webauthn" ./wai-middleware-webauthn { inherit (self) webauthn; };
      wai-middleware-webauthn-demo = self.callCabal2nix "demo" ./wai-middleware-webauthn/demo { inherit (self) wai-middleware-webauthn; };
    };
  };

in
  hpkgs.shellFor {
    packages = ps: with hpkgs; [
      webauthn
      webauthn-demo
      webauthn-test
      wai-middleware-webauthn
      wai-middleware-webauthn-demo
      ];
    buildInputs = with pkgs; [
      cabal-install
      hlint
      hpkgs0.haskell-language-server
      nodejs
      ];
  }
