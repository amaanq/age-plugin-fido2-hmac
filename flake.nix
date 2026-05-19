{
  description = "Encrypt files with age and FIDO2 tokens via the hmac-secret extension.";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    inputs:
    let
      inherit (inputs.nixpkgs) lib;
      inherit (inputs) self;
      inherit (lib) genAttrs optionals;

      eachSystem =
        f: genAttrs lib.systems.flakeExposed (system: f inputs.nixpkgs.legacyPackages.${system});

      # Fenix only exposes outputs for systems where upstream Rust ships
      # binaries. For arches without fenix coverage, we fall back to nixpkgs's
      # bundled rustc.
      hasFenix = system: inputs.fenix.packages ? ${system};

      # mold + clang are only used on Linux tier-1 arches
      hasMold = plat: plat.isLinux && (plat.isx86_64 || plat.isAarch64);
    in
    {
      packages = eachSystem (
        pkgs:
        let
          packageName = "age-plugin-fido2-hmac";
          inherit (pkgs.stdenv.hostPlatform) system;
          rustPlatform =
            if hasFenix system then
              let
                fenixPkgs = inputs.fenix.packages.${system};
              in
              pkgs.makeRustPlatform {
                cargo = fenixPkgs.latest.cargo;
                rustc = fenixPkgs.latest.rustc;
              }
            else
              pkgs.rustPlatform;
        in
        {
          age-plugin-fido2-hmac = rustPlatform.buildRustPackage {
            pname = packageName;
            src = ./.;
            version = "0.1.0";

            cargoLock.lockFile = ./Cargo.lock;

            nativeBuildInputs = [
              pkgs.pkg-config
            ]
            ++ optionals (hasMold pkgs.stdenv.hostPlatform) [
              pkgs.clang
              pkgs.mold
              pkgs.wild
            ];

            # hidapi (via ctap-hid-fido2) needs libudev on Linux.
            buildInputs = optionals pkgs.stdenv.hostPlatform.isLinux [
              pkgs.udev
            ];

            meta = {
              description = "Encrypt files with age and FIDO2 tokens via the hmac-secret extension";
              homepage = "https://github.com/amaanq/age-plugin-fido2-hmac";
              license = lib.licenses.mit;
              maintainers = [ lib.maintainers.amaanq ];
              mainProgram = packageName;
            };
          };

          default = self.packages.${system}.age-plugin-fido2-hmac;
        }
      );

      devShells = eachSystem (
        pkgs:
        let
          inherit (pkgs.stdenv.hostPlatform) system;
          toolchain =
            if hasFenix system then
              (inputs.fenix.packages.${system}.complete.withComponents [
                "cargo"
                "clippy"
                "rust-src"
                "rustc"
                "rustfmt"
                "rust-analyzer"
              ])
            else
              pkgs.rustc;
        in
        {
          default = pkgs.mkShell {
            packages = [
              pkgs.nixfmt
              pkgs.pkg-config
              pkgs.taplo
              toolchain
            ]
            ++ optionals pkgs.stdenv.hostPlatform.isLinux [
              pkgs.udev
            ]
            ++ optionals (hasMold pkgs.stdenv.hostPlatform) [
              pkgs.clang
              pkgs.mold
              pkgs.wild
            ];
          };
        }
      );
    };
}
