{
  description = "Logos keystore module — scrypt vaults, BIP39/BIP32 HD derivation, secp256k1 signing (offline, no network).";

  inputs = {
    logos-module-builder.url = "github:logos-co/logos-module-builder";
  };

  outputs = inputs@{ self, logos-module-builder, ... }:
    let
      nixpkgs = logos-module-builder.inputs.nixpkgs;
      systems = [ "aarch64-darwin" "x86_64-darwin" "aarch64-linux" "x86_64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems f;
      moduleFor = system: logos-module-builder.lib.mkLogosModule {
        src = ./.;
        configFile = ./metadata.json;
        flakeInputs = inputs;
      };
    in
    {
      packages = forAllSystems (system: (moduleFor system).packages.${system});

      # The `web` variant, driven across a page reload. See nix/web-variant-test.nix
      # for what it asserts and why two images is the only honest way to ask.
      #
      # A SKIP THAT SAYS SO when the builder publishes no `web` output for this
      # module -- a pin whose logos-protocol has no wasm subset, or one from
      # before the builder could compile a Rust core to wasm32 at all. That is a
      # pin rollout, not a defect, and an absent check would be a green run with
      # a silently missing test.
      checks = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          modulePkgs = (moduleFor system).packages.${system};
        in {
          web-variant =
            if modulePkgs ? web
            then import ./nix/web-variant-test.nix { inherit pkgs; webVariant = modulePkgs.web; }
            else pkgs.runCommand "keystore-web-variant-tests-skipped" { } ''
              echo "SKIP: web-variant -- this logos-module-builder pin publishes no"
              echo "      \`web\` output for a codegen.rust module. Run through the"
              echo "      workspace flake: ws test logos-evm-keystore-module --local \\"
              echo "        logos-module-builder logos-rust-sdk"
              mkdir -p $out
              echo skipped > $out/result
            '';
        });
    };
}
