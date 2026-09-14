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

      # x86_64-windows is a cross PSEUDO-SYSTEM the builder already understands
      # (logos-module-builder lib/common.nix routes it to
      # logos-nix.lib.mkWindowsPkgs, and picks the build platform separately).
      # It is a target, never a host we evaluate nixpkgs natively for, so it
      # only ever belongs in `packages`.
      targets = systems ++ [ "x86_64-windows" ];
      forAllTargets = f: nixpkgs.lib.genAttrs targets f;

      # One module definition; it is `packages.<system>` on it that is per-system.
      module = logos-module-builder.lib.mkLogosModule {
        src = ./.;
        configFile = ./metadata.json;
        flakeInputs = inputs;
      };
    in
    {
      packages = forAllTargets (system: module.packages.${system});

      # The `web` variant, driven across a page reload. See nix/web-variant-test.nix
      # for what it asserts and why two images is the only honest way to ask.
      #
      # forAllSystems, not forAllTargets: a check is BUILT and RUN here, and
      # x86_64-windows is a cross target this machine cannot run.
      #
      # A SKIP THAT SAYS SO when the builder publishes no `web` output for this
      # module -- a pin whose logos-protocol has no wasm subset, or one from
      # before the builder could compile a Rust core to wasm32 at all. That is a
      # pin rollout, not a defect, and an absent check would be a green run with
      # a silently missing test.
      checks = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          modulePkgs = module.packages.${system};
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
