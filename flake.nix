{
  description = "Kubebuilder Flake";

  inputs = {
    nixpkgs = { url = "github:nixos/nixpkgs/nixos-23.05"; };
    flake-parts.url = "github:hercules-ci/flake-parts";
    devenv.url = "github:cachix/devenv";
  };

  outputs = inputs@{ self, nixpkgs, flake-parts, devenv }:
  flake-parts.lib.mkFlake { inherit inputs; } {
    imports = [ inputs.devenv.flakeModule ];
    systems = nixpkgs.lib.systems.flakeExposed;

    perSystem = { config, system, pkgs, ... }: {

      devenv.shells.default = {
        languages.go.enable = true;
        packages = with pkgs; [
          gopls
          gotools
          go-tools
          kubebuilder
          kustomize
          gnumake
        ];
      };

    };

  };
}
