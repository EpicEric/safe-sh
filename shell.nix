{
  system ? builtins.currentSystem,
  inputs ? import ./.tack,
  pkgs ? import inputs.nixpkgs { inherit system; },
  pyproject-nix ? import inputs."pyproject.nix" { inherit (pkgs) lib; },
  uv2nix ? import inputs.uv2nix {
    inherit (pkgs) lib;
    inherit pyproject-nix;
  },
  pyproject-build-systems ? import inputs.pyproject-build-systems {
    inherit (pkgs) lib;
    inherit pyproject-nix uv2nix;
  },
}:
(import ./nix {
  inherit
    system
    inputs
    pkgs
    pyproject-nix
    uv2nix
    pyproject-build-systems
    ;
}).devShell
