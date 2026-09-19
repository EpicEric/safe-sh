{
  description = "Static shell script analysis with Jev";

  inputs = { };

  outputs =
    { self, ... }@args:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];

      eachSystem =
        f:
        (builtins.foldl' (
          acc: system:
          let
            fSystem = f system;
          in
          builtins.foldl' (
            acc': attr:
            acc'
            // {
              ${attr} = (acc'.${attr} or { }) // fSystem.${attr};
            }
          ) acc (builtins.attrNames fSystem)
        ) { } systems);

      inputs = import ./.tack {
        overrides = args.tackOverrides or { };
      };
    in
    eachSystem (
      system:
      let
        pkgs = import inputs.nixpkgs { inherit system; };
        pyproject-nix = import inputs."pyproject.nix" { inherit (pkgs) lib; };
        uv2nix = import inputs.uv2nix {
          inherit (pkgs) lib;
          inherit pyproject-nix;
        };
        pyproject-build-systems = import inputs.pyproject-build-systems {
          inherit (pkgs) lib;
          inherit pyproject-nix uv2nix;
        };
        inherit
          (import ./nix {
            inherit
              system
              inputs
              pkgs
              pyproject-nix
              uv2nix
              pyproject-build-systems
              ;
          })
          safe-sh
          devShell
          ;
      in
      {
        packages.${system} = {
          default = safe-sh;
          inherit safe-sh;
        };

        apps.${system}.default = {
          type = "app";
          program = pkgs.lib.getExe safe-sh;
        };

        devShells.${system}.default = devShell;
      }
    );
}
