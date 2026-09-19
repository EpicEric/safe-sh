{
  system ? builtins.currentSystem,
  inputs ? import ../.tack,
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
let
  inherit (pkgs) lib;

  workspace = uv2nix.lib.workspace.loadWorkspace { workspaceRoot = ../.; };

  python = lib.head (
    pyproject-nix.lib.util.filterPythonInterpreters {
      inherit (workspace) requires-python;
      inherit (pkgs) pythonInterpreters;
    }
  );

  pythonBase = pkgs.callPackage pyproject-nix.build.packages {
    inherit python;
  };

  overlay = workspace.mkPyprojectOverlay {
    sourcePreference = "wheel";
  };

  pythonSet = pythonBase.overrideScope (
    lib.composeManyExtensions [
      pyproject-build-systems.overlays.wheel
      overlay
    ]
  );

  inherit (pkgs.callPackages pyproject-nix.build.util { }) mkApplication;
in
{
  safe-sh = mkApplication {
    venv = pythonSet.mkVirtualEnv "safe-sh-venv" workspace.deps.default;
    package = pythonSet.safe-sh;
  };

  devShell = {
    default = pkgs.mkShell {
      packages = [
        (pythonSet.mkVirtualEnv "safe-sh-venv" workspace.deps.all)
        pkgs.uv
      ];
      env = {
        UV_NO_SYNC = "1";
        UV_PYTHON = pythonSet.python.interpreter;
        UV_PYTHON_DOWNLOADS = "never";
      };
      shellHook = ''
        unset PYTHONPATH
        export REPO_ROOT=$(git rev-parse --show-toplevel)
      '';
    };
  };
}
