# safe-sh

Static shell script analysis with Jev.

> [!Note]
> LLM disclaimer: This repo includes minor contributions from large language models, all of them thoroughly reviewed by a human.

## Usage

Install with `uv`:

```bash
uv tool install git+https://codeberg.org/EpicEric9/safe-sh.git
```

You can also install it with Nix (via `default.nix` or `flake.nix`).

Make sure that the `TYPESAFE_API_KEY` environment variable is set, then replace wherever the script asks for `sh`/`bash` with `safe-sh`. For example:

```bash
curl -fsSL https://malicious.website/install.sh | safe-sh
# --- OR ---
safe-sh -c "$(curl -fsSL https://malicious.website/install.sh)"
```

Adjust the warning threshold with `--warn-on` and the error threshold with `--error-on`, or make the logs shorter with `--short`.
