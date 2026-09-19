# safe-sh

Static shell script analysis with Jev.

## Usage

Make sure the `TYPESAFE_API_KEY` environment variable is set and that you're in the root directory of this repo.

Replace wherever the script asks for `sh`/`bash` with `uv run safe-sh`. For example:

```bash
curl -fsSL https://malicious.website/install.sh | uv run safe-sh
# --- OR ---
uv run safe-sh -c "$(curl -fsSL https://malicious.website/install.sh)"
```

Adjust the warning threshold with `--warn-on` and the error threshold with `--error-on`, or make the logs shorter with `--short`.
