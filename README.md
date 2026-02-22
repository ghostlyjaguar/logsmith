# Logsmith (Synthetic Log Generator)

Logsmith generates **synthetic** cybersecurity log files for education and practice. It never creates real logs and labels outputs as synthetic to prevent misuse.

## One‑minute setup (non‑technical)

1. Install Python 3.11 from the official site.
2. Open **Command Prompt** (Windows) or **Terminal** (Mac/Linux).
3. Go to the project folder.

Windows example:

```bat
cd C:\path\to\logsmith
python --version
```

You should see something like `Python 3.11.x`.

## Quick start

```bash
python logsmith.py list
python logsmith.py wizard
python logsmith.py generate --log windows_security=50 --log apache_access=200 --seed 7 --zip
```

## What gets created

- A folder named `generated_logs`
- One subfolder per log type
- A `MANIFEST.json` describing exactly what was generated
- Every log line is labeled `SYNTHETIC`

## Commands

- `list` prints supported log types.
- `wizard` runs the interactive generator (best for beginners).
- `generate` runs non‑interactively with CLI flags.

## Global options

- `--out_dir PATH` output directory (default: `./generated_logs`)
- `--seed INT` random seed for reproducible output
- `--timeframe_days INT` timestamps within last N days (default: 30)

## Generate options

- `--log TYPE=COUNT` repeatable log type selection
- `--all COUNT` generate all log types with the same count
- `--zip` zip the output directory when done

## Example (wizard)

```bash
python logsmith.py wizard
```

Then follow the prompts to pick log types and counts.

## Example (generate)

```bash
python logsmith.py generate --log windows_security=50 --log apache_access=200 --seed 7
```

## Troubleshooting

- **"python" not found**: Make sure Python 3.11 is installed and added to PATH.
- **Wrong Python version**: Run `python --version` and confirm 3.11.x.
- **Permission errors**: Try running the command from a folder you own, like your Desktop.

## Output example

```
generated_logs/
  MANIFEST.json
  windows_security/windows_security.log
  apache_access/apache_access.log
```


