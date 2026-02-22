# Logsmith (Student-Friendly Synthetic Log Generator)

Logsmith creates **synthetic** cybersecurity logs for learning and practice. It does not create real logs. Every log line is labeled `SYNTHETIC` to prevent misuse.

If you are new to the command line, this README is designed to walk you through the basics in small steps.

**Who this is for**
- Students learning SOC, SIEM, or incident response basics
- Instructors who need safe practice data
- Anyone who wants example logs without privacy concerns

## 1. Install Python (one-time)

You need **Python 3.11**.

1. Install Python 3.11 from the official site.
2. Open **Command Prompt** (Windows) or **Terminal** (Mac/Linux).
3. Check your version:

```bat
python --version
```

You should see something like `Python 3.11.x`.

## 2. Open the project folder

Move into the folder where you downloaded Logsmith.

Windows example:

```bat
cd C:\path\to\logsmith
```

Mac/Linux example:

```bash
cd /path/to/logsmith
```

## 3. First run (recommended)

The `wizard` asks questions and helps you choose log types.

```bash
python logsmith.py wizard
```

Follow the prompts to pick log types and counts.

## 4. Common commands

```bash
python logsmith.py list
python logsmith.py wizard
python logsmith.py generate --log windows_security=50 --log apache_access=200 --seed 7 --zip
```

**What these do**
- `list` shows all available log types.
- `wizard` is interactive and beginner friendly.
- `generate` is for quick, scripted runs.

## What gets created

- A folder named `generated_logs`
- One subfolder per log type
- A `MANIFEST.json` describing exactly what was generated
- Every log line is labeled `SYNTHETIC`

## Output example

```
generated_logs/
  MANIFEST.json
  windows_security/windows_security.log
  apache_access/apache_access.log
```

## Helpful options

**Global options**
- `--out_dir PATH` output directory (default: `./generated_logs`)
- `--seed INT` random seed for reproducible output
- `--timeframe_days INT` timestamps within last N days (default: 30)

**Generate options**
- `--log TYPE=COUNT` repeatable log type selection
- `--all COUNT` generate all log types with the same count
- `--zip` zip the output directory when done

## Common student tasks

**Make 100 Windows logs**

```bash
python logsmith.py generate --log windows_security=100
```

**Generate all log types (25 each)**

```bash
python logsmith.py generate --all 25
```

**Repeat the same data for a lab**

```bash
python logsmith.py generate --log apache_access=50 --seed 42
```

## Troubleshooting

- **"python" not found**: Make sure Python 3.11 is installed and added to PATH.
- **Wrong Python version**: Run `python --version` and confirm 3.11.x.
- **Permission errors**: Run the command from a folder you own, like your Desktop.

## Notes for teachers

- `MANIFEST.json` records what was generated, the seed, and timing details.
- All logs are synthetic and labeled for safe classroom use.
