# Logsmith
Student-friendly synthetic cybersecurity log generator for labs, demos, and automated testing.

Logsmith generates **synthetic** cybersecurity logs for learning and practice. It does not create real logs. Every generated log line includes a **synthetic marker** (see "Synthetic marker" below) to reduce misuse and make datasets safe to share.

**Who this is for**
- Students learning SOC, SIEM, or incident response basics
- Instructors who need safe practice data
- Anyone who wants example logs without privacy concerns

## Use cases
- SOC / SIEM / incident-response training data (safe classroom datasets)
- Demo data for dashboards without using production logs
- CI tests for log parsers, ingest pipelines, and detection content
- Benchmark datasets for AI/agent log summarization and correlation (seeded + manifested)

## Quickstart (recommended)
From the repo root (where `logsmith.py` is):

```bash
# See supported log types
python logsmith.py list

# Interactive wizard (beginner-friendly)
python logsmith.py wizard

# Scripted generation (example)
python logsmith.py generate --log windows_security=50 --log apache_access=200 --seed 7 --zip
```

## What gets created

Default output is a folder named `generated_logs/` containing:

- One file per selected log type
- Optional: `consolidated_logs.log` combining all generated logs (`--consolidate`)
- `MANIFEST.json` describing exactly what was generated (types, counts, seed, timing)
- Optional: zipped output directory (`--zip`)

**Example output:**

```
generated_logs/
  MANIFEST.json
  consolidated_logs.log
  windows_security.log
  apache_access.log
```

## Synthetic marker

- Structured logs include `synthetic: true`.
- Text logs include `[SYNTHETIC]` inside the message field without breaking standard formats.
- Access logs include `SyntheticLog` in the User-Agent field.

## Using Logsmith with AI/agent workflows

Logsmith can generate controlled datasets (seeded + manifested) for evaluating log summarizers, correlation agents, and alert triage workflows without using sensitive production logs.

## Beginner walkthrough (install + first run)

If you are new to the command line, this section walks you through the basics in small steps.

### 1. Install Python (one-time)

You need Python 3.11.

1. Install Python 3.11 from the [official site](https://www.python.org/downloads/).
2. Open Command Prompt (Windows) or Terminal (Mac/Linux).
3. Check your version:

```bash
python --version
```

You should see something like `Python 3.11.x`.

### 2. Open the project folder

Move into the folder where you downloaded Logsmith.

**Windows example:**
```bash
cd C:\path\to\logsmith
```

**Mac/Linux example:**
```bash
cd /path/to/logsmith
```

### 3. First run (recommended)

The wizard asks questions and helps you choose log types.

```bash
python logsmith.py wizard
```

Follow the prompts to pick log types and counts.

### 4. Common commands

```bash
python logsmith.py list
python logsmith.py wizard
python logsmith.py generate --log windows_security=50 --log apache_access=200 --seed 7 --zip
```

What these do:
- `list` shows all available log types.
- `wizard` is interactive and beginner friendly.
- `generate` is for quick, scripted runs.

## Default lab topology (used for hostnames)

- **Windows:** `win10-lab`, `win11-lab`
- **Linux:** `web01`, `web02`, `db01`, `db02`, `app01`, `app02`
- **Network:** `fw01`, `router1`, `switch1`
- **ESXi:** `esxi01`
- **Kubernetes nodes:** `k8s-node1`, `k8s-node2`

Each log source uses only plausible hosts (e.g., Windows logs only on Windows hosts).

## Timestamps

- All timestamps are generated in UTC.
- Syslog-style lines use RFC3164 format (no year/timezone). Other formats are ISO8601 or source-typical.

## Helpful options

**Global options:**

| Option | Description |
|---|---|
| `--out_dir PATH` | Output directory (default: `./generated_logs`) |
| `--seed INT` | Random seed for reproducible output |
| `--timeframe_days INT` | Timestamps within last N days (default: 30) |

If you do not provide `--seed`, each run produces different randomized logs.

**Generate options:**

| Option | Description |
|---|---|
| `--log TYPE=COUNT` | Repeatable log type selection |
| `--all COUNT` | Generate all log types with the same count |
| `--consolidate` | Write `consolidated_logs.log` with all generated logs |
| `--zip` | Zip the output directory when done |

## Common student tasks

**Make 100 Windows logs:**
```bash
python logsmith.py generate --log windows_security=100
```

**Generate all log types (25 each):**
```bash
python logsmith.py generate --all 25
```

**Repeat the same data for a lab:**
```bash
python logsmith.py generate --log apache_access=50 --seed 42
```

## Troubleshooting

- **"python" not found:** Make sure Python 3.11 is installed and added to PATH.
- **Wrong Python version:** Run `python --version` and confirm `3.11.x`.
- **Permission errors:** Run the command from a folder you own, like your Desktop.

## Notes for teachers

- `MANIFEST.json` records what was generated, the seed, and timing details.
- All logs are synthetic and labeled for safe classroom use.
