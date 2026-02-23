from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import random
import sys
import zipfile

from generators import LogType, get_log_types

TOOL_VERSION = "1.0.0"
DISCLAIMER = "Synthetic logs generated for educational purposes."


@dataclass
class GenerationResult:
    log_type: LogType
    count: int
    file_path: Path


def _default_out_dir() -> Path:
    return Path.cwd() / "generated_logs"


def _parse_log_arg(value: str) -> tuple[str, int]:
    if "=" not in value:
        raise argparse.ArgumentTypeError("--log must be in TYPE=COUNT format")
    t, c = value.split("=", 1)
    t = t.strip()
    try:
        count = int(c.strip())
    except ValueError as exc:
        raise argparse.ArgumentTypeError("COUNT must be an integer") from exc
    if count <= 0:
        raise argparse.ArgumentTypeError("COUNT must be > 0")
    return t, count


def _select_types_from_args(args: argparse.Namespace, types: dict[str, LogType]) -> dict[str, int]:
    selected: dict[str, int] = {}
    if args.all is not None:
        if args.all <= 0:
            raise SystemExit("--all COUNT must be > 0")
        for name in types:
            selected[name] = args.all
    if args.log:
        for t, c in args.log:
            if t not in types:
                raise SystemExit(f"Unknown log type: {t}")
            selected[t] = c
    return selected


def _wizard_select(types: dict[str, LogType]) -> dict[str, int]:
    print("SYNTHETIC LOG GENERATOR (educational use only)")
    print("Select log types to generate. Enter numbers separated by commas, or 'all'.")
    entries = list(types.values())
    for i, lt in enumerate(entries, start=1):
        print(f"{i}. {lt.name} - {lt.description}")
    choice = input("Selection: ").strip()
    selected: dict[str, int] = {}
    if choice.lower() == "all":
        count = _prompt_count("Count for ALL types", default=50)
        for lt in entries:
            selected[lt.name] = count
        return selected
    if not choice:
        raise SystemExit("No log types selected.")
    indices = []
    for part in choice.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            indices.append(int(part))
        except ValueError:
            raise SystemExit("Invalid selection. Use numbers separated by commas.")
    for idx in indices:
        if idx < 1 or idx > len(entries):
            raise SystemExit("Selection out of range.")
        lt = entries[idx - 1]
        count = _prompt_count(f"Count for {lt.name}", default=50)
        selected[lt.name] = count
    return selected


def _prompt_count(prompt: str, default: int = 50) -> int:
    raw = input(f"{prompt} [{default}]: ").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise SystemExit("Count must be an integer.")
    if value <= 0:
        raise SystemExit("Count must be > 0.")
    return value


def _write_lines(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as f:
        for line in lines:
            f.write(line)
            f.write("\n")


def _validate_count(path: Path, expected: int, is_csv: bool) -> None:
    with path.open("r", encoding="utf-8") as f:
        lines = f.readlines()
    actual = len(lines)
    if is_csv:
        actual = max(0, actual - 1)
    if actual != expected:
        raise RuntimeError(f"Validation failed for {path}: expected {expected}, got {actual}")


def _generate_one(log_type: LogType, count: int, rnd: random.Random, timeframe_days: int, out_dir: Path) -> GenerationResult:
    lines = log_type.generator(count, rnd, timeframe_days)
    file_name = f"{log_type.name}.{log_type.extension}"
    file_path = out_dir / log_type.name / file_name
    _write_lines(file_path, lines)
    _validate_count(file_path, count, log_type.extension == "csv")
    return GenerationResult(log_type=log_type, count=count, file_path=file_path)


def _write_manifest(out_dir: Path, results: list[GenerationResult], seed: int | None, timeframe_days: int) -> Path:
    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "tool_version": TOOL_VERSION,
        "seed": seed,
        "timeframe_days": timeframe_days,
        "disclaimer": DISCLAIMER,
        "generated": [
            {
                "type": r.log_type.name,
                "count": r.count,
                "filename": str(r.file_path.relative_to(out_dir)),
            }
            for r in results
        ],
    }
    path = out_dir / "MANIFEST.json"
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return path


def _zip_output(out_dir: Path) -> Path:
    zip_path = out_dir.with_suffix(".zip")
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for file_path in out_dir.rglob("*"):
            if file_path.is_file():
                zf.write(file_path, arcname=file_path.relative_to(out_dir))
    return zip_path


def run_list(types: dict[str, LogType]) -> None:
    print("Supported log types:")
    for name in sorted(types):
        lt = types[name]
        print(f"- {lt.name}: {lt.description}")


def run_generate(args: argparse.Namespace, types: dict[str, LogType]) -> None:
    selected = _select_types_from_args(args, types)
    if not selected:
        raise SystemExit("No log types selected. Use --log or --all.")

    out_dir = Path(args.out_dir) if args.out_dir else _default_out_dir()
    out_dir.mkdir(parents=True, exist_ok=True)

    rnd = random.Random(args.seed)
    results: list[GenerationResult] = []

    for name, count in selected.items():
        results.append(_generate_one(types[name], count, rnd, args.timeframe_days, out_dir))

    manifest_path = _write_manifest(out_dir, results, args.seed, args.timeframe_days)
    zip_path = _zip_output(out_dir) if args.zip else None

    print(DISCLAIMER)
    print(f"Output directory: {out_dir}")
    for res in results:
        print(f"- {res.log_type.name}: {res.count} lines -> {res.file_path}")
    print(f"Manifest: {manifest_path}")
    if zip_path:
        print(f"Zip archive: {zip_path}")


def run_wizard(args: argparse.Namespace, types: dict[str, LogType]) -> None:
    selected = _wizard_select(types)
    out_dir = Path(args.out_dir) if args.out_dir else _default_out_dir()
    out_dir.mkdir(parents=True, exist_ok=True)

    rnd = random.Random(args.seed)
    results: list[GenerationResult] = []

    for name, count in selected.items():
        results.append(_generate_one(types[name], count, rnd, args.timeframe_days, out_dir))

    manifest_path = _write_manifest(out_dir, results, args.seed, args.timeframe_days)
    zip_path = _zip_output(out_dir) if args.zip else None

    print(DISCLAIMER)
    print(f"Output directory: {out_dir}")
    for res in results:
        print(f"- {res.log_type.name}: {res.count} lines -> {res.file_path}")
    print(f"Manifest: {manifest_path}")
    if zip_path:
        print(f"Zip archive: {zip_path}")


def build_parser() -> argparse.ArgumentParser:
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument("--out_dir", help="Output directory (default: ./generated_logs)")
    parent.add_argument("--seed", type=int, help="Random seed for reproducible output")
    parent.add_argument("--timeframe_days", type=int, default=30, help="Days back for timestamps (default: 30)")

    parser = argparse.ArgumentParser(
        prog="logsmith",
        description="Synthetic log generator (educational use only)",
        parents=[parent],
    )

    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("list", help="List supported log types", parents=[parent])

    gen = subparsers.add_parser("generate", help="Generate logs", parents=[parent])
    gen.add_argument("--log", action="append", type=_parse_log_arg, help="Log type and count (TYPE=COUNT)")
    gen.add_argument("--all", type=int, help="Generate all log types with the same COUNT")
    gen.add_argument("--zip", action="store_true", help="Zip output directory")

    wiz = subparsers.add_parser("wizard", help="Interactive wizard", parents=[parent])
    wiz.add_argument("--zip", action="store_true", help="Zip output directory")

    return parser


def main(argv: list[str] | None = None) -> None:
    types = get_log_types()
    parser = build_parser()
    args = parser.parse_args(argv)

    if not hasattr(args, 'zip'):
        args.zip = False

    if args.command is None:
        # No args -> wizard
        run_wizard(args, types)
        return

    if args.timeframe_days <= 0:
        raise SystemExit("--timeframe_days must be > 0")

    if args.command == "list":
        run_list(types)
        return
    if args.command == "generate":
        run_generate(args, types)
        return
    if args.command == "wizard":
        run_wizard(args, types)
        return

    raise SystemExit("Unknown command")


if __name__ == "__main__":
    main(sys.argv[1:])







