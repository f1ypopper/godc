import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from importlib import resources
import json
import subprocess
import sys
import time
from pathlib import Path

from gobbler.output.corpus_index import build_feature_index, write_feature_index
from gobbler.output.diff import diff_analysis_files
from gobbler.pipeline import analyze_binary, write_analysis_with_options


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze Go binaries.")
    subparsers = parser.add_subparsers(dest="command")

    analyze = subparsers.add_parser("analyze", help="Analyze one binary")
    analyze.add_argument("binary", type=Path)
    analyze.add_argument("--out", type=Path, default=Path("output"))
    analyze.add_argument("--entry", default="main.main")
    analyze.add_argument("--goresym", type=Path, default=Path("GoReSym"))
    analyze.add_argument("--compare", type=Path, help="Existing analysis JSON to diff against")
    analyze.add_argument("--index", action="store_true", help="Refresh feature_index.* in the output directory")
    analyze.add_argument("--output-profile", choices=("full", "evaluator"), default="full")
    analyze.add_argument("--compact-json", action="store_true", help="Write compact JSON without indentation")

    batch = subparsers.add_parser("batch", help="Analyze binaries in a directory")
    batch.add_argument("directory", type=Path, default=Path("data"))
    batch.add_argument("--glob", default="*.exe")
    batch.add_argument("--out", type=Path, default=Path("output"))
    batch.add_argument("--entry", default="main.main")
    batch.add_argument("--goresym", type=Path, default=Path("GoReSym"))
    batch.add_argument("--no-index", action="store_true", help="Do not refresh feature_index.* after batch analysis")
    batch.add_argument("--limit", type=int, help="Analyze at most this many matching binaries")
    batch.add_argument("--timeout", type=int, help="Per-binary timeout in seconds")
    batch.add_argument("--skip-existing", action="store_true", help="Skip binaries that already have JSON output")
    batch.add_argument("--jobs", type=int, default=1, help="Number of binaries to analyze concurrently")
    batch.add_argument("--output-profile", choices=("full", "evaluator"), default="full")
    batch.add_argument("--compact-json", action="store_true", help="Write compact JSON without indentation")

    diff = subparsers.add_parser("diff", help="Compare two analysis JSON files")
    diff.add_argument("before", type=Path)
    diff.add_argument("after", type=Path)
    diff.add_argument("--out", type=Path, help="Write diff text to this path")

    corpus = subparsers.add_parser("corpus", help="Inspect a corpus feature index")
    corpus_subparsers = corpus.add_subparsers(dest="corpus_command")
    corpus_list = corpus_subparsers.add_parser("list", help="List indexed feature names")
    corpus_list.add_argument("--out", type=Path, default=Path("output"))
    corpus_find = corpus_subparsers.add_parser("find", help="Find samples with a feature")
    corpus_find.add_argument("feature")
    corpus_find.add_argument("--out", type=Path, default=Path("output"))

    viewer = subparsers.add_parser("viewer", help="Write the standalone single-binary HTML viewer")
    viewer.add_argument("--out", type=Path, default=Path("output/gobbler_viewer.html"))

    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.command == "analyze":
        result = analyze_binary(args.binary, args.goresym, args.entry)
        json_path, _text_path = write_analysis_with_options(
            result,
            args.out,
            args.binary.stem,
            output_profile=args.output_profile,
            compact_json=args.compact_json,
        )
        if args.compare:
            diff_text = diff_analysis_files(args.compare, json_path)
            diff_path = args.out / f"{args.binary.stem}.diff.txt"
            diff_path.write_text(diff_text)
            print(diff_text, end="")
        if args.index:
            write_feature_index(args.out)
        return 0

    if args.command == "batch":
        processed = 0
        failed = 0
        skipped = 0
        records = []
        binaries = sorted(args.directory.glob(args.glob))
        if args.limit is not None:
            binaries = binaries[: args.limit]
        jobs = max(1, args.jobs)
        if jobs == 1:
            for binary in binaries:
                record = analyze_batch_binary(args, binary)
                records.append(record)
                print_batch_record(binary, record)
        else:
            with ThreadPoolExecutor(max_workers=jobs) as executor:
                futures = {
                    executor.submit(analyze_batch_binary, args, binary): binary
                    for binary in binaries
                }
                for future in as_completed(futures):
                    binary = futures[future]
                    record = future.result()
                    records.append(record)
                    print_batch_record(binary, record)
        for record in records:
            if record["status"] == "processed":
                processed += 1
            elif record["status"] == "skipped_existing":
                skipped += 1
            else:
                failed += 1
        args.out.mkdir(parents=True, exist_ok=True)
        write_batch_report(args.out, records, processed, failed, skipped)
        print(f"processed={processed} failed={failed} skipped={skipped}", flush=True)
        if processed and not args.no_index:
            write_feature_index(args.out)
        return 1 if failed else 0

    if args.command == "diff":
        diff_text = diff_analysis_files(args.before, args.after)
        if args.out:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(diff_text)
        print(diff_text, end="")
        return 0

    if args.command == "corpus":
        if args.corpus_command is None:
            print("missing corpus subcommand: list or find")
            return 2
        index = load_feature_index(args.out)
        if args.corpus_command == "list":
            for feature in sorted((index.get("features") or {}).keys()):
                print(feature)
            return 0
        if args.corpus_command == "find":
            samples = (index.get("features") or {}).get(args.feature, [])
            for sample in samples:
                functions = ", ".join(sample.get("functions") or [])
                details = "; ".join(sample.get("details") or [])
                suffix = ""
                if functions:
                    suffix += f" functions=[{functions}]"
                if details:
                    suffix += f" details=[{details}]"
                print(f"{sample['sample']} confidence={sample.get('confidence', 'medium')}{suffix}")
            return 0
        return 2

    if args.command == "viewer":
        write_viewer(args.out)
        print(args.out)
        return 0

    # Backward-compatible default: analyze every .exe under data/.
    for binary in sorted(Path("data").glob("*.exe")):
        try:
            result = analyze_binary(binary, Path("GoReSym"), "main.main")
            write_analysis_with_options(result, Path("output"), binary.stem)
        except Exception as exc:
            print(f"failed {binary}: {exc}")
    write_feature_index(Path("output"))
    return 0


def load_feature_index(output_dir: Path) -> dict:
    path = output_dir / "feature_index.json"
    if path.exists():
        return json.loads(path.read_text())
    return build_feature_index(output_dir)


def write_viewer(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    html = resources.files("gobbler.ui").joinpath("single_binary_viewer.html").read_text()
    path.write_text(html)


def run_analyze_subprocess(
    binary: Path,
    output_dir: Path,
    goresym: Path,
    entry: str,
    timeout: int | None,
    output_profile: str,
    compact_json: bool,
) -> None:
    command = [
        sys.executable,
        "-m",
        "gobbler.cli",
        "analyze",
        str(binary),
        "--out",
        str(output_dir),
        "--goresym",
        str(goresym),
        "--entry",
        entry,
        "--output-profile",
        output_profile,
    ]
    if compact_json:
        command.append("--compact-json")
    proc = subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False)
    if proc.returncode != 0:
        detail = short_error(proc.stderr.strip() or proc.stdout.strip() or f"exit={proc.returncode}")
        raise RuntimeError(detail)


def analyze_batch_binary(args: argparse.Namespace, binary: Path) -> dict:
    if args.skip_existing and (args.out / f"{binary.stem}.json").exists():
        return {"sample": binary.name, "status": "skipped_existing"}
    print(f"analysis start sample={binary.name} path={binary}", flush=True)
    started = time.monotonic()
    try:
        if args.timeout or args.jobs > 1:
            run_analyze_subprocess(
                binary,
                args.out,
                args.goresym,
                args.entry,
                args.timeout,
                args.output_profile,
                args.compact_json,
            )
        else:
            result = analyze_binary(binary, args.goresym, args.entry)
            write_analysis_with_options(
                result,
                args.out,
                binary.stem,
                output_profile=args.output_profile,
                compact_json=args.compact_json,
            )
        return {
            "sample": binary.name,
            "status": "processed",
            "duration_seconds": round(time.monotonic() - started, 3),
        }
    except subprocess.TimeoutExpired:
        return {
            "sample": binary.name,
            "status": "timeout",
            "duration_seconds": round(time.monotonic() - started, 3),
            "error": f"timeout after {args.timeout}s",
        }
    except Exception as exc:
        return {
            "sample": binary.name,
            "status": "failed",
            "duration_seconds": round(time.monotonic() - started, 3),
            "error": short_error(str(exc)),
        }


def print_batch_record(binary: Path, record: dict) -> None:
    status = record["status"]
    elapsed = record.get("duration_seconds")
    elapsed_text = f" elapsed={elapsed:.3f}s" if isinstance(elapsed, (int, float)) else ""
    if status == "processed":
        print(f"analysis done sample={binary.name} status=processed{elapsed_text} path={binary}", flush=True)
    elif status == "skipped_existing":
        print(f"analysis skipped sample={binary.name} status=skipped_existing path={binary}", flush=True)
    elif status == "timeout":
        print(f"analysis timeout sample={binary.name} status=timeout{elapsed_text} error={record.get('error', '')} path={binary}", flush=True)
    else:
        print(f"analysis failed sample={binary.name} status=failed{elapsed_text} error={record.get('error', '')} path={binary}", flush=True)


def write_batch_report(
    output_dir: Path,
    records: list[dict],
    processed: int,
    failed: int,
    skipped: int,
) -> None:
    report = {
        "processed": processed,
        "failed": failed,
        "skipped": skipped,
        "records": records,
    }
    (output_dir / "batch_report.json").write_text(json.dumps(report, indent=2))
    lines = [
        "Batch report",
        f"  processed={processed} failed={failed} skipped={skipped}",
    ]
    for record in records:
        line = f"  - {record['sample']} status={record['status']}"
        if record.get("duration_seconds") is not None:
            line += f" duration={record['duration_seconds']}s"
        if record.get("error"):
            line += f" error={record['error']}"
        lines.append(line)
    (output_dir / "batch_report.txt").write_text("\n".join(lines) + "\n")


def short_error(message: str, limit: int = 500) -> str:
    lines = [line.strip() for line in message.splitlines() if line.strip()]
    if not lines:
        return ""
    useful = []
    for line in lines:
        if line.startswith(("Traceback ", "File ", "^")):
            continue
        useful.append(line)
    text = useful[-1] if useful else lines[-1]
    if len(text) > limit:
        return text[: limit - 3] + "..."
    return text


if __name__ == "__main__":
    raise SystemExit(main())
