#!/usr/bin/env python3
"""Analyze every direct file in a directory with Gobbler."""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from gobbler.pipeline import analyze_binary, write_analysis_with_options


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze every direct file in a directory.")
    parser.add_argument("samples_dir", type=Path)
    parser.add_argument("-o", "--out", required=True, type=Path)
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--goresym", type=Path, default=Path("GoReSym"))
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.worker:
        return run_worker(args.samples_dir, args.out, args.goresym)

    samples = sorted(path for path in args.samples_dir.iterdir() if path.is_file())
    args.out.mkdir(parents=True, exist_ok=True)
    if not samples:
        print(f"no files found in {args.samples_dir}", file=sys.stderr)
        return 1

    failed = 0
    jobs = max(1, args.jobs)
    print(f"analysis batch start samples={len(samples)} jobs={jobs} out={args.out}", flush=True)
    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=jobs) as executor:
        futures = {
            executor.submit(analyze_one, sample, args.out, args.goresym, args.timeout): (index, sample)
            for index, sample in enumerate(samples, 1)
        }
        for future in as_completed(futures):
            index, sample = futures[future]
            try:
                result = future.result()
            except subprocess.TimeoutExpired:
                failed += 1
                print(
                    f"analysis timeout [{index}/{len(samples)}] {sample.name} "
                    f"timeout={args.timeout}s",
                    flush=True,
                )
                continue
            except Exception as exc:
                failed += 1
                print(f"analysis failed [{index}/{len(samples)}] {sample.name}: {exc}", flush=True)
                continue
            print(
                f"analysis ok [{index}/{len(samples)}] {result['sample']} "
                f"elapsed={result['elapsed']}s json={result['json']}",
                flush=True,
            )

    elapsed = time.monotonic() - started
    print(f"analysis batch done total={len(samples)} failed={failed} elapsed={elapsed:.3f}s out={args.out}")
    return 1 if failed else 0


def analyze_one(sample: Path, out_dir: Path, goresym: Path, timeout: float) -> dict[str, object]:
    print(f"analysis start {sample.name}", flush=True)
    started = time.monotonic()
    command = [
        sys.executable,
        str(Path(__file__).resolve()),
        str(sample),
        "-o",
        str(out_dir),
        "--goresym",
        str(goresym),
        "--worker",
    ]
    proc = subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False)
    if proc.returncode != 0:
        raise RuntimeError(short_error(proc.stderr or proc.stdout or f"exit={proc.returncode}"))
    return {
        "sample": sample.name,
        "status": "ok",
        "json": str(out_dir / f"{sample.stem}.json"),
        "text": str(out_dir / f"{sample.stem}.txt"),
        "elapsed": round(time.monotonic() - started, 3),
    }


def run_worker(sample: Path, out_dir: Path, goresym: Path) -> int:
    result = analyze_binary(sample, goresym)
    write_analysis_with_options(
        result,
        out_dir,
        sample.stem,
        output_profile="evaluator",
        compact_json=False,
    )
    return 0


def short_error(message: str, limit: int = 500) -> str:
    lines = [line.strip() for line in message.splitlines() if line.strip()]
    text = lines[-1] if lines else ""
    if len(text) > limit:
        return text[: limit - 3] + "..."
    return text


if __name__ == "__main__":
    raise SystemExit(main())
