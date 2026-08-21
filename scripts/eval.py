#!/usr/bin/env python3
"""Run LLM verdicts for Gobbler analysis JSON files."""

from __future__ import annotations

import argparse
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from gobbler.llm.provider import LLMConfig, load_env_file
from gobbler.passes.llm_verdict import (
    DEFAULT_APP_TITLE,
    DEFAULT_ENDPOINT,
    analyze_llm_verdict,
)

ENV_FILE = Path(".env")
API_KEY_ENV = "LLM_KEY"
MODEL_ENV = "OPENROUTER_MODEL"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run LLM verdicts for analysis JSON files.")
    parser.add_argument("analysis_output_dir", type=Path)
    parser.add_argument("-o", "--out", required=True, type=Path)
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=90.0)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    analysis_files = sorted(
        path
        for path in args.analysis_output_dir.iterdir()
        if path.is_file() and path.suffix == ".json" and not path.name.endswith(".verdict.json")
    )
    args.out.mkdir(parents=True, exist_ok=True)
    if not analysis_files:
        print(f"no analysis JSON files found in {args.analysis_output_dir}", file=sys.stderr)
        return 1
    model = required_env(MODEL_ENV)
    api_key = required_env(API_KEY_ENV)

    config = LLMConfig(
        model=model,
        provider_name="openrouter",
        api_key=api_key,
        api_key_env=API_KEY_ENV,
        env_file=ENV_FILE,
        endpoint=DEFAULT_ENDPOINT,
        timeout=args.timeout,
        temperature=0.1,
        max_tokens=1400,
        app_name=DEFAULT_APP_TITLE,
        response_format="json_object",
    )

    failed = 0
    jobs = max(1, args.jobs)
    print(f"verdict batch start samples={len(analysis_files)} jobs={jobs} model={model} out={args.out}", flush=True)
    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=jobs) as executor:
        futures = {
            executor.submit(eval_one, path, args.out, config): (index, path)
            for index, path in enumerate(analysis_files, 1)
        }
        for future in as_completed(futures):
            index, path = futures[future]
            try:
                result = future.result()
            except Exception as exc:
                failed += 1
                out_path = write_error_verdict(path, args.out, model, str(exc))
                print(f"verdict failed [{index}/{len(analysis_files)}] {path.name}: {exc}", flush=True)
                print(f"verdict error-json [{index}/{len(analysis_files)}] {out_path}", flush=True)
                continue
            cost = result.get("cost")
            cost_text = f" cost=${float(cost):.6f}" if isinstance(cost, (int, float)) else ""
            token_text = f" tokens={result['tokens']}" if result.get("tokens") is not None else ""
            print(
                f"verdict ok [{index}/{len(analysis_files)}] {result['sample']} "
                f"elapsed={result['elapsed']}s verdict={result['verdict']}{cost_text}{token_text}",
                flush=True,
            )

    elapsed = time.monotonic() - started
    print(f"verdict batch done total={len(analysis_files)} failed={failed} elapsed={elapsed:.3f}s out={args.out}")
    return 1 if failed else 0


def required_env(name: str) -> str:
    value = load_env_file(ENV_FILE, name)
    if not value:
        raise SystemExit(f"{name} is required in {ENV_FILE}")
    return value


def eval_one(path: Path, out_dir: Path, config: LLMConfig) -> dict[str, object]:
    print(f"verdict start {path.name}", flush=True)
    started = time.monotonic()
    report = json.loads(path.read_text(encoding="utf-8"))
    result = analyze_llm_verdict(report, path, config)
    out_path = out_dir / f"{path.stem}.verdict.json"
    out_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    usage = result.get("usage") if isinstance(result.get("usage"), dict) else {}
    return {
        "sample": path.name,
        "status": "ok",
        "out": str(out_path),
        "verdict": result.get("verdict", "unknown"),
        "cost": result.get("cost"),
        "tokens": usage.get("total_tokens"),
        "elapsed": round(time.monotonic() - started, 3),
    }


def write_error_verdict(path: Path, out_dir: Path, model: str, error: str) -> Path:
    out_path = out_dir / f"{path.stem}.verdict.json"
    result = {
        "verdict": "unknown",
        "behavioral_summary": "",
        "reasoning": [],
        "key_behaviors": [],
        "indicators": {
            "urls": [],
            "domains": [],
            "ips": [],
            "paths": [],
            "commands": [],
            "mutexes": [],
            "embedded_artifacts": [],
            "other": [],
        },
        "caveats": [error],
        "model": model,
        "provider": "openrouter",
        "error": error,
    }
    out_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return out_path


if __name__ == "__main__":
    raise SystemExit(main())
