#!/usr/bin/env python3
from __future__ import annotations

import argparse
import concurrent.futures
import csv
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


DEFAULT_CLEAN_DIRS = [Path("corpus/clean/synthetic"), Path("corpus/clean/gomod")]
DEFAULT_DIRTY_DIRS = [Path("data")]
DEFAULT_OUT = Path("eval_runs")
DEFAULT_MODEL = "google/gemini-2.5-flash"
DEFAULT_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a labeled Gobbler/OpenRouter eval.")
    parser.add_argument("--clean-dir", type=Path, action="append", default=[], help="Directory of known-clean .exe files. Can be repeated.")
    parser.add_argument("--dirty-dir", type=Path, action="append", default=[], help="Directory of known-dirty or malware-candidate .exe files. Can be repeated.")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--run-name", help="Output run name. Default: timestamped run directory.")
    parser.add_argument("--glob", default="*.exe")
    parser.add_argument("--analysis-timeout", type=int, default=180)
    parser.add_argument("--analysis-jobs", type=int, default=4)
    parser.add_argument("--analysis-output-profile", choices=("full", "evaluator"), default="evaluator")
    parser.add_argument("--analysis-pretty-json", action="store_true", help="Write indented analysis JSON instead of compact JSON.")
    parser.add_argument("--verdict-timeout", type=float, default=90.0)
    parser.add_argument("--verdict-jobs", type=int, default=2)
    parser.add_argument("--model", default=DEFAULT_MODEL, help=f"Single OpenRouter model slug. Default: {DEFAULT_MODEL}")
    parser.add_argument("--models", action="append", default=[], help="Comma-separated OpenRouter model slugs. Can be repeated.")
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
    parser.add_argument("--env-file", type=Path, default=Path(".env"), help="Optional .env file used for OPENROUTER_API_KEY if not already set.")
    parser.add_argument("--api-key-env", default="OPENROUTER_API_KEY")
    parser.add_argument("--http-referer", default=os.environ.get("OPENROUTER_HTTP_REFERER", ""))
    parser.add_argument("--app-title", default=os.environ.get("OPENROUTER_APP_TITLE", "Gobbler Eval"))
    parser.add_argument("--temperature", type=float, default=0.1)
    parser.add_argument("--max-tokens", type=int, default=1400)
    parser.add_argument("--no-json-mode", action="store_true")
    parser.add_argument("--skip-analysis", action="store_true", help="Use existing Gobbler JSON files in the run directory.")
    parser.add_argument("--existing-analysis-only", action="store_true", help="With --skip-analysis, evaluate only Gobbler JSON files already present in the run directory.")
    parser.add_argument("--skip-verdicts", action="store_true", help="Only run Gobbler analysis and dataset accounting.")
    parser.add_argument("--report-existing-verdicts", action="store_true", help="Compute metrics from existing verdict JSON files without calling the LLM.")
    parser.add_argument("--skip-existing-analysis", action="store_true", help="Do not re-analyze samples with existing Gobbler JSON output.")
    parser.add_argument("--skip-existing-verdicts", action="store_true", help="Do not re-query the LLM for existing verdict JSON files.")
    parser.add_argument("--limit-per-label", type=int, help="Analyze/evaluate at most this many samples per label.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    run_dir = args.out / (args.run_name or time.strftime("eval_%Y%m%d_%H%M%S"))
    analysis_root = run_dir / "analysis"
    verdict_root = run_dir / "verdicts"
    models = parse_models(args)
    run_dir.mkdir(parents=True, exist_ok=True)

    clean_dirs = args.clean_dir or DEFAULT_CLEAN_DIRS
    dirty_dirs = args.dirty_dir or DEFAULT_DIRTY_DIRS

    if args.skip_analysis and args.existing_analysis_only:
        dataset = build_dataset_from_existing_analysis(analysis_root, args.limit_per_label)
    else:
        dataset = build_dataset(clean_dirs, dirty_dirs, args.glob, args.limit_per_label)
    write_json(run_dir / "dataset.json", dataset)

    analysis_reports = []
    if not args.skip_analysis:
        analysis_reports = run_analysis(args, dataset, analysis_root)
        write_json(run_dir / "analysis_reports.json", analysis_reports)

    records = collect_analysis_records(dataset, analysis_root)
    if args.skip_verdicts:
        report = build_analysis_only_report(dataset, records, analysis_reports, run_dir)
        write_outputs(run_dir, report, [])
        print(run_dir)
        return 0

    if args.report_existing_verdicts:
        verdict_records = []
        for model in models:
            verdict_records.extend(collect_existing_verdicts(records, verdict_root, model))
        report = build_verdict_report(dataset, records, verdict_records, analysis_reports, run_dir, models)
        write_outputs(run_dir, report, verdict_records)
        print(run_dir)
        return 0

    load_env_file(args.env_file, args.api_key_env)
    if not os.environ.get(args.api_key_env):
        print(f"{args.api_key_env} is required for verdict eval. Re-run with --skip-verdicts for analysis-only.", file=sys.stderr)
        return 2

    verdict_records = []
    for model in models:
        verdict_records.extend(run_verdicts(args, records, verdict_root, model))
    report = build_verdict_report(dataset, records, verdict_records, analysis_reports, run_dir, models)
    write_outputs(run_dir, report, verdict_records)
    print(run_dir)
    failed = sum((metrics.get("failed_verdicts") or 0) for metrics in (report.get("metrics_by_model") or {}).values())
    return 0 if failed == 0 else 1


def parse_models(args: argparse.Namespace) -> list[str]:
    values = args.models or [args.model]
    models = []
    seen = set()
    for value in values:
        for model in str(value).split(","):
            model = model.strip()
            if model and model not in seen:
                seen.add(model)
                models.append(model)
    return models or [DEFAULT_MODEL]


def build_dataset(clean_dirs: list[Path], dirty_dirs: list[Path], pattern: str, limit_per_label: int | None) -> list[dict[str, Any]]:
    dataset: list[dict[str, Any]] = []
    for label, dirs in (("clean", clean_dirs), ("dirty", dirty_dirs)):
        items: list[dict[str, Any]] = []
        for directory in dirs:
            for path in sorted(directory.glob(pattern)):
                if path.is_file():
                    items.append({"label": label, "path": str(path), "name": path.name, "source_dir": str(directory)})
        if limit_per_label is not None:
            items = items[:limit_per_label]
        dataset.extend(items)
    return dataset


def build_dataset_from_existing_analysis(analysis_root: Path, limit_per_label: int | None) -> list[dict[str, Any]]:
    dataset: list[dict[str, Any]] = []
    for label in ("clean", "dirty"):
        items = []
        for path in sorted((analysis_root / label).glob("*/*.json")):
            if path.name in {"batch_report.json", "feature_index.json"} or not path.stat().st_size:
                continue
            items.append(
                {
                    "label": label,
                    "path": str(path),
                    "name": path.stem + ".exe",
                    "source_dir": analysis_source_for_existing(analysis_root, label, path),
                    "existing_analysis_json": str(path),
                }
            )
        if limit_per_label is not None:
            items = items[:limit_per_label]
        dataset.extend(items)
    return dataset


def run_analysis(args: argparse.Namespace, dataset: list[dict[str, Any]], analysis_root: Path) -> list[dict[str, Any]]:
    reports = []
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for item in dataset:
        grouped.setdefault((item["label"], item["source_dir"]), []).append(item)

    for (label, source_dir), items in sorted(grouped.items()):
        output_dir = analysis_dir_for(analysis_root, label, Path(source_dir))
        command = [
            sys.executable,
            "-m",
            "gobbler.cli",
            "batch",
            source_dir,
            "--glob",
            args.glob,
            "--out",
            str(output_dir),
            "--timeout",
            str(args.analysis_timeout),
            "--jobs",
            str(args.analysis_jobs),
            "--output-profile",
            args.analysis_output_profile,
        ]
        if not args.analysis_pretty_json:
            command.append("--compact-json")
        if args.skip_existing_analysis:
            command.append("--skip-existing")
        if args.limit_per_label is not None:
            command.extend(["--limit", str(len(items))])
        print(
            f"analysis group start label={label} source={source_dir} samples={len(items)} "
            f"jobs={args.analysis_jobs} timeout={args.analysis_timeout}s",
            flush=True,
        )
        print("analysis command " + " ".join(command), flush=True)
        started = time.monotonic()
        proc = run_streaming_command(command)
        elapsed = round(time.monotonic() - started, 3)
        print(
            f"analysis group done label={label} source={source_dir} "
            f"returncode={proc.returncode} elapsed={elapsed:.3f}s",
            flush=True,
        )
        report = {
            "label": label,
            "source_dir": source_dir,
            "output_dir": str(output_dir),
            "returncode": proc.returncode,
            "duration_seconds": elapsed,
            "stdout": tail(proc.stdout),
            "stderr": tail(proc.stderr),
        }
        batch_report = output_dir / "batch_report.json"
        if batch_report.exists():
            try:
                report["batch_report"] = json.loads(batch_report.read_text())
            except json.JSONDecodeError as exc:
                report["batch_report_error"] = str(exc)
        reports.append(report)
    return reports


def run_streaming_command(command: list[str]) -> subprocess.CompletedProcess[str]:
    proc = subprocess.Popen(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=1,
    )
    lines: list[str] = []
    assert proc.stdout is not None
    for line in proc.stdout:
        print(line, end="", flush=True)
        lines.append(line)
    returncode = proc.wait()
    return subprocess.CompletedProcess(command, returncode, "".join(lines), "")


def collect_analysis_records(dataset: list[dict[str, Any]], analysis_root: Path) -> list[dict[str, Any]]:
    records = []
    for item in dataset:
        if item.get("existing_analysis_json"):
            json_path = Path(item["existing_analysis_json"])
        else:
            output_dir = analysis_dir_for(analysis_root, item["label"], Path(item["source_dir"]))
            json_path = output_dir / f"{Path(item['path']).stem}.json"
        records.append(
            {
                **item,
                "analysis_json": str(json_path),
                "analysis_status": "ok" if json_path.exists() and json_path.stat().st_size else "missing",
            }
        )
    return records


def run_verdicts(args: argparse.Namespace, records: list[dict[str, Any]], verdict_root: Path, model: str) -> list[dict[str, Any]]:
    model_root = verdict_root_for_model(verdict_root, model)
    model_root.mkdir(parents=True, exist_ok=True)
    eligible = [record for record in records if record["analysis_status"] == "ok"]
    results: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.verdict_jobs)) as executor:
        futures = {
            executor.submit(run_one_verdict, args, record, model_root, model, index, len(eligible)): record
            for index, record in enumerate(eligible, start=1)
        }
        completed = 0
        for future in concurrent.futures.as_completed(futures):
            record = futures[future]
            try:
                result = future.result()
            except Exception as exc:
                result = {**record, "model": model, "status": "failed", "verdict_json": None, "error": short_error(str(exc))}
            results.append(result)
            completed += 1
            print_verdict_progress(result, model, completed, len(eligible))
    missing = [
        {**record, "model": model, "status": "missing_analysis", "verdict_json": None}
        for record in records
        if record["analysis_status"] != "ok"
    ]
    return sorted(results + missing, key=lambda item: (item["label"], item["name"]))


def print_verdict_progress(result: dict[str, Any], model: str, completed: int | None = None, total: int | None = None) -> None:
    parts = [
        "verdict",
        str(result.get("status")),
        progress_text(completed, total),
        f"model={safe_model_name(model)}",
        str(result.get("name")),
    ]
    elapsed = result.get("duration_seconds")
    if isinstance(elapsed, (int, float)):
        parts.append(f"elapsed={elapsed:.3f}s")
    if result.get("status") == "ok":
        cost = result.get("cost")
        if isinstance(cost, (int, float)):
            parts.append(f"cost=${cost:.6f}")
        total_tokens = int_or_zero(result.get("total_tokens"))
        if total_tokens:
            parts.append(f"tokens={total_tokens}")
        verdict = result.get("verdict")
        if verdict:
            parts.append(f"verdict={verdict}")
    elif result.get("error"):
        parts.append(f"error={short_error(str(result.get('error')), 160)}")
    print(" ".join(part for part in parts if part), flush=True)


def collect_existing_verdicts(records: list[dict[str, Any]], verdict_root: Path, model: str) -> list[dict[str, Any]]:
    model_root = verdict_root_for_model(verdict_root, model)
    results = []
    for record in records:
        if record["analysis_status"] != "ok":
            results.append({**record, "model": model, "status": "missing_analysis", "verdict_json": None})
            continue
        out_path = model_root / record["label"] / f"{Path(record['analysis_json']).stem}.verdict.json"
        if not out_path.exists() or not out_path.stat().st_size:
            results.append({**record, "model": model, "status": "missing_verdict", "verdict_json": str(out_path)})
            continue
        try:
            verdict = json.loads(out_path.read_text())
        except json.JSONDecodeError as exc:
            results.append({**record, "model": model, "status": "failed", "verdict_json": str(out_path), "error": str(exc)})
            continue
        results.append({**record, "model": model, "status": "ok", "verdict_json": str(out_path), **flatten_verdict(verdict)})
    return sorted(results, key=lambda item: (item["label"], item["name"]))


def run_one_verdict(
    args: argparse.Namespace,
    record: dict[str, Any],
    model_root: Path,
    model: str,
    index: int | None = None,
    total: int | None = None,
) -> dict[str, Any]:
    label_dir = model_root / record["label"]
    label_dir.mkdir(parents=True, exist_ok=True)
    out_path = label_dir / f"{Path(record['analysis_json']).stem}.verdict.json"
    if args.skip_existing_verdicts and out_path.exists() and out_path.stat().st_size:
        started = time.monotonic()
        print(
            f"verdict skipped-existing {progress_text(index, total)} model={safe_model_name(model)} {record['name']}",
            flush=True,
        )
        try:
            verdict = json.loads(out_path.read_text())
        except json.JSONDecodeError as exc:
            return {**record, "model": model, "status": "failed", "verdict_json": str(out_path), "duration_seconds": round(time.monotonic() - started, 3), "error": str(exc)}
        return {**record, "model": model, "status": "ok", "verdict_json": str(out_path), "duration_seconds": round(time.monotonic() - started, 3), **flatten_verdict(verdict)}

    command = [
        sys.executable,
        "scripts/llm_verdict.py",
        record["analysis_json"],
        "--out",
        str(out_path),
        "--model",
        model,
        "--endpoint",
        args.endpoint,
        "--env-file",
        str(args.env_file),
        "--api-key-env",
        args.api_key_env,
        "--temperature",
        str(args.temperature),
        "--max-tokens",
        str(args.max_tokens),
        "--timeout",
        str(args.verdict_timeout),
    ]
    if args.http_referer:
        command.extend(["--http-referer", args.http_referer])
    if args.app_title:
        command.extend(["--app-title", args.app_title])
    if args.no_json_mode:
        command.append("--no-json-mode")
    print(
        f"verdict start {progress_text(index, total)} model={safe_model_name(model)} "
        f"{record['name']} timeout={args.verdict_timeout}s",
        flush=True,
    )
    started = time.monotonic()
    try:
        proc = subprocess.run(command, text=True, capture_output=True, timeout=args.verdict_timeout + 10, check=False)
    except subprocess.TimeoutExpired:
        return {**record, "model": model, "status": "failed", "verdict_json": str(out_path), "duration_seconds": round(time.monotonic() - started, 3), "error": f"timeout after {args.verdict_timeout}s"}
    elapsed = round(time.monotonic() - started, 3)
    if proc.returncode != 0:
        return {**record, "model": model, "status": "failed", "verdict_json": str(out_path), "duration_seconds": elapsed, "error": short_error(proc.stderr or proc.stdout)}
    try:
        verdict = json.loads(out_path.read_text())
    except Exception as exc:
        return {**record, "model": model, "status": "failed", "verdict_json": str(out_path), "duration_seconds": elapsed, "error": str(exc)}
    return {**record, "model": model, "status": "ok", "verdict_json": str(out_path), "duration_seconds": elapsed, **flatten_verdict(verdict)}


def flatten_verdict(verdict: dict[str, Any]) -> dict[str, Any]:
    usage = verdict.get("usage") if isinstance(verdict.get("usage"), dict) else {}
    return {
        "verdict": verdict.get("verdict", "unknown"),
        "behavioral_summary": verdict.get("behavioral_summary", ""),
        "reasoning": verdict.get("reasoning", []),
        "key_behaviors": verdict.get("key_behaviors", []),
        "usage": usage,
        "cost": numeric_cost(verdict),
        "prompt_tokens": int_or_zero(usage.get("prompt_tokens")),
        "completion_tokens": int_or_zero(usage.get("completion_tokens")),
        "total_tokens": int_or_zero(usage.get("total_tokens")),
        "indicator_counts": {
            key: len(value) if isinstance(value, list) else 0
            for key, value in (verdict.get("indicators") or {}).items()
        },
    }


def build_analysis_only_report(
    dataset: list[dict[str, Any]],
    records: list[dict[str, Any]],
    analysis_reports: list[dict[str, Any]],
    run_dir: Path,
) -> dict[str, Any]:
    by_label = summarize_by_label(dataset, records)
    return {
        "run_dir": str(run_dir),
        "mode": "analysis_only",
        "dataset": {"total": len(dataset), "by_label": by_label},
        "analysis_reports": compact_analysis_reports(analysis_reports),
    }


def build_verdict_report(
    dataset: list[dict[str, Any]],
    analysis_records: list[dict[str, Any]],
    verdict_records: list[dict[str, Any]],
    analysis_reports: list[dict[str, Any]],
    run_dir: Path,
    models: list[str],
) -> dict[str, Any]:
    metrics_by_model = {
        model: compute_metrics([record for record in verdict_records if record.get("model") == model])
        for model in models
    }
    metrics = metrics_by_model.get(models[0], compute_metrics(verdict_records)) if models else compute_metrics(verdict_records)
    return {
        "run_dir": str(run_dir),
        "mode": "verdict_eval",
        "models": models,
        "dataset": {"total": len(dataset), "by_label": summarize_by_label(dataset, analysis_records)},
        "metrics": metrics,
        "metrics_by_model": metrics_by_model,
        "analysis_reports": compact_analysis_reports(analysis_reports),
    }


def compute_metrics(records: list[dict[str, Any]]) -> dict[str, Any]:
    tp = tn = fp = fn = unknown_clean = unknown_dirty = failed = missing_analysis = missing_verdict = 0
    verdict_counts: dict[str, int] = {}
    cost = 0.0
    cost_count = 0
    prompt_tokens = 0
    completion_tokens = 0
    total_tokens = 0
    for record in records:
        if record.get("status") == "missing_analysis":
            missing_analysis += 1
            continue
        if record.get("status") == "missing_verdict":
            missing_verdict += 1
            continue
        if record.get("status") != "ok":
            failed += 1
            continue
        label = record["label"]
        verdict = str(record.get("verdict", "unknown")).lower()
        verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
        record_cost = record.get("cost")
        if isinstance(record_cost, (int, float)):
            cost += float(record_cost)
            cost_count += 1
        prompt_tokens += int_or_zero(record.get("prompt_tokens"))
        completion_tokens += int_or_zero(record.get("completion_tokens"))
        total_tokens += int_or_zero(record.get("total_tokens"))
        predicted_dirty = verdict in {"dirty", "suspicious"}
        if verdict == "unknown":
            if label == "clean":
                unknown_clean += 1
            else:
                unknown_dirty += 1
        elif label == "dirty" and predicted_dirty:
            tp += 1
        elif label == "dirty":
            fn += 1
        elif label == "clean" and predicted_dirty:
            fp += 1
        else:
            tn += 1
    evaluated = tp + tn + fp + fn + unknown_clean + unknown_dirty
    decisive = tp + tn + fp + fn
    return {
        "true_positive_dirty": tp,
        "true_negative_clean": tn,
        "false_positive_clean_as_dirty": fp,
        "false_negative_dirty_as_clean": fn,
        "unknown_clean": unknown_clean,
        "unknown_dirty": unknown_dirty,
        "missing_analysis": missing_analysis,
        "missing_verdicts": missing_verdict,
        "failed_verdicts": failed,
        "evaluated": evaluated,
        "decisive": decisive,
        "accuracy_decisive": round((tp + tn) / decisive, 4) if decisive else None,
        "dirty_recall_decisive": round(tp / (tp + fn), 4) if (tp + fn) else None,
        "clean_specificity_decisive": round(tn / (tn + fp), 4) if (tn + fp) else None,
        "cost_total_usd": round(cost, 8),
        "cost_count": cost_count,
        "cost_average_usd": round(cost / cost_count, 8) if cost_count else None,
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": total_tokens,
        "verdict_counts": dict(sorted(verdict_counts.items())),
    }


def summarize_by_label(dataset: list[dict[str, Any]], records: list[dict[str, Any]]) -> dict[str, Any]:
    summary: dict[str, dict[str, int]] = {}
    for item in dataset:
        summary.setdefault(item["label"], {"samples": 0, "analysis_ok": 0, "analysis_missing": 0})
        summary[item["label"]]["samples"] += 1
    for record in records:
        label = record["label"]
        summary.setdefault(label, {"samples": 0, "analysis_ok": 0, "analysis_missing": 0})
        if record.get("analysis_status") == "ok":
            summary[label]["analysis_ok"] += 1
        else:
            summary[label]["analysis_missing"] += 1
    return summary


def compact_analysis_reports(reports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    compact = []
    for report in reports:
        batch = report.get("batch_report") or {}
        compact.append(
            {
                "label": report.get("label"),
                "source_dir": report.get("source_dir"),
                "output_dir": report.get("output_dir"),
                "returncode": report.get("returncode"),
                "duration_seconds": report.get("duration_seconds"),
                "processed": batch.get("processed"),
                "failed": batch.get("failed"),
                "skipped": batch.get("skipped"),
                "stderr": report.get("stderr"),
            }
        )
    return compact


def write_outputs(run_dir: Path, report: dict[str, Any], verdict_records: list[dict[str, Any]]) -> None:
    write_json(run_dir / "eval_report.json", report)
    write_text_report(run_dir / "eval_report.txt", report)
    if verdict_records:
        write_json(run_dir / "verdict_records.json", verdict_records)
        write_csv(run_dir / "verdict_records.csv", verdict_records)


def write_text_report(path: Path, report: dict[str, Any]) -> None:
    lines = ["Gobbler eval report", f"  run_dir={report['run_dir']}", f"  mode={report['mode']}"]
    if report.get("models"):
        lines.append("  models=" + ", ".join(report["models"]))
    dataset = report.get("dataset", {})
    lines.append(f"  dataset_total={dataset.get('total')}")
    for label, info in sorted((dataset.get("by_label") or {}).items()):
        lines.append(f"  {label}: samples={info.get('samples')} analysis_ok={info.get('analysis_ok')} analysis_missing={info.get('analysis_missing')}")
    metrics = report.get("metrics")
    if metrics:
        lines.append("  metrics:")
        for key, value in metrics.items():
            lines.append(f"    {key}={value}")
    metrics_by_model = report.get("metrics_by_model") or {}
    if len(metrics_by_model) > 1:
        lines.append("  metrics_by_model:")
        for model, model_metrics in metrics_by_model.items():
            lines.append(f"    {model}:")
            for key, value in model_metrics.items():
                lines.append(f"      {key}={value}")
    lines.append("  analysis:")
    for item in report.get("analysis_reports") or []:
        lines.append(
            "    "
            + f"{item.get('label')} {item.get('source_dir')} processed={item.get('processed')} "
            + f"failed={item.get('failed')} skipped={item.get('skipped')} returncode={item.get('returncode')}"
        )
        if item.get("stderr"):
            lines.append(f"      stderr={item['stderr']}")
    path.write_text("\n".join(lines) + "\n")


def write_csv(path: Path, records: list[dict[str, Any]]) -> None:
    fields = [
        "model",
        "label",
        "name",
        "status",
        "verdict",
        "behavioral_summary",
        "cost",
        "duration_seconds",
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
        "analysis_json",
        "verdict_json",
        "error",
    ]
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for record in records:
            writer.writerow({field: record.get(field) for field in fields})


def analysis_dir_for(root: Path, label: str, source_dir: Path) -> Path:
    return root / label / safe_name(str(source_dir))


def analysis_source_for_existing(root: Path, label: str, path: Path) -> str:
    parent = path.parent
    try:
        relative = parent.relative_to(root / label)
    except ValueError:
        return str(parent)
    return str(relative)


def load_env_file(path: Path, key_name: str = "OPENROUTER_API_KEY") -> None:
    if os.environ.get(key_name) or not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key.strip() == key_name:
            os.environ[key_name] = value.strip().strip("\"'")
            return


def verdict_root_for_model(root: Path, model: str) -> Path:
    return root / safe_model_name(model)


def safe_model_name(model: str) -> str:
    return safe_name(model.replace("/", "_").replace(":", "_"))


def progress_text(index: int | None, total: int | None) -> str:
    if index is None or total is None:
        return ""
    return f"[{index}/{total}]"


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def safe_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in value)


def tail(text: str, limit: int = 2000) -> str:
    text = text.strip()
    return text if len(text) <= limit else text[-limit:]


def short_error(text: str, limit: int = 500) -> str:
    text = " ".join(line.strip() for line in text.splitlines() if line.strip())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def numeric_cost(verdict: dict[str, Any]) -> float | None:
    for value in (verdict.get("cost"), (verdict.get("usage") or {}).get("cost")):
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str):
            try:
                return float(value)
            except ValueError:
                pass
    return None


def int_or_zero(value: Any) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(float(value))
        except ValueError:
            return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
