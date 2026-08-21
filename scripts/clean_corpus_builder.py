#!/usr/bin/env python3
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import requests


DEFAULT_CONFIG = Path("corpus/clean_config.json")
DEFAULT_OUT = Path("corpus/clean")
DEFAULT_GOOS = "windows"
DEFAULT_GOARCH = "amd64"
MANIFEST_NAME = "manifest.jsonl"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build or download a labeled clean Go binary corpus.")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--goos", default=DEFAULT_GOOS)
    parser.add_argument("--goarch", default=DEFAULT_GOARCH)
    parser.add_argument("--providers", default="synthetic", help="Comma-separated: synthetic,gomod,gobinaries")
    parser.add_argument("--limit", type=int, help="Maximum samples per provider")
    parser.add_argument("--target-count", type=int, help="Stop after collecting this many successful samples")
    parser.add_argument("--jobs", type=int, default=1, help="Parallel gomod builds")
    parser.add_argument("--force", action="store_true", help="Overwrite existing binaries")
    parser.add_argument("--dry-run", action="store_true", help="Print planned work without building/downloading")
    parser.add_argument("--refresh-existing", action="store_true", help="Refresh manifest records for existing corpus binaries without building/downloading")
    parser.add_argument("--summary", action="store_true", help="Print manifest summary and exit")
    parser.add_argument("--timeout", type=int, default=180)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.summary:
        print_manifest_summary(args.out / MANIFEST_NAME)
        return 0
    config = load_config(args.config)
    providers = {item.strip() for item in args.providers.split(",") if item.strip()}
    records = []
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    if args.refresh_existing:
        records = refresh_existing(config, providers, args, started)
        write_manifest(args.out / MANIFEST_NAME, records)
        print(f"refreshed {len(records)} existing records in {args.out / MANIFEST_NAME}")
        return 0

    if "synthetic" in providers:
        records.extend(build_synthetic(config.get("synthetic") or [], args, started, remaining_target(records, args)))
    if "gomod" in providers and not target_reached(records, args):
        records.extend(build_gomod(config.get("gomod") or [], args, started, remaining_target(records, args)))
    if "gobinaries" in providers and not target_reached(records, args):
        records.extend(download_gobinaries(config.get("gobinaries") or [], args, started, remaining_target(records, args)))

    if args.dry_run:
        return 0
    write_manifest(args.out / MANIFEST_NAME, records)
    print(f"wrote {len(records)} records to {args.out / MANIFEST_NAME}")
    if args.target_count and len(records) < args.target_count:
        print(f"target-count not reached: collected {len(records)} of {args.target_count}", file=sys.stderr)
        return 2
    return 0


def load_config(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text())
    except Exception as exc:
        raise SystemExit(f"failed to read config {path}: {exc}")


def refresh_existing(
    config: dict[str, Any],
    providers: set[str],
    args: argparse.Namespace,
    collected_at: str,
) -> list[dict[str, Any]]:
    records = []
    if "synthetic" in providers:
        for item in limited(config.get("synthetic") or [], args.limit):
            path = args.out / "synthetic" / binary_filename(item["name"], args.goos)
            if path.exists():
                command = "go build -trimpath -ldflags -s -w -o <output> ."
                records.append(record_for_existing(path, item, "synthetic", args, collected_at, source_dir=Path("corpus/synthetic") / item["name"], build_command=command))
    if "gomod" in providers:
        for item in limited(config.get("gomod") or [], args.limit):
            name = item["name"]
            version = item.get("version", "latest")
            path = args.out / "gomod" / binary_filename(f"{name}_{sanitize_version(version)}", args.goos)
            if path.exists():
                command = f"go install {item['package']}@{version}"
                records.append(record_for_existing(path, item, "gomod", args, collected_at, build_command=command))
    if "gobinaries" in providers:
        for item in limited(config.get("gobinaries") or [], args.limit):
            name = item["name"]
            version = item.get("version", "latest")
            path = args.out / "gobinaries" / binary_filename(f"{name}_{sanitize_version(version)}", args.goos)
            if path.exists():
                records.append(record_for_existing(path, item, "gobinaries", args, collected_at, download_url=gobinaries_url(item["package"], version, args.goos, args.goarch)))
    return records


def build_synthetic(
    items: list[dict[str, Any]],
    args: argparse.Namespace,
    collected_at: str,
    max_successes: int | None = None,
) -> list[dict[str, Any]]:
    records = []
    for item in limited(items, args.limit):
        if max_successes is not None and len(records) >= max_successes:
            break
        name = item["name"]
        source_dir = Path("corpus/synthetic") / name
        output_dir = args.out / "synthetic"
        binary_name = binary_filename(name, args.goos)
        output_path = output_dir / binary_name
        command = [
            "go",
            "build",
            "-trimpath",
            "-ldflags",
            "-s -w",
            "-o",
            str(output_path.resolve()),
            ".",
        ]
        print(f"synthetic {name}: {output_path}")
        if args.dry_run:
            continue
        output_dir.mkdir(parents=True, exist_ok=True)
        if output_path.exists() and not args.force:
            records.append(record_for_existing(output_path, item, "synthetic", args, collected_at, source_dir=source_dir))
            continue
        env = os.environ.copy()
        cache_dir = args.out.parent / ".cache" / "go-build"
        cache_dir.mkdir(parents=True, exist_ok=True)
        env.update(
            {
                "GOOS": args.goos,
                "GOARCH": args.goarch,
                "CGO_ENABLED": "0",
                "GO111MODULE": "off",
                "GOCACHE": str(cache_dir.resolve()),
            }
        )
        proc = subprocess.run(command, cwd=source_dir, env=env, text=True, capture_output=True, timeout=args.timeout, check=False)
        if proc.returncode != 0:
            print(f"failed synthetic {name}: {short_error(proc.stderr or proc.stdout)}", file=sys.stderr)
            continue
        records.append(record_for_existing(output_path, item, "synthetic", args, collected_at, source_dir=source_dir, build_command=" ".join(command)))
    return records


def build_gomod(
    items: list[dict[str, Any]],
    args: argparse.Namespace,
    collected_at: str,
    max_successes: int | None = None,
) -> list[dict[str, Any]]:
    selected = limited(items, args.limit)
    if args.jobs <= 1 or args.dry_run:
        return build_gomod_sequential(selected, args, collected_at, max_successes)

    records = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as executor:
        future_to_name = {
            executor.submit(build_one_gomod, item, args, collected_at): item.get("name", item.get("package", "unknown"))
            for item in selected
        }
        try:
            for future in concurrent.futures.as_completed(future_to_name):
                record = future.result()
                if record:
                    records.append(record)
                    if max_successes is not None and len(records) >= max_successes:
                        for pending in future_to_name:
                            pending.cancel()
                        break
        finally:
            executor.shutdown(wait=True, cancel_futures=True)
    return records


def build_gomod_sequential(
    items: list[dict[str, Any]],
    args: argparse.Namespace,
    collected_at: str,
    max_successes: int | None = None,
) -> list[dict[str, Any]]:
    records = []
    for item in items:
        if max_successes is not None and len(records) >= max_successes:
            break
        record = build_one_gomod(item, args, collected_at)
        if record:
            records.append(record)
    return records


def build_one_gomod(item: dict[str, Any], args: argparse.Namespace, collected_at: str) -> dict[str, Any] | None:
    name = item["name"]
    package = item["package"]
    version = item.get("version", "latest")
    binary = item.get("binary") or Path(package).name
    output_dir = args.out / "gomod"
    output_path = output_dir / binary_filename(f"{name}_{sanitize_version(version)}", args.goos)
    gopath_dir = args.out.parent / ".cache" / "gomod-gopath" / safe_name(f"{name}_{version}_{args.goos}_{args.goarch}")
    command = ["go", "install", f"{package}@{version}"]
    print(f"gomod {name}@{version}: {output_path}")
    if args.dry_run:
        print(f"  {' '.join(command)}")
        return None
    output_dir.mkdir(parents=True, exist_ok=True)
    gopath_dir.mkdir(parents=True, exist_ok=True)
    if output_path.exists() and not args.force:
        return record_for_existing(output_path, item, "gomod", args, collected_at, build_command=" ".join(command))
    env = os.environ.copy()
    cache_dir = args.out.parent / ".cache" / "go-build"
    mod_cache_dir = args.out.parent / ".cache" / "go-mod"
    cache_dir.mkdir(parents=True, exist_ok=True)
    mod_cache_dir.mkdir(parents=True, exist_ok=True)
    env.update(
        {
            "GOOS": args.goos,
            "GOARCH": args.goarch,
            "CGO_ENABLED": "0",
            "GOPATH": str(gopath_dir.resolve()),
            "GOCACHE": str(cache_dir.resolve()),
            "GOMODCACHE": str(mod_cache_dir.resolve()),
        }
    )
    env.pop("GOBIN", None)
    proc = subprocess.run(command, env=env, text=True, capture_output=True, timeout=args.timeout, check=False)
    if proc.returncode != 0:
        print(f"failed gomod {name}: {short_error(proc.stderr or proc.stdout)}", file=sys.stderr)
        return None
    installed_path = find_installed_binary(gopath_dir, binary, args.goos, args.goarch)
    if installed_path is None:
        print(f"failed gomod {name}: could not find installed binary {binary_filename(binary, args.goos)} under {gopath_dir / 'bin'}", file=sys.stderr)
        return None
    shutil.copy2(installed_path, output_path)
    return record_for_existing(output_path, item, "gomod", args, collected_at, build_command=" ".join(command))


def download_gobinaries(
    items: list[dict[str, Any]],
    args: argparse.Namespace,
    collected_at: str,
    max_successes: int | None = None,
) -> list[dict[str, Any]]:
    records = []
    for item in limited(items, args.limit):
        if max_successes is not None and len(records) >= max_successes:
            break
        name = item["name"]
        package = item["package"]
        version = item.get("version", "latest")
        output_dir = args.out / "gobinaries"
        output_path = output_dir / binary_filename(f"{name}_{sanitize_version(version)}", args.goos)
        url = gobinaries_url(package, version, args.goos, args.goarch)
        print(f"gobinaries {name}@{version}: {output_path}")
        if args.dry_run:
            print(f"  {url}")
            continue
        output_dir.mkdir(parents=True, exist_ok=True)
        if output_path.exists() and not args.force:
            records.append(record_for_existing(output_path, item, "gobinaries", args, collected_at, download_url=url))
            continue
        try:
            response = requests.get(
                url,
                headers={"User-Agent": "gobbler-clean-corpus-builder/1.0"},
                timeout=args.timeout,
            )
            response.raise_for_status()
            data = response.content
        except requests.RequestException as exc:
            print(f"failed gobinaries {name}: {exc}", file=sys.stderr)
            continue
        output_path.write_bytes(data)
        records.append(record_for_existing(output_path, item, "gobinaries", args, collected_at, download_url=url))
    return records


def record_for_existing(
    path: Path,
    item: dict[str, Any],
    provider: str,
    args: argparse.Namespace,
    collected_at: str,
    *,
    source_dir: Path | None = None,
    build_command: str | None = None,
    download_url: str | None = None,
) -> dict[str, Any]:
    stat = path.stat()
    record = {
        "sha256": sha256_file(path),
        "path": str(path),
        "file_name": path.name,
        "file_size": stat.st_size,
        "label": "clean",
        "label_confidence": "high" if provider in {"synthetic", "gomod"} else "medium",
        "provider": provider,
        "name": item.get("name"),
        "description": item.get("description"),
        "package": item.get("package"),
        "version": item.get("version"),
        "goos": args.goos,
        "goarch": args.goarch,
        "expected_behaviors": item.get("expected_behaviors", []),
        "hard_negative": bool(item.get("hard_negative")),
        "collected_at": collected_at,
    }
    if source_dir is not None:
        record["source_dir"] = str(source_dir)
    if build_command:
        record["build_command"] = build_command
        record["go_version"] = go_version()
        if provider == "gomod":
            record["provenance_notes"] = "Built locally from a curated public Go module command package."
    if download_url:
        record["download_url"] = download_url
        record["provenance_notes"] = "Built by gobinaries third-party service; lower confidence than local source build."
    return {key: value for key, value in record.items() if value not in (None, [], {})}


def write_manifest(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = []
    if path.exists():
        for line in path.read_text().splitlines():
            if line.strip():
                try:
                    existing.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    by_path = {record.get("path"): record for record in existing if record.get("path")}
    for record in records:
        by_path[record["path"]] = record
    rendered = "\n".join(json.dumps(record, sort_keys=True) for record in sorted(by_path.values(), key=lambda item: item["path"]))
    path.write_text(rendered + ("\n" if rendered else ""))


def print_manifest_summary(path: Path) -> None:
    if not path.exists():
        print(f"manifest not found: {path}")
        return
    records = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    providers: dict[str, int] = {}
    hard_negative = 0
    behaviors: dict[str, int] = {}
    for record in records:
        providers[record.get("provider", "unknown")] = providers.get(record.get("provider", "unknown"), 0) + 1
        if record.get("hard_negative"):
            hard_negative += 1
        for behavior in record.get("expected_behaviors") or []:
            behaviors[behavior] = behaviors.get(behavior, 0) + 1
    print(f"manifest={path}")
    print(f"samples={len(records)} hard_negative={hard_negative}")
    print("providers=" + json.dumps(dict(sorted(providers.items())), sort_keys=True))
    print("expected_behaviors=" + json.dumps(dict(sorted(behaviors.items())), sort_keys=True))


def gobinaries_url(package: str, version: str, goos: str, goarch: str) -> str:
    package = package if package.startswith("github.com/") or "." in package.split("/", 1)[0] else f"github.com/{package}"
    request = requests.Request(
        "GET",
        f"https://gobinaries.com/binary/{package}",
        params={"os": goos, "arch": goarch, "version": version},
    ).prepare()
    return request.url or f"https://gobinaries.com/binary/{package}"


def binary_filename(name: str, goos: str) -> str:
    suffix = ".exe" if goos == "windows" else ""
    return f"{safe_name(name)}{suffix}"


def find_installed_binary(gopath_dir: Path, binary: str, goos: str, goarch: str) -> Path | None:
    expected_name = binary_filename(binary, goos)
    candidates = [
        gopath_dir / "bin" / f"{goos}_{goarch}" / expected_name,
        gopath_dir / "bin" / expected_name,
    ]
    for candidate in candidates:
        if candidate.exists() and candidate.is_file():
            return candidate
    matches = sorted((gopath_dir / "bin").rglob(expected_name)) if (gopath_dir / "bin").exists() else []
    return matches[0] if matches else None


def safe_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in value)


def sanitize_version(value: str) -> str:
    return safe_name(value.replace("/", "_"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def go_version() -> str:
    try:
        proc = subprocess.run(["go", "version"], text=True, capture_output=True, check=False)
    except Exception:
        return "unknown"
    return (proc.stdout or proc.stderr).strip() or "unknown"


def limited(items: list[dict[str, Any]], limit: int | None) -> list[dict[str, Any]]:
    return items if limit is None else items[:limit]


def target_reached(records: list[dict[str, Any]], args: argparse.Namespace) -> bool:
    return bool(args.target_count and len(records) >= args.target_count)


def remaining_target(records: list[dict[str, Any]], args: argparse.Namespace) -> int | None:
    if not args.target_count:
        return None
    return max(args.target_count - len(records), 0)


def short_error(message: str, limit: int = 500) -> str:
    message = " ".join(line.strip() for line in message.splitlines() if line.strip())
    return message if len(message) <= limit else message[: limit - 3] + "..."


if __name__ == "__main__":
    raise SystemExit(main())
