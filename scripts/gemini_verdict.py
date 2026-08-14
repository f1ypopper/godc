#!/usr/bin/env python3
"""
Send a Gobbler JSON report to Gemini Flash for malware triage.

The script uses only Python stdlib modules. Set GEMINI_API_KEY before running:

    GEMINI_API_KEY=... python3 scripts/gemini_verdict.py output/sample.json

The default model is intentionally overrideable because Gemini model IDs change:

    python3 scripts/gemini_verdict.py output/sample.json --model gemini-3.5-flash
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import textwrap
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


DEFAULT_MODEL = "gemini-3.6-flash"
DEFAULT_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta"
MAX_PROMPT_JSON_CHARS = 160_000

BEHAVIOR_TERMS = (
    "http",
    "url",
    "net.",
    "tls.",
    "dns",
    "socket",
    "file",
    "open",
    "readfile",
    "writefile",
    "remove",
    "rename",
    "mkdir",
    "temp",
    "exec",
    "command",
    "process",
    "startprocess",
    "shell",
    "powershell",
    "cmd.exe",
    "syscall",
    "virtualalloc",
    "virtualprotect",
    "writeprocessmemory",
    "createremotethread",
    "loadlibrary",
    "getprocaddress",
    "registry",
    "regopenkey",
    "service",
    "crypto/",
    "aes",
    "xor",
    "base64",
    "gzip",
    "zlib",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Send one Gobbler output JSON to Google Gemini Flash and return a "
            "strict JSON verdict."
        ),
        epilog=(
            "Uses GEMINI_API_KEY. Default endpoint follows the Gemini "
            "generateContent REST API shape, but both --model and --endpoint "
            "are configurable for API/model changes."
        ),
    )
    parser.add_argument("input_json", type=Path, help="Path to a Gobbler output JSON file.")
    parser.add_argument("--out", type=Path, help="Optional path to write the verdict JSON.")
    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help=f"Gemini model ID to use. Default: {DEFAULT_MODEL}",
    )
    parser.add_argument(
        "--endpoint",
        default=DEFAULT_ENDPOINT,
        help=f"Gemini API base endpoint. Default: {DEFAULT_ENDPOINT}",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=90.0,
        help="HTTP timeout in seconds. Default: 90",
    )
    parser.add_argument(
        "--env-file",
        type=Path,
        default=Path(".env"),
        help="Optional .env file used for GEMINI_API_KEY if not already set.",
    )
    parser.add_argument(
        "--max-prompt-json-chars",
        type=int,
        default=MAX_PROMPT_JSON_CHARS,
        help=(
            "Maximum characters of compacted Gobbler evidence to include in "
            f"the prompt. Default: {MAX_PROMPT_JSON_CHARS}"
        ),
    )
    return parser.parse_args()


def take(items: Any, limit: int) -> list[Any]:
    if not isinstance(items, list):
        return []
    return items[:limit]


def compact_value(value: Any, max_len: int = 180) -> Any:
    if isinstance(value, str):
        value = value.replace("\x00", "")
        return value if len(value) <= max_len else value[: max_len - 3] + "..."
    if isinstance(value, list):
        return [compact_value(item, max_len) for item in value[:20]]
    if isinstance(value, dict):
        return {str(k): compact_value(v, max_len) for k, v in value.items()}
    return value


def dedupe_dicts(items: list[dict[str, Any]], keys: tuple[str, ...], limit: int) -> list[dict[str, Any]]:
    seen: set[tuple[Any, ...]] = set()
    out: list[dict[str, Any]] = []
    for item in items:
        marker = tuple(item.get(key) for key in keys)
        if marker in seen:
            continue
        seen.add(marker)
        out.append(item)
        if len(out) >= limit:
            break
    return out


def function_is_interesting(name: str, flow: list[dict[str, Any]]) -> bool:
    text = name.lower() + " " + " ".join(
        str(op.get("kind", "")) + " " + str(op.get("target", "")) for op in flow
    ).lower()
    return any(term in text for term in BEHAVIOR_TERMS)


def collect_behavior_ops(behavior_ir: dict[str, Any]) -> list[dict[str, Any]]:
    functions = behavior_ir.get("functions")
    if not isinstance(functions, dict):
        return []

    ops: list[dict[str, Any]] = []
    for function, info in functions.items():
        if not isinstance(info, dict):
            continue
        flow = info.get("flow")
        if not isinstance(flow, list) or not function_is_interesting(function, flow):
            continue
        for op in flow:
            if not isinstance(op, dict):
                continue
            text = (
                str(op.get("kind", ""))
                + " "
                + str(op.get("target", ""))
                + " "
                + " ".join(str(arg) for arg in op.get("string_args", []) if isinstance(arg, str))
            ).lower()
            if any(term in text for term in BEHAVIOR_TERMS):
                ops.append(
                    {
                        "function": function,
                        "kind": op.get("kind"),
                        "target": op.get("target"),
                        "tags": take(op.get("tags"), 8),
                        "string_args": take(op.get("string_args"), 8),
                    }
                )
    return dedupe_dicts(ops, ("function", "kind", "target"), 80)


def collect_chains(semantic_chains: dict[str, Any]) -> list[dict[str, Any]]:
    chains = []
    for chain in take(semantic_chains.get("chains"), 80):
        if not isinstance(chain, dict):
            continue
        chains.append(
            {
                "kind": chain.get("kind"),
                "function": chain.get("function"),
                "confidence": chain.get("confidence"),
                "evidence": take(chain.get("evidence"), 8),
                "sinks": take(chain.get("sinks"), 8),
                "recovered_indicators": take(chain.get("recovered_indicators"), 10),
            }
        )
    return chains


def collect_runtime_decoding(runtime_decoding: dict[str, Any]) -> dict[str, Any]:
    functions = []
    for item in take(runtime_decoding.get("functions"), 50):
        if not isinstance(item, dict):
            continue
        labels = item.get("feature_labels") or []
        indicators = item.get("recovered_indicators") or []
        if not labels and not indicators:
            continue
        functions.append(
            {
                "function": item.get("function"),
                "classification": item.get("classification"),
                "feature_labels": take(labels, 8),
                "confidence": item.get("confidence"),
                "decoder_calls": take(item.get("decoder_calls"), 8),
                "recovered_indicators": take(indicators, 10),
            }
        )
    return {
        "summary": runtime_decoding.get("summary", {}),
        "functions": functions,
        "recovered_indicators": take(runtime_decoding.get("recovered_indicators"), 50),
    }


def collect_strings(call_graph: dict[str, Any]) -> list[dict[str, Any]]:
    strings: list[dict[str, Any]] = []
    for function, calls in call_graph.items():
        if not isinstance(calls, list):
            continue
        for call in calls:
            if not isinstance(call, dict):
                continue
            values = [s for s in call.get("string_args", []) if isinstance(s, str) and len(s) >= 4]
            values = [s for s in values if any(term in s.lower() for term in BEHAVIOR_TERMS)]
            if values:
                strings.append(
                    {
                        "function": function,
                        "target": call.get("target"),
                        "strings": values[:8],
                    }
                )
    return dedupe_dicts(strings, ("function", "target"), 80)


def build_evaluator_view(report: dict[str, Any], input_path: Path) -> dict[str, Any]:
    semantic = report.get("semantic_analysis") if isinstance(report.get("semantic_analysis"), dict) else {}
    call_graph = report.get("call_graph") if isinstance(report.get("call_graph"), dict) else {}

    suspicious_blobs = semantic.get("suspicious_data_blobs") or []
    payload_blobs = []
    for blob in take(suspicious_blobs, 40):
        if not isinstance(blob, dict):
            continue
        magic = blob.get("magic_offsets") or []
        reasons = blob.get("reasons") or []
        if magic or any(reason in reasons for reason in ("large_copy_source", "contains_magic_bytes", "high_entropy")):
            payload_blobs.append(
                {
                    "id": blob.get("id"),
                    "section": blob.get("section"),
                    "size": blob.get("size"),
                    "entropy": blob.get("entropy"),
                    "reasons": take(reasons, 8),
                    "magic_offsets": take(magic, 8),
                    "duplicate_count": blob.get("duplicate_count"),
                }
            )

    return {
        "input_file": str(input_path),
        "behavior_story": compact_value(semantic.get("behavior_story") or {}, 500),
        "top_level_summary": {
            "call_graph_functions": len(call_graph),
            "behavior_ir": (semantic.get("behavior_ir") or {}).get("summary", {}),
            "semantic_chain_summary": (semantic.get("semantic_chains") or {}).get("summary", {}),
            "assessment_hints": take(semantic.get("assessment_hints"), 30),
        },
        "decryption_recovery": compact_value(semantic.get("decryption_recovery") or {}, 500),
        "behavior_operations": collect_behavior_ops(semantic.get("behavior_ir") or {}),
        "semantic_chains": collect_chains(semantic.get("semantic_chains") or {}),
        "runtime_decoding": collect_runtime_decoding(semantic.get("runtime_decoding") or {}),
        "embedded_payloads": take(semantic.get("embedded_payloads"), 30),
        "loader_behaviors": take(semantic.get("loader_behaviors"), 30),
        "suspicious_payload_blobs": payload_blobs[:30],
        "behavior_strings": collect_strings(call_graph),
        "top_interesting_functions": take(semantic.get("interesting_functions"), 25),
    }


def truncate_json_for_prompt(evidence: dict[str, Any], max_chars: int) -> str:
    rendered = json.dumps(compact_value(evidence), indent=2, sort_keys=True)
    if len(rendered) <= max_chars:
        return rendered
    return rendered[: max_chars - 200] + "\n... <truncated evaluator evidence> ..."


def build_prompt(evidence: dict[str, Any], max_chars: int) -> str:
    evidence_json = truncate_json_for_prompt(evidence, max_chars)
    return textwrap.dedent(
        f"""
        You are a malware triage evaluator reviewing Gobbler semantic output for a Go binary.

        Decide whether the binary is clean, suspicious, dirty, or unknown. Focus on what the
        binary appears to do to the system: file I/O, network activity, process creation,
        command execution, memory execution, dynamic loading, persistence, decoded artifacts,
        embedded payloads, and suspicious crypto/decoder use.

        Ignore debug implementation details such as array IDs, addresses, Go runtime noise,
        stack checks, GC calls, and generic compiler artifacts unless they support a behavior.

        Return only valid JSON with this exact shape:
        {{
          "verdict": "clean|suspicious|dirty|unknown",
          "confidence": 0.0,
          "reasoning": ["short reason 1", "short reason 2"],
          "key_behaviors": [
            {{
              "kind": "file_io|network|process_execution|dynamic_code_loading|persistence|credential_access|runtime_decoding|embedded_payload|other",
              "description": "what happened",
              "evidence": ["specific Gobbler facts"]
            }}
          ],
          "indicators": {{
            "urls": [],
            "domains": [],
            "ips": [],
            "paths": [],
            "commands": [],
            "mutexes": [],
            "payloads": [],
            "other": []
          }},
          "caveats": ["analysis limitations or uncertainty"]
        }}

        Gobbler evaluator evidence:
        {evidence_json}
        """
    ).strip()


def gemini_url(endpoint: str, model: str) -> str:
    endpoint = endpoint.rstrip("/")
    model_path = model if model.startswith("models/") else f"models/{model}"
    return f"{endpoint}/{model_path}:generateContent"


def call_gemini(prompt: str, args: argparse.Namespace, api_key: str) -> dict[str, Any]:
    payload = {
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.1,
            "responseMimeType": "application/json",
        },
    }
    request = urllib.request.Request(
        gemini_url(args.endpoint, args.model),
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "x-goog-api-key": api_key},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=args.timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def extract_response_text(response: dict[str, Any]) -> str:
    candidates = response.get("candidates")
    if not isinstance(candidates, list) or not candidates:
        raise ValueError("Gemini response did not contain candidates")
    parts = ((candidates[0].get("content") or {}).get("parts") or [])
    texts = [part.get("text", "") for part in parts if isinstance(part, dict)]
    text = "\n".join(text for text in texts if text)
    if not text:
        raise ValueError("Gemini response did not contain text")
    return text


def parse_model_json(text: str) -> dict[str, Any]:
    cleaned = text.strip()
    fenced = re.search(r"```(?:json)?\s*(.*?)\s*```", cleaned, flags=re.S)
    if fenced:
        cleaned = fenced.group(1).strip()
    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError:
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start == -1 or end == -1 or end <= start:
            raise
        parsed = json.loads(cleaned[start : end + 1])
    if not isinstance(parsed, dict):
        raise ValueError("Gemini returned JSON, but not an object")
    return parsed


def normalize_verdict(result: dict[str, Any], model: str) -> dict[str, Any]:
    verdict = str(result.get("verdict", "unknown")).lower()
    if verdict not in {"clean", "suspicious", "dirty", "unknown"}:
        verdict = "unknown"

    try:
        confidence = float(result.get("confidence", 0.0))
    except (TypeError, ValueError):
        confidence = 0.0
    confidence = max(0.0, min(1.0, confidence))

    indicators = result.get("indicators")
    if not isinstance(indicators, dict):
        indicators = {}
    normalized_indicators = {
        key: take(indicators.get(key), 100)
        for key in ("urls", "domains", "ips", "paths", "commands", "mutexes", "payloads", "other")
    }

    return {
        "verdict": verdict,
        "confidence": confidence,
        "reasoning": take(result.get("reasoning"), 20),
        "key_behaviors": take(result.get("key_behaviors"), 30),
        "indicators": normalized_indicators,
        "caveats": take(result.get("caveats"), 20),
        "model": model,
    }


def write_output(result: dict[str, Any], out_path: Path | None) -> None:
    rendered = json.dumps(result, indent=2, sort_keys=True)
    if out_path:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)


def load_env_file(path: Path) -> None:
    if os.environ.get("GEMINI_API_KEY") or not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key.strip() == "GEMINI_API_KEY":
            os.environ["GEMINI_API_KEY"] = value.strip().strip("\"'")
            return


def main() -> int:
    args = parse_args()
    load_env_file(args.env_file)
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("GEMINI_API_KEY is required", file=sys.stderr)
        return 2

    try:
        report = json.loads(args.input_json.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"failed to read Gobbler JSON: {exc}", file=sys.stderr)
        return 2

    evidence = build_evaluator_view(report, args.input_json)
    prompt = build_prompt(evidence, args.max_prompt_json_chars)

    try:
        response = call_gemini(prompt, args, api_key)
        text = extract_response_text(response)
        result = normalize_verdict(parse_model_json(text), args.model)
    except (urllib.error.URLError, urllib.error.HTTPError, ValueError, json.JSONDecodeError) as exc:
        print(f"Gemini evaluation failed: {exc}", file=sys.stderr)
        return 1

    write_output(result, args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
