#!/usr/bin/env python3
"""
Send a Gobbler JSON report to an OpenRouter model for malware triage.

The script uses only Python stdlib modules. Set OPENROUTER_API_KEY before running:

    OPENROUTER_API_KEY=... python3 scripts/llm_verdict.py output/sample.json

The model is intentionally overrideable because OpenRouter model IDs are the
unit of comparison for evals:

    python3 scripts/llm_verdict.py output/sample.json --model google/gemini-2.5-flash
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


DEFAULT_MODEL = "google/gemini-2.5-flash"
DEFAULT_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_APP_TITLE = "Gobbler Eval"
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

LOW_LEVEL_EXECUTION_KINDS = {
    "dynamic_library_load",
    "dynamic_import_resolution",
    "dynamic_syscall_call",
    "raw_syscall",
    "executable_memory_allocation",
    "memory_protection_change",
    "thread_creation",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Send one Gobbler output JSON to an OpenRouter model and return a "
            "strict JSON verdict."
        ),
        epilog=(
            "Uses OPENROUTER_API_KEY. Default endpoint follows OpenRouter's "
            "OpenAI-compatible chat completions API, but --model and --endpoint "
            "are configurable."
        ),
    )
    parser.add_argument("input_json", type=Path, help="Path to a Gobbler output JSON file.")
    parser.add_argument("--out", type=Path, help="Optional path to write the verdict JSON.")
    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help=f"OpenRouter model slug to use. Default: {DEFAULT_MODEL}",
    )
    parser.add_argument(
        "--endpoint",
        default=DEFAULT_ENDPOINT,
        help=f"OpenRouter chat completions endpoint. Default: {DEFAULT_ENDPOINT}",
    )
    parser.add_argument(
        "--api-key-env",
        default="OPENROUTER_API_KEY",
        help="Environment variable containing the OpenRouter API key. Default: OPENROUTER_API_KEY",
    )
    parser.add_argument(
        "--http-referer",
        default=os.environ.get("OPENROUTER_HTTP_REFERER", ""),
        help="Optional OpenRouter HTTP-Referer attribution header.",
    )
    parser.add_argument(
        "--app-title",
        default=os.environ.get("OPENROUTER_APP_TITLE", DEFAULT_APP_TITLE),
        help=f"Optional OpenRouter X-OpenRouter-Title header. Default: {DEFAULT_APP_TITLE}",
    )
    parser.add_argument(
        "--temperature",
        type=float,
        default=0.1,
        help="Model temperature. Default: 0.1",
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=1400,
        help="Maximum response tokens. Default: 1400",
    )
    parser.add_argument(
        "--no-json-mode",
        action="store_true",
        help="Do not send response_format=json_object.",
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
        help="Optional .env file used for OPENROUTER_API_KEY if not already set.",
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


def collect_behavior_ops(
    behavior_ir: dict[str, Any], promoted_loader_functions: set[str] | None = None
) -> list[dict[str, Any]]:
    functions = behavior_ir.get("functions")
    if not isinstance(functions, dict):
        return []

    promoted_loader_functions = promoted_loader_functions or set()
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
            if (
                op.get("kind") in LOW_LEVEL_EXECUTION_KINDS
                and function not in promoted_loader_functions
            ):
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


def compact_source(source: Any) -> dict[str, Any]:
    if not isinstance(source, dict):
        return {}
    return {
        key: source.get(key)
        for key in ("section", "size", "entropy", "va")
        if source.get(key) is not None
    }


def compact_artifact(artifact: Any) -> dict[str, Any]:
    if not isinstance(artifact, dict):
        return {}
    out = {
        key: artifact.get(key)
        for key in ("type", "value", "confidence")
        if artifact.get(key) is not None
    }
    details = artifact.get("details")
    if isinstance(details, dict):
        summarized_details: dict[str, Any] = {}
        source = compact_source(details.get("source"))
        if source:
            summarized_details["source"] = source
        loaders = take(details.get("loaders"), 3)
        if loaders:
            summarized_details["loaders"] = loaders
        transformers = take(details.get("transformers"), 3)
        if transformers:
            summarized_details["transformers"] = transformers
            summarized_details["transformer_count"] = len(details.get("transformers") or [])
        if summarized_details:
            out["details"] = summarized_details
    return out


def compact_behavior_story(story: Any) -> dict[str, Any]:
    if not isinstance(story, dict):
        return {}
    flow = []
    for step in take(story.get("execution_flow"), 12):
        if not isinstance(step, dict):
            continue
        actions = []
        for action in take(step.get("actions"), 6):
            if not isinstance(action, dict):
                continue
            artifacts = [
                item for item in (compact_artifact(artifact) for artifact in take(action.get("artifacts"), 6)) if item
            ]
            compact_action = {
                key: action.get(key)
                for key in ("kind", "category", "description", "target_api")
                if action.get(key) is not None
            }
            if artifacts:
                compact_action["artifacts"] = artifacts
            actions.append(compact_action)
        if actions:
            flow.append({"function": step.get("function"), "actions": actions})
    return {
        "summary": story.get("summary", {}),
        "narrative": take(story.get("narrative"), 8),
        "execution_flow": flow,
    }


def compact_embedded_payloads(payloads: Any) -> list[dict[str, Any]]:
    out = []
    for payload in take(payloads, 10):
        if not isinstance(payload, dict):
            continue
        transformers = payload.get("transformers") or []
        item = {
            key: payload.get(key)
            for key in ("kind", "confidence")
            if payload.get(key) is not None
        }
        source = compact_source(payload.get("source"))
        if source:
            item["source"] = source
        evidence = take(payload.get("evidence"), 6)
        if evidence:
            item["evidence"] = evidence
        loaders = take(payload.get("loaders"), 3)
        if loaders:
            item["loaders"] = loaders
        if transformers:
            item["transformers"] = take(transformers, 3)
            item["transformer_count"] = len(transformers)
        out.append(item)
    return out


def compact_loader_behaviors(loaders: Any) -> list[dict[str, Any]]:
    out = []
    for loader in take(loaders, 10):
        if not isinstance(loader, dict):
            continue
        functions = loader.get("functions") or []
        called_transformers = loader.get("called_transformers") or []
        item = {
            key: loader.get(key)
            for key in ("function", "kind", "confidence")
            if loader.get(key) is not None
        }
        for key in ("evidence", "allocation_constants", "protection_constants"):
            values = take(loader.get(key), 6)
            if values:
                item[key] = values
        if functions:
            item["functions"] = take(functions, 3)
            item["function_count"] = len(functions)
        if called_transformers:
            item["called_transformer_count"] = len(called_transformers)
        out.append(item)
    return out


def blob_prompt_score(blob: dict[str, Any]) -> float:
    reasons = set(blob.get("reasons") or [])
    try:
        entropy = float(blob.get("entropy") or 0)
    except (TypeError, ValueError):
        entropy = 0.0
    return (
        entropy
        + (6 if "large_copy_source" in reasons else 0)
        + (4 if "consumed_by_transformer" in reasons else 0)
        + (2 if blob.get("magic_offsets") else 0)
    )


def compact_payload_blobs(blobs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ranked = sorted(blobs, key=blob_prompt_score, reverse=True)
    out = []
    for blob in ranked[:3]:
        item = {
            key: blob.get(key)
            for key in ("section", "size", "entropy", "reasons", "duplicate_count")
            if blob.get(key) is not None
        }
        magic_offsets = take(blob.get("magic_offsets"), 3)
        if magic_offsets:
            item["magic_offsets"] = magic_offsets
        out.append(item)
    return out


def compact_interesting_functions(functions: Any) -> list[dict[str, Any]]:
    out = []
    for function in take(functions, 5):
        if not isinstance(function, dict):
            continue
        out.append(
            {
                "function": function.get("function"),
                "score": function.get("score"),
                "reasons": take(function.get("reasons"), 6),
            }
        )
    return out


def build_evaluator_view(report: dict[str, Any], input_path: Path) -> dict[str, Any]:
    semantic = report.get("semantic_analysis") if isinstance(report.get("semantic_analysis"), dict) else {}
    call_graph = report.get("call_graph") if isinstance(report.get("call_graph"), dict) else {}

    embedded_payloads = semantic.get("embedded_payloads") or []
    loader_behaviors = semantic.get("loader_behaviors") or []
    decryption_recovery = semantic.get("decryption_recovery") or {}
    decryption_summary = decryption_recovery.get("summary") if isinstance(decryption_recovery, dict) else {}
    payload_context = bool(
        embedded_payloads
        or loader_behaviors
        or (isinstance(decryption_summary, dict) and decryption_summary.get("xor_recovered_artifact_count"))
        or (isinstance(decryption_summary, dict) and decryption_summary.get("aes_decrypted_artifact_count"))
    )

    suspicious_blobs = semantic.get("suspicious_data_blobs") or []
    payload_blobs = []
    for blob in take(suspicious_blobs, 40):
        if not isinstance(blob, dict):
            continue
        magic = blob.get("magic_offsets") or []
        reasons = blob.get("reasons") or []
        is_large_payload_candidate = "large_copy_source" in reasons
        if payload_context or is_large_payload_candidate:
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
        "behavior_story": compact_behavior_story(semantic.get("behavior_story") or {}),
        "top_level_summary": {
            "call_graph_functions": len(call_graph),
            "behavior_ir": (semantic.get("behavior_ir") or {}).get("summary", {}),
            "semantic_chain_summary": (semantic.get("semantic_chains") or {}).get("summary", {}),
            "assessment_hints": filtered_assessment_hints(semantic.get("assessment_hints"), payload_context),
        },
        "decryption_recovery": compact_value(decryption_recovery or {}, 500),
        "behavior_operations": collect_behavior_ops(
            semantic.get("behavior_ir") or {},
            {item.get("function") for item in loader_behaviors if isinstance(item, dict) and item.get("function")},
        ),
        "semantic_chains": collect_chains(semantic.get("semantic_chains") or {}),
        "runtime_decoding": collect_runtime_decoding(semantic.get("runtime_decoding") or {}),
        "embedded_payloads": compact_embedded_payloads(embedded_payloads),
        "loader_behaviors": compact_loader_behaviors(loader_behaviors),
        "suspicious_payload_blobs": compact_payload_blobs(payload_blobs),
        "behavior_strings": collect_strings(call_graph),
        "top_interesting_functions": compact_interesting_functions(semantic.get("interesting_functions")),
    }


def filtered_assessment_hints(hints: Any, payload_context: bool) -> list[Any]:
    out = []
    for hint in take(hints, 30):
        text = str(hint).lower()
        if not payload_context and ("high-entropy" in text or "magic-containing data blobs" in text):
            continue
        out.append(hint)
    return out


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

        Also write a concise behavioral summary in execution order, starting from main or the
        earliest user-level entry point Gobbler exposes. Describe the flow as actions, not
        implementation mechanics. Include concrete recovered artifacts when available, such as
        paths, URLs, commands, decoded payload names, PE loading, writes to disk, process
        spawning, registry changes, or network calls. If ordering is uncertain, say so briefly
        while still summarizing the likely behavior.

        Ignore debug implementation details such as array IDs, addresses, Go runtime noise,
        stack checks, GC calls, and generic compiler artifacts unless they support a behavior.
        Treat generic high-entropy Go data sections or incidental MZ/PE byte sequences as weak
        evidence unless Gobbler also shows loader behavior, executable memory, decoded payloads,
        or an embedded payload object tying the data to runtime behavior.

        Return only valid JSON with this exact shape:
        {{
          "verdict": "clean|suspicious|dirty|unknown",
          "behavioral_summary": "one short paragraph summarizing the likely execution flow from main",
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


def call_openrouter(prompt: str, args: argparse.Namespace, api_key: str) -> dict[str, Any]:
    payload = {
        "model": args.model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": args.temperature,
        "max_tokens": args.max_tokens,
    }
    if not args.no_json_mode:
        payload["response_format"] = {"type": "json_object"}

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }
    if args.http_referer:
        headers["HTTP-Referer"] = args.http_referer
    if args.app_title:
        headers["X-OpenRouter-Title"] = args.app_title

    request = urllib.request.Request(
        args.endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=args.timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"OpenRouter HTTP {exc.code}: {detail[:800]}") from exc


def extract_response_text(response: dict[str, Any]) -> str:
    choices = response.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ValueError("OpenRouter response did not contain choices")
    message = choices[0].get("message") if isinstance(choices[0], dict) else None
    content = message.get("content") if isinstance(message, dict) else None
    if isinstance(content, list):
        text = "\n".join(str(part.get("text", "")) for part in content if isinstance(part, dict))
    else:
        text = str(content or "")
    if not text:
        raise ValueError("OpenRouter response did not contain message content")
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
        raise ValueError("model returned JSON, but not an object")
    return parsed


def normalize_verdict(result: dict[str, Any], model: str, provider: str, raw_response: dict[str, Any]) -> dict[str, Any]:
    verdict = str(result.get("verdict", "unknown")).lower()
    if verdict not in {"clean", "suspicious", "dirty", "unknown"}:
        verdict = "unknown"

    indicators = result.get("indicators")
    if not isinstance(indicators, dict):
        indicators = {}
    normalized_indicators = {
        key: take(indicators.get(key), 100)
        for key in ("urls", "domains", "ips", "paths", "commands", "mutexes", "payloads", "other")
    }
    usage = raw_response.get("usage", {})
    cost = usage.get("cost") if isinstance(usage, dict) else None
    behavioral_summary = result.get("behavioral_summary", "")
    if not isinstance(behavioral_summary, str):
        behavioral_summary = ""
    behavioral_summary = " ".join(behavioral_summary.split())[:2000]

    return {
        "verdict": verdict,
        "behavioral_summary": behavioral_summary,
        "reasoning": take(result.get("reasoning"), 20),
        "key_behaviors": take(result.get("key_behaviors"), 30),
        "indicators": normalized_indicators,
        "caveats": take(result.get("caveats"), 20),
        "model": model,
        "provider": provider,
        "usage": usage,
        "cost": cost,
    }


def write_output(result: dict[str, Any], out_path: Path | None) -> None:
    rendered = json.dumps(result, indent=2, sort_keys=True)
    if out_path:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)


def load_env_file(path: Path, key_name: str) -> None:
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


def main() -> int:
    args = parse_args()
    load_env_file(args.env_file, args.api_key_env)
    api_key = os.environ.get(args.api_key_env)
    if not api_key:
        print(f"{args.api_key_env} is required", file=sys.stderr)
        return 2

    try:
        report = json.loads(args.input_json.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"failed to read Gobbler JSON: {exc}", file=sys.stderr)
        return 2

    evidence = build_evaluator_view(report, args.input_json)
    prompt = build_prompt(evidence, args.max_prompt_json_chars)

    try:
        response = call_openrouter(prompt, args, api_key)
        text = extract_response_text(response)
        result = normalize_verdict(parse_model_json(text), args.model, "openrouter", response)
    except (urllib.error.URLError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        print(f"LLM evaluation failed: {exc}", file=sys.stderr)
        return 1

    write_output(result, args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
