"""LLM verdict pass for Gobbler analysis JSON."""

from __future__ import annotations

import json
import re
import textwrap
from pathlib import Path
from typing import Any

from gobbler.llm.provider import CompleteJSONFn, LLMConfig, complete_json


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

VERDICT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "verdict": {"type": "string", "enum": ["clean", "dirty", "unknown"]},
        "behavioral_summary": {"type": "string"},
        "reasoning": {"type": "array", "items": {"type": "string"}},
        "key_behaviors": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": True,
                "properties": {
                    "kind": {"type": "string"},
                    "description": {"type": "string"},
                    "evidence": {"type": "array", "items": {"type": "string"}},
                },
            },
        },
        "indicators": {
            "type": "object",
            "additionalProperties": True,
            "properties": {
                "urls": {"type": "array", "items": {"type": "string"}},
                "domains": {"type": "array", "items": {"type": "string"}},
                "ips": {"type": "array", "items": {"type": "string"}},
                "paths": {"type": "array", "items": {"type": "string"}},
                "commands": {"type": "array", "items": {"type": "string"}},
                "mutexes": {"type": "array", "items": {"type": "string"}},
                "embedded_artifacts": {"type": "array", "items": {"type": "string"}},
                "other": {"type": "array", "items": {"type": "string"}},
            },
        },
        "caveats": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["verdict", "behavioral_summary", "reasoning", "key_behaviors", "indicators", "caveats"],
}

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


def compact_embedded_artifacts(payloads: Any) -> list[dict[str, Any]]:
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


def compact_static_data_blobs(blobs: list[dict[str, Any]]) -> list[dict[str, Any]]:
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


def compact_artifact_classification(artifacts: Any) -> dict[str, Any]:
    if not isinstance(artifacts, dict):
        return {}
    return {
        "summary": compact_artifact_summary(artifacts.get("summary")),
        "embedded_artifacts": compact_classified_sources(artifacts.get("embedded_artifacts"), 2),
        "notable_blobs": compact_classified_sources(artifacts.get("notable_blobs"), 2),
        "decoded_artifacts": take(artifacts.get("decoded_artifacts"), 3),
    }


def compact_artifact_summary(summary: Any) -> dict[str, Any]:
    if not isinstance(summary, dict):
        return {}
    return {
        key: summary.get(key)
        for key in (
            "classified_notable_blob_count",
            "classified_embedded_artifact_count",
            "decoded_artifact_count",
            "type_counts",
            "magika_available",
        )
        if summary.get(key) not in (None, [], {})
    }


def compact_classified_sources(items: Any, limit: int) -> list[dict[str, Any]]:
    out = []
    for item in take(items, limit):
        if not isinstance(item, dict):
            continue
        classification = item.get("artifact_classification") if isinstance(item.get("artifact_classification"), dict) else {}
        compacted = {
            key: item.get(key)
            for key in ("id", "kind", "section", "size", "entropy", "confidence")
            if item.get(key) is not None
        }
        compacted["classification"] = {
            key: classification.get(key)
            for key in ("type", "mime_type", "confidence", "signals", "entropy", "printable_ratio")
            if classification.get(key) not in (None, [], {})
        }
        magic_offsets = take(classification.get("magic_offsets"), 3)
        if magic_offsets:
            compacted["classification"]["magic_offsets"] = magic_offsets
        strings = take(classification.get("strings"), 3)
        if strings:
            compacted["classification"]["strings"] = strings
        magika = classification.get("magika")
        if isinstance(magika, dict) and magika:
            compacted["classification"]["magika"] = magika
        out.append(compacted)
    return out


def compact_go_types(go_types: Any) -> dict[str, Any]:
    if not isinstance(go_types, dict):
        return {}
    return {
        "summary": compact_go_type_summary(go_types.get("summary")),
        "interesting_packages": [
            package
            for package in take(go_types.get("packages"), 8)
            if isinstance(package, dict) and package.get("interesting_terms")
        ][:4],
        "interesting_types": compact_type_items(go_types.get("interesting_types"), 4),
        "struct_like_types": compact_type_items(go_types.get("struct_like_types"), 2),
        "interface_like_types": compact_type_items(go_types.get("interface_like_types"), 2),
    }


def compact_go_type_summary(summary: Any) -> dict[str, Any]:
    if not isinstance(summary, dict):
        return {}
    return {
        key: summary.get(key)
        for key in (
            "available",
            "go_version",
            "module_path",
            "goos",
            "goarch",
            "extraction_sources",
            "package_count",
            "type_name_count",
            "declared_type_record_count",
            "struct_like_type_count",
            "interface_like_type_count",
            "interesting_type_count",
            )
        if summary.get(key) not in (None, [], {})
    }


def compact_type_items(items: Any, limit: int) -> list[dict[str, Any]]:
    out = []
    for item in take(items, limit):
        if not isinstance(item, dict):
            continue
        out.append(
            {
                key: item.get(key)
                for key in ("name", "kind", "matched_terms", "score")
                if item.get(key) not in (None, [], {})
            }
        )
    return out


def compact_sink_args(sink_args: Any) -> dict[str, Any]:
    if not isinstance(sink_args, dict):
        return {}
    return {
        "summary": sink_args.get("summary", {}),
        "sinks": [compact_sink(item) for item in take(sink_args.get("sinks"), 10) if isinstance(item, dict)],
    }


def compact_sink(item: dict[str, Any]) -> dict[str, Any]:
    compacted = {
        key: item.get(key)
        for key in ("function", "target", "kind", "category", "address", "operation_summary")
        if item.get(key) not in (None, [], {})
    }
    arg_roles = item.get("arg_roles")
    if isinstance(arg_roles, dict) and arg_roles:
        compacted["arg_roles"] = compact_value(arg_roles, 180)
    strings = take(item.get("strings"), 5)
    if strings:
        compacted["strings"] = strings
    artifacts = take(item.get("artifacts"), 5)
    if artifacts:
        compacted["artifacts"] = artifacts
    args = item.get("args")
    if isinstance(args, dict) and args:
        compacted["args"] = compact_value(args, 160)
    data_sources = take(item.get("data_sources"), 2)
    if data_sources:
        compacted["data_sources"] = data_sources
    evidence = take(item.get("evidence"), 5)
    if evidence:
        compacted["evidence"] = evidence
    return compacted


def build_evaluator_view(report: dict[str, Any], input_path: Path) -> dict[str, Any]:
    semantic = report.get("semantic_analysis") if isinstance(report.get("semantic_analysis"), dict) else {}
    call_graph = report.get("call_graph") if isinstance(report.get("call_graph"), dict) else {}

    embedded_artifacts = semantic.get("embedded_artifacts") or []
    loader_behaviors = semantic.get("loader_behaviors") or []
    decryption_recovery = semantic.get("decryption_recovery") or {}
    decryption_summary = decryption_recovery.get("summary") if isinstance(decryption_recovery, dict) else {}
    payload_context = bool(
        embedded_artifacts
        or loader_behaviors
        or (isinstance(decryption_summary, dict) and decryption_summary.get("xor_recovered_artifact_count"))
        or (isinstance(decryption_summary, dict) and decryption_summary.get("aes_decrypted_artifact_count"))
    )

    notable_blobs = semantic.get("notable_data_blobs") or []
    notable_artifact_blobs = []
    for blob in take(notable_blobs, 40):
        if not isinstance(blob, dict):
            continue
        magic = blob.get("magic_offsets") or []
        reasons = blob.get("reasons") or []
        is_large_payload_candidate = "large_copy_source" in reasons
        if payload_context or is_large_payload_candidate:
            notable_artifact_blobs.append(
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
            "binary_info": semantic.get("binary_info", {}),
            "call_graph_functions": len(call_graph),
            "behavior_ir": (semantic.get("behavior_ir") or {}).get("summary", {}),
            "semantic_chain_summary": (semantic.get("semantic_chains") or {}).get("summary", {}),
            "assessment_hints": filtered_assessment_hints(semantic.get("assessment_hints"), payload_context),
            "imports": compact_value(semantic.get("imports") or {}, 500),
        },
        "decryption_recovery": compact_value(decryption_recovery or {}, 500),
        "artifact_classification": compact_artifact_classification(semantic.get("artifact_classification")),
        "go_types": compact_go_types(semantic.get("go_types")),
        "sink_args": compact_sink_args(semantic.get("sink_args")),
        "behavior_operations": collect_behavior_ops(
            semantic.get("behavior_ir") or {},
            {item.get("function") for item in loader_behaviors if isinstance(item, dict) and item.get("function")},
        ),
        "semantic_chains": collect_chains(semantic.get("semantic_chains") or {}),
        "runtime_decoding": collect_runtime_decoding(semantic.get("runtime_decoding") or {}),
        "embedded_artifacts": compact_embedded_artifacts(embedded_artifacts),
        "loader_behaviors": compact_loader_behaviors(loader_behaviors),
        "notable_static_data": compact_static_data_blobs(notable_artifact_blobs),
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
        You are a binary behavior evaluator reviewing Gobbler semantic output for a Go binary.

        Decide whether the binary is clean, dirty, or unknown. Focus on what the
        binary appears to do to the system: file I/O, network activity, process creation,
        command execution, memory execution, dynamic loading, persistence, decoded artifacts,
        embedded static artifacts, and crypto/decoder use.

        Do not use a middle-ground verdict. If the evidence shows behavior that would
        normally make an analyst call the binary malicious or unwanted, return dirty. Use unknown
        only when Gobbler output is too sparse, contradictory, or failed to expose meaningful
        behavior. Use clean only for ordinary benign behavior without loader, persistence,
        credential/secret, process-spawn, destructive file, or unusual network evidence.

        Also write a concise behavioral summary in execution order, starting from main or the
        earliest user-level entry point Gobbler exposes. Describe the flow as actions, not
        implementation mechanics. Include concrete recovered artifacts when available, such as
        paths, URLs, commands, decoded artifact names, PE/ELF loading, writes to disk, process
        spawning, registry changes, or network calls. If ordering is uncertain, say so briefly
        while still summarizing the likely behavior.

        Ignore debug implementation details such as array IDs, addresses, Go runtime noise,
        stack checks, GC calls, and generic compiler artifacts unless they support a behavior.
        Use Gobbler fields as observations, not conclusions about intent. Treat generic high-entropy
        Go data sections or incidental MZ/PE/ELF byte sequences as weak
        evidence unless Gobbler also shows loader behavior, executable memory, decoded artifacts,
        or an embedded artifact object tying the data to runtime behavior.

        Return dirty for strong malicious-behavior combinations, including:
        - reflective PE/ELF loading or manual executable mapping
        - embedded executable/static artifact transformed and passed to loader-relevant code
        - executable memory allocation/protection changes combined with raw syscalls or dynamic API resolution
        - decoded payloads/configuration used with file, process, network, persistence, or loader behavior
        - process execution, persistence, credential/secret artifacts, or destructive filesystem behavior with concrete arguments

        Return only valid JSON with this exact shape:
        {{
          "verdict": "clean|dirty|unknown",
          "behavioral_summary": "one short paragraph summarizing the likely execution flow from main",
          "reasoning": ["short reason 1", "short reason 2"],
          "key_behaviors": [
            {{
              "kind": "file_io|network|process_execution|dynamic_code_loading|persistence|credential_or_secret_artifact|runtime_decoding|embedded_artifact|other",
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
            "embedded_artifacts": [],
            "other": []
          }},
          "caveats": ["analysis limitations or uncertainty"]
        }}

        Gobbler evaluator evidence:
        {evidence_json}
        """
    ).strip()


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
    if verdict == "suspicious":
        verdict = "dirty"
    if verdict not in {"clean", "dirty", "unknown"}:
        verdict = "unknown"

    indicators = result.get("indicators")
    if not isinstance(indicators, dict):
        indicators = {}
    normalized_indicators = {
        key: take(indicators.get(key), 100)
        for key in ("urls", "domains", "ips", "paths", "commands", "mutexes", "embedded_artifacts", "other")
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


def analyze_llm_verdict(
    report: dict[str, Any],
    input_path: Path | str,
    config: LLMConfig,
    complete_fn: CompleteJSONFn | None = None,
    max_prompt_json_chars: int = MAX_PROMPT_JSON_CHARS,
    schema: dict[str, Any] | None = VERDICT_SCHEMA,
) -> dict[str, Any]:
    evidence = build_evaluator_view(report, Path(input_path))
    prompt = build_prompt(evidence, max_prompt_json_chars)
    completion = (complete_fn or complete_json)(prompt, config, schema)

    parsed = completion.parsed_json
    if not isinstance(parsed, dict):
        parsed = parse_model_json(completion.text)

    raw_response = completion.raw_response if isinstance(completion.raw_response, dict) else {}
    usage = dict(completion.usage or {})
    if completion.cost is not None:
        usage.setdefault("cost", completion.cost)
    if usage:
        raw_response = {**raw_response, "usage": usage}
    normalized = normalize_verdict(
        parsed,
        completion.model or config.model,
        config.provider_name,
        raw_response,
    )
    if completion.cost is not None:
        normalized["cost"] = completion.cost
    return normalized


def write_output(result: dict[str, Any], out_path: Path | None) -> None:
    rendered = json.dumps(result, indent=2, sort_keys=True)
    if out_path:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
