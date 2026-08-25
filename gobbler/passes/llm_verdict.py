"""LLM verdict pass for Gobbler analysis JSON."""

from __future__ import annotations

import json
import re
import textwrap
from pathlib import Path
from typing import Any

from gobbler.llm.provider import CompleteJSONFn, LLMConfig, complete_json
from gobbler.output.evaluator import build_evaluator_document


DEFAULT_MODEL = "google/gemini-2.5-flash"
DEFAULT_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_APP_TITLE = "Gobbler Eval"
MAX_PROMPT_JSON_CHARS = 160_000

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


def build_evaluator_view(report: dict[str, Any], input_path: Path) -> dict[str, Any]:
    return build_evaluator_document(report, input_path)


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
