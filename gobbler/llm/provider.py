"""Small replaceable interface for JSON LLM completions.

The project should call ``complete_json(prompt, config, schema)``. To use a
different provider, replace that function with an implementation that returns
``LLMResponse``.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, TypeAlias

import requests


@dataclass(slots=True)
class LLMConfig:
    model: str
    provider_name: str = "openrouter"
    api_key: str | None = None
    api_key_env: str = "LLM_KEY"
    env_file: str | Path | None = ".env"
    endpoint: str = "https://openrouter.ai/api/v1/chat/completions"
    timeout: float = 90.0
    temperature: float = 0.0
    max_tokens: int | None = None
    site_url: str | None = None
    app_name: str = "gobbler"
    response_format: str | None = "json_object"
    extra_headers: dict[str, str] = field(default_factory=dict)
    provider_extras: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class LLMResponse:
    text: str
    parsed_json: Any | None = None
    usage: dict[str, Any] = field(default_factory=dict)
    cost: float | None = None
    model: str | None = None
    finish_reason: str | None = None
    raw_response: dict[str, Any] = field(default_factory=dict)


CompleteJSONFn: TypeAlias = Callable[[str, LLMConfig, dict[str, Any] | None], LLMResponse]


def load_env_file(path: str | Path | None, key: str) -> str | None:
    """Return ``key`` from a dotenv-style file without requiring python-dotenv."""
    if not path:
        return None
    env_path = Path(path)
    if not env_path.exists():
        return None
    try:
        lines = env_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None

    prefix = f"{key}="
    export_prefix = f"export {key}="
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(export_prefix):
            value = line[len(export_prefix) :]
        elif line.startswith(prefix):
            value = line[len(prefix) :]
        else:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        return value
    return None


def complete_json_openrouter(
    prompt: str,
    config: LLMConfig,
    schema: dict[str, Any] | None = None,
) -> LLMResponse:
    """Call an OpenRouter/OpenAI-style chat completions endpoint."""
    api_key = config.api_key or os.environ.get(config.api_key_env)
    if not api_key:
        api_key = load_env_file(config.env_file, config.api_key_env)
    if not api_key:
        raise RuntimeError(
            f"Missing LLM API key. Set config.api_key or {config.api_key_env}."
        )

    payload: dict[str, Any] = {
        "model": config.model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": config.temperature,
    }
    if config.max_tokens is not None:
        payload["max_tokens"] = config.max_tokens
    if config.response_format:
        payload["response_format"] = {"type": config.response_format}
    extras = dict(config.provider_extras)
    use_tools = bool(extras.pop("use_tools", False))
    if schema and use_tools:
        payload["tools"] = [
            {
                "type": "function",
                "function": {
                    "name": "emit_verdict_json",
                    "description": "Return the requested structured JSON object.",
                    "parameters": schema,
                },
            }
        ]
        payload["tool_choice"] = {
            "type": "function",
            "function": {"name": "emit_verdict_json"},
        }
    payload.update(extras)

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    if config.site_url:
        headers["HTTP-Referer"] = config.site_url
    if config.app_name:
        headers["X-OpenRouter-Title"] = config.app_name
    headers.update(config.extra_headers)

    try:
        response = requests.post(
            config.endpoint,
            json=payload,
            headers=headers,
            timeout=config.timeout,
        )
        response.raise_for_status()
        raw_body = response.text
    except requests.HTTPError as exc:
        body = exc.response.text if exc.response is not None else ""
        status = exc.response.status_code if exc.response is not None else "unknown"
        raise RuntimeError(f"LLM HTTP {status}: {body}") from exc
    except requests.RequestException as exc:
        raise RuntimeError(f"LLM request failed: {exc}") from exc

    try:
        raw = json.loads(raw_body)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"LLM returned non-JSON response: {raw_body[:500]}") from exc

    choice = _first_choice(raw)
    message = choice.get("message", {}) if isinstance(choice, dict) else {}
    text = _extract_message_text(message)
    parsed = _parse_json_text(text)
    usage = raw.get("usage") if isinstance(raw.get("usage"), dict) else {}
    cost = _extract_cost(raw, usage)

    return LLMResponse(
        text=text,
        parsed_json=parsed,
        usage=usage,
        cost=cost,
        model=raw.get("model") or config.model,
        finish_reason=choice.get("finish_reason") if isinstance(choice, dict) else None,
        raw_response=raw,
    )


def complete_json(
    prompt: str,
    config: LLMConfig,
    schema: dict[str, Any] | None = None,
) -> LLMResponse:
    """Default project LLM hook. Replace this function to swap providers."""
    return complete_json_openrouter(prompt, config, schema)


def _first_choice(raw: dict[str, Any]) -> dict[str, Any]:
    choices = raw.get("choices")
    if not isinstance(choices, list) or not choices:
        return {}
    first = choices[0]
    return first if isinstance(first, dict) else {}


def _extract_message_text(message: dict[str, Any]) -> str:
    tool_calls = message.get("tool_calls")
    if isinstance(tool_calls, list):
        for call in tool_calls:
            if not isinstance(call, dict):
                continue
            function = call.get("function")
            if isinstance(function, dict) and isinstance(function.get("arguments"), str):
                return function["arguments"]

    content = message.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for part in content:
            if isinstance(part, dict) and isinstance(part.get("text"), str):
                parts.append(part["text"])
            elif isinstance(part, str):
                parts.append(part)
        return "".join(parts)
    return ""


def _parse_json_text(text: str) -> Any | None:
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end > start:
        try:
            return json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            return None
    return None


def _extract_cost(raw: dict[str, Any], usage: dict[str, Any]) -> float | None:
    for container in (raw, usage):
        for key in ("cost", "total_cost", "estimated_cost"):
            value = container.get(key)
            if isinstance(value, (int, float)):
                return float(value)
            if isinstance(value, str):
                try:
                    return float(value.lstrip("$"))
                except ValueError:
                    continue
    return None
