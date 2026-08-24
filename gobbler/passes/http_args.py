from __future__ import annotations

import re
from typing import Any


MAX_PREVIEW = 240
MAX_BODY_COMPONENTS = 8


HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
BODY_BUILDER_MARKERS = (
    "strings.NewReader",
    "bytes.NewReader",
    "bytes.NewBuffer",
    "bytes.NewBufferString",
    "io.NopCloser",
)


def enrich_http_arguments(
    sink: dict[str, Any],
    body_producers: dict[str, list[dict[str, Any]]] | None = None,
) -> None:
    if sink.get("category") != "network":
        return
    shape = http_shape(sink)
    if shape is None:
        return

    named: dict[str, Any] = {"api_shape": shape}
    ordered_strings = ordered_string_arguments(sink)
    typed_args = typed_arguments(sink)
    producers = (body_producers or {}).get(sink.get("function") or "", [])

    if shape == "http_get":
        url = string_at(ordered_strings, 0) or first_url_candidate(sink)
        if url:
            named["method"] = "GET"
            named["url"] = argument_value(url)
    elif shape == "http_post":
        url = first_url_candidate(sink) or string_at(ordered_strings, 0)
        content_type = first_content_type_candidate(sink) or string_at(ordered_strings, 1)
        if url:
            named["method"] = "POST"
            named["url"] = argument_value(url)
        if content_type:
            named["content_type"] = argument_value(content_type)
        named["body"] = infer_body_argument(sink, typed_args, producers)
    elif shape == "http_new_request":
        method = string_at(ordered_strings, 0)
        url = string_at(ordered_strings, 1) or first_url_candidate(sink)
        if method and method["value"].upper() in HTTP_METHODS:
            named["method"] = argument_value(method, transform=str.upper)
        if url:
            named["url"] = argument_value(url)
        named["body"] = infer_body_argument(sink, typed_args, producers)
    elif shape in {"http_client_do", "http_request_write"}:
        url = first_url_candidate(sink)
        if url:
            named["url"] = argument_value(url)
        named["request"] = {
            "source": "request_object_argument",
            "classification": "request_object",
        }

    if useful_http_arguments(named):
        sink["http_arguments"] = named


def http_shape(sink: dict[str, Any]) -> str | None:
    kind = str(sink.get("kind") or "").lower()
    target = str(sink.get("target") or sink.get("api") or "")
    lowered = target.lower()
    if kind == "http_get" or "http.get" in lowered:
        return "http_get"
    if kind == "http_post" or "http.post" in lowered or ".post" in lowered:
        return "http_post"
    if kind == "http_request" or "http.newrequest" in lowered or "http.newrequestwithcontext" in lowered:
        return "http_new_request"
    if "client).do" in lowered or "client.do" in lowered:
        return "http_client_do"
    if "request).write" in lowered or "request.write" in lowered:
        return "http_request_write"
    return None


def ordered_string_arguments(sink: dict[str, Any]) -> list[dict[str, Any]]:
    values: list[dict[str, Any]] = []
    values.extend(strings_from_typed_pairs(sink))
    for key, value in (sink.get("args") or {}).get("registers", {}).items():
        if isinstance(value, str):
            values.append({"location": key, "value": value, "source": "call_graph"})
    for item in (sink.get("args") or {}).get("typed_string_args", []):
        if isinstance(item, dict) and isinstance(item.get("value"), str):
            values.append(
                {
                    "location": item.get("location"),
                    "value": item.get("value"),
                    "source": "dataflow",
                }
            )
    if not values:
        for index, value in enumerate(sink.get("strings") or []):
            if isinstance(value, str):
                values.append({"location": f"strings[{index}]", "value": value, "source": "sink_strings"})
    return dedupe_ordered(values)


def typed_arguments(sink: dict[str, Any]) -> list[dict[str, Any]]:
    args = sink.get("args") or {}
    values = []
    for key in ("typed_args", "typed_stack_args"):
        for item in args.get(key) or []:
            if isinstance(item, dict):
                values.append(item)
    return values


def string_at(values: list[dict[str, Any]], index: int) -> dict[str, Any] | None:
    if index >= len(values):
        return None
    return values[index]


def first_url_candidate(sink: dict[str, Any]) -> dict[str, Any] | None:
    for value in sink.get("strings") or []:
        if isinstance(value, str) and looks_like_url(value):
            return {"value": clean_url(value), "source": "sink_strings"}
    for artifact in sink.get("artifacts") or []:
        if artifact.get("type") == "url" and isinstance(artifact.get("value"), str):
            return {"value": clean_url(artifact["value"]), "source": "artifact"}
    for source in sink.get("data_sources") or []:
        for key in ("preview", "text_preview"):
            value = source.get(key)
            if isinstance(value, str) and looks_like_url(value):
                return {"value": clean_url(value), "source": "static_data_preview"}
    return None


def first_content_type_candidate(sink: dict[str, Any]) -> dict[str, Any] | None:
    for item in ordered_string_arguments(sink):
        value = item.get("value")
        if isinstance(value, str) and looks_like_content_type(value):
            return item
    for source in sink.get("data_sources") or []:
        for key in ("preview", "text_preview"):
            value = source.get(key)
            if not isinstance(value, str):
                continue
            content_type = extract_content_type(value)
            if content_type:
                return {"value": content_type, "source": "static_data_preview"}
    return None


def argument_value(item: dict[str, Any], transform=None) -> dict[str, Any]:
    value = item.get("value")
    if transform and isinstance(value, str):
        value = transform(value)
    result = {"value": value, "source": item.get("source") or "recovered_argument"}
    if item.get("location"):
        result["location"] = item["location"]
    return result


def infer_body_argument(
    sink: dict[str, Any],
    typed_args: list[dict[str, Any]],
    producers: list[dict[str, Any]],
) -> dict[str, Any]:
    producer = producer_for_sink(sink, typed_args, producers)
    if producer is not None:
        return body_from_producer(producer)

    body_candidate = body_from_static_data(sink)
    if body_candidate is not None:
        return body_candidate

    for arg in typed_args:
        if arg.get("kind") == "call_return":
            label = str(arg.get("label") or "")
            if any(marker in label for marker in BODY_BUILDER_MARKERS):
                return {
                    "source": "reader_or_buffer_call_return",
                    "producer": label,
                    "classification": "body_reader",
                }

    data_sources = sink.get("data_sources") or []
    if data_sources:
        return {
            "source": "related_static_data",
            "classification": "data_source",
            "components": compact_body_components(data_sources),
        }

    return {
        "source": "unresolved_reader_or_interface",
        "classification": "unknown_body",
    }


def body_from_static_data(sink: dict[str, Any]) -> dict[str, Any] | None:
    for source in sink.get("data_sources") or []:
        for key in ("text_preview", "preview"):
            value = source.get(key)
            if not isinstance(value, str):
                continue
            body = extract_body_candidate(value)
            if not body:
                continue
            return {
                "source": "nearby_static_body_candidate",
                "classification": classify_body_preview(body),
                "preview": preview(body),
                "source_kind": source.get("kind"),
            }
    return None


def producer_for_sink(
    sink: dict[str, Any],
    typed_args: list[dict[str, Any]],
    producers: list[dict[str, Any]],
) -> dict[str, Any] | None:
    if not producers:
        return None
    sink_address = parse_hex(sink.get("address"))
    targets = {
        str(arg.get("label") or "")
        for arg in typed_args
        if arg.get("kind") == "call_return"
    }
    candidates = [
        producer
        for producer in producers
        if not targets or any(marker in producer.get("target", "") for marker in targets)
    ]
    if sink_address is not None:
        before = [item for item in candidates if parse_hex(item.get("address")) is not None and parse_hex(item.get("address")) <= sink_address]
        if before:
            return max(before, key=lambda item: parse_hex(item.get("address")) or 0)
    return candidates[-1] if candidates else None


def body_from_producer(producer: dict[str, Any]) -> dict[str, Any]:
    strings = [item for item in producer.get("strings") or [] if isinstance(item, str)]
    slices = producer.get("slices") or []
    if strings:
        body = {
            "source": "literal_body_reader",
            "producer": producer.get("target"),
            "classification": classify_body_preview(strings[0]),
            "preview": preview(strings[0]),
        }
        if len(strings) > 1:
            body["components"] = [preview(value) for value in strings[:MAX_BODY_COMPONENTS]]
        return body
    if slices:
        return {
            "source": "byte_slice_body_reader",
            "producer": producer.get("target"),
            "classification": "byte_slice",
            "components": compact_body_components(slices),
        }
    return {
        "source": "reader_or_buffer_call",
        "producer": producer.get("target"),
        "classification": "body_reader",
    }


def compact_body_components(values: list[Any]) -> list[Any]:
    components = []
    for value in values[:MAX_BODY_COMPONENTS]:
        if isinstance(value, dict):
            compact = {
                key: value.get(key)
                for key in ("kind", "label", "size", "entropy", "preview", "source")
                if value.get(key) not in (None, "", [], {})
            }
            if compact:
                components.append(compact)
        elif isinstance(value, str):
            components.append(preview(value))
    return components


def classify_body_preview(value: str) -> str:
    text = value.strip()
    if text.startswith("{") or text.startswith("["):
        return "json_like"
    if "=" in text and "&" in text:
        return "form_like"
    if looks_like_url(text):
        return "url_like"
    return "literal_string"


def useful_http_arguments(named: dict[str, Any]) -> bool:
    return any(key in named for key in ("url", "method", "content_type", "body", "request"))


def body_producers_from_dataflow(semantics: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {}
    dataflow = semantics.get("dataflow") or {}
    for function, facts in (dataflow.get("functions") or {}).items():
        for call in facts.get("call_arguments") or []:
            target = str(call.get("target") or "")
            if not any(marker in target for marker in BODY_BUILDER_MARKERS):
                continue
            producer = {
                "function": function,
                "target": target,
                "address": call.get("address"),
                "strings": [item.get("value") for item in call.get("string_args") or [] if isinstance(item, dict) and item.get("value")],
                "slices": call.get("slice_args") or [],
            }
            result.setdefault(function, []).append(producer)
    for producers in result.values():
        producers.sort(key=lambda item: parse_hex(item.get("address")) or 0)
    return result


def compact_typed_call_args(call_args: dict[str, Any] | None) -> dict[str, list[dict[str, Any]]]:
    if not isinstance(call_args, dict):
        return {}
    result: dict[str, list[dict[str, Any]]] = {}
    typed = [compact_arg(arg) for arg in call_args.get("args") or []]
    typed = [arg for arg in typed if arg]
    if typed:
        result["typed_args"] = typed[:12]
    stack = [compact_stack_arg(arg) for arg in call_args.get("stack_args") or []]
    stack = [arg for arg in stack if arg]
    if stack:
        result["typed_stack_args"] = stack[:12]
    strings = [compact_string_arg(arg) for arg in call_args.get("string_args") or []]
    strings = [arg for arg in strings if arg]
    if strings:
        result["typed_string_args"] = strings[:12]
    return result


def compact_arg(arg: Any) -> dict[str, Any]:
    if not isinstance(arg, dict):
        return {}
    result = {
        key: arg.get(key)
        for key in ("reg", "kind", "label", "address", "value")
        if arg.get(key) not in (None, "", [], {})
    }
    metadata = arg.get("metadata") or {}
    if metadata.get("target"):
        result["producer"] = metadata.get("target")
    if metadata.get("call_address"):
        result["producer_address"] = metadata.get("call_address")
    return result


def compact_stack_arg(arg: Any) -> dict[str, Any]:
    if not isinstance(arg, dict):
        return {}
    value = compact_arg(arg.get("value") or {})
    if not value:
        return {}
    value["reg"] = arg.get("slot")
    return value


def compact_string_arg(arg: Any) -> dict[str, Any]:
    if not isinstance(arg, dict) or not isinstance(arg.get("value"), str):
        return {}
    return {
        "location": string_arg_location(arg),
        "value": arg.get("value"),
    }


def string_arg_location(arg: dict[str, Any]) -> str | None:
    ptr = arg.get("ptr_reg")
    length = arg.get("len_reg")
    if ptr and length:
        return f"{ptr}/{length}"
    return None


def dedupe_ordered(values: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    result = []
    for item in values:
        key = (item.get("location"), item.get("value"))
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def parse_hex(value: Any) -> int | None:
    if not isinstance(value, str):
        return None
    try:
        return int(value, 16)
    except ValueError:
        return None


def looks_like_url(value: str) -> bool:
    return bool(re.match(r"https?://[A-Za-z0-9_.:-]+", value))


def clean_url(value: str) -> str:
    match = re.search(r"https?://", value)
    if not match:
        return value
    start = match.start()
    value = value[start:]
    second = re.search(r"https?:", value[match.end() - start :])
    if second:
        value = value[: match.end() - start + second.start()]
    return value.rstrip(".,);]}'\"")


def looks_like_content_type(value: str) -> bool:
    return extract_content_type(value) is not None


def extract_content_type(value: str) -> str | None:
    common = re.search(
        r"(application/json|application/x-www-form-urlencoded|application/octet-stream|multipart/form-data|text/plain|text/html|text/xml)",
        value,
        flags=re.IGNORECASE,
    )
    if common:
        return common.group(1)
    match = re.search(
        r"(?:application|text|multipart|image|audio|video)/[A-Za-z0-9_.+-]+",
        value,
    )
    return match.group(0) if match else None


def extract_body_candidate(value: str) -> str | None:
    json_match = re.search(r"(\{[^{}]{2,240}\}|\[[^\[\]]{2,240}\])", value)
    if json_match:
        return json_match.group(1)
    form_match = re.search(r"\b[A-Za-z0-9_.-]+=[^&\s]{1,120}(?:&[A-Za-z0-9_.-]+=[^&\s]{1,120})+", value)
    if form_match:
        return form_match.group(0)
    return None


def strings_from_typed_pairs(sink: dict[str, Any]) -> list[dict[str, Any]]:
    typed = typed_arguments(sink)
    if not typed:
        return []
    by_reg = {arg.get("reg"): arg for arg in typed if arg.get("reg")}
    order = ("RAX", "RBX", "RCX", "RDI", "RSI", "R8", "R9", "R10", "R11")
    start = 1 if receiver_method_shape(sink) else 0
    values = []
    for index in range(start, len(order) - 1, 2):
        ptr_reg = order[index]
        len_reg = order[index + 1]
        pointer = by_reg.get(ptr_reg)
        length = by_reg.get(len_reg)
        if not pointer or not length or length.get("kind") != "int":
            continue
        text = string_from_pointer_length(sink, pointer, int(length.get("value") or 0))
        if not text:
            continue
        values.append(
            {
                "location": f"{ptr_reg}/{len_reg}",
                "value": text,
                "source": "typed_pointer_length",
            }
        )
    return values


def receiver_method_shape(sink: dict[str, Any]) -> bool:
    target = str(sink.get("target") or sink.get("api") or "")
    return "(*" in target or ")." in target


def string_from_pointer_length(sink: dict[str, Any], pointer: dict[str, Any], length: int) -> str | None:
    value = pointer.get("value")
    if isinstance(value, str) and 0 < length <= len(value):
        return value[:length]
    label = pointer.get("label")
    candidates = []
    for source in sink.get("data_sources") or []:
        if label and source.get("id") not in {None, label}:
            continue
        for key in ("preview", "text_preview"):
            source_value = source.get(key)
            if isinstance(source_value, str):
                candidates.append(source_value)
    if not candidates and not label:
        candidates = [
            value
            for value in sink.get("strings") or []
            if isinstance(value, str)
        ]
    for candidate in candidates:
        if length <= 0:
            continue
        if looks_like_url(candidate):
            return clean_url(candidate)
        content_type = extract_content_type(candidate)
        if content_type:
            return content_type
        body = extract_body_candidate(candidate)
        if body and len(body) == length:
            return body
    return None


def preview(value: str) -> str:
    value = " ".join(value.split())
    if len(value) > MAX_PREVIEW:
        return value[:MAX_PREVIEW] + "...<truncated>"
    return value
