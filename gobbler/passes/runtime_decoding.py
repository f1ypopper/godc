import base64
import binascii
import re
from typing import Any

from gobbler.utils.ownership import is_library_function


DECODER_TARGETS = {
    "encoding/base64": "base64",
    "encoding/hex": "hex",
    "compress/gzip": "gzip",
    "compress/zlib": "zlib",
    "crypto/aes": "aes",
    "crypto/rc4": "rc4",
    "chacha20": "chacha20",
}

STRING_MATERIALIZER_KINDS = {"bytes_to_string"}
MAX_STATIC_SOURCE_BYTES = 0x20000


def analyze_runtime_decoding(
    analyzer: Any, graph: dict[str, list[Any]], semantics: dict[str, Any]
) -> dict[str, Any]:
    behavior_ir = semantics.get("behavior_ir") or {}
    functions = behavior_ir.get("functions") or {}
    results = []
    generated_identifier_functions = {
        item.get("function")
        for item in ((semantics.get("semantic_chains") or {}).get("chains") or [])
        if item.get("kind") == "generated_identifier"
    }

    for function, item in functions.items():
        evidence = []
        decoder_calls = decoder_operations(item)
        materializers = string_materializers(item)
        transform_loops = (item.get("control") or {}).get("probable_transform_loops") or []
        static_sources = static_data_sources(item)
        literal_callers = callers_with_literals(graph, function)

        if decoder_calls:
            evidence.append("calls_decoder_api")
        if materializers:
            evidence.append("materializes_go_string_from_bytes")
        if transform_loops:
            evidence.append("has_byte_transform_loop")
        if static_sources:
            evidence.append("uses_static_data")
        if literal_callers:
            evidence.append("called_with_string_literals")

        classification = classify_decoding_behavior(
            decoder_calls,
            materializers,
            transform_loops,
            static_sources,
            literal_callers,
        )
        if classification is None:
            continue
        if (
            function in generated_identifier_functions
            and not decoder_calls
            and not literal_callers
        ):
            continue
        if is_library_function(function) and classification != "explicit_string_decoder":
            continue

        static_recoveries = recover_static_source_previews(analyzer, static_sources)
        result = (
            {
                "function": function,
                "classification": classification,
                "feature_labels": decoding_feature_labels(
                    decoder_calls,
                    materializers,
                    transform_loops,
                    static_sources,
                    literal_callers,
                    static_recoveries,
                ),
                "confidence": confidence_for_decoding(
                    decoder_calls,
                    materializers,
                    transform_loops,
                    static_sources,
                    literal_callers,
                    static_recoveries,
                ),
                "evidence": evidence,
                "decoder_calls": decoder_calls,
                "string_materializers": materializers,
                "transform_loops": transform_loops[:5],
                "static_sources": static_sources[:20],
                "static_source_recoveries": static_recoveries[:20],
                "literal_callers": literal_callers[:20],
            }
        )
        result["recovered_indicators"] = recovered_indicators_for_function(result)
        results.append(result)

    results.sort(
        key=lambda item: (
            confidence_rank(item["confidence"]),
            item["classification"],
            item["function"],
        )
    )
    return {
        "functions": results,
        "recovered_indicators": recovered_indicators_for_results(results),
        "summary": {
            "function_count": len(results),
            "explicit_decoder_api_count": sum(
                1 for item in results if "explicit_decoder_api" in item.get("feature_labels", [])
            ),
            "encoder_api_count": sum(
                1 for item in results if "encoder_api_usage" in item.get("feature_labels", [])
            ),
            "custom_decoder_candidate_count": sum(
                1 for item in results if "custom_decoder_candidate" in item.get("feature_labels", [])
            ),
            "runtime_string_materialization_count": sum(
                1
                for item in results
                if "runtime_string_materialization" in item.get("feature_labels", [])
            ),
            "likely_string_decoder_count": sum(
                1
                for item in results
                if "explicit_decoder_api" in item.get("feature_labels", [])
                or "custom_decoder_candidate" in item.get("feature_labels", [])
            ),
            "byte_transformer_string_output_count": sum(
                1
                for item in results
                if item["classification"] == "byte_transformer_materializes_string"
            ),
            "recovered_indicator_count": len(recovered_indicators_for_results(results)),
        },
    }


def decoder_operations(item: dict[str, Any]) -> list[dict[str, Any]]:
    operations = []
    for operation in item.get("flow", []):
        target = operation.get("target", "")
        kind = operation.get("kind", "")
        decoder = decoder_kind(target, kind)
        if decoder is None:
            continue
        operations.append(
            {
                "address": operation.get("address"),
                "target": target,
                "decoder": decoder,
                "direction": decoder_direction(target, kind),
                "string_args": operation.get("string_args", []),
            }
        )
    return operations


def decoder_kind(target: str, kind: str) -> str | None:
    if kind in {"base64_decode_or_encode", "hex_decode_or_encode"}:
        return kind.split("_", 1)[0]
    for needle, label in DECODER_TARGETS.items():
        if needle in target:
            return label
    return None


def decoder_direction(target: str, kind: str) -> str:
    lowered = f"{target} {kind}".lower()
    if "encode" in lowered:
        return "encode"
    if "decode" in lowered:
        return "decode"
    if any(needle in lowered for needle in ("aes", "rc4", "cipher", "chacha20")):
        return "crypto"
    if any(needle in lowered for needle in ("gzip", "zlib", "compress")):
        return "codec"
    return "unknown"


def string_materializers(item: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "address": operation.get("address"),
            "target": operation.get("target"),
            "kind": operation.get("kind"),
        }
        for operation in item.get("flow", [])
        if operation.get("kind") in STRING_MATERIALIZER_KINDS
    ]


def static_data_sources(item: dict[str, Any]) -> list[dict[str, Any]]:
    data = item.get("data") or {}
    sources = []
    for key in ("data_blobs", "constant_arrays", "strings"):
        for source in data.get(key, []):
            sources.append({"kind": key[:-1], **source})
    return sources


def callers_with_literals(
    graph: dict[str, list[Any]], target_function: str
) -> list[dict[str, Any]]:
    callers = []
    for caller, calls in graph.items():
        for call in calls:
            if call.target != target_function:
                continue
            strings = [value for value in call.string_args if plausible_encoded_literal(value)]
            if not strings:
                continue
            callers.append(
                {
                    "caller": caller,
                    "address": hex(call.address),
                    "strings": strings[:8],
                    "decoded_previews": decoded_previews(strings),
                }
            )
    return callers


def plausible_encoded_literal(value: str) -> bool:
    if len(value) < 4 or len(value) > 4096:
        return False
    if not all(32 <= ord(ch) <= 126 for ch in value):
        return False
    alphabet = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-.")
    encoded_ratio = sum(ch in alphabet for ch in value) / len(value)
    return encoded_ratio >= 0.85


def classify_decoding_behavior(
    decoder_calls: list[dict[str, Any]],
    materializers: list[dict[str, Any]],
    transform_loops: list[dict[str, Any]],
    static_sources: list[dict[str, Any]],
    literal_callers: list[dict[str, Any]],
) -> str | None:
    decode_calls = [
        call
        for call in decoder_calls
        if call.get("direction") in {"decode", "crypto", "codec", "unknown"}
    ]
    encode_calls = [call for call in decoder_calls if call.get("direction") == "encode"]
    if decode_calls and materializers:
        return "explicit_string_decoder"
    if decode_calls:
        return "explicit_decoder"
    if encode_calls:
        return "encoder_api_usage"
    if transform_loops and materializers and (static_sources or literal_callers):
        return "likely_runtime_string_decoder"
    if transform_loops and materializers:
        return "byte_transformer_materializes_string"
    return None


def confidence_for_decoding(
    decoder_calls: list[dict[str, Any]],
    materializers: list[dict[str, Any]],
    transform_loops: list[dict[str, Any]],
    static_sources: list[dict[str, Any]],
    literal_callers: list[dict[str, Any]],
    static_recoveries: list[dict[str, Any]],
) -> str:
    score = 0
    if any(call.get("direction") != "encode" for call in decoder_calls):
        score += 2
    elif decoder_calls:
        score += 1
    if materializers:
        score += 1
    if transform_loops:
        score += 1
    if static_sources:
        score += 1
    if literal_callers:
        score += 1
    if static_recoveries:
        score += 2
    if score >= 4:
        return "high"
    if score >= 2:
        return "medium"
    return "low"


def decoding_feature_labels(
    decoder_calls: list[dict[str, Any]],
    materializers: list[dict[str, Any]],
    transform_loops: list[dict[str, Any]],
    static_sources: list[dict[str, Any]],
    literal_callers: list[dict[str, Any]],
    static_recoveries: list[dict[str, Any]],
) -> list[str]:
    labels = set()
    if static_recoveries:
        labels.add("recovered_indicator")
    if any(call.get("direction") == "encode" for call in decoder_calls):
        labels.add("encoder_api_usage")
    if any(call.get("direction") != "encode" for call in decoder_calls):
        labels.add("explicit_decoder_api")
    if transform_loops and materializers and (static_sources or literal_callers):
        labels.add("custom_decoder_candidate")
    elif transform_loops and materializers:
        labels.add("runtime_string_materialization")
    return sorted(labels)


def confidence_rank(confidence: str) -> int:
    return {"high": 0, "medium": 1, "low": 2}.get(confidence, 3)


def decoded_previews(strings: list[str]) -> list[dict[str, Any]]:
    previews = []
    for value in strings:
        for candidate in decoded_literal_candidates(value):
            previews.append(format_decoded_preview(value, candidate))
            for key in xor_key_candidates(strings, value):
                xored = xor_repeating(candidate["data"], key.encode("utf-8"))
                if not useful_recovered_text(xored):
                    continue
                chained = {
                    "encoding": candidate["encoding"],
                    "data": xored,
                    "transforms": candidate.get("transforms", [])
                    + [{"kind": "xor_repeating_key", "key": key}],
                }
                previews.append(format_decoded_preview(value, chained))
    return dedupe_previews(previews)[:8]


def decoded_literal_candidates(value: str) -> list[dict[str, Any]]:
    candidates = []
    try:
        decoded = base64.b64decode(value, validate=True)
    except Exception:
        decoded = b""
    if decoded:
        candidates.append({"encoding": "base64", "data": decoded, "transforms": []})

    if len(value) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", value or ""):
        try:
            decoded = binascii.unhexlify(value)
        except Exception:
            decoded = b""
        if decoded:
            candidates.append({"encoding": "hex", "data": decoded, "transforms": []})
    candidates.extend(layered_encoded_candidates(candidates))
    return candidates


def layered_encoded_candidates(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    layered = []
    for candidate in candidates:
        text = decoded_text(candidate["data"])
        if text is None or not plausible_encoded_literal(text):
            continue
        try:
            decoded = base64.b64decode(text, validate=True)
        except Exception:
            decoded = b""
        if decoded:
            layered.append(
                {
                    "encoding": "base64",
                    "data": decoded,
                    "transforms": candidate.get("transforms", [])
                    + [{"kind": "nested_decode", "encoding": candidate["encoding"]}],
                }
            )
            continue
        if len(text) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", text or ""):
            try:
                decoded = binascii.unhexlify(text)
            except Exception:
                decoded = b""
            if decoded:
                layered.append(
                    {
                        "encoding": "hex",
                        "data": decoded,
                        "transforms": candidate.get("transforms", [])
                        + [{"kind": "nested_decode", "encoding": candidate["encoding"]}],
                    }
                )
    return layered


def xor_key_candidates(strings: list[str], encoded_value: str) -> list[str]:
    keys = []
    for value in strings:
        if value == encoded_value:
            continue
        if not (1 <= len(value) <= 64):
            continue
        if not all(32 <= ord(ch) <= 126 for ch in value):
            continue
        if plausible_encoded_literal(value) and len(value) > 12:
            continue
        keys.append(value)
    return keys[:6]


def xor_repeating(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    return bytes(byte ^ key[index % len(key)] for index, byte in enumerate(data))


def useful_recovered_text(data: bytes) -> bool:
    text = decoded_text(data)
    if text is None:
        return False
    return classify_recovered_indicator(text) != "text"


def decoded_text(data: bytes) -> str | None:
    if not data:
        return None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = data.decode("latin-1")
        except UnicodeDecodeError:
            return None
    if not text:
        return None
    printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in text)
    if printable / len(text) < 0.9:
        return None
    return text


def format_decoded_preview(input_value: str, candidate: dict[str, Any]) -> dict[str, Any]:
    data = candidate["data"]
    text = decoded_text(data)
    preview = {
        "encoding": candidate["encoding"],
        "input_length": len(input_value),
        "decoded_length": len(data),
        "ascii_preview": ascii_preview(data[:120]),
        "hex_preview": data[:32].hex(),
        "transforms": candidate.get("transforms", []),
    }
    if text is not None:
        preview["text"] = text[:500]
        preview["indicator_type"] = classify_recovered_indicator(text)
    return preview


def dedupe_previews(previews: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped = []
    seen = set()
    for preview in previews:
        key = (
            preview.get("encoding"),
            preview.get("hex_preview"),
            tuple((item.get("kind"), item.get("key")) for item in preview.get("transforms", [])),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(preview)
    return deduped


def classify_recovered_indicator(text: str) -> str:
    lowered = text.lower().strip()
    if lowered.startswith(("http://", "https://")):
        return "url"
    if re.match(r"^[a-zA-Z]:\\", text) or text.startswith("\\\\"):
        return "windows_path"
    if "/" in text and not any(ch in text for ch in "\r\n\t"):
        return "path_or_url_fragment"
    if lowered.endswith((".exe", ".dll", ".ps1", ".bat", ".cmd", ".zip", ".dat", ".json", ".txt")):
        return "file_name_or_path"
    if any(marker in lowered for marker in ("cmd.exe", "powershell", "rundll32", "regsvr32", "wscript", "cscript")):
        return "command"
    if re.fullmatch(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}(:[0-9]{1,5})?", text.strip()):
        return "domain"
    return "text"


def recovered_indicators_for_function(item: dict[str, Any]) -> list[dict[str, Any]]:
    indicators = []
    for caller in item.get("literal_callers", []) or []:
        for preview in caller.get("decoded_previews", []) or []:
            indicator_type = preview.get("indicator_type")
            text = preview.get("text")
            if not text or indicator_type in {None, "text"}:
                continue
            indicators.append(
                {
                    "type": indicator_type,
                    "value": text,
                    "producer": item.get("function"),
                    "caller": caller.get("caller"),
                    "address": caller.get("address"),
                    "encoding": preview.get("encoding"),
                    "transforms": preview.get("transforms", []),
                    "confidence": "high" if indicator_type in {"url", "domain", "command"} else "medium",
                }
            )
    for recovery in item.get("static_source_recoveries", []) or []:
        preview = recovery.get("preview") or {}
        indicator_type = preview.get("indicator_type")
        text = preview.get("text")
        if not text or indicator_type in {None, "text"}:
            continue
        indicators.append(
            {
                "type": indicator_type,
                "value": text,
                "producer": item.get("function"),
                "source": recovery.get("source"),
                "address": recovery.get("address"),
                "encoding": preview.get("encoding"),
                "transforms": preview.get("transforms", []),
                "confidence": "high" if indicator_type in {"url", "domain", "command"} else "medium",
            }
        )
    return dedupe_indicators(indicators)[:20]


def recovered_indicators_for_results(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    indicators = []
    for item in results:
        indicators.extend(item.get("recovered_indicators", []) or [])
    return dedupe_indicators(indicators)[:100]


def dedupe_indicators(indicators: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped = []
    seen = set()
    for indicator in indicators:
        key = (
            indicator.get("type"),
            indicator.get("value"),
            indicator.get("producer"),
            tuple((item.get("kind"), item.get("key")) for item in indicator.get("transforms", [])),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(indicator)
    return deduped


def ascii_preview(data: bytes) -> str:
    return "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in data)


def recover_static_source_previews(
    analyzer: Any, static_sources: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    recoveries = []
    for source in static_sources[:20]:
        data = read_static_source_bytes(analyzer, source)
        candidates = []
        if data:
            candidates.extend(static_plaintext_candidates(data))
            candidates.extend(static_encoded_candidates(data))
        elif source.get("ascii_preview"):
            candidates.extend(static_preview_candidates(source["ascii_preview"]))
        for candidate in candidates:
            preview = format_decoded_preview(candidate["input"], candidate)
            text = preview.get("text")
            indicator_type = preview.get("indicator_type")
            if (
                not text
                or indicator_type in {None, "text"}
                or not is_strong_static_indicator(text, indicator_type)
            ):
                continue
            recoveries.append(
                {
                    "source": source.get("id") or source.get("kind"),
                    "address": source.get("va") or source.get("address"),
                    "preview": preview,
                }
            )
    return dedupe_static_recoveries(recoveries)[:20]


def read_static_source_bytes(analyzer: Any, source: dict[str, Any]) -> bytes:
    address = source.get("va") or source.get("address")
    size = source.get("size")
    if not address or not size:
        return b""
    try:
        start = int(str(address), 16)
        length = min(int(str(size), 16), MAX_STATIC_SOURCE_BYTES)
        if length <= 0:
            return b""
        return bytes(analyzer.binary.get_content_from_virtual_address(start, length))
    except Exception:
        return b""


def static_plaintext_candidates(data: bytes) -> list[dict[str, Any]]:
    candidates = []
    for text in extract_ascii_strings(data) + extract_utf16le_strings(data):
        indicator_type = classify_recovered_indicator(text)
        if not is_strong_static_indicator(text, indicator_type):
            continue
        candidates.append(
            {
                "encoding": "plain_static",
                "input": text,
                "data": text.encode("utf-8", errors="replace"),
                "transforms": [],
            }
        )
    return candidates


def static_encoded_candidates(data: bytes) -> list[dict[str, Any]]:
    candidates = []
    for text in extract_ascii_strings(data):
        if not plausible_encoded_literal(text):
            continue
        for candidate in decoded_literal_candidates(text):
            if useful_recovered_text(candidate["data"]):
                candidate = dict(candidate)
                candidate["input"] = text
                candidates.append(candidate)
    return candidates


def static_preview_candidates(preview: str) -> list[dict[str, Any]]:
    candidates = []
    for text in extract_ascii_strings(preview.encode("utf-8", errors="replace")):
        indicator_type = classify_recovered_indicator(text)
        if not is_strong_static_indicator(text, indicator_type):
            continue
        candidates.append(
            {
                "encoding": "plain_static_preview",
                "input": text,
                "data": text.encode("utf-8", errors="replace"),
                "transforms": [],
            }
        )
    return candidates


def is_strong_static_indicator(text: str, indicator_type: str) -> bool:
    stripped = text.strip()
    lowered = stripped.lower()
    if indicator_type == "url":
        return not looks_like_go_runtime_noise(stripped)
    if indicator_type == "command":
        return not looks_like_go_runtime_noise(stripped) and bool(
            re.search(
                r"(^|[^A-Za-z0-9_])"
                r"(cmd\.exe|powershell(?:\.exe)?|rundll32(?:\.exe)?|regsvr32(?:\.exe)?|wscript(?:\.exe)?|cscript(?:\.exe)?)"
                r"($|[^A-Za-z0-9_])",
                stripped,
                re.IGNORECASE,
            )
        )
    if indicator_type == "windows_path":
        if looks_like_go_runtime_noise(stripped):
            return False
        return is_plausible_static_windows_path(stripped)
    if indicator_type == "domain":
        return False
    if indicator_type != "file_name_or_path":
        return False
    if looks_like_go_runtime_noise(stripped):
        return False
    if re.match(r"^[a-zA-Z]:\\", stripped) or stripped.startswith("\\\\"):
        return True
    if "/" in stripped or "\\" in stripped:
        return True
    if lowered.endswith((".exe", ".ps1", ".bat", ".cmd", ".zip", ".dat", ".json", ".txt")):
        return len(stripped) <= 160 and "\n" not in stripped and "\t" not in stripped
    return False


def looks_like_go_runtime_noise(text: str) -> bool:
    lowered = text.lower()
    return any(
        marker in lowered
        for marker in (
            "runtime:",
            "/memory/classes/",
            "/gc/",
            "goroutine",
            "invalid argument",
            "interrupted system call",
            "certificate",
            "crypt32.dll",
            "kernel32.dll",
            "psapi.dll",
            "bcrypt.dll",
            "advapi32.dll",
        )
    )


def is_plausible_static_windows_path(text: str) -> bool:
    lowered = text.lower()
    if re.match(r"^[a-zA-Z]:\\", text):
        remainder = text[3:]
        if "\\" in remainder:
            return True
        if lowered.endswith((".exe", ".dll", ".ps1", ".bat", ".cmd", ".zip", ".dat", ".json", ".txt")):
            return True
        return len(remainder) >= 8
    match = re.match(r"^\\\\([^\\/:*?\"<>|\r\n]+)\\([^\\/:*?\"<>|\r\n]+)(.*)", text)
    if not match:
        return False
    host, share, rest = match.groups()
    return len(host) >= 2 and len(share) >= 2 and (bool(rest) or "." in host)


def extract_ascii_strings(data: bytes, min_length: int = 5) -> list[str]:
    values = []
    current = bytearray()
    for byte in data:
        if 32 <= byte <= 126:
            current.append(byte)
            continue
        if len(current) >= min_length:
            values.append(current.decode("ascii", errors="ignore"))
        current = bytearray()
    if len(current) >= min_length:
        values.append(current.decode("ascii", errors="ignore"))
    return values[:400]


def extract_utf16le_strings(data: bytes, min_length: int = 5) -> list[str]:
    values = []
    current = bytearray()
    for index in range(0, len(data) - 1, 2):
        byte = data[index]
        zero = data[index + 1]
        if zero == 0 and 32 <= byte <= 126:
            current.append(byte)
            continue
        if len(current) >= min_length:
            values.append(current.decode("ascii", errors="ignore"))
        current = bytearray()
    if len(current) >= min_length:
        values.append(current.decode("ascii", errors="ignore"))
    return values[:200]


def dedupe_static_recoveries(recoveries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped = []
    seen = set()
    for recovery in recoveries:
        preview = recovery.get("preview") or {}
        key = (
            recovery.get("source"),
            recovery.get("address"),
            preview.get("indicator_type"),
            preview.get("text"),
            preview.get("encoding"),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(recovery)
    return deduped
