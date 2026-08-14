from __future__ import annotations

import re
from typing import Any


MAX_SOURCE_BYTES = 0x40000
XOR_PROBE_BYTES = 0x2000
MAX_XOR_SOURCES = 8
MAX_REPEATING_KEYS = 8
MAX_RESULTS = 40


def analyze_decryption_recovery(analyzer: Any, semantics: dict[str, Any]) -> dict[str, Any]:
    runtime = semantics.get("runtime_decoding") or {}
    functions = runtime.get("functions") or []
    xor_results = []
    aes_candidates = []

    for item in functions:
        function = item.get("function")
        sources = item.get("static_sources") or []
        key_candidates = candidate_keys(item)
        if "custom_decoder_candidate" in (item.get("feature_labels") or []):
            xor_results.extend(recover_xor_for_function(analyzer, function, sources, key_candidates))
        if any(call.get("decoder") in {"aes", "cipher"} for call in item.get("decoder_calls") or []):
            aes_candidates.append(aes_candidate_for_function(function, item, sources, key_candidates))

    xor_results = dedupe_recoveries(xor_results)[:MAX_RESULTS]
    aes_candidates = [item for item in aes_candidates if item][:MAX_RESULTS]
    return {
        "version": 1,
        "summary": {
            "xor_recovered_artifact_count": len(xor_results),
            "aes_candidate_count": len(aes_candidates),
            "aes_decrypted_artifact_count": 0,
        },
        "xor_recovered_artifacts": xor_results,
        "aes_candidates": aes_candidates,
        "notes": [
            "XOR recovery is conservative and only reports outputs with strong artifact evidence.",
            "AES paths are identified, but AES decryption requires key, mode, IV/nonce, and ciphertext argument reconstruction.",
        ],
    }


def recover_xor_for_function(
    analyzer: Any,
    function: str | None,
    sources: list[dict[str, Any]],
    keys: list[bytes],
) -> list[dict[str, Any]]:
    results = []
    for source in sources[:MAX_XOR_SOURCES]:
        data = read_source_bytes(analyzer, source)
        if len(data) < 8:
            continue
        for key in single_byte_keys():
            key_bytes = bytes([key])
            artifact, decoded = recover_xor_with_probe(data, key_bytes)
            if artifact:
                results.append(format_recovery(function, source, decoded, "xor_single_byte", key_bytes, artifact))
        for key in keys[:MAX_REPEATING_KEYS]:
            artifact, decoded = recover_xor_with_probe(data, key)
            if artifact:
                results.append(format_recovery(function, source, decoded, "xor_repeating_key", key, artifact))
    results.sort(key=lambda item: (-artifact_rank(item.get("artifact_type")), item.get("function") or ""))
    return results


def recover_xor_with_probe(data: bytes, key: bytes) -> tuple[dict[str, Any] | None, bytes]:
    probe = xor_repeating(data[: min(len(data), XOR_PROBE_BYTES)], key)
    artifact = classify_decoded_artifact(probe)
    if not artifact:
        return None, probe
    if len(data) <= len(probe):
        return artifact, probe
    decoded = xor_repeating(data, key)
    full_artifact = classify_decoded_artifact(decoded)
    return full_artifact or artifact, decoded


def aes_candidate_for_function(
    function: str | None,
    item: dict[str, Any],
    sources: list[dict[str, Any]],
    keys: list[bytes],
) -> dict[str, Any]:
    calls = [
        {
            "target": call.get("target"),
            "address": call.get("address"),
            "decoder": call.get("decoder"),
            "direction": call.get("direction"),
        }
        for call in item.get("decoder_calls") or []
        if call.get("decoder") in {"aes", "cipher"}
    ]
    if not calls:
        return {}
    return {
        "function": function,
        "status": "identified_not_decrypted",
        "calls": calls[:8],
        "static_input_count": len(sources),
        "candidate_key_lengths": sorted({len(key) for key in keys if len(key) in {16, 24, 32}}),
        "reason_not_decrypted": "AES mode, nonce/IV, ciphertext argument, and padding/framing were not fully reconstructed.",
    }


def candidate_keys(item: dict[str, Any]) -> list[bytes]:
    values = []
    for caller in item.get("literal_callers") or []:
        values.extend(caller.get("strings") or [])
    for call in item.get("decoder_calls") or []:
        values.extend(call.get("string_args") or [])
    for source in item.get("static_sources") or []:
        preview = source.get("ascii_preview")
        if preview:
            values.extend(extract_ascii_strings(preview.encode("utf-8", errors="replace"), min_length=1))
    keys = []
    for value in values:
        if not isinstance(value, str):
            continue
        if not (1 <= len(value) <= 64):
            continue
        if not all(32 <= ord(ch) <= 126 for ch in value):
            continue
        data = value.encode("utf-8", errors="replace")
        if data not in keys:
            keys.append(data)
    return keys[:24]


def read_source_bytes(analyzer: Any, source: dict[str, Any]) -> bytes:
    address = source.get("va") or source.get("address")
    size = source.get("size")
    if not address or not size:
        return b""
    try:
        start = int(str(address), 16)
        length = min(int(str(size), 16), MAX_SOURCE_BYTES)
        if length <= 0:
            return b""
        return bytes(analyzer.binary.get_content_from_virtual_address(start, length))
    except Exception:
        return b""


def single_byte_keys() -> list[int]:
    return list(range(1, 256))


def xor_repeating(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    return bytes(byte ^ key[index % len(key)] for index, byte in enumerate(data))


def classify_decoded_artifact(data: bytes) -> dict[str, Any] | None:
    pe_offset = valid_pe_offset(data)
    if pe_offset is not None:
        return {
            "type": "embedded_pe",
            "confidence": "high",
            "description": "decoded bytes contain a valid MZ/PE header near the start",
            "offset": hex(pe_offset),
        }
    if data.startswith(b"PK\x03\x04"):
        return {"type": "zip_archive", "confidence": "high", "description": "decoded bytes start with ZIP magic"}
    if data.startswith(b"\x1f\x8b"):
        return {"type": "gzip_stream", "confidence": "high", "description": "decoded bytes start with gzip magic"}

    strings = extract_ascii_strings(data)
    indicators = strong_indicators(strings)
    if indicators:
        return {
            "type": "decoded_indicators",
            "confidence": "medium",
            "description": "decoded bytes contain URL/path/command-like strings",
            "indicators": indicators[:12],
        }
    return None


def valid_pe_offset(data: bytes) -> int | None:
    start = 0
    while True:
        offset = data.find(b"MZ", start)
        if offset == -1 or offset > 0x100:
            return None
        if offset + 0x40 <= len(data):
            e_lfanew = int.from_bytes(data[offset + 0x3C : offset + 0x40], "little", signed=False)
            pe_offset = offset + e_lfanew
            if 0x40 <= e_lfanew <= 0x100000 and pe_offset + 4 <= len(data):
                if data[pe_offset : pe_offset + 4] == b"PE\x00\x00":
                    return offset
        start = offset + 1


def strong_indicators(strings: list[str]) -> list[dict[str, str]]:
    results = []
    for value in strings:
        stripped = value.strip()
        lowered = stripped.lower()
        if re.match(r"^https?://[A-Za-z0-9.-]+", stripped):
            results.append({"type": "url", "value": stripped[:240]})
        elif re.match(r"^[A-Za-z]:\\[^\\/:*?\"<>|\r\n]+\\", stripped):
            results.append({"type": "windows_path", "value": stripped[:240]})
        elif any(token in lowered for token in ("cmd.exe", "powershell.exe", "rundll32.exe", "regsvr32.exe")):
            results.append({"type": "command", "value": stripped[:240]})
    return dedupe_indicator_values(results)


def format_recovery(
    function: str | None,
    source: dict[str, Any],
    decoded: bytes,
    method: str,
    key: bytes,
    artifact: dict[str, Any],
) -> dict[str, Any]:
    return {
        "function": function,
        "method": method,
        "key_hex": key.hex(),
        "key_ascii": printable_preview(key) if all(32 <= byte <= 126 for byte in key) else None,
        "artifact_type": artifact.get("type"),
        "confidence": artifact.get("confidence", "medium"),
        "description": artifact.get("description"),
        "decoded_preview": printable_preview(decoded[:240]),
        "decoded_size": len(decoded),
        "source_summary": summarize_source(source),
        "artifact": artifact,
    }


def summarize_source(source: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in {
            "kind": source.get("kind"),
            "section": source.get("section"),
            "size": source.get("size"),
            "entropy": source.get("entropy"),
            "reasons": source.get("reasons"),
        }.items()
        if value not in (None, [], {})
    }


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
    return values[:500]


def printable_preview(data: bytes) -> str:
    return "".join(chr(byte) if 32 <= byte <= 126 or byte in {9, 10, 13} else "." for byte in data)


def dedupe_indicator_values(items: list[dict[str, str]]) -> list[dict[str, str]]:
    result = []
    seen = set()
    for item in items:
        key = (item.get("type"), item.get("value"))
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def dedupe_recoveries(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    seen = set()
    for item in items:
        key = (
            item.get("function"),
            item.get("method"),
            item.get("key_hex"),
            item.get("artifact_type"),
            item.get("decoded_preview")[:80],
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def artifact_rank(kind: str | None) -> int:
    return {
        "embedded_pe": 5,
        "zip_archive": 4,
        "gzip_stream": 4,
        "decoded_indicators": 3,
    }.get(kind or "", 0)
