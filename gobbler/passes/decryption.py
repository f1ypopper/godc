from __future__ import annotations

import base64
import binascii
import gzip
import hashlib
import re
import zlib
from typing import Any

from gobbler.passes.artifact_classifier import classify_bytes


MAX_SOURCE_BYTES = 0x40000
XOR_PROBE_BYTES = 0x2000
MAX_XOR_SOURCES = 8
MAX_REPEATING_KEYS = 8
MAX_RESULTS = 40
MAX_DECODED_ARTIFACTS = 60
MAX_LAYER_DEPTH = 4
MAX_LITERAL_STRINGS = 80


def analyze_decryption_recovery(analyzer: Any, semantics: dict[str, Any]) -> dict[str, Any]:
    runtime = semantics.get("runtime_decoding") or {}
    functions = runtime.get("functions") or []
    xor_results = []
    decoded_results = []
    aes_candidates = []
    suppressed_recoveries = []

    for item in functions:
        function = item.get("function")
        sources = item.get("static_sources") or []
        key_candidates = candidate_keys(item)
        decoded_results.extend(recover_encoded_artifacts_for_function(analyzer, function, item, sources))
        if "custom_decoder_candidate" in (item.get("feature_labels") or []):
            recovered, suppressed = recover_xor_for_function(analyzer, function, sources, key_candidates)
            xor_results.extend(recovered)
            decoded_results.extend(recovered)
            suppressed_recoveries.extend(suppressed)
        if any(call.get("decoder") in {"aes", "cipher"} for call in item.get("decoder_calls") or []):
            aes_candidates.append(aes_candidate_for_function(function, item, sources, key_candidates))

    xor_results = dedupe_recoveries(xor_results)[:MAX_RESULTS]
    decoded_results = dedupe_recoveries(decoded_results)[:MAX_DECODED_ARTIFACTS]
    aes_candidates = [item for item in aes_candidates if item][:MAX_RESULTS]
    return {
        "version": 2,
        "summary": {
            "xor_recovered_artifact_count": len(xor_results),
            "decoded_artifact_count": len(decoded_results),
            "base64_decoded_artifact_count": count_method(decoded_results, "base64"),
            "hex_decoded_artifact_count": count_method(decoded_results, "hex"),
            "compressed_decoded_artifact_count": count_any_transform(decoded_results, {"gzip_decompress", "zlib_decompress"}),
            "aes_candidate_count": len(aes_candidates),
            "aes_decrypted_artifact_count": 0,
            "suppressed_recovery_count": len(suppressed_recoveries),
        },
        "decoded_artifacts": decoded_results,
        "xor_recovered_artifacts": xor_results,
        "suppressed_recoveries": dedupe_suppressed_recoveries(suppressed_recoveries)[:MAX_RESULTS],
        "aes_candidates": aes_candidates,
        "notes": [
            "XOR recovery is conservative and only reports outputs with strong artifact evidence.",
            "Base64/hex/gzip/zlib reconstruction reports only decoded outputs that classify as concrete artifacts or contain strong indicators.",
            "AES paths are identified, but AES decryption requires key, mode, IV/nonce, and ciphertext argument reconstruction.",
        ],
    }


def recover_encoded_artifacts_for_function(
    analyzer: Any,
    function: str | None,
    item: dict[str, Any],
    sources: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    results = []
    for source in sources[:MAX_XOR_SOURCES]:
        data = read_source_bytes(analyzer, source)
        if len(data) >= 8:
            for candidate in layered_decode_candidates(data, [{"kind": "static_blob"}]):
                artifact = classify_decoded_artifact(candidate["data"])
                if artifact:
                    results.append(
                        format_recovery(
                            function,
                            source,
                            candidate["data"],
                            method_from_transforms(candidate["transforms"]),
                            b"",
                            artifact,
                            transforms=candidate["transforms"],
                        )
                    )
            for literal in encoded_literals_from_bytes(data):
                results.extend(
                    recover_literal_artifacts(
                        function,
                        literal,
                        source,
                        source_context={"kind": "static_source_literal"},
                    )
                )
        preview = source.get("ascii_preview")
        if isinstance(preview, str):
            for literal in encoded_literals_from_text(preview):
                results.extend(
                    recover_literal_artifacts(
                        function,
                        literal,
                        source,
                        source_context={"kind": "static_source_preview_literal"},
                    )
                )

    for caller in item.get("literal_callers") or []:
        if not isinstance(caller, dict):
            continue
        for literal in caller.get("strings") or []:
            if not isinstance(literal, str):
                continue
            results.extend(
                recover_literal_artifacts(
                    function,
                    literal,
                    {},
                    source_context={
                        "kind": "literal_argument",
                        "caller": caller.get("caller"),
                        "address": caller.get("address"),
                    },
                )
            )
    results.sort(key=recovery_sort_key)
    return results


def recover_xor_for_function(
    analyzer: Any,
    function: str | None,
    sources: list[dict[str, Any]],
    keys: list[bytes],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    results = []
    suppressed = []
    for source in sources[:MAX_XOR_SOURCES]:
        reason = source_suppression_reason(source)
        if reason:
            suppressed.append(
                {
                    "function": function,
                    "method": "xor_probe",
                    "reason": reason,
                    "source_summary": summarize_source(source),
                }
            )
            continue
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
    results.sort(key=recovery_sort_key)
    return results, suppressed


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


def recover_literal_artifacts(
    function: str | None,
    literal: str,
    source: dict[str, Any],
    source_context: dict[str, Any],
) -> list[dict[str, Any]]:
    results = []
    initial = literal.encode("utf-8", errors="replace")
    for candidate in layered_decode_candidates(
        initial,
        [{"kind": "literal", "input_length": len(literal)}],
        require_first_text_decode=True,
    ):
        artifact = classify_decoded_artifact(candidate["data"])
        if not artifact:
            continue
        formatted = format_recovery(
            function,
            source,
            candidate["data"],
            method_from_transforms(candidate["transforms"]),
            b"",
            artifact,
            transforms=candidate["transforms"],
        )
        formatted["source_context"] = {
            key: value for key, value in source_context.items() if value not in (None, [], {})
        }
        results.append(formatted)
    return results


def layered_decode_candidates(
    data: bytes,
    transforms: list[dict[str, Any]],
    *,
    require_first_text_decode: bool = False,
) -> list[dict[str, Any]]:
    results = []
    queue = [(data, transforms, 0)]
    seen = set()
    while queue:
        current, chain, depth = queue.pop(0)
        if depth >= MAX_LAYER_DEPTH:
            continue
        for transform in possible_decodes(current, require_text_decode=require_first_text_decode and depth == 0):
            decoded = transform.pop("data")
            if not decoded or decoded == current:
                continue
            key = (hashlib.sha256(decoded).hexdigest(), tuple(item.get("kind") for item in chain + [transform]))
            if key in seen:
                continue
            seen.add(key)
            next_chain = chain + [transform]
            results.append({"data": decoded, "transforms": next_chain})
            queue.append((decoded, next_chain, depth + 1))
    return results


def possible_decodes(data: bytes, *, require_text_decode: bool = False) -> list[dict[str, Any]]:
    decodes = []
    if not require_text_decode:
        if data.startswith(b"\x1f\x8b"):
            try:
                decodes.append({"kind": "gzip_decompress", "data": gzip.decompress(data)})
            except Exception:
                pass
        if looks_like_zlib(data):
            try:
                decodes.append({"kind": "zlib_decompress", "data": zlib.decompress(data)})
            except Exception:
                pass

    text = decoded_ascii_text(data)
    if text is None:
        return decodes
    cleaned = text.strip()
    if plausible_base64_literal(cleaned):
        try:
            decoded = base64.b64decode(cleaned, validate=True)
        except Exception:
            decoded = b""
        if decoded:
            decodes.append({"kind": "base64_decode", "data": decoded})
    if plausible_hex_literal(cleaned):
        try:
            decoded = binascii.unhexlify(cleaned)
        except Exception:
            decoded = b""
        if decoded:
            decodes.append({"kind": "hex_decode", "data": decoded})
    return decodes


def looks_like_zlib(data: bytes) -> bool:
    if len(data) < 2:
        return False
    cmf, flg = data[0], data[1]
    return cmf & 0x0F == 8 and ((cmf << 8) + flg) % 31 == 0


def encoded_literals_from_bytes(data: bytes) -> list[str]:
    return encoded_literals_from_text("\n".join(extract_ascii_strings(data, min_length=8)))


def encoded_literals_from_text(text: str) -> list[str]:
    literals = []
    for value in extract_ascii_strings(text.encode("utf-8", errors="replace"), min_length=8):
        stripped = value.strip()
        if plausible_base64_literal(stripped) or plausible_hex_literal(stripped):
            literals.append(stripped)
        for match in re.finditer(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{16,}={0,2})(?![A-Za-z0-9+/=])", stripped):
            candidate = match.group(1)
            if plausible_base64_literal(candidate):
                literals.append(candidate)
        for match in re.finditer(r"(?<![0-9A-Fa-f])([0-9A-Fa-f]{24,})(?![0-9A-Fa-f])", stripped):
            candidate = match.group(1)
            if plausible_hex_literal(candidate):
                literals.append(candidate)
        if len(literals) >= MAX_LITERAL_STRINGS:
            break
    return dedupe_strings(literals)


def plausible_base64_literal(value: str) -> bool:
    stripped = "".join(value.split())
    if len(stripped) < 16 or len(stripped) % 4 != 0:
        return False
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", stripped):
        return False
    return sum(ch.isalpha() for ch in stripped) >= 4


def plausible_hex_literal(value: str) -> bool:
    stripped = "".join(value.split())
    if len(stripped) < 24 or len(stripped) % 2 != 0:
        return False
    if not re.fullmatch(r"[0-9a-fA-F]+", stripped):
        return False
    return len(set(stripped.lower())) >= 4


def decoded_ascii_text(data: bytes) -> str | None:
    if not data:
        return None
    if len(data) > MAX_SOURCE_BYTES:
        return None
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return None
    if not text:
        return None
    printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in text)
    if printable / len(text) < 0.95:
        return None
    return text


def method_from_transforms(transforms: list[dict[str, Any]]) -> str:
    for item in reversed(transforms):
        kind = item.get("kind")
        if kind in {"base64_decode", "hex_decode", "gzip_decompress", "zlib_decompress"}:
            return str(kind)
    return "layered_decode"


def count_method(items: list[dict[str, Any]], needle: str) -> int:
    return sum(
        1
        for item in items
        if needle in str(item.get("method", ""))
        or any(needle in str(transform.get("kind", "")) for transform in item.get("transforms", []) or [])
    )


def count_any_transform(items: list[dict[str, Any]], needles: set[str]) -> int:
    return sum(
        1
        for item in items
        if any(transform.get("kind") in needles for transform in item.get("transforms", []) or [])
    )


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


def source_suppression_reason(source: dict[str, Any]) -> str | None:
    section = str(source.get("section") or "").lower()
    reasons = set(source.get("reasons") or [])
    entropy = source.get("entropy")
    try:
        entropy_value = float(entropy)
    except (TypeError, ValueError):
        entropy_value = 8.0
    preview = str(source.get("ascii_preview") or "")
    lowered_preview = preview.lower()
    magic = source.get("magic_offsets") or []

    if magic:
        return None
    if section in {".gopclntab", ".go.buildinfo", ".typelink", ".itablink"}:
        return "go_metadata_section"
    if section in {".rdata", ".rodata", ".data"} and "referenced_global_data" in reasons:
        go_metadata_terms = (
            "runtime.",
            "type:",
            "go:string",
            "gostring",
            "gcbits",
            "itab",
            "moduledata",
            "string",
            "[]byte",
            "map[",
            "chan ",
            "interface",
            "reflect.",
            "panic",
            "fatal error",
        )
        if entropy_value < 6.2 and any(term in lowered_preview for term in go_metadata_terms):
            return "go_metadata_or_string_table_like_source"
        if entropy_value < 4.0 and printable_preview_is_pointer_table(preview):
            return "low_entropy_pointer_table_like_source"
    return None


def printable_preview_is_pointer_table(preview: str) -> bool:
    if not preview:
        return False
    punctuation = sum(ch in ".@\\x00" for ch in preview)
    alnum = sum(ch.isalnum() for ch in preview)
    return punctuation > alnum


def single_byte_keys() -> list[int]:
    return list(range(1, 256))


def xor_repeating(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    return bytes(byte ^ key[index % len(key)] for index, byte in enumerate(data))


def classify_decoded_artifact(data: bytes) -> dict[str, Any] | None:
    classification = classify_bytes(data)
    classification_type = classification.get("type")
    if classification_type in {"pe", "elf", "zip", "gzip", "zlib", "script"}:
        if classification_type == "pe" and valid_pe_offset(data) is None:
            return None
        if classification_type in {"gzip", "zlib"} and not valid_compressed_artifact(data, classification_type):
            return None
        confidence = "high" if classification_type in {"pe", "elf", "zip", "gzip"} else "medium"
        indicators = indicators_from_classification(classification)
        return {
            "type": f"decoded_{classification_type}",
            "confidence": confidence,
            "description": decoded_artifact_description(classification_type, indicators),
            "classification": compact_classification(classification),
            "indicators": indicators[:16],
        }
    if classification_type in {"json_like", "text"}:
        indicators = indicators_from_classification(classification)
        if not indicators:
            return None
        return {
            "type": "decoded_text_config",
            "confidence": "high" if classification_type == "json_like" else "medium",
            "description": decoded_artifact_description(classification_type, indicators),
            "classification": compact_classification(classification),
            "indicators": indicators[:16],
        }

    pe_offset = valid_pe_offset(data)
    if pe_offset is not None:
        return {
            "type": "embedded_pe",
            "confidence": "high",
            "description": "decoded bytes contain a valid MZ/PE header near the start",
            "offset": hex(pe_offset),
        }
    elf_offset = data.find(b"\x7fELF", 0, min(len(data), 0x1000))
    if elf_offset != -1:
        return {
            "type": "embedded_elf",
            "confidence": "high",
            "description": "decoded bytes contain an ELF header near the start",
            "offset": hex(elf_offset),
        }
    if data.startswith(b"PK\x03\x04"):
        return {"type": "zip_archive", "confidence": "high", "description": "decoded bytes start with ZIP magic"}
    if data.startswith(b"\x1f\x8b"):
        return {"type": "gzip_stream", "confidence": "high", "description": "decoded bytes start with gzip magic"}

    strings = extract_ascii_strings(data)
    indicators = strong_indicators(strings)
    if indicators:
        classification = compact_classification(classification)
        return {
            "type": "decoded_indicators",
            "confidence": "medium",
            "description": "decoded bytes contain URL/path/command-like strings",
            "indicators": indicators[:12],
            "classification": classification,
        }
    return None


def indicators_from_classification(classification: dict[str, Any]) -> list[dict[str, str]]:
    results = []
    for item in classification.get("strings") or []:
        if not isinstance(item, dict):
            continue
        kind = str(item.get("type") or "")
        value = item.get("value")
        if not isinstance(value, str):
            continue
        if kind in {"url", "ip_address"}:
            results.append({"type": normalize_indicator_type(kind), "value": value[:240]})
        elif kind == "windows_path" and is_robust_windows_path(value):
            results.append({"type": "windows_path", "value": value[:240]})
        elif kind == "command" and is_robust_command_indicator(value):
            results.append({"type": "command", "value": value[:240]})
        elif kind == "path" and is_robust_path_indicator(value):
            results.append({"type": "path", "value": value[:240]})
        elif kind == "domain_or_file" and is_robust_domain_or_file_indicator(value):
            results.append({"type": "domain_or_file", "value": value[:240]})
    return dedupe_indicator_values(results)


def normalize_indicator_type(kind: str) -> str:
    return {
        "ip_address": "ip",
        "domain_or_file": "domain_or_file",
        "path": "path",
    }.get(kind, kind)


def valid_compressed_artifact(data: bytes, classification_type: str) -> bool:
    try:
        if classification_type == "gzip":
            gzip.decompress(data)
            return True
        if classification_type == "zlib":
            zlib.decompress(data)
            return True
    except Exception:
        return False
    return True


def is_robust_windows_path(value: str) -> bool:
    stripped = value.strip()
    if not re.match(r"^[A-Za-z]:\\[A-Za-z0-9_. $(){}\\-]+(?:\\[A-Za-z0-9_. $(){}\\-]+)+", stripped):
        return False
    lowered = stripped.lower()
    return any(
        marker in lowered
        for marker in (
            "\\users\\",
            "\\programdata\\",
            "\\windows\\",
            "\\temp\\",
            "\\appdata\\",
            ".exe",
            ".dll",
            ".ps1",
            ".bat",
            ".cmd",
        )
    )


def is_robust_command_indicator(value: str) -> bool:
    return bool(
        re.search(
            r"(^|[^A-Za-z0-9_])(cmd\.exe|powershell(?:\.exe)?|rundll32(?:\.exe)?|regsvr32(?:\.exe)?|wscript(?:\.exe)?|cscript(?:\.exe)?|/bin/sh|/bin/bash)($|[^A-Za-z0-9_])",
            value,
            re.IGNORECASE,
        )
    )


def is_robust_path_indicator(value: str) -> bool:
    stripped = value.strip()
    lowered = stripped.lower()
    if len(stripped) < 4 or any(ord(ch) < 32 for ch in stripped):
        return False
    if stripped.startswith(("/bin/", "/etc/", "/tmp/", "/var/", "/usr/", "/home/", "./", "../")):
        return True
    if lowered.startswith(("http://", "https://")):
        return True
    return bool(re.search(r"(^|[/\\])(cmd|powershell|rundll32|regsvr32|wscript|cscript|sh|bash)\.?(exe)?($|\\s|[/\\])", lowered))


def is_robust_domain_or_file_indicator(value: str) -> bool:
    stripped = value.strip()
    lowered = stripped.lower()
    return lowered.endswith((".exe", ".dll", ".ps1", ".bat", ".cmd", ".sh", ".zip", ".json"))


def compact_classification(classification: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in {
            "type": classification.get("type"),
            "mime_type": classification.get("mime_type"),
            "confidence": classification.get("confidence"),
            "signals": classification.get("signals"),
            "size": classification.get("size"),
            "entropy": classification.get("entropy"),
            "printable_ratio": classification.get("printable_ratio"),
            "sha256": classification.get("sha256"),
            "sha256_prefix": classification.get("sha256_prefix"),
            "magic_offsets": classification.get("magic_offsets"),
            "strings": classification.get("strings"),
            "ascii_preview": classification.get("ascii_preview"),
            "hex_preview": classification.get("hex_preview"),
            "magika": classification.get("magika"),
        }.items()
        if value not in (None, [], {})
    }


def decoded_artifact_description(classification_type: str | None, indicators: list[dict[str, str]]) -> str:
    if indicators:
        kinds = ", ".join(sorted({item["type"] for item in indicators if item.get("type")}))
        return f"decoded bytes contain behavior-relevant indicators: {kinds}"
    return f"decoded bytes classify as {classification_type or 'artifact'}"


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
        if re.match(r"^https?://[A-Za-z0-9.-]+", stripped):
            results.append({"type": "url", "value": stripped[:240]})
        elif is_robust_windows_path(stripped):
            results.append({"type": "windows_path", "value": stripped[:240]})
        elif is_robust_command_indicator(stripped):
            results.append({"type": "command", "value": stripped[:240]})
    return dedupe_indicator_values(results)


def format_recovery(
    function: str | None,
    source: dict[str, Any],
    decoded: bytes,
    method: str,
    key: bytes,
    artifact: dict[str, Any],
    transforms: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    sha256 = hashlib.sha256(decoded).hexdigest()
    return {
        "function": function,
        "method": method,
        "transforms": transforms or ([{"kind": method}] if method else []),
        "key_hex": key.hex() or None,
        "key_ascii": printable_preview(key) if all(32 <= byte <= 126 for byte in key) else None,
        "artifact_type": artifact.get("type"),
        "confidence": artifact.get("confidence", "medium"),
        "description": artifact.get("description"),
        "sha256": sha256,
        "sha256_prefix": sha256[:16],
        "decoded_preview": printable_preview(decoded[:240]),
        "decoded_hex_preview": decoded[:64].hex(),
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
            item.get("sha256_prefix") or item.get("decoded_preview")[:80],
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def dedupe_suppressed_recoveries(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    seen = set()
    for item in items:
        source = item.get("source_summary") if isinstance(item.get("source_summary"), dict) else {}
        key = (item.get("function"), item.get("method"), item.get("reason"), source.get("section"), source.get("size"))
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def artifact_rank(kind: str | None) -> int:
    return {
        "decoded_pe": 6,
        "decoded_elf": 6,
        "embedded_pe": 5,
        "embedded_elf": 5,
        "decoded_zip": 4,
        "decoded_gzip": 4,
        "zip_archive": 4,
        "gzip_stream": 4,
        "decoded_script": 4,
        "decoded_text_config": 4,
        "decoded_indicators": 3,
        "decoded_zlib": 3,
    }.get(kind or "", 0)


def recovery_sort_key(item: dict[str, Any]) -> tuple[int, int, str]:
    return (
        -artifact_rank(item.get("artifact_type")),
        -len(item.get("transforms") or []),
        item.get("function") or "",
    )


def dedupe_strings(values: list[str]) -> list[str]:
    result = []
    seen = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
