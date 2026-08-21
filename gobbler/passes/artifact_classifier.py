from __future__ import annotations

import hashlib
import json
import math
import re
import string
import zlib
from pathlib import Path
from typing import Any

MAX_CLASSIFY_BYTES = 0x20000
MAX_SOURCE_READ_BYTES = 0x20000
MAX_STRING_SCAN_BYTES = 0x10000
MAX_STRINGS = 24
MAX_STRING_LENGTH = 180
MIN_STRING_LENGTH = 4
_MAGIKA_INSTANCE: Any = None
_MAGIKA_IMPORT_ATTEMPTED = False

SCRIPT_MARKERS = (
    b"#!/bin/sh",
    b"#!/bin/bash",
    b"#!/usr/bin/env",
    b"powershell",
    b"cmd.exe",
    b"@echo off",
    b"function ",
    b"param(",
)

MAGIC_SIGNATURES: tuple[tuple[str, bytes, str], ...] = (
    ("pe", b"MZ", "application/vnd.microsoft.portable-executable"),
    ("elf", b"\x7fELF", "application/x-elf"),
    ("zip", b"PK\x03\x04", "application/zip"),
    ("zip", b"PK\x05\x06", "application/zip"),
    ("zip", b"PK\x07\x08", "application/zip"),
    ("gzip", b"\x1f\x8b\x08", "application/gzip"),
)


def classify_bytes(data: bytes) -> dict[str, Any]:
    """Classify a byte buffer for evaluator-facing artifact output."""
    if not isinstance(data, bytes):
        raise TypeError("classify_bytes expects bytes")

    sample = data[:MAX_CLASSIFY_BYTES]
    magic_matches = magic_offsets(sample)
    entropy = shannon_entropy(sample)
    printable = printable_ratio(sample)
    strings = extract_ascii_strings(sample[:MAX_STRING_SCAN_BYTES])
    kind, confidence, signals, mime = classify_kind(sample, printable, magic_matches, strings)
    magika = classify_with_magika(sample)

    result: dict[str, Any] = {
        "type": kind,
        "mime_type": mime,
        "confidence": confidence,
        "signals": signals,
        "size": len(data),
        "analyzed_size": len(sample),
        "truncated": len(data) > len(sample),
        "entropy": round(entropy, 3),
        "printable_ratio": round(printable, 3),
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha256_prefix": hashlib.sha256(data).hexdigest()[:16],
        "magic_offsets": magic_matches[:8],
        "strings": select_interesting_strings(strings),
        "hex_preview": sample[:64].hex(),
        "ascii_preview": ascii_preview(sample[:96]),
    }
    if magika is not None:
        result["magika"] = magika
    return result


def classify_sources(analyzer: Any, sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Classify source dicts that either contain bytes or point at a VA/size."""
    classified = []
    for source in sources:
        item = dict(source)
        data, error = source_bytes(analyzer, source)
        if data is None:
            item["artifact_classification"] = {
                "type": "unreadable",
                "confidence": "low",
                "signals": [],
                "error": error or "could not read source bytes",
            }
            classified.append(item)
            continue
        classification = classify_bytes(data)
        declared_size = parse_int(source.get("size") or source.get("length"))
        if declared_size is not None and declared_size > len(data):
            classification["source_declared_size"] = declared_size
            classification["source_read_truncated"] = True
        item["artifact_classification"] = classification
        classified.append(item)
    return classified


def analyze_artifacts(analyzer: Any, semantics: dict[str, Any]) -> dict[str, Any]:
    """Classify evaluator-relevant binary artifacts already found by semantic passes."""
    notable_blob_sources = [
        source_for_blob(blob)
        for blob in semantics.get("notable_data_blobs") or []
        if isinstance(blob, dict)
    ]
    embedded_artifact_sources = [
        source_for_embedded_artifact(artifact)
        for artifact in semantics.get("embedded_artifacts") or []
        if isinstance(artifact, dict)
    ]
    decoded_artifacts = [
        summarize_decoded_artifact(item)
        for item in (semantics.get("decryption_recovery") or {}).get("xor_recovered_artifacts") or []
        if isinstance(item, dict)
    ]

    notable_blobs = classify_sources(analyzer, notable_blob_sources[:20])
    embedded_artifacts = classify_sources(analyzer, embedded_artifact_sources[:20])
    counts: dict[str, int] = {}
    for item in notable_blobs + embedded_artifacts:
        classification = item.get("artifact_classification") or {}
        kind = classification.get("type", "unknown")
        counts[kind] = counts.get(kind, 0) + 1

    return {
        "version": 1,
        "summary": {
            "classified_notable_blob_count": len(notable_blobs),
            "classified_embedded_artifact_count": len(embedded_artifacts),
            "decoded_artifact_count": len(decoded_artifacts),
            "type_counts": dict(sorted(counts.items())),
            "magika_available": magika_available(),
        },
        "notable_blobs": notable_blobs,
        "embedded_artifacts": embedded_artifacts,
        "decoded_artifacts": decoded_artifacts[:40],
    }


def source_for_blob(blob: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in {
            "id": blob.get("id"),
            "kind": "notable_data_blob",
            "section": blob.get("section"),
            "va": blob.get("va"),
            "size": blob.get("size"),
            "entropy": blob.get("entropy"),
            "reasons": blob.get("reasons"),
            "magic_offsets": blob.get("magic_offsets"),
            "referenced_by": blob.get("referenced_by"),
        }.items()
        if value not in (None, [], {})
    }


def source_for_embedded_artifact(artifact: dict[str, Any]) -> dict[str, Any]:
    source = artifact.get("source") if isinstance(artifact.get("source"), dict) else {}
    return {
        key: value
        for key, value in {
            "id": artifact.get("source_blob"),
            "kind": artifact.get("kind") or "embedded_artifact",
            "section": source.get("section"),
            "va": source.get("va"),
            "size": source.get("size"),
            "entropy": source.get("entropy"),
            "confidence": artifact.get("confidence"),
            "evidence": artifact.get("evidence"),
            "transformers": artifact.get("transformers"),
            "loaders": artifact.get("loaders"),
        }.items()
        if value not in (None, [], {})
    }


def summarize_decoded_artifact(item: dict[str, Any]) -> dict[str, Any]:
    artifact = item.get("artifact") if isinstance(item.get("artifact"), dict) else {}
    return {
        key: value
        for key, value in {
            "function": item.get("function"),
            "method": item.get("method"),
            "artifact_type": item.get("artifact_type"),
            "confidence": item.get("confidence"),
            "decoded_size": item.get("decoded_size"),
            "decoded_preview": item.get("decoded_preview"),
            "source_summary": item.get("source_summary"),
            "artifact": artifact,
        }.items()
        if value not in (None, [], {})
    }


def source_bytes(analyzer: Any, source: dict[str, Any]) -> tuple[bytes | None, str | None]:
    embedded = source.get("bytes")
    if embedded is None:
        embedded = source.get("data")
    if embedded is None:
        embedded = source.get("content")
    if isinstance(embedded, bytes):
        return embedded, None
    if isinstance(embedded, bytearray):
        return bytes(embedded), None
    if isinstance(embedded, str):
        decoded = decode_embedded_string(embedded)
        if decoded is not None:
            return decoded, None

    path_value = source.get("path") or source.get("file_path")
    if path_value:
        try:
            path = Path(str(path_value))
            return path.read_bytes()[:MAX_SOURCE_READ_BYTES], None
        except OSError as exc:
            return None, f"could not read path: {exc}"

    va = parse_int(source.get("va") or source.get("address"))
    size = parse_int(source.get("size") or source.get("length"))
    if va is None or size is None:
        return None, "source has no bytes/path or va+size"
    if size <= 0:
        return None, "source size is zero"

    data = read_va(analyzer, va, min(size, MAX_SOURCE_READ_BYTES))
    if data is None:
        return None, f"could not read va={hex(va)} size={hex(size)}"
    return data, None


def decode_embedded_string(value: str) -> bytes | None:
    text = value.strip()
    if text.startswith("hex:"):
        text = text[4:]
    if len(text) >= 2 and len(text) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", text):
        try:
            return bytes.fromhex(text)
        except ValueError:
            return None
    return value.encode("utf-8", errors="replace")


def coerce_bytes(value: Any) -> bytes | None:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, list):
        try:
            return bytes(value)
        except ValueError:
            return None
    if isinstance(value, str):
        return decode_embedded_string(value)
    return None


def read_va(analyzer: Any, va: int, size: int) -> bytes | None:
    binary = getattr(analyzer, "binary", None)
    if binary is not None:
        reader = getattr(binary, "read_va", None)
        if callable(reader):
            data = reader(va, size)
            if data is not None:
                return bytes(data)
        reader = getattr(binary, "get_content_from_virtual_address", None)
        if callable(reader):
            try:
                data = reader(va, size)
            except Exception:
                data = None
            if data is not None:
                return bytes(data)

    binary_view = getattr(analyzer, "binary_view", None)
    if binary_view is not None and callable(getattr(binary_view, "sections", None)):
        data = read_va_from_sections(binary_view.sections(), va, size)
        if data is not None:
            return data

    sections = getattr(analyzer, "sections", None)
    if sections:
        return read_va_from_sections(sections, va, size)
    return None


def read_va_from_sections(sections: Any, va: int, size: int) -> bytes | None:
    for section in sections or []:
        start = int(getattr(section, "va", 0) or 0)
        data = bytes(getattr(section, "data", b"") or b"")
        end = start + len(data)
        if start <= va < end:
            offset = va - start
            return data[offset : offset + min(size, end - va)]
        if isinstance(section, dict):
            start = parse_int(section.get("va")) or 0
            data_value = section.get("data") or b""
            data = coerce_bytes(data_value)
            if data is None:
                continue
            end = start + len(data)
            if start <= va < end:
                offset = va - start
                return data[offset : offset + min(size, end - va)]
    return None


def classify_kind(
    data: bytes,
    printable: float,
    magic_matches: list[dict[str, Any]],
    strings: list[str],
) -> tuple[str, str, list[str], str]:
    signals = []
    by_offset_zero = {item["type"] for item in magic_matches if item["offset"] == 0}
    all_magic = {item["type"] for item in magic_matches}

    if "pe" in by_offset_zero:
        return "pe", "high", ["mz_header"], "application/vnd.microsoft.portable-executable"
    if "elf" in by_offset_zero:
        return "elf", "high", ["elf_header"], "application/x-elf"
    if "zip" in by_offset_zero:
        return "zip", "high", ["zip_header"], "application/zip"
    if "gzip" in by_offset_zero:
        return "gzip", "high", ["gzip_header"], "application/gzip"
    if looks_like_zlib(data):
        return "zlib", "medium", ["zlib_header"], "application/zlib"

    if all_magic:
        signals.append("embedded_magic")

    if looks_like_json(data):
        return "json_like", "high", signals + ["json_like_text"], "application/json"
    if looks_like_script(data, strings):
        return "script", "medium", signals + ["script_markers"], "text/x-script"
    if looks_like_text(data, printable):
        return "text", "medium", signals + ["mostly_printable"], "text/plain"
    if looks_like_compressed_zlib(data):
        return "zlib", "low", signals + ["zlib_decompressible"], "application/zlib"

    return "unknown_binary", "low", signals, "application/octet-stream"


def magic_offsets(data: bytes) -> list[dict[str, Any]]:
    matches = []
    for kind, signature, mime in MAGIC_SIGNATURES:
        start = 0
        while True:
            offset = data.find(signature, start)
            if offset == -1:
                break
            matches.append({"type": kind, "offset": offset, "mime_type": mime})
            start = offset + 1
            if len(matches) >= 32:
                return matches
    return sorted(matches, key=lambda item: (item["offset"], item["type"]))


def looks_like_zlib(data: bytes) -> bool:
    if len(data) < 2:
        return False
    cmf, flg = data[0], data[1]
    return cmf & 0x0F == 8 and ((cmf << 8) + flg) % 31 == 0


def looks_like_compressed_zlib(data: bytes) -> bool:
    if len(data) < 8 or not looks_like_zlib(data):
        return False
    try:
        zlib.decompress(data[:MAX_CLASSIFY_BYTES], bufsize=1024)
        return True
    except zlib.error:
        return False


def looks_like_json(data: bytes) -> bool:
    text = data[:MAX_STRING_SCAN_BYTES].lstrip()
    if not text.startswith((b"{", b"[")):
        return False
    try:
        json.loads(text.decode("utf-8", errors="strict"))
        return True
    except (UnicodeDecodeError, json.JSONDecodeError):
        return bool(re.match(rb"[\{\[]\s*[\}\"A-Za-z0-9_\[\{]", text[:128]))


def looks_like_script(data: bytes, strings: list[str]) -> bool:
    lowered = data[:4096].lower()
    if any(marker in lowered for marker in SCRIPT_MARKERS):
        return True
    joined = "\n".join(strings[:16]).lower()
    return any(marker.decode("ascii", errors="ignore") in joined for marker in SCRIPT_MARKERS)


def looks_like_text(data: bytes, printable: float) -> bool:
    if not data:
        return False
    if b"\x00" in data[:4096]:
        return False
    return printable >= 0.9


def classify_with_magika(data: bytes) -> dict[str, Any] | None:
    magika = magika_instance()
    if magika is None:
        return None

    try:
        result = magika.identify_bytes(data[:MAX_CLASSIFY_BYTES])
    except Exception as exc:
        return {"error": str(exc)}

    output = safe_getattr(result, "output")
    if output is None:
        return {"raw": str(result)}
    label = safe_getattr(output, "label")
    mime_type = safe_getattr(output, "mime_type")
    group = safe_getattr(output, "group")
    score = safe_getattr(result, "score")
    return {
        key: value
        for key, value in {
            "label": label,
            "mime_type": mime_type,
            "group": group,
            "score": round(float(score), 3) if isinstance(score, (int, float)) else score,
        }.items()
        if value is not None
    }


def magika_available() -> bool:
    return magika_instance() is not None


def magika_instance() -> Any:
    global _MAGIKA_IMPORT_ATTEMPTED, _MAGIKA_INSTANCE
    if _MAGIKA_IMPORT_ATTEMPTED:
        return _MAGIKA_INSTANCE
    _MAGIKA_IMPORT_ATTEMPTED = True
    try:
        from magika import Magika  # type: ignore
    except Exception:
        _MAGIKA_INSTANCE = None
        return None
    try:
        _MAGIKA_INSTANCE = Magika()
    except Exception:
        _MAGIKA_INSTANCE = None
    return _MAGIKA_INSTANCE


def safe_getattr(item: Any, name: str) -> Any:
    try:
        return getattr(item, name)
    except Exception:
        return None


def extract_ascii_strings(data: bytes) -> list[str]:
    values = []
    current = bytearray()
    allowed = set(bytes(string.printable, "ascii")) - {0x0b, 0x0c}
    for byte in data:
        if byte in allowed and byte not in (0x00,):
            current.append(byte)
            if len(current) >= MAX_STRING_LENGTH:
                values.append(current.decode("ascii", errors="ignore"))
                current.clear()
        else:
            if len(current) >= MIN_STRING_LENGTH:
                values.append(current.decode("ascii", errors="ignore"))
            current.clear()
    if len(current) >= MIN_STRING_LENGTH:
        values.append(current.decode("ascii", errors="ignore"))
    return dedupe(values)[:200]


def select_interesting_strings(strings: list[str]) -> list[dict[str, str]]:
    ranked = sorted(strings, key=string_rank)
    selected = []
    seen = set()
    for value in ranked:
        clean = normalize_string(value)
        if not clean or clean in seen:
            continue
        seen.add(clean)
        selected.append({"type": classify_string(clean), "value": clean})
        if len(selected) >= MAX_STRINGS:
            break
    return selected


def string_rank(value: str) -> tuple[int, int]:
    classification = classify_string(value)
    priority = {
        "url": 0,
        "ip_address": 1,
        "windows_path": 2,
        "path": 3,
        "command": 4,
        "domain_or_file": 5,
        "text": 8,
    }.get(classification, 9)
    return priority, -min(len(value), MAX_STRING_LENGTH)


def classify_string(value: str) -> str:
    lowered = value.lower()
    if re.search(r"https?://|tcp://|udp://|wss?://", lowered):
        return "url"
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?", value):
        return "ip_address"
    if re.search(r"[a-z]:\\|\\\\[a-z0-9_.-]+\\", lowered):
        return "windows_path"
    if value.startswith(("/", "./", "../")) or "/" in value:
        return "path"
    if any(token in lowered for token in ("cmd.exe", "powershell", "/bin/sh", "/bin/bash", "chmod ", "curl ", "wget ")):
        return "command"
    if re.search(r"\.[a-z0-9]{2,8}($|[:/\\])", lowered):
        return "domain_or_file"
    return "text"


def normalize_string(value: str) -> str | None:
    text = " ".join(value.strip().split())
    if len(text) < MIN_STRING_LENGTH:
        return None
    if len(text) > MAX_STRING_LENGTH:
        text = text[: MAX_STRING_LENGTH - 3] + "..."
    if text.count("%") > 6:
        return None
    return text


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    entropy = 0.0
    length = len(data)
    for count in counts:
        if count:
            probability = count / length
            entropy -= probability * math.log2(probability)
    return entropy


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(byte in b"\t\r\n" or 32 <= byte <= 126 for byte in data)
    return printable / len(data)


def ascii_preview(data: bytes) -> str:
    return "".join(chr(byte) if byte in b"\t\r\n" or 32 <= byte <= 126 else "." for byte in data)


def parse_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None


def dedupe(values: list[str]) -> list[str]:
    seen = set()
    result = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
