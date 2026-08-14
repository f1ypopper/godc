from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from gobbler.utils.ownership import is_library_function


SOURCE_OPERATION_KINDS = {
    "crypto_random",
    "file_read",
    "stream_read",
    "environment_read",
    "base64_decode_or_encode",
    "hex_decode_or_encode",
    "gzip_compression",
    "zlib_compression",
    "aes_crypto",
    "cipher_crypto",
    "chacha20_crypto",
}

TRANSFORM_OPERATION_KINDS = {
    "string_to_bytes",
    "bytes_to_string",
    "string_concat",
    "make_slice",
    "make_slice_copy",
    "grow_slice",
    "map_write",
}

SINK_OPERATION_KINDS = {
    "file_read",
    "file_write",
    "file_create",
    "file_open",
    "directory_create",
    "http_network",
    "http_request",
    "http_get",
    "http_post",
    "network_connect",
    "network_listen",
    "process_launch",
    "dynamic_library_load",
    "dynamic_import_resolution",
    "dynamic_syscall_call",
    "raw_syscall",
    "permission_change",
    "environment_write",
}

DECODER_OPERATION_KINDS = {
    "base64_decode_or_encode",
    "hex_decode_or_encode",
    "gzip_compression",
    "zlib_compression",
    "aes_crypto",
    "cipher_crypto",
    "chacha20_crypto",
}

HTTP_OPERATION_KINDS = {"http_network", "http_request", "http_get", "http_post"}
FILE_WRITE_OPERATION_KINDS = {"file_write", "file_create"}
FILE_READ_OPERATION_KINDS = {"file_read", "file_open"}
LOADER_OPERATION_KINDS = {
    "process_launch",
    "dynamic_library_load",
    "dynamic_import_resolution",
    "dynamic_syscall_call",
    "raw_syscall",
}

def build_semantic_chains(graph: dict[str, list[Any]], semantics: dict[str, Any]) -> dict[str, Any]:
    builder = SemanticChainBuilder(graph, semantics)
    return builder.build()


class SemanticChainBuilder:
    def __init__(self, graph: dict[str, list[Any]], semantics: dict[str, Any]):
        self.graph = graph
        self.semantics = semantics
        self.behavior_functions = (semantics.get("behavior_ir") or {}).get("functions") or {}
        self.callers = self._index_callers()
        self.crypto_random_functions = self._index_crypto_random_functions()
        self.promoted_loader_functions = {
            item.get("function")
            for item in self.semantics.get("loader_behaviors") or []
            if item.get("function")
        }
        self.chains: list[dict[str, Any]] = []
        self.seen: set[tuple[Any, ...]] = set()

    def build(self) -> dict[str, Any]:
        for function, item in self.behavior_functions.items():
            self._add_function_chains(function, item)
        self.chains.sort(key=lambda item: (-confidence_rank(item["confidence"]), item["kind"], item["function"]))
        return {
            "version": 1,
            "chains": self.chains[:200],
            "summary": self._summary(),
        }

    def _add_function_chains(self, function: str, item: dict[str, Any]) -> None:
        operations = item.get("flow") or []
        kinds = {operation.get("kind") for operation in operations}
        if is_library_function(function) and not has_high_level_loader_behavior(kinds):
            return
        data = item.get("data") or {}
        control = item.get("control") or {}
        map_fields = map_field_names(operations)
        literal_values = literal_strings(operations)
        static_sources = static_data_sources(data)
        binary_static_sources = [
            source for source in static_sources if source.get("kind") in {"data_blob", "constant_array"}
        ]
        sources = source_operations(operations)
        transforms = transform_operations(operations, control)
        sinks = sink_operations(operations)
        generated_callee_calls = [
            operation_ref(operation)
            for operation in operations
            if operation.get("kind") == "call_user"
            and operation.get("target") in self.crypto_random_functions
        ]

        if ("crypto_random" in kinds or generated_callee_calls) and (
            kinds & {"bytes_to_string", "string_to_bytes", "file_write", "map_write"}
            or generated_callee_calls
        ):
            generated_sources = [op for op in sources if op["kind"] == "crypto_random"] + generated_callee_calls
            self._add_chain(
                {
                    "kind": "generated_identifier",
                    "function": function,
                    "confidence": "high" if sinks else "medium",
                    "sources": generated_sources,
                    "transforms": transforms,
                    "sinks": [op for op in sinks if op["kind"] in FILE_WRITE_OPERATION_KINDS | FILE_READ_OPERATION_KINDS],
                    "related_fields": interesting_fields(map_fields),
                    "evidence": [
                        "crypto_random_source",
                        "identifier_like_field" if has_identifier_field(map_fields) else "byte_materialization",
                    ],
                }
            )

        if kinds & HTTP_OPERATION_KINDS:
            related_fields = interesting_fields(map_fields + caller_map_fields(function, self.behavior_functions, self.callers))
            self._add_chain(
                {
                    "kind": "outbound_http",
                    "function": function,
                    "confidence": "high" if related_fields or literal_values else "medium",
                    "sources": sources + static_source_refs(static_sources),
                    "transforms": transforms,
                    "sinks": [op for op in sinks if op["kind"] in HTTP_OPERATION_KINDS],
                    "related_fields": related_fields,
                    "literals": literal_values[:12],
                    "evidence": ["http_sink"] + (["request_fields"] if related_fields else []),
                }
            )

        if kinds & FILE_WRITE_OPERATION_KINDS:
            self._add_chain(
                {
                    "kind": "file_write",
                    "function": function,
                    "confidence": "high" if sources or static_sources or literal_values else "medium",
                    "sources": sources + static_source_refs(static_sources),
                    "transforms": transforms,
                    "sinks": [op for op in sinks if op["kind"] in FILE_WRITE_OPERATION_KINDS],
                    "related_fields": interesting_fields(map_fields),
                    "literals": path_like_literals(literal_values),
                    "evidence": ["file_write_sink"],
                }
            )

        if kinds & FILE_READ_OPERATION_KINDS:
            self._add_chain(
                {
                    "kind": "file_read",
                    "function": function,
                    "confidence": "medium",
                    "sources": static_source_refs(static_sources),
                    "transforms": transforms,
                    "sinks": [op for op in sinks if op["kind"] in FILE_READ_OPERATION_KINDS],
                    "related_fields": interesting_fields(map_fields),
                    "literals": path_like_literals(literal_values),
                    "evidence": ["file_read_sink"],
                }
            )

        if kinds & LOADER_OPERATION_KINDS:
            loader_sinks = [op for op in sinks if op["kind"] in LOADER_OPERATION_KINDS]
            if is_library_function(function) and not any(
                sink["kind"] in {"process_launch", "dynamic_library_load", "dynamic_import_resolution"}
                for sink in loader_sinks
            ):
                loader_sinks = []
            if loader_sinks and (
                "process_launch" in kinds
                or function in self.promoted_loader_functions
            ):
                self._add_chain(
                    {
                        "kind": "execution_or_loader",
                        "function": function,
                        "confidence": "high" if (kinds & {"process_launch", "dynamic_library_load"}) else "medium",
                        "sources": sources + static_source_refs(static_sources),
                        "transforms": transforms,
                        "sinks": loader_sinks,
                        "literals": literal_values[:12],
                        "evidence": ["execution_or_loader_sink"],
                    }
                )

        if (kinds & DECODER_OPERATION_KINDS) or (
            control.get("probable_transform_loops")
            and "bytes_to_string" in kinds
            and binary_static_sources
            and not (kinds & {"file_read", "file_write", "crypto_random"})
        ):
            decoder_sources = sources + static_source_refs(static_sources)
            self._add_chain(
                {
                    "kind": "runtime_string_materialization",
                    "function": function,
                    "confidence": "high" if kinds & DECODER_OPERATION_KINDS else "medium",
                    "sources": decoder_sources,
                    "transforms": transforms,
                    "sinks": sinks,
                    "literals": literal_values[:12],
                    "evidence": ["decoder_api" if kinds & DECODER_OPERATION_KINDS else "static_bytes_to_string"],
                }
            )

    def _add_chain(self, chain: dict[str, Any]) -> None:
        key = (
            chain.get("kind"),
            chain.get("function"),
            tuple((sink.get("kind"), sink.get("target")) for sink in chain.get("sinks", [])[:4]),
        )
        if key in self.seen:
            return
        self.seen.add(key)
        self.chains.append(compact_chain(chain))

    def _summary(self) -> dict[str, Any]:
        counts: dict[str, int] = defaultdict(int)
        for chain in self.chains:
            counts[chain["kind"]] += 1
        return {
            "chain_count": len(self.chains),
            "by_kind": dict(sorted(counts.items())),
            "high_confidence_count": sum(1 for chain in self.chains if chain["confidence"] == "high"),
        }

    def _index_callers(self) -> dict[str, list[str]]:
        callers: dict[str, list[str]] = defaultdict(list)
        for caller, calls in self.graph.items():
            for call in calls:
                if getattr(call, "visible", True):
                    callers[call.target].append(caller)
        return callers

    def _index_crypto_random_functions(self) -> set[str]:
        functions = set()
        for function, item in self.behavior_functions.items():
            if any(operation.get("kind") == "crypto_random" for operation in item.get("flow") or []):
                functions.add(function)
        return functions


def source_operations(operations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        operation_ref(operation)
        for operation in operations
        if operation.get("kind") in SOURCE_OPERATION_KINDS
    ][:20]


def transform_operations(operations: list[dict[str, Any]], control: dict[str, Any]) -> list[dict[str, Any]]:
    transforms = [
        operation_ref(operation)
        for operation in operations
        if operation.get("kind") in TRANSFORM_OPERATION_KINDS
    ]
    for loop in control.get("probable_transform_loops") or []:
        transforms.append(
            {
                "kind": "transform_loop",
                "address": loop.get("start"),
                "target": loop.get("classification", "probable_transform_loop"),
                "evidence": (loop.get("evidence") or {}).get("transform_ops", [])[:8],
            }
        )
    return transforms[:30]


def sink_operations(operations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        operation_ref(operation)
        for operation in operations
        if operation.get("kind") in SINK_OPERATION_KINDS
    ][:20]


def operation_ref(operation: dict[str, Any]) -> dict[str, Any]:
    result = {
        "kind": operation.get("kind"),
        "target": operation.get("target"),
        "address": operation.get("address"),
    }
    strings = operation.get("string_args") or []
    if strings:
        result["strings"] = strings[:6]
    return result


def static_data_sources(data: dict[str, Any]) -> list[dict[str, Any]]:
    sources = []
    for key in ("data_blobs", "constant_arrays", "strings"):
        for source in data.get(key, []) or []:
            sources.append({"kind": key[:-1], **source})
    return sources[:40]


def static_source_refs(sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
    refs = []
    for source in sources:
        ref = {
            "kind": source.get("kind"),
            "id": source.get("id") or source.get("address"),
            "section": source.get("section"),
            "size": source.get("size"),
            "entropy": source.get("entropy"),
        }
        value = source.get("value") or source.get("ascii_preview")
        if value:
            ref["preview"] = str(value)[:80]
        refs.append({k: v for k, v in ref.items() if v not in (None, [], {})})
    return refs[:20]


def map_field_names(operations: list[dict[str, Any]]) -> list[str]:
    fields = []
    for operation in operations:
        if operation.get("kind") != "map_write":
            continue
        for value in operation.get("string_args") or []:
            if usable_field(value) and value not in fields:
                fields.append(value)
        for arg in ((operation.get("arguments") or {}).get("strings") or []):
            value = arg.get("value") if isinstance(arg, dict) else None
            if usable_field(value) and value not in fields:
                fields.append(value)
    return fields[:30]


def caller_map_fields(
    function: str,
    behavior_functions: dict[str, dict[str, Any]],
    callers: dict[str, list[str]],
) -> list[str]:
    fields = []
    for caller in callers.get(function, [])[:12]:
        item = behavior_functions.get(caller) or {}
        for field in map_field_names(item.get("flow") or []):
            if field not in fields:
                fields.append(field)
    return fields[:30]


def literal_strings(operations: list[dict[str, Any]]) -> list[str]:
    values = []
    for operation in operations:
        for value in operation.get("string_args") or []:
            if usable_literal(value) and value not in values:
                values.append(value)
        for arg in ((operation.get("arguments") or {}).get("strings") or []):
            value = arg.get("value") if isinstance(arg, dict) else None
            if usable_literal(value) and value not in values:
                values.append(value)
    return values[:40]


def path_like_literals(values: list[str]) -> list[str]:
    return [
        value
        for value in values
        if ("/" in value or "\\" in value or "." in value) and plausible_path_literal(value)
    ][:12]


def plausible_path_literal(value: str) -> bool:
    if value.startswith("^") or value.endswith("$"):
        return False
    if any(marker in value for marker in (r"\w", r"\s", r"\d", "(?:", ".*", ".+", "[^")):
        return False
    if len(value) <= 12 and re.search(r"[\\/\]\[]", value) and not re.search(r"\.[A-Za-z0-9]{1,6}$", value):
        return False
    return True


def interesting_fields(fields: list[str]) -> list[str]:
    preferred = []
    fallback = []
    for field in fields:
        lowered = field.lower()
        if any(marker in lowered for marker in ("id", "token", "key", "host", "url", "user", "pass", "db", "ver", "ip")):
            preferred.append(field)
        elif len(field) <= 32:
            fallback.append(field)
    result = []
    for field in preferred + fallback:
        if field not in result:
            result.append(field)
    return result[:20]


def has_identifier_field(fields: list[str]) -> bool:
    return any("id" in field.lower() or field.lower() in {"guid", "uuid"} for field in fields)


def usable_field(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 64
        and re.fullmatch(r"[A-Za-z0-9_.-]+", value) is not None
    )


def usable_literal(value: Any) -> bool:
    return isinstance(value, str) and 2 <= len(value) <= 240 and all(ord(ch) >= 9 for ch in value)


def compact_chain(chain: dict[str, Any]) -> dict[str, Any]:
    result = {
        "kind": chain["kind"],
        "function": chain["function"],
        "confidence": chain["confidence"],
        "evidence": chain.get("evidence", [])[:8],
    }
    for key, limit in (
        ("sources", 12),
        ("transforms", 12),
        ("sinks", 12),
        ("related_fields", 20),
        ("literals", 12),
    ):
        values = chain.get(key)
        if values:
            result[key] = values[:limit]
    return result


def confidence_rank(confidence: str) -> int:
    return {"high": 3, "medium": 2, "low": 1}.get(confidence, 0)


def has_high_level_loader_behavior(kinds: set[str | None]) -> bool:
    return bool(kinds & {"process_launch", "dynamic_library_load", "dynamic_import_resolution"})
