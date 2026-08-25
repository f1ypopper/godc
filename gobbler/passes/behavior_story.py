from __future__ import annotations

import re
from collections import Counter, defaultdict, deque
from typing import Any

from gobbler.utils.ownership import is_app_function


ACTION_KINDS = {
    "http_network": ("network", "uses HTTP client behavior"),
    "http_request": ("network", "creates HTTP request"),
    "http_get": ("network", "performs HTTP GET"),
    "http_post": ("network", "performs HTTP POST"),
    "network_connect": ("network", "opens network connection"),
    "network_listen": ("network", "listens on a network socket"),
    "file_read": ("filesystem", "reads file"),
    "file_open": ("filesystem", "opens file"),
    "file_write": ("filesystem", "writes file"),
    "file_create": ("filesystem", "creates file"),
    "file_delete": ("filesystem", "deletes file"),
    "file_rename": ("filesystem", "renames file"),
    "directory_create": ("filesystem", "creates directory"),
    "recursive_filesystem_walk": ("filesystem", "walks filesystem tree"),
    "permission_change": ("filesystem", "changes file permissions"),
    "process_launch": ("process", "launches process"),
    "dynamic_library_load": ("execution", "loads dynamic library"),
    "dynamic_import_resolution": ("execution", "resolves dynamic import"),
    "dynamic_syscall_call": ("execution", "invokes dynamically resolved syscall/API"),
    "raw_syscall": ("execution", "invokes raw syscall"),
    "executable_memory_allocation": ("execution", "allocates executable memory"),
    "memory_protection_change": ("execution", "changes memory protection"),
    "thread_creation": ("execution", "creates thread"),
    "environment_read": ("environment", "reads environment variable"),
    "environment_write": ("environment", "writes environment variable"),
    "start_goroutine": ("concurrency", "starts goroutine"),
}

ACTION_RANK = {
    "network": 0,
    "filesystem": 1,
    "process": 2,
    "execution": 3,
    "concurrency": 4,
    "environment": 5,
    "crypto_or_decoding": 6,
    "embedded_artifact": 7,
}

LOW_LEVEL_EXECUTION_KINDS = {
    "dynamic_library_load",
    "dynamic_import_resolution",
    "dynamic_syscall_call",
    "raw_syscall",
    "executable_memory_allocation",
    "memory_protection_change",
    "thread_creation",
}


def build_behavior_story(graph: dict[str, list[Any]], semantics: dict[str, Any]) -> dict[str, Any]:
    builder = BehaviorStoryBuilder(graph, semantics)
    return builder.build()


class BehaviorStoryBuilder:
    def __init__(self, graph: dict[str, list[Any]], semantics: dict[str, Any]):
        self.graph = graph
        self.semantics = semantics
        self.functions = (semantics.get("behavior_ir") or {}).get("functions") or {}
        self.function_order = self._function_order()
        self.indicators_by_function = self._indicators_by_function()
        self.promoted_loader_functions = {
            item.get("function")
            for item in self.semantics.get("loader_behaviors") or []
            if item.get("function")
        }

    def build(self) -> dict[str, Any]:
        actions = self._actions()
        embedded_artifacts = self._embedded_artifact_observations()
        decryptions = self._decryption_observations()
        actions.extend(embedded_artifacts)
        actions.extend(decryptions)
        actions = dedupe_actions(actions)
        actions.sort(key=self._action_sort_key)
        artifacts = collect_artifacts(actions, self.semantics)
        return {
            "version": 1,
            "purpose": "evaluator_facing_behavior_flow",
            "summary": self._summary(actions, artifacts),
            "execution_flow": self._execution_flow(actions),
            "actions": actions[:120],
            "artifacts": artifacts,
            "narrative": narrative_for_actions(actions, artifacts),
            "debug_note": "This view intentionally hides array/blob identifiers unless they explain recovered or embedded artifacts.",
        }

    def _actions(self) -> list[dict[str, Any]]:
        actions = []
        for function, item in self.functions.items():
            if not is_app_function(function):
                continue
            for operation in item.get("flow") or []:
                kind = operation.get("kind")
                if kind not in ACTION_KINDS:
                    continue
                category, description = ACTION_KINDS[kind]
                if self._is_unpromoted_low_level_execution(kind, function):
                    continue
                artifacts = artifacts_for_operation(operation)
                artifacts.extend(self.indicators_by_function.get(function, []))
                action = {
                    "category": category,
                    "kind": kind,
                    "function": function,
                    "description": description,
                    "target_api": operation.get("target"),
                    "address": operation.get("address"),
                    "confidence": confidence_for_operation(operation, artifacts),
                    "artifacts": dedupe_artifacts(artifacts)[:20],
                    "data_summary": data_summary_for_function(item),
                }
                for role_key in ("network_role", "process_role", "filesystem_role"):
                    if operation.get(role_key):
                        action[role_key] = operation.get(role_key)
                actions.append(clean_action(action))
        actions.extend(self._semantic_chain_actions())
        return actions

    def _is_unpromoted_low_level_execution(self, kind: str, function: str) -> bool:
        if kind not in LOW_LEVEL_EXECUTION_KINDS:
            return False
        return function not in self.promoted_loader_functions

    def _semantic_chain_actions(self) -> list[dict[str, Any]]:
        actions = []
        for chain in (self.semantics.get("semantic_chains") or {}).get("chains") or []:
            function = chain.get("function")
            if not function or not is_app_function(function):
                continue
            category = category_for_chain(chain.get("kind"))
            if not category:
                continue
            artifacts = artifacts_for_chain(chain)
            artifacts.extend(self.indicators_by_function.get(function, []))
            action = {
                "category": category,
                "kind": chain.get("kind"),
                "function": function,
                "description": description_for_chain(chain),
                "confidence": chain.get("confidence", "medium"),
                "sinks": compact_sinks(chain.get("sinks") or []),
                "artifacts": dedupe_artifacts(artifacts)[:20],
                "evidence": chain.get("evidence", [])[:8],
            }
            for role_key in ("network_role", "process_role", "filesystem_role"):
                if chain.get(role_key):
                    action[role_key] = chain.get(role_key)
            actions.append(clean_action(action))
        return actions

    def _embedded_artifact_observations(self) -> list[dict[str, Any]]:
        actions = []
        for payload in self.semantics.get("embedded_artifacts") or []:
            artifact = {
                "type": "embedded_artifact",
                "value": payload.get("kind", "embedded_artifact"),
                "confidence": payload.get("confidence", "medium"),
                "details": {
                    "source": payload.get("source"),
                    "transformers": payload.get("transformers", [])[:8],
                    "loaders": payload.get("loaders", [])[:8],
                },
            }
            for function in payload.get("loaders") or payload.get("transformers") or ["<reachable_component>"]:
                actions.append(
                    clean_action(
                        {
                            "category": "embedded_artifact",
                            "kind": payload.get("kind", "embedded_artifact"),
                            "function": function,
                            "description": "contains embedded static data that is transformed and/or passed to loader-relevant code",
                            "confidence": payload.get("confidence", "medium"),
                            "artifacts": [artifact],
                            "evidence": payload.get("evidence", [])[:8],
                        }
                    )
                )
        return actions

    def _decryption_observations(self) -> list[dict[str, Any]]:
        actions = []
        recovery = self.semantics.get("decryption_recovery") or {}
        decoded_artifacts = recovery.get("decoded_artifacts") or recovery.get("xor_recovered_artifacts") or []
        for item in decoded_artifacts:
            if not isinstance(item, dict):
                continue
            actions.append(
                clean_action(
                    {
                        "category": "crypto_or_decoding",
                        "kind": "decoded_artifact_recovered",
                        "function": item.get("function"),
                        "description": decoded_artifact_action_description(item),
                        "confidence": item.get("confidence", "medium"),
                        "artifacts": [artifact_for_decryption(item)],
                        "evidence": [item.get("method"), item.get("description")],
                    }
                )
            )
        for item in recovery.get("aes_candidates") or []:
            actions.append(
                clean_action(
                    {
                        "category": "crypto_or_decoding",
                        "kind": "aes_decryption_candidate",
                        "function": item.get("function"),
                        "description": "uses AES/cipher APIs but plaintext was not recovered",
                        "confidence": "medium",
                        "artifacts": [
                            {
                                "type": "crypto",
                                "value": "AES/cipher path identified",
                                "details": {
                                    "status": item.get("status"),
                                    "candidate_key_lengths": item.get("candidate_key_lengths", []),
                                    "static_input_count": item.get("static_input_count", 0),
                                },
                            }
                        ],
                        "evidence": [item.get("reason_not_decrypted")],
                    }
                )
            )
        return actions

    def _execution_flow(self, actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for action in actions:
            grouped[action.get("function", "<unknown>")].append(action)
        flow = []
        for function in sorted(grouped, key=lambda name: self.function_order.get(name, 9999)):
            function_actions = sorted(grouped[function], key=action_rank)
            flow.append(
                {
                    "function": function,
                    "actions": [
                        {
                            "kind": action.get("kind"),
                            "category": action.get("category"),
                            "description": action.get("description"),
                            "target_api": action.get("target_api"),
                            "artifacts": action.get("artifacts", [])[:8],
                        }
                        for action in function_actions[:20]
                    ],
                }
            )
        return flow[:80]

    def _summary(self, actions: list[dict[str, Any]], artifacts: dict[str, Any]) -> dict[str, Any]:
        categories = Counter(action.get("category") for action in actions)
        return {
            "action_count": len(actions),
            "categories": dict(sorted(categories.items())),
            "network_action_count": categories.get("network", 0),
            "filesystem_action_count": categories.get("filesystem", 0),
            "process_or_execution_action_count": categories.get("process", 0) + categories.get("execution", 0),
            "concurrency_action_count": categories.get("concurrency", 0),
            "embedded_artifact_action_count": categories.get("embedded_artifact", 0),
            "artifact_counts": {key: len(value) for key, value in artifacts.items()},
        }

    def _function_order(self) -> dict[str, int]:
        order = {}
        queue = deque(["main.main"])
        while queue:
            function = queue.popleft()
            if function in order:
                continue
            order[function] = len(order)
            for call in self.graph.get(function, []) or []:
                target = getattr(call, "target", None)
                if target in self.graph and target not in order:
                    queue.append(target)
        for function in self.graph:
            order.setdefault(function, len(order))
        return order

    def _indicators_by_function(self) -> dict[str, list[dict[str, Any]]]:
        indexed: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for indicator in (self.semantics.get("runtime_decoding") or {}).get("recovered_indicators") or []:
            artifact = {
                "type": indicator.get("type", "indicator"),
                "value": indicator.get("value"),
                "confidence": indicator.get("confidence", "medium"),
                "details": {
                    "producer": indicator.get("producer"),
                    "caller": indicator.get("caller"),
                    "encoding": indicator.get("encoding"),
                },
            }
            for key in (indicator.get("producer"), indicator.get("caller")):
                if key:
                    indexed[key].append(artifact)
            for consumer in indicator.get("consumed_by") or []:
                if consumer.get("function"):
                    indexed[consumer["function"]].append(artifact)
        return indexed

    def _action_sort_key(self, action: dict[str, Any]) -> tuple[int, int, str]:
        return (
            self.function_order.get(action.get("function", ""), 9999),
            action_rank(action),
            action.get("kind", ""),
        )


def artifacts_for_operation(operation: dict[str, Any]) -> list[dict[str, Any]]:
    artifacts = []
    for value in operation.get("string_args") or []:
        artifact = classify_artifact(value)
        if artifact:
            artifacts.append(artifact)
    args = operation.get("arguments") or {}
    for item in args.get("strings") or []:
        value = item.get("value") if isinstance(item, dict) else item
        artifact = classify_artifact(value)
        if artifact:
            artifacts.append(artifact)
    return artifacts


def artifacts_for_chain(chain: dict[str, Any]) -> list[dict[str, Any]]:
    artifacts = []
    for value in chain.get("literals") or []:
        artifact = classify_artifact(value)
        if artifact:
            artifacts.append(artifact)
    for sink in chain.get("sinks") or []:
        for value in sink.get("strings") or []:
            artifact = classify_artifact(value)
            if artifact:
                artifacts.append(artifact)
    for field in chain.get("related_fields") or []:
        if isinstance(field, str) and field:
            artifacts.append({"type": "field_name", "value": field})
    return artifacts


def classify_artifact(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    lowered = stripped.lower()
    if len(stripped) < 2 or len(stripped) > 2000:
        return None
    if is_noisy_evaluator_literal(stripped):
        return None
    if lowered.startswith(("http://", "https://")):
        return {"type": "url", "value": stripped}
    if any(token in lowered for token in ("cmd.exe", "powershell", "rundll32", "regsvr32", "wscript", "cscript")):
        return {"type": "command", "value": stripped}
    if stripped.startswith("\\\\") or (len(stripped) >= 3 and stripped[1:3] == ":\\"):
        return {"type": "windows_path", "value": stripped}
    if "/" in stripped or "\\" in stripped:
        if not is_plausible_path_artifact(stripped):
            return None
        return {"type": "path", "value": stripped}
    if lowered.endswith((".exe", ".dll", ".ps1", ".bat", ".cmd", ".zip", ".dat", ".json", ".txt")):
        return {"type": "file_name", "value": stripped}
    if "." in stripped and " " not in stripped and len(stripped) >= 6:
        return {"type": "domain_or_file", "value": stripped}
    return None


def is_noisy_evaluator_literal(value: str) -> bool:
    if "\x00" in value:
        return True
    if looks_like_regex(value):
        return True
    if len(value) <= 12 and re.search(r"[\\/\]\[]", value) and not re.search(r"\.[A-Za-z0-9]{1,6}$", value):
        return True
    return False


def looks_like_regex(value: str) -> bool:
    if value.startswith("^") or value.endswith("$"):
        return True
    regex_markers = (r"\w", r"\s", r"\d", "(?:", "(?P", ".*", ".+", "[^", "\\b")
    if any(marker in value for marker in regex_markers):
        return True
    return bool(re.search(r"\[[^\]]{2,}\].*[+*?]", value))


def is_plausible_path_artifact(value: str) -> bool:
    if len(value) < 5:
        return False
    if any(marker in value for marker in ("MiB/s", "KiB/s", "%!s", "%!d")):
        return False
    if value.startswith(("/", "\\", "./", "../")):
        return True
    if re.match(r"^[A-Za-z]:[\\/]", value):
        return True
    if value.startswith("\\\\"):
        return True
    if re.search(r"\.[A-Za-z0-9]{1,8}($|[\\/\s])", value):
        return True
    parts = re.split(r"[\\/]+", value)
    return len(parts) >= 3 and all(part for part in parts)


def data_summary_for_function(item: dict[str, Any]) -> dict[str, Any]:
    data = item.get("data") or {}
    arrays = data.get("constant_arrays") or []
    blobs = data.get("data_blobs") or []
    strings = [source.get("value") for source in data.get("strings") or [] if source.get("value")]
    summary = {}
    if strings:
        summary["literal_artifacts"] = [artifact for value in strings if (artifact := classify_artifact(value))][:12]
    if arrays or blobs:
        summary["static_data"] = {
            "high_entropy_or_blob_count": len(arrays) + len(blobs),
            "contains_magic": any((source.get("magic_offsets") or []) for source in arrays + blobs),
        }
    return summary


def category_for_chain(kind: str | None) -> str | None:
    return {
        "outbound_http": "network",
        "outbound_network_client": "network",
        "inbound_network_service": "network",
        "network_activity": "network",
        "file_write": "filesystem",
        "file_read": "filesystem",
        "file_delete": "filesystem",
        "file_rename": "filesystem",
        "recursive_filesystem_walk": "filesystem",
        "process_launch": "process",
        "goroutine_spawn": "concurrency",
        "dynamic_loader": "execution",
        "execution_or_loader": "execution",
        "generated_identifier": "filesystem",
        "runtime_string_materialization": "crypto_or_decoding",
    }.get(kind or "")


def description_for_chain(chain: dict[str, Any]) -> str:
    return {
        "outbound_http": "communicates over HTTP",
        "outbound_network_client": "opens outbound network/client connections",
        "inbound_network_service": "listens for inbound network connections",
        "network_activity": "uses network APIs",
        "file_write": "writes data to the filesystem",
        "file_read": "reads data from the filesystem",
        "file_delete": "deletes filesystem paths",
        "file_rename": "renames filesystem paths",
        "recursive_filesystem_walk": "walks filesystem paths recursively",
        "process_launch": "launches an external process",
        "goroutine_spawn": "starts a goroutine",
        "dynamic_loader": "uses dynamic loading or low-level execution APIs",
        "execution_or_loader": "uses dynamic loading or low-level execution APIs",
        "generated_identifier": "generates identifier-like data",
        "runtime_string_materialization": "materializes strings or data at runtime",
    }.get(chain.get("kind"), "performs behavior")


def compact_sinks(sinks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            key: value
            for key, value in {
                "kind": sink.get("kind"),
                "target": sink.get("target"),
                "address": sink.get("address"),
                "strings": sink.get("strings"),
            }.items()
            if value not in (None, [], {})
        }
        for sink in sinks[:12]
    ]


def artifact_for_decryption(item: dict[str, Any]) -> dict[str, Any]:
    artifact = item.get("artifact") or {}
    details = {
        "method": item.get("method"),
        "transforms": item.get("transforms"),
        "key_ascii": item.get("key_ascii"),
        "key_hex": item.get("key_hex"),
        "sha256_prefix": item.get("sha256_prefix"),
        "decoded_size": item.get("decoded_size"),
        "decoded_preview": item.get("decoded_preview"),
    }
    if artifact.get("indicators"):
        details["indicators"] = artifact.get("indicators")
    return {
        "type": item.get("artifact_type", "decoded_artifact"),
        "value": item.get("description") or item.get("artifact_type"),
        "confidence": item.get("confidence", "medium"),
        "details": {key: value for key, value in details.items() if value not in (None, [], {})},
    }


def decoded_artifact_action_description(item: dict[str, Any]) -> str:
    method = item.get("method") or "decode"
    artifact_type = item.get("artifact_type") or "artifact"
    return f"recovers {artifact_type} via {method}"


def collect_artifacts(actions: list[dict[str, Any]], semantics: dict[str, Any]) -> dict[str, list[Any]]:
    buckets: dict[str, list[Any]] = {
        "urls": [],
        "paths": [],
        "commands": [],
        "files": [],
        "domains": [],
        "embedded_artifacts": [],
        "decoded_artifacts": [],
        "fields": [],
    }
    for action in actions:
        for artifact in action.get("artifacts") or []:
            add_artifact_to_bucket(buckets, artifact)
    for payload in semantics.get("embedded_artifacts") or []:
        add_unique(
            buckets["embedded_artifacts"],
            {
                "type": payload.get("kind"),
                "confidence": payload.get("confidence", "medium"),
                "source": payload.get("source"),
            },
        )
    return {key: value for key, value in buckets.items() if value}


def add_artifact_to_bucket(buckets: dict[str, list[Any]], artifact: dict[str, Any]) -> None:
    kind = artifact.get("type")
    if kind == "url":
        add_unique(buckets["urls"], artifact)
    elif kind in {"windows_path", "path"}:
        add_unique(buckets["paths"], artifact)
    elif kind == "command":
        add_unique(buckets["commands"], artifact)
    elif kind in {"file_name", "domain_or_file"}:
        add_unique(buckets["files"], artifact)
    elif kind in {"domain"}:
        add_unique(buckets["domains"], artifact)
    elif kind == "embedded_artifact":
        add_unique(buckets["embedded_artifacts"], artifact)
    elif kind in {
        "embedded_pe",
        "embedded_elf",
        "zip_archive",
        "gzip_stream",
        "decoded_indicators",
        "decoded_text_config",
        "decoded_pe",
        "decoded_elf",
        "decoded_zip",
        "decoded_gzip",
        "decoded_zlib",
        "decoded_script",
    }:
        add_unique(buckets["decoded_artifacts"], artifact)
    elif kind == "field_name":
        add_unique(buckets["fields"], artifact)


def narrative_for_actions(actions: list[dict[str, Any]], artifacts: dict[str, Any]) -> list[str]:
    lines = []
    categories = Counter(action.get("category") for action in actions)
    if categories.get("network"):
        inbound = sum(1 for action in actions if action.get("network_role") == "inbound_listener")
        outbound = sum(1 for action in actions if action.get("network_role") == "outbound_client")
        if inbound and not outbound:
            lines.append("The binary listens for inbound network connections.")
        elif outbound:
            lines.append("The binary opens outbound network/client connections" + artifact_suffix(artifacts.get("urls"), "URLs") + ".")
        else:
            lines.append("The binary uses network APIs" + artifact_suffix(artifacts.get("urls"), "URLs") + ".")
    if categories.get("filesystem"):
        lines.append("The binary performs filesystem reads/writes" + artifact_suffix(artifacts.get("paths"), "paths") + ".")
    if categories.get("process"):
        lines.append("The binary launches external processes" + artifact_suffix(artifacts.get("commands"), "commands") + ".")
    if categories.get("execution"):
        lines.append("The binary uses dynamic loading, executable memory, or low-level syscall/API behavior.")
    if categories.get("embedded_artifact"):
        lines.append("The binary contains embedded static data connected to transformation and loader-relevant code.")
    if categories.get("crypto_or_decoding"):
        lines.append("The binary materializes or decodes runtime data; recovered plaintext is listed only when confidence is strong.")
    if artifacts.get("commands"):
        lines.append("Command-like artifacts are present near execution-related behavior.")
    return lines[:8]


def artifact_suffix(values: list[Any] | None, label: str) -> str:
    if not values:
        return ""
    rendered = ", ".join(str((item or {}).get("value", item))[:120] for item in values[:3])
    return f" using {label}: {rendered}"


def clean_action(action: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in action.items() if value not in (None, [], {})}


def dedupe_actions(actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    seen = set()
    for action in actions:
        key = (
            action.get("function"),
            action.get("kind"),
            action.get("target_api"),
            tuple((artifact.get("type"), artifact.get("value")) for artifact in action.get("artifacts", [])[:6]),
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(action)
    return result


def dedupe_artifacts(artifacts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    seen = set()
    for artifact in artifacts:
        key = (artifact.get("type"), artifact.get("value"))
        if key in seen:
            continue
        seen.add(key)
        result.append(artifact)
    return result


def add_unique(items: list[Any], value: Any) -> None:
    if value not in items:
        items.append(value)


def confidence_for_operation(operation: dict[str, Any], artifacts: list[dict[str, Any]]) -> str:
    if artifacts:
        return "high"
    if operation.get("kind") in {"raw_syscall", "dynamic_syscall_call", "process_launch", "http_post", "http_get"}:
        return "high"
    return "medium"


def action_rank(action: dict[str, Any]) -> int:
    return ACTION_RANK.get(action.get("category", ""), 99)
