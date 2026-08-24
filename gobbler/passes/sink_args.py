from __future__ import annotations

import re
from collections import Counter, deque
from typing import Any

from gobbler.passes.http_args import (
    body_producers_from_dataflow,
    compact_typed_call_args,
    enrich_http_arguments,
)
from gobbler.passes.process_file_args import enrich_process_and_file_arguments


MAX_SINKS = 200
MAX_STRINGS = 12
MAX_ARTIFACTS = 20
MAX_ARGS_PER_KIND = 12
MAX_EVIDENCE = 16
MAX_DATA_SOURCES = 8
MAX_VALUE_LENGTH = 500


FILE_KINDS = {
    "file_read",
    "file_write",
    "file_create",
    "file_open",
    "file_delete",
    "file_rename",
    "directory_create",
    "recursive_filesystem_walk",
    "permission_change",
    "stream_read",
}

NETWORK_KINDS = {
    "http_network",
    "http_request",
    "http_get",
    "http_post",
    "network_connect",
    "network_listen",
}

PROCESS_KINDS = {
    "process_launch",
    "process_execution",
}

LOADER_KINDS = {
    "dynamic_library_load",
    "dynamic_import_resolution",
    "dynamic_syscall_call",
    "raw_syscall",
    "executable_memory_allocation",
    "memory_protection_change",
    "thread_creation",
}

REGISTRY_KINDS = {
    "registry_read",
    "registry_write",
    "registry_create",
    "registry_delete",
}

PERSISTENCE_KINDS = {
    "service_create",
    "scheduled_task_create",
    "persistence_setup",
}

KIND_CATEGORIES = {
    **{kind: "filesystem" for kind in FILE_KINDS},
    **{kind: "network" for kind in NETWORK_KINDS},
    **{kind: "process" for kind in PROCESS_KINDS},
    **{kind: "loader" for kind in LOADER_KINDS},
    **{kind: "registry" for kind in REGISTRY_KINDS},
    **{kind: "persistence" for kind in PERSISTENCE_KINDS},
}

CHAIN_KIND_CATEGORIES = {
    "outbound_http": "network",
    "outbound_network_client": "network",
    "inbound_network_service": "network",
    "network_activity": "network",
    "file_write": "filesystem",
    "file_read": "filesystem",
    "process_launch": "process",
    "dynamic_loader": "loader",
    "execution_or_loader": "loader",
}

CHAIN_KIND_TO_SINK_KIND = {
    "outbound_http": "http_network",
    "outbound_network_client": "network_connect",
    "inbound_network_service": "network_listen",
    "network_activity": "network_connect",
    "file_write": "file_write",
    "file_read": "file_read",
    "process_launch": "process_launch",
    "dynamic_loader": "dynamic_code_or_process_execution",
    "execution_or_loader": "dynamic_code_or_process_execution",
}

TARGET_HINTS: tuple[tuple[str, str, str], ...] = (
    ("net/http", "http_network", "network"),
    ("http.", "http_network", "network"),
    ("http.get", "http_get", "network"),
    ("http.post", "http_post", "network"),
    ("http.newrequest", "http_request", "network"),
    ("net.dial", "network_connect", "network"),
    ("dialtcp", "network_connect", "network"),
    ("net.listen", "network_listen", "network"),
    ("os.readfile", "file_read", "filesystem"),
    ("ioutil.readfile", "file_read", "filesystem"),
    ("os.writefile", "file_write", "filesystem"),
    ("ioutil.writefile", "file_write", "filesystem"),
    ("os.openfile", "file_open", "filesystem"),
    ("os.open", "file_open", "filesystem"),
    ("os.create", "file_create", "filesystem"),
    ("os.remove", "file_delete", "filesystem"),
    ("os.rename", "file_rename", "filesystem"),
    ("os.mkdir", "directory_create", "filesystem"),
    ("filepath.walk", "recursive_filesystem_walk", "filesystem"),
    ("filepath.walkdir", "recursive_filesystem_walk", "filesystem"),
    ("exec.command", "process_launch", "process"),
    ("os/exec.command", "process_launch", "process"),
    ("os.startprocess", "process_launch", "process"),
    ("cmd.start", "process_launch", "process"),
    ("cmd.run", "process_launch", "process"),
    ("syscall.exec", "process_launch", "process"),
    ("forkexec", "process_launch", "process"),
    ("createprocess", "process_launch", "process"),
    ("shellexecute", "process_launch", "process"),
    ("winexec", "process_launch", "process"),
    ("execve", "process_launch", "process"),
    ("posix_spawn", "process_launch", "process"),
    ("loadlibrary", "dynamic_library_load", "loader"),
    ("dlopen", "dynamic_library_load", "loader"),
    ("getprocaddress", "dynamic_import_resolution", "loader"),
    ("dlsym", "dynamic_import_resolution", "loader"),
    ("virtualalloc", "executable_memory_allocation", "loader"),
    ("mmap", "executable_memory_allocation", "loader"),
    ("virtualprotect", "memory_protection_change", "loader"),
    ("mprotect", "memory_protection_change", "loader"),
    ("createthread", "thread_creation", "loader"),
    ("syscall.syscall", "raw_syscall", "loader"),
    ("syscalln", "raw_syscall", "loader"),
    ("registry.", "registry_write", "registry"),
    ("windows/registry", "registry_write", "registry"),
    ("regsetvalue", "registry_write", "registry"),
    ("regcreatekey", "registry_create", "registry"),
    ("regopenkey", "registry_read", "registry"),
    ("createservice", "service_create", "persistence"),
    ("startservice", "service_create", "persistence"),
)

PERSISTENCE_TEXT_PATTERNS = (
    re.compile(r"\\software\\microsoft\\windows\\currentversion\\run", re.IGNORECASE),
    re.compile(r"\\software\\microsoft\\windows\\currentversion\\runonce", re.IGNORECASE),
    re.compile(r"\bschtasks(?:\.exe)?\b", re.IGNORECASE),
    re.compile(r"\bat(?:\.exe)?\s+", re.IGNORECASE),
    re.compile(r"/etc/(?:cron|systemd)|/lib/systemd|/usr/lib/systemd", re.IGNORECASE),
    re.compile(r"\.config/systemd/user|launchagents|launchdaemons", re.IGNORECASE),
    re.compile(r"authorized_keys|\.bashrc|\.profile|\.zshrc", re.IGNORECASE),
)

COMMAND_NAME_ALLOWLIST = {
    "cmd",
    "cmd.exe",
    "powershell",
    "powershell.exe",
    "pwsh",
    "pwsh.exe",
    "whoami",
    "curl",
    "wget",
    "sh",
    "bash",
    "zsh",
    "python",
    "python.exe",
    "rundll32",
    "rundll32.exe",
    "regsvr32",
    "regsvr32.exe",
    "wscript",
    "wscript.exe",
    "cscript",
    "cscript.exe",
}


def analyze_sink_args(graph: dict[str, list[Any]], semantics: dict[str, Any]) -> dict[str, Any]:
    """Summarize evaluator-facing arguments for important system sinks.

    The pass intentionally avoids new disassembly. It aggregates the existing
    call graph, behavior IR, semantic chains, and behavior story into compact
    sink records that answer: what external system interaction happened, where,
    and which concrete strings/artifacts were visible near that interaction.
    """

    builder = SinkArgumentSummaryBuilder(graph or {}, semantics or {})
    return builder.build()


class SinkArgumentSummaryBuilder:
    def __init__(self, graph: dict[str, list[Any]], semantics: dict[str, Any]):
        self.graph = graph
        self.semantics = semantics
        self.sinks: dict[tuple[str, str, str, str | None], dict[str, Any]] = {}
        self.function_order = self._function_order()
        self.call_args = self._index_call_args()
        self.body_producers = body_producers_from_dataflow(semantics)

    def build(self) -> dict[str, Any]:
        self._collect_from_behavior_ir()
        self._collect_from_semantic_chains()
        self._collect_from_behavior_story()
        self._collect_from_loader_behaviors()
        self._collect_from_call_graph()

        for sink in self.sinks.values():
            enrich_sink_arguments(sink, self.body_producers)
        sinks = sorted(self.sinks.values(), key=self._sink_sort_key)[:MAX_SINKS]
        return {
            "version": 1,
            "purpose": "evaluator_facing_sink_argument_summary",
            "summary": self._summary(sinks),
            "sinks": sinks,
            "limitations": [
                "This pass does not disassemble or emulate code; it summarizes evidence recovered by earlier passes.",
                "Arguments are best-effort and may be incomplete when values are built dynamically or passed through interfaces.",
                "Static data sources are summarized by content hints, size, entropy, and magic instead of exposing raw array/blob identifiers.",
            ],
        }

    def _collect_from_behavior_ir(self) -> None:
        functions = (self.semantics.get("behavior_ir") or {}).get("functions") or {}
        for function, item in functions.items():
            for operation in item.get("flow") or []:
                kind = operation.get("kind")
                category = category_for_kind_or_target(kind, operation.get("target"))
                if not category:
                    continue
                sink = self._upsert_sink(
                    function=function,
                    kind=kind or "unknown_sink",
                    category=category,
                    target=operation.get("target"),
                    address=operation.get("address"),
                )
                sink["evidence"].append("behavior_ir_operation")
                if operation.get("tags"):
                    sink["evidence"].extend(f"tag:{tag}" for tag in operation.get("tags") or [])
                merge_strings(sink, operation.get("string_args") or [])
                merge_args(sink, operation.get("arguments") or {})
                merge_typed_call_args(sink, self.call_args.get((function, operation.get("address"))))
                merge_artifacts(sink, artifacts_from_operation(operation))
                merge_data_sources(sink, data_sources_from_function(item))
                merge_role_annotations(sink, operation)
                if operation.get("via"):
                    add_unique(sink["evidence"], f"via:{operation.get('via')}")

    def _collect_from_semantic_chains(self) -> None:
        chains = (self.semantics.get("semantic_chains") or {}).get("chains") or []
        for chain in chains:
            chain_kind = chain.get("kind")
            category = CHAIN_KIND_CATEGORIES.get(chain_kind or "")
            if not category:
                continue
            function = chain.get("function") or "<unknown>"
            sinks = chain.get("sinks") or []
            if not sinks:
                sinks = [
                    {
                        "kind": CHAIN_KIND_TO_SINK_KIND.get(chain_kind or "", chain_kind),
                        "target": chain_kind,
                    }
                ]
            for sink_ref in sinks:
                kind = sink_ref.get("kind") or CHAIN_KIND_TO_SINK_KIND.get(chain_kind or "", "unknown_sink")
                target = sink_ref.get("target") or chain_kind
                sink = self._upsert_sink(
                    function=function,
                    kind=kind,
                    category=category_for_kind_or_target(kind, target) or category,
                    target=target,
                    address=sink_ref.get("address"),
                )
                sink["evidence"].append(f"semantic_chain:{chain_kind}")
                sink["evidence"].extend(chain.get("evidence") or [])
                merge_strings(sink, sink_ref.get("strings") or [])
                merge_strings(sink, chain.get("literals") or [])
                merge_artifacts(sink, artifacts_from_strings(sink_ref.get("strings") or []))
                merge_artifacts(sink, artifacts_from_strings(chain.get("literals") or []))
                merge_field_args(sink, chain.get("related_fields") or [])
                merge_data_sources(sink, chain.get("sources") or [])
                merge_role_annotations(sink, sink_ref)
                merge_role_annotations(sink, chain)
                if chain.get("confidence"):
                    add_unique(sink["evidence"], f"chain_confidence:{chain.get('confidence')}")

    def _collect_from_behavior_story(self) -> None:
        story = self.semantics.get("behavior_story") or {}
        for action in story.get("actions") or []:
            category = normalize_category(action.get("category"))
            kind = action.get("kind")
            if not category_for_kind_or_target(kind, action.get("target_api")) and category not in {
                "filesystem",
                "network",
                "process",
                "execution",
                "loader",
                "registry",
                "persistence",
                "registry_or_persistence",
            }:
                continue
            sink = self._upsert_sink(
                function=action.get("function") or "<unknown>",
                kind=kind or "unknown_sink",
                category="loader" if category == "execution" else category,
                target=action.get("target_api"),
                address=action.get("address"),
            )
            sink["evidence"].append("behavior_story_action")
            if action.get("description"):
                add_unique(sink["evidence"], f"description:{action.get('description')}")
            merge_role_annotations(sink, action)
            merge_artifacts(sink, action.get("artifacts") or [])
            for nested in action.get("sinks") or []:
                merge_strings(sink, nested.get("strings") or [])
                merge_artifacts(sink, artifacts_from_strings(nested.get("strings") or []))

        for flow_item in story.get("execution_flow") or []:
            function = flow_item.get("function") or "<unknown>"
            for action in flow_item.get("actions") or []:
                category = normalize_category(action.get("category"))
                kind = action.get("kind")
                if not category_for_kind_or_target(kind, action.get("target_api")) and category not in {
                    "filesystem",
                    "network",
                    "process",
                    "execution",
                    "loader",
                    "registry",
                    "persistence",
                    "registry_or_persistence",
                }:
                    continue
                sink = self._upsert_sink(
                    function=function,
                    kind=kind or "unknown_sink",
                    category="loader" if category == "execution" else category,
                    target=action.get("target_api"),
                    address=None,
                )
                sink["evidence"].append("behavior_story_execution_flow")
                merge_role_annotations(sink, action)
                merge_artifacts(sink, action.get("artifacts") or [])

    def _collect_from_loader_behaviors(self) -> None:
        for loader in self.semantics.get("loader_behaviors") or []:
            function = loader.get("function") or "<unknown>"
            kind = loader.get("kind") or "dynamic_code_loader"
            sink = self._upsert_sink(
                function=function,
                kind=kind,
                category="loader",
                target=loader.get("target_api") or kind,
                address=None,
            )
            sink["evidence"].append("loader_behavior")
            sink["evidence"].extend(loader.get("evidence") or [])
            for key in ("allocation_constants", "protection_constants"):
                values = loader.get(key) or []
                if values:
                    sink["args"].setdefault(key, [])
                    extend_unique(sink["args"][key], values, MAX_ARGS_PER_KIND)
            if loader.get("called_transformer_count") is not None:
                sink["args"]["called_transformer_count"] = loader.get("called_transformer_count")
            merge_data_sources(sink, loader.get("data_sources") or [])

    def _collect_from_call_graph(self) -> None:
        for function, calls in self.graph.items():
            for call in calls or []:
                if not getattr(call, "visible", True):
                    continue
                target = getattr(call, "target", None)
                kind, category = classify_target(target)
                if not category:
                    continue
                sink = self._upsert_sink(
                    function=function,
                    kind=kind,
                    category=category,
                    target=target,
                    address=hex_address(getattr(call, "address", None)),
                )
                sink["evidence"].append("call_graph")
                call_kind = getattr(call, "kind", None)
                if call_kind:
                    add_unique(sink["evidence"], f"call_kind:{call_kind}")
                via = getattr(call, "via", None)
                if via:
                    add_unique(sink["evidence"], f"via:{via}")
                merge_strings(sink, getattr(call, "string_args", []) or [])
                merge_artifacts(sink, artifacts_from_strings(getattr(call, "string_args", []) or []))
                arg_registers = getattr(call, "arg_registers", None)
                if arg_registers:
                    sink["args"].setdefault("registers", {})
                    sink["args"]["registers"].update(arg_registers)
                merge_typed_call_args(
                    sink,
                    self.call_args.get((function, hex_address(getattr(call, "address", None)))),
                )

    def _upsert_sink(
        self,
        *,
        function: str,
        kind: str,
        category: str,
        target: str | None,
        address: str | None,
    ) -> dict[str, Any]:
        normalized_function = function or "<unknown>"
        normalized_kind = kind or "unknown_sink"
        normalized_category = normalize_category(category) or "unknown"
        normalized_target = target or normalized_kind
        key = (normalized_function, normalized_kind, normalized_target, address)
        sink = self.sinks.get(key)
        if sink is None:
            sink = {
                "function": normalized_function,
                "target": normalized_target,
                "api": normalized_target,
                "kind": normalized_kind,
                "category": normalized_category,
                "address": address,
                "strings": [],
                "artifacts": [],
                "args": {},
                "data_sources": [],
                "evidence": [],
            }
            self.sinks[key] = sink
        return sink

    def _summary(self, sinks: list[dict[str, Any]]) -> dict[str, Any]:
        by_category = Counter(sink.get("category") for sink in sinks)
        by_kind = Counter(sink.get("kind") for sink in sinks)
        artifact_counts = Counter()
        role_counts = Counter()
        for sink in sinks:
            for artifact in sink.get("artifacts") or []:
                artifact_counts[artifact.get("type") or "unknown"] += 1
            for role, values in (sink.get("arg_roles") or {}).items():
                if values:
                    role_counts[role] += len(values)
        return {
            "sink_count": len(sinks),
            "function_count": len({sink.get("function") for sink in sinks}),
            "by_category": dict(sorted(by_category.items())),
            "by_kind": dict(sorted(by_kind.items())),
            "sinks_with_strings": sum(1 for sink in sinks if sink.get("strings")),
            "sinks_with_artifacts": sum(1 for sink in sinks if sink.get("artifacts")),
            "sinks_with_arg_roles": sum(1 for sink in sinks if sink.get("arg_roles")),
            "sinks_with_data_sources": sum(1 for sink in sinks if sink.get("data_sources")),
            "artifact_counts": dict(sorted(artifact_counts.items())),
            "arg_role_counts": dict(sorted(role_counts.items())),
        }

    def _function_order(self) -> dict[str, int]:
        order = {}
        story = self.semantics.get("behavior_story") or {}
        for item in story.get("execution_flow") or []:
            function = item.get("function")
            if function and function not in order:
                order[function] = len(order)
        if order:
            for function in self.graph:
                order.setdefault(function, len(order))
            return order

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

    def _index_call_args(self) -> dict[tuple[str, str], dict[str, Any]]:
        indexed = {}
        dataflow = self.semantics.get("dataflow") or {}
        for function, facts in (dataflow.get("functions") or {}).items():
            for call in facts.get("call_arguments") or []:
                address = call.get("address")
                if address:
                    indexed[(function, address)] = call
        return indexed

    def _sink_sort_key(self, sink: dict[str, Any]) -> tuple[int, int, str, str, str]:
        return (
            self.function_order.get(sink.get("function", ""), 9999),
            category_rank(sink.get("category")),
            sink.get("function") or "",
            sink.get("address") or "",
            sink.get("target") or "",
        )


def category_for_kind_or_target(kind: Any, target: Any) -> str | None:
    kind_text = str(kind or "")
    if kind_text in KIND_CATEGORIES:
        return KIND_CATEGORIES[kind_text]
    if kind_text in CHAIN_KIND_CATEGORIES:
        return CHAIN_KIND_CATEGORIES[kind_text]
    _, category = classify_target(target)
    return category


def classify_target(target: Any) -> tuple[str, str | None]:
    if not isinstance(target, str) or not target:
        return "unknown_sink", None
    lowered = target.lower()
    for needle, kind, category in TARGET_HINTS:
        if needle in lowered:
            return kind, category
    return "unknown_sink", None


def normalize_category(category: Any) -> str:
    text = str(category or "")
    if text == "execution":
        return "loader"
    if text in {"filesystem", "network", "process", "loader", "registry", "persistence", "registry_or_persistence"}:
        return text
    return text


def merge_strings(sink: dict[str, Any], values: list[Any]) -> None:
    for value in values:
        if isinstance(value, dict):
            value = value.get("value")
        if not isinstance(value, str):
            continue
        cleaned = clean_value(value)
        if not cleaned:
            continue
        extracted = extract_artifacts(cleaned)
        if extracted and not classify_artifact(cleaned):
            for artifact in extracted:
                add_unique(sink["strings"], artifact.get("value"), MAX_STRINGS)
            continue
        if useful_sink_string(cleaned):
            add_unique(sink["strings"], cleaned, MAX_STRINGS)


def merge_artifacts(sink: dict[str, Any], artifacts: list[Any]) -> None:
    for artifact in artifacts:
        compact = compact_artifact(artifact)
        if compact:
            add_unique_dict(sink["artifacts"], compact, MAX_ARTIFACTS)


def merge_args(sink: dict[str, Any], args: dict[str, Any]) -> None:
    if not isinstance(args, dict):
        return
    if args.get("strings"):
        merge_strings(sink, args.get("strings") or [])
        string_args = compact_string_args(args.get("strings") or [])
        if string_args:
            sink["args"].setdefault("strings", [])
            extend_unique(sink["args"]["strings"], string_args, MAX_ARGS_PER_KIND)
    if args.get("slices"):
        slice_args = compact_symbolic_values(args.get("slices") or [])
        if slice_args:
            sink["args"].setdefault("slices", [])
            extend_unique_dict(sink["args"]["slices"], slice_args, MAX_ARGS_PER_KIND)
    if args.get("symbolic"):
        symbolic_args = compact_symbolic_values(args.get("symbolic") or [])
        if symbolic_args:
            sink["args"].setdefault("symbolic", [])
            extend_unique_dict(sink["args"]["symbolic"], symbolic_args, MAX_ARGS_PER_KIND)


def merge_typed_call_args(sink: dict[str, Any], call_args: dict[str, Any] | None) -> None:
    compact = compact_typed_call_args(call_args)
    for key, values in compact.items():
        if not values:
            continue
        sink["args"].setdefault(key, [])
        extend_unique_dict(sink["args"][key], values, MAX_ARGS_PER_KIND)


def merge_field_args(sink: dict[str, Any], fields: list[Any]) -> None:
    values = [clean_value(field) for field in fields if isinstance(field, str)]
    values = [value for value in values if value]
    if not values:
        return
    sink["args"].setdefault("related_fields", [])
    extend_unique(sink["args"]["related_fields"], values, MAX_ARGS_PER_KIND)
    for value in values:
        merge_artifacts(sink, [{"type": "field_name", "value": value}])


def merge_data_sources(sink: dict[str, Any], sources: list[Any]) -> None:
    for source in sources:
        compact = compact_data_source(source)
        if compact:
            add_unique_dict(sink["data_sources"], compact, MAX_DATA_SOURCES)
            preview = compact.get("preview")
            if preview:
                preview_artifacts = artifacts_from_strings([preview])
                if preview_artifacts:
                    merge_strings(sink, [preview])
                    merge_artifacts(sink, preview_artifacts)


def merge_role_annotations(sink: dict[str, Any], source: dict[str, Any]) -> None:
    for key in ("network_role", "process_role", "filesystem_role"):
        value = source.get(key)
        if value and not sink.get(key):
            sink[key] = value
            add_unique(sink["evidence"], f"{key}:{value}")


def artifacts_from_operation(operation: dict[str, Any]) -> list[dict[str, Any]]:
    artifacts = []
    artifacts.extend(artifacts_from_strings(operation.get("string_args") or []))
    args = operation.get("arguments") or {}
    for value in args.get("strings") or []:
        if isinstance(value, dict):
            value = value.get("value")
        artifact = classify_artifact(value)
        if artifact:
            artifacts.append(artifact)
    return artifacts


def enrich_sink_arguments(
    sink: dict[str, Any],
    body_producers: dict[str, list[dict[str, Any]]] | None = None,
) -> None:
    enrich_http_arguments(sink, body_producers)
    enrich_process_and_file_arguments(sink)
    strip_internal_data_source_ids(sink)
    coalesce_data_sources(sink)
    roles = build_arg_roles(sink)
    if roles:
        sink["arg_roles"] = roles
    summary = operation_summary(sink, roles)
    if summary:
        sink["operation_summary"] = summary


def strip_internal_data_source_ids(sink: dict[str, Any]) -> None:
    for source in sink.get("data_sources") or []:
        if isinstance(source, dict):
            source.pop("id", None)


def coalesce_data_sources(sink: dict[str, Any]) -> None:
    sources = []
    by_key: dict[tuple[Any, ...], dict[str, Any]] = {}
    for source in sink.get("data_sources") or []:
        if not isinstance(source, dict):
            continue
        key = (
            source.get("kind"),
            source.get("section"),
            source.get("size"),
            source.get("entropy"),
            source.get("preview"),
            source.get("text_preview"),
        )
        existing = by_key.get(key)
        if existing is None:
            by_key[key] = source
            sources.append(source)
            continue
        for field in ("reasons", "magic_offsets"):
            if not existing.get(field) and source.get(field):
                existing[field] = source[field]
    sink["data_sources"] = sources[:MAX_DATA_SOURCES]


def build_arg_roles(sink: dict[str, Any]) -> dict[str, list[Any]]:
    roles: dict[str, list[Any]] = {}
    for source_key, role_key in (
        ("network_role", "network_role"),
        ("process_role", "process_role"),
        ("filesystem_role", "filesystem_role"),
    ):
        if sink.get(source_key):
            role_add(roles, role_key, sink.get(source_key))

    for artifact in sink.get("artifacts") or []:
        add_artifact_to_roles(roles, artifact)

    for value in sink.get("strings") or []:
        for artifact in extract_artifacts(value):
            add_artifact_to_roles(roles, artifact)

    args = sink.get("args") or {}
    for value in args.get("strings") or []:
        for artifact in extract_artifacts(value):
            add_artifact_to_roles(roles, artifact)

    category = sink.get("category")
    kind = sink.get("kind")
    if category == "process":
        add_process_roles(roles, sink)
    elif category == "network":
        add_network_roles(roles, sink)
    elif category == "filesystem":
        add_filesystem_roles(roles, sink)
    elif category == "loader":
        add_loader_roles(roles, sink)
    elif category in {"registry", "persistence", "registry_or_persistence"}:
        add_registry_roles(roles, sink)

    if kind in {"file_write", "file_create"} and sink.get("data_sources"):
        role_add(roles, "write_data_sources", compact_role_values(sink.get("data_sources") or [])[:4])
    if kind in {"file_read", "file_open", "stream_read"} and sink.get("data_sources"):
        role_add(roles, "read_related_data_sources", compact_role_values(sink.get("data_sources") or [])[:4])
    normalize_role_lists(roles)
    return {key: value for key, value in sorted(roles.items()) if value}


def add_artifact_to_roles(roles: dict[str, list[Any]], artifact: dict[str, Any]) -> None:
    artifact_type = artifact.get("type")
    value = artifact.get("value")
    if value in (None, "", [], {}):
        return
    if artifact_type == "url":
        cleaned_url = clean_url_value(str(value))
        role_add(roles, "urls", cleaned_url)
        host = host_from_url(cleaned_url)
        if host:
            role_add(roles, "hosts", host)
    elif artifact_type == "ip_address":
        role_add(roles, "ips", value)
    elif artifact_type in {"windows_path", "path"}:
        role_add(roles, "paths", value)
    elif artifact_type == "file_name":
        role_add(roles, "files", value)
    elif artifact_type == "domain_or_file":
        role_add(roles, "hosts_or_files", value)
    elif artifact_type == "command":
        role_add(roles, "commands", value)
    elif artifact_type == "persistence_indicator":
        role_add(roles, "persistence_locations", value)
    elif artifact_type == "field_name":
        role_add(roles, "field_names", value)


def add_process_roles(roles: dict[str, list[Any]], sink: dict[str, Any]) -> None:
    command_parts = []
    process_targets = []
    for value in sink.get("strings") or []:
        cleaned = clean_value(value)
        if cleaned and useful_process_string(cleaned):
            command_parts.append(cleaned)
    if command_parts:
        role_add(roles, "command_parts", command_parts[:MAX_ARGS_PER_KIND])
        inferred_role = classify_process_role(command_parts)
        if not roles.get("process_role") or inferred_role != "process_launch":
            role_add(roles, "process_role", inferred_role)
    for artifact in sink.get("artifacts") or []:
        if artifact.get("type") in {"command", "file_name", "path", "windows_path"}:
            role_add(roles, "process_targets", artifact.get("value"))
            process_targets.append(artifact.get("value"))
    target_role = classify_process_role(process_targets)
    if target_role != "process_launch":
        role_add(roles, "process_role", target_role)
    if not roles.get("process_role"):
        role_add(roles, "process_role", classify_process_role(sink.get("strings") or []))


def add_network_roles(roles: dict[str, list[Any]], sink: dict[str, Any]) -> None:
    role_add(roles, "network_role", classify_network_role(sink))
    for value in sink.get("strings") or []:
        cleaned = clean_value(value)
        if not cleaned:
            continue
        if re.fullmatch(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?::\d{1,5})?", cleaned):
            role_add(roles, "hosts", cleaned)
        elif re.fullmatch(r":?\d{1,5}", cleaned):
            role_add(roles, "ports", cleaned.lstrip(":"))


def add_filesystem_roles(roles: dict[str, list[Any]], sink: dict[str, Any]) -> None:
    role = classify_filesystem_role(sink)
    if role:
        role_add(roles, "filesystem_role", role)
    for artifact in sink.get("artifacts") or []:
        if artifact.get("type") in {"windows_path", "path", "file_name", "domain_or_file"}:
            role_add(roles, "filesystem_targets", artifact.get("value"))


def add_loader_roles(roles: dict[str, list[Any]], sink: dict[str, Any]) -> None:
    for artifact in sink.get("artifacts") or []:
        value = artifact.get("value")
        if not isinstance(value, str):
            continue
        lowered = value.lower()
        if lowered.endswith((".dll", ".so", ".dylib")):
            role_add(roles, "libraries", value)
        elif artifact.get("type") in {"file_name", "path", "windows_path"}:
            role_add(roles, "loader_artifacts", value)
    args = sink.get("args") or {}
    for key in ("allocation_constants", "protection_constants"):
        if args.get(key):
            role_add(roles, key, args.get(key)[:MAX_ARGS_PER_KIND])


def add_registry_roles(roles: dict[str, list[Any]], sink: dict[str, Any]) -> None:
    if sink.get("category") == "persistence":
        role_add(roles, "persistence_mechanism", sink.get("kind"))
    for value in sink.get("strings") or []:
        cleaned = clean_value(value)
        if cleaned and ("\\software\\" in cleaned.lower() or "registry" in cleaned.lower()):
            role_add(roles, "registry_paths", cleaned)
            if is_persistence_location(cleaned):
                role_add(roles, "persistence_locations", cleaned)


def operation_summary(sink: dict[str, Any], roles: dict[str, list[Any]]) -> str | None:
    category = sink.get("category") or "system"
    kind = sink.get("kind") or "operation"
    target = sink.get("target") or sink.get("api")
    pieces = [f"{category} {kind}"]
    if target:
        pieces.append(f"via {target}")

    role_order = (
        "network_role",
        "process_role",
        "filesystem_role",
        "urls",
        "hosts",
        "ips",
        "ports",
        "paths",
        "files",
        "filesystem_targets",
        "commands",
        "command_parts",
        "process_targets",
        "libraries",
        "persistence_mechanism",
        "persistence_locations",
        "registry_paths",
    )
    details = []
    for role in role_order:
        values = roles.get(role)
        if values:
            details.append(f"{role}={render_role_values(values)}")
        if len(details) >= 3:
            break
    if details:
        pieces.append("(" + "; ".join(details) + ")")
    return " ".join(pieces)


def role_add(roles: dict[str, list[Any]], role: str, value: Any) -> None:
    if value in (None, "", [], {}):
        return
    roles.setdefault(role, [])
    if isinstance(value, list):
        for item in value:
            add_unique(roles[role], item, MAX_ARGS_PER_KIND)
        return
    add_unique(roles[role], value, MAX_ARGS_PER_KIND)


def compact_role_values(values: list[Any]) -> list[Any]:
    compacted = []
    for value in values:
        if isinstance(value, dict):
            compacted.append(clean_dict({key: value.get(key) for key in ("kind", "size", "entropy", "preview", "magic_offsets")}))
        else:
            compacted.append(value)
    return [value for value in compacted if value not in (None, "", [], {})]


def render_role_values(values: list[Any]) -> str:
    rendered = []
    for value in values[:3]:
        if isinstance(value, dict):
            preview = value.get("preview") or value.get("kind") or value.get("size")
            rendered.append(str(preview)[:80])
        else:
            rendered.append(str(value)[:80])
    suffix = "" if len(values) <= 3 else f" +{len(values) - 3}"
    return ", ".join(rendered) + suffix


def host_from_url(value: str) -> str | None:
    match = re.match(r"https?://([^/:?#]+)", value)
    return match.group(1) if match else None


def clean_url_value(value: str) -> str:
    match = re.search(r"https?://", value)
    if not match:
        return value
    start = match.start()
    value = value[start:]
    scheme_end = match.end() - start
    repeated = re.search(r"https?:", value[scheme_end:])
    if repeated:
        value = value[: scheme_end + repeated.start()]
    return value.rstrip(".,);]}'\"")


def classify_process_role(values: list[Any]) -> str:
    strings = [clean_value(value) for value in values if clean_value(value)]
    joined = " ".join(strings).lower()
    commands = {command_basename(value) for value in strings}
    commands.discard("")
    if commands & {"git", "go", "make", "gcc", "g++", "clang", "uname", "whoami", "hostname"}:
        return "developer_tooling_or_environment_probe"
    if commands & {"rundll32", "rundll32.exe", "regsvr32", "regsvr32.exe", "mshta", "mshta.exe", "wscript", "wscript.exe", "cscript", "cscript.exe"}:
        return "lolbin_execution"
    if commands & {"cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe", "sh", "bash", "zsh"}:
        if any(marker in joined for marker in (" -enc", "frombase64string", "downloadstring", "iex", "curl ", "wget ")):
            return "shell_with_encoded_or_download_command"
        return "shell_execution"
    if commands & {"curl", "wget"}:
        return "downloader_command"
    return "process_launch"


def classify_network_role(sink: dict[str, Any]) -> str:
    kind = str(sink.get("kind") or "")
    target = str(sink.get("target") or "").lower()
    if kind == "network_listen" or any(marker in target for marker in ("listen", "listenandserve", ".serve", "handlefunc", ".accept", "grpc.server")):
        return "inbound_listener"
    if kind in {"http_get", "http_post", "http_request", "network_connect"} or any(marker in target for marker in ("http.get", "http.post", ".get", ".post", "newrequest", ".dial", "client.do")):
        return "outbound_client"
    if "lookup" in target or "resolve" in target:
        return "dns_lookup"
    return "network_activity"


def classify_filesystem_role(sink: dict[str, Any]) -> str | None:
    kind = sink.get("kind")
    if kind != "directory_create":
        return None
    values = []
    values.extend(sink.get("strings") or [])
    for artifact in sink.get("artifacts") or []:
        values.append(artifact.get("value"))
    joined = " ".join(str(value).lower() for value in values if isinstance(value, str))
    if is_persistence_location(joined):
        return "startup_or_persistence_location"
    if any(marker in joined for marker in ("tmp", "temp", "cache", "build", "dist", "workspace", "bigstorageenv", "tmproot")):
        return "workspace_or_cache_directory"
    if any(marker in joined for marker in ("config", ".config", "appdata")):
        return "config_directory"
    return "directory_create"


def is_persistence_location(value: str) -> bool:
    return any(pattern.search(value) for pattern in PERSISTENCE_TEXT_PATTERNS)


def command_basename(value: str) -> str:
    token = value.strip().strip("\"'").split(" ", 1)[0]
    return token.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()


def normalize_role_lists(roles: dict[str, list[Any]]) -> None:
    if "process_role" in roles and len(roles["process_role"]) > 1:
        specific = [role for role in roles["process_role"] if role != "process_launch"]
        if specific:
            roles["process_role"] = specific
    if "network_role" in roles and len(roles["network_role"]) > 1:
        specific = [role for role in roles["network_role"] if role not in {"network_activity", "outbound_network_client", "inbound_network_service"}]
        roles["network_role"] = specific or roles["network_role"]
    if "filesystem_role" in roles and len(roles["filesystem_role"]) > 1:
        specific = [role for role in roles["filesystem_role"] if role != "directory_create"]
        if specific:
            roles["filesystem_role"] = specific


def artifacts_from_strings(values: list[Any]) -> list[dict[str, Any]]:
    artifacts = []
    for value in values:
        if isinstance(value, dict):
            value = value.get("value")
        artifacts.extend(extract_artifacts(value))
    return artifacts


def extract_artifacts(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, str):
        return []
    stripped = clean_value(value)
    if not stripped:
        return []
    artifacts = []
    for match in re.finditer(r"https?://[^\s\"'<>`]+", stripped):
        url = trim_url(match.group(0))
        if valid_url_artifact(url):
            artifacts.append({"type": "url", "value": url})
    if artifacts:
        return artifacts[:8]
    artifact = classify_artifact(stripped)
    return [artifact] if artifact else []


def classify_artifact(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, str):
        return None
    stripped = clean_value(value)
    if not stripped:
        return None
    lowered = stripped.lower()
    if len(stripped) < 2 or len(stripped) > 2000:
        return None
    if looks_like_binary_preview(stripped):
        return None
    if looks_like_concatenated_runtime_text(stripped):
        return None
    for pattern in PERSISTENCE_TEXT_PATTERNS:
        if pattern.search(stripped):
            return {"type": "persistence_indicator", "value": stripped}
    if lowered.startswith(("http://", "https://")):
        return {"type": "url", "value": stripped}
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?", stripped):
        return {"type": "ip_address", "value": stripped}
    if lowered in COMMAND_NAME_ALLOWLIST or any(
        token in lowered for token in ("cmd.exe", "powershell", "rundll32", "regsvr32", "wscript", "cscript", "/bin/sh", "/bin/bash")
    ):
        return {"type": "command", "value": stripped}
    if stripped.startswith("\\\\") or re.match(r"^[A-Za-z]:[\\/]", stripped):
        return {"type": "windows_path", "value": stripped}
    if "/" in stripped or "\\" in stripped:
        if is_plausible_path(stripped):
            return {"type": "path", "value": stripped}
        return None
    if lowered.endswith((".exe", ".dll", ".so", ".dylib", ".ps1", ".bat", ".cmd", ".sh", ".zip", ".dat", ".json", ".txt")):
        return {"type": "file_name", "value": stripped}
    if looks_noisy(stripped):
        return None
    if is_plausible_domain(stripped):
        return {"type": "domain_or_file", "value": stripped}
    return None


def data_sources_from_function(function_item: dict[str, Any]) -> list[dict[str, Any]]:
    data = function_item.get("data") or {}
    sources = []
    for key in ("data_blobs", "constant_arrays"):
        for source in data.get(key) or []:
            sources.append({"kind": key[:-1], **source})
    for source in data.get("strings") or []:
        sources.append({"kind": "string", **source})
    return sources


def compact_data_source(source: Any) -> dict[str, Any] | None:
    if not isinstance(source, dict):
        return None
    kind = source.get("kind")
    if kind not in {"data_blob", "constant_array", "constant_array", "string"}:
        kind = kind or source.get("type")
    if kind not in {"data_blob", "constant_array", "string"}:
        return None
    preview = source.get("preview") or source.get("ascii_preview") or source.get("value")
    compact_preview = None
    text_preview = None
    if isinstance(preview, str):
        cleaned_preview = clean_value(preview)
        if cleaned_preview:
            preview_artifacts = extract_artifacts(cleaned_preview)
            if preview_artifacts:
                compact_preview = preview_artifacts[0].get("value")
                text_preview = compact_http_relevant_preview(cleaned_preview)
            elif content_type_from_text(cleaned_preview):
                compact_preview = content_type_from_text(cleaned_preview)
                text_preview = compact_http_relevant_preview(cleaned_preview)
            elif body_candidate_from_text(cleaned_preview):
                compact_preview = body_candidate_from_text(cleaned_preview)
                text_preview = compact_http_relevant_preview(cleaned_preview)
            elif kind == "string" and useful_sink_string(cleaned_preview):
                compact_preview = cleaned_preview
    if kind in {"constant_array", "data_blob"} and not should_keep_data_source(source, compact_preview):
        return None
    result = {
        "id": source.get("id"),
        "kind": kind,
        "section": source.get("section"),
        "size": source.get("size"),
        "entropy": source.get("entropy"),
        "magic_offsets": compact_magic_offsets(source.get("magic_offsets") or []),
        "reasons": source.get("reasons")[:6] if isinstance(source.get("reasons"), list) else None,
        "preview": compact_preview,
        "text_preview": text_preview,
    }
    return clean_dict(result)


def should_keep_data_source(source: dict[str, Any], preview: str | None) -> bool:
    if preview:
        return True
    if source.get("magic_offsets"):
        return True
    entropy = source.get("entropy")
    if isinstance(entropy, (int, float)) and entropy >= 7.0:
        return True
    reasons = source.get("reasons") or []
    if not isinstance(reasons, list):
        return False
    generic_reasons = {"referenced_global_data"}
    return any(reason not in generic_reasons for reason in reasons)


def compact_http_relevant_preview(value: str) -> str | None:
    parts = []
    body = body_candidate_from_text(value)
    if body:
        parts.append(body)
    content_type = content_type_from_text(value)
    if content_type:
        parts.append(content_type)
    for artifact in extract_artifacts(value):
        if artifact.get("type") == "url" and artifact.get("value"):
            parts.append(str(artifact["value"]))
            break
    if not parts:
        return None
    rendered = " ".join(parts)
    return rendered[:240] + ("...<truncated>" if len(rendered) > 240 else "")


def content_type_from_text(value: str) -> str | None:
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


def body_candidate_from_text(value: str) -> str | None:
    json_match = re.search(r"(\{[^{}]{2,240}\}|\[[^\[\]]{2,240}\])", value)
    if json_match:
        return json_match.group(1)
    form_match = re.search(r"\b[A-Za-z0-9_.-]+=[^&\s]{1,120}(?:&[A-Za-z0-9_.-]+=[^&\s]{1,120})+", value)
    return form_match.group(0) if form_match else None


def compact_magic_offsets(values: list[Any]) -> list[dict[str, Any]]:
    compacted = []
    for value in values[:6]:
        if isinstance(value, dict):
            compacted.append(clean_dict({"offset": value.get("offset"), "magic": value.get("magic")}))
        else:
            compacted.append({"value": str(value)[:80]})
    return compacted


def compact_string_args(values: list[Any]) -> list[str]:
    result = []
    for value in values:
        if isinstance(value, dict):
            value = value.get("value")
        cleaned = clean_value(value) if isinstance(value, str) else None
        if cleaned and useful_sink_string(cleaned):
            add_unique(result, cleaned, MAX_ARGS_PER_KIND)
    return result


def compact_symbolic_values(values: list[Any]) -> list[dict[str, Any]]:
    result = []
    for value in values:
        if not isinstance(value, dict):
            continue
        source = compact_data_source(value.get("source")) if isinstance(value.get("source"), dict) else None
        if value.get("kind") in {"constant_array", "data_blob"} and source is None:
            continue
        compact = {
            "kind": value.get("kind"),
            "register": value.get("register"),
            "value": clean_value(value.get("value")) if isinstance(value.get("value"), str) else value.get("value"),
            "length": value.get("length"),
            "cap": value.get("cap"),
            "source": source,
        }
        compact = clean_dict(compact)
        if compact:
            result.append(compact)
    return result


def compact_artifact(artifact: Any) -> dict[str, Any] | None:
    if not isinstance(artifact, dict):
        return None
    value = artifact.get("value")
    compact = {
        "type": artifact.get("type") or artifact.get("kind"),
        "value": clean_value(value) if isinstance(value, str) else value,
        "confidence": artifact.get("confidence"),
        "details": compact_details(artifact.get("details")),
    }
    return clean_dict(compact)


def compact_details(details: Any) -> dict[str, Any] | None:
    if not isinstance(details, dict):
        return None
    allowed = {}
    for key in ("encoding", "method", "decoded_size", "decoded_preview", "producer", "caller", "status"):
        value = details.get(key)
        if isinstance(value, str):
            value = clean_value(value)
        if value not in (None, "", [], {}):
            allowed[key] = value
    indicators = details.get("indicators")
    if indicators:
        allowed["indicators"] = indicators[:8] if isinstance(indicators, list) else indicators
    source = details.get("source")
    if isinstance(source, dict):
        allowed["source"] = compact_data_source(source)
    return allowed or None


def clean_value(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    if not stripped:
        return None
    stripped = stripped.replace("\x00", "")
    if len(stripped) > MAX_VALUE_LENGTH:
        stripped = stripped[:MAX_VALUE_LENGTH] + "...<truncated>"
    return stripped


def looks_noisy(value: str) -> bool:
    if len(value) <= 12 and re.search(r"[\\/\]\[]", value) and not re.search(r"\.[A-Za-z0-9]{1,8}$", value):
        return True
    if value.startswith("^") or value.endswith("$"):
        return True
    regex_markers = (r"\w", r"\s", r"\d", "(?:", "(?P", ".*", ".+", "[^", "\\b")
    return any(marker in value for marker in regex_markers)


def is_plausible_path(value: str) -> bool:
    if len(value) < 5:
        return False
    if len(value) > 260 and not value.startswith(("http://", "https://")):
        return False
    lowered = value.lower()
    if "http/" in lowered or "http2:" in lowered or "parseuint" in lowered:
        return False
    if "[" in value and "]" in value:
        return False
    if any(marker in value for marker in ("MiB/s", "KiB/s", "%!s", "%!d")):
        return False
    if len(value) > 80 and noisy_symbol_ratio(value) > 0.25:
        return False
    if looks_like_binary_preview(value):
        return False
    if " " in value and not (value.startswith(("/", "\\", "./", "../")) or re.match(r"^[A-Za-z]:[\\/]", value)):
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


def useful_sink_string(value: str) -> bool:
    if classify_artifact(value):
        return True
    if len(value) < 2:
        return False
    if len(value) <= 3:
        return value.startswith("-") or value in {"sh", "cmd", "run"}
    if len(value) > 240:
        return bool(extract_artifacts(value))
    if looks_noisy(value):
        return False
    if looks_like_binary_preview(value):
        return False
    if noisy_symbol_ratio(value) > 0.35:
        return False
    if is_unqualified_bare_word(value):
        return value.lower() in COMMAND_NAME_ALLOWLIST or value.startswith("-")
    if len(value) > 80 and not re.search(r"\s", value):
        return False
    return True


def useful_process_string(value: str) -> bool:
    artifact = classify_artifact(value)
    if artifact and artifact.get("type") in {"command", "file_name", "path", "windows_path"}:
        return True
    if value.startswith(("-", "/")) and len(value) <= 80:
        return True
    return value.lower() in COMMAND_NAME_ALLOWLIST


def is_unqualified_bare_word(value: str) -> bool:
    return re.fullmatch(r"[A-Za-z0-9_-]{4,80}", value) is not None


def noisy_symbol_ratio(value: str) -> float:
    if not value:
        return 1.0
    noisy = sum(1 for ch in value if not (ch.isalnum() or ch.isspace() or ch in "-_./\\:$%?&=+@"))
    return noisy / len(value)


def trim_url(value: str) -> str:
    trimmed = value.rstrip(".,);]}'\"")
    for marker_text in ("http://", "https://"):
        marker = trimmed.find(marker_text, len(marker_text))
        if marker > 0:
            trimmed = trimmed[:marker]
    for marker_text in (
        "reflect.",
        "runtime.",
        "GetFileInformationByHandle",
        "ChanDir",
        "Value>:",
    ):
        marker = trimmed.find(marker_text)
        if marker > 0:
            trimmed = trimmed[:marker]
    marker = trimmed.find("http2:")
    if marker > 0:
        trimmed = trimmed[:marker]
    return trimmed.rstrip(".,);]}'\"")


def valid_url_artifact(value: str) -> bool:
    match = re.match(r"https?://([^/:?#]+)", value)
    if not match:
        return False
    host = match.group(1)
    return host in {"localhost"} or "." in host or re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host) is not None


def is_plausible_domain(value: str) -> bool:
    if " " in value or len(value) > 120 or value.startswith(".") or ".." in value:
        return False
    if not re.fullmatch(r"[A-Za-z0-9_.:-]+", value):
        return False
    host = value.rsplit(":", 1)[0] if re.search(r":\d{1,5}$", value) else value
    if not re.fullmatch(r"(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24}", host):
        return False
    return not looks_like_concatenated_runtime_text(value)


def looks_like_concatenated_runtime_text(value: str) -> bool:
    lowered = value.lower()
    markers = (
        "parseuint",
        "http/1.1",
        "http2:",
        "reflect.value",
        "reflect.",
        "runtime.",
        "0123456789abcdef",
        "vpclmulqdq",
        "sha2-512",
        "getfileinformationbyhandle",
        "float32float64",
        "uintptr",
        "chandir",
        "forcegc",
    )
    hits = sum(1 for marker in markers if marker in lowered)
    return hits >= 2 or (len(value) > 80 and hits >= 1)


def looks_like_binary_preview(value: str) -> bool:
    if len(value) < 24:
        return False
    dot_ratio = value.count(".") / len(value)
    if dot_ratio > 0.20:
        return True
    alnum_ratio = sum(1 for ch in value if ch.isalnum()) / len(value)
    if alnum_ratio < 0.35 and dot_ratio > 0.10:
        return True
    return False


def add_unique(values: list[Any], value: Any, limit: int = MAX_ARGS_PER_KIND) -> None:
    if value in (None, "", [], {}):
        return
    if value in values:
        return
    if len(values) >= limit:
        return
    values.append(value)


def extend_unique(values: list[Any], new_values: list[Any], limit: int = MAX_ARGS_PER_KIND) -> None:
    for value in new_values:
        add_unique(values, value, limit)


def add_unique_dict(values: list[dict[str, Any]], value: dict[str, Any], limit: int = MAX_ARGS_PER_KIND) -> None:
    if value in ({}, None):
        return
    key = tuple(sorted(flatten_for_key(value)))
    for existing in values:
        if tuple(sorted(flatten_for_key(existing))) == key:
            return
    if len(values) >= limit:
        return
    values.append(value)


def extend_unique_dict(values: list[dict[str, Any]], new_values: list[dict[str, Any]], limit: int = MAX_ARGS_PER_KIND) -> None:
    for value in new_values:
        add_unique_dict(values, value, limit)


def flatten_for_key(value: Any, prefix: str = "") -> list[tuple[str, str]]:
    if isinstance(value, dict):
        result = []
        for key, nested in sorted(value.items()):
            result.extend(flatten_for_key(nested, f"{prefix}.{key}" if prefix else str(key)))
        return result
    if isinstance(value, list):
        result = []
        for index, nested in enumerate(value):
            result.extend(flatten_for_key(nested, f"{prefix}[{index}]"))
        return result
    return [(prefix, repr(value))]


def clean_dict(value: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if item not in (None, "", [], {})}


def hex_address(address: Any) -> str | None:
    if isinstance(address, int):
        return hex(address)
    if isinstance(address, str):
        return address
    return None


def category_rank(category: Any) -> int:
    return {
        "process": 0,
        "loader": 1,
        "network": 2,
        "filesystem": 3,
        "persistence": 4,
        "registry": 5,
        "registry_or_persistence": 6,
    }.get(str(category or ""), 9)


__all__ = ["analyze_sink_args"]
