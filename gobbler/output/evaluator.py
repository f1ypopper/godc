"""Compact evaluator-facing Gobbler output projection."""

from __future__ import annotations

from pathlib import Path
from typing import Any

SCHEMA_VERSION = 3
MAX_FLOW_FUNCTIONS = 20
MAX_ACTIONS_PER_FUNCTION = 8
MAX_CARDS = 120
MAX_CHAIN_EVENTS = 40
MAX_UNLINKED_EVENTS = 30
MAX_LIST_ITEMS = 40
MAX_STRING_LEN = 240

SYSTEM_CATEGORIES = {
    "network",
    "filesystem",
    "process",
    "concurrency",
    "loader",
    "execution",
    "registry",
}

CARD_CATEGORY_ORDER = {
    "loader": 0,
    "execution": 0,
    "process": 1,
    "network": 2,
    "filesystem": 3,
    "registry": 4,
    "concurrency": 5,
    "decoded_artifact": 6,
    "runtime_decoding": 7,
}


def build_evaluator_document(
    report: dict[str, Any],
    input_path: Path | str | None = None,
) -> dict[str, Any]:
    """Return the concise human/LLM evaluator view for a full Gobbler report."""

    if report.get("schema_version") == SCHEMA_VERSION and report.get("output_profile") == "evaluator":
        out = dict(report)
        if input_path is not None:
            out["input_file"] = str(input_path)
        return out

    semantic = report.get("semantic_analysis") if isinstance(report.get("semantic_analysis"), dict) else {}
    call_graph = report.get("call_graph") if isinstance(report.get("call_graph"), dict) else {}

    decoded_artifacts = compact_decoded_artifacts(semantic.get("decryption_recovery"))
    loader_activity = compact_loader_activity(semantic.get("loader_behaviors"))
    sink_cards = cards_from_sinks(semantic.get("sink_args"))
    decoder_cards = cards_from_runtime_decoding(semantic.get("runtime_decoding"), decoded_artifacts)
    artifact_cards = cards_from_decoded_artifacts(decoded_artifacts)
    loader_cards = cards_from_loader_activity(loader_activity)
    chain_cards = dedupe_cards(sink_cards + loader_cards + artifact_cards + decoder_cards)[:MAX_CARDS]
    evidence_cards = sorted(
        chain_cards,
        key=card_sort_key,
    )[:MAX_CARDS]
    behavior_flow = compact_behavior_flow(semantic.get("behavior_story"), chain_cards)
    embedded_artifacts = compact_embedded_artifacts(
        semantic.get("embedded_artifacts"),
        semantic.get("artifact_classification"),
        payload_context=bool(decoded_artifacts or loader_activity),
    )
    runtime_decoding = compact_runtime_decoding(semantic.get("runtime_decoding"), decoded_artifacts)
    indicators = collect_indicators(evidence_cards, decoded_artifacts, semantic)
    paths = call_paths(call_graph)
    chains, linked_event_keys = build_behavior_chains(behavior_flow, chain_cards, call_graph, paths)
    unlinked_events = [
        event
        for event in (event_from_mapping(card, paths) for card in chain_cards)
        if event and event_key(event) not in linked_event_keys
    ][:MAX_UNLINKED_EVENTS]

    output: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "output_profile": "evaluator",
        "entry_function": entry_function(call_graph, behavior_flow),
        "behavior_chains": chains,
        "unlinked_events": unlinked_events,
        "decoded_artifacts": decoded_artifacts,
        "embedded_artifacts": embedded_artifacts,
        "runtime_decoding": runtime_decoding,
        "indicators": indicators,
        "limitations": limitations(semantic, runtime_decoding),
    }
    if input_path is not None:
        output["input_file"] = str(input_path)
    return prune_empty(output)


def take(items: Any, limit: int) -> list[Any]:
    if not isinstance(items, list):
        return []
    return items[:limit]


def compact_value(value: Any, max_len: int = MAX_STRING_LEN) -> Any:
    if isinstance(value, str):
        value = value.replace("\x00", "")
        return value if len(value) <= max_len else value[: max_len - 3] + "..."
    if isinstance(value, list):
        return [compact_value(item, max_len) for item in value[:20]]
    if isinstance(value, dict):
        return {str(key): compact_value(val, max_len) for key, val in value.items()}
    return value


def prune_empty(value: Any) -> Any:
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            compacted = prune_empty(item)
            if compacted not in (None, [], {}):
                out[key] = compacted
        return out
    if isinstance(value, list):
        return [item for item in (prune_empty(item) for item in value) if item not in (None, [], {})]
    return value


def compact_mapping(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    return {str(key): compact_value(val) for key, val in value.items() if val not in (None, [], {})}


def compact_binary_info(semantic: dict[str, Any]) -> dict[str, Any]:
    binary = dict(semantic.get("binary_info") or {})
    go_summary = ((semantic.get("go_types") or {}).get("summary") or {})
    for key in ("go_version", "module_path", "goos", "goarch"):
        if go_summary.get(key) is not None:
            binary.setdefault(key, go_summary.get(key))
    return prune_empty(compact_mapping(binary))


def execution_summary(
    semantic: dict[str, Any],
    evidence_cards: list[dict[str, Any]],
    decoded_artifacts: list[dict[str, Any]],
    embedded_artifacts: list[dict[str, Any]],
    loader_activity: list[dict[str, Any]],
    call_graph_functions: int,
) -> dict[str, Any]:
    categories: dict[str, int] = {}
    for card in evidence_cards:
        category = card.get("category") or category_for_card(card)
        if category:
            categories[str(category)] = categories.get(str(category), 0) + 1

    story_summary = ((semantic.get("behavior_story") or {}).get("summary") or {})
    chain_summary = ((semantic.get("semantic_chains") or {}).get("summary") or {})
    sink_summary = ((semantic.get("sink_args") or {}).get("summary") or {})
    return prune_empty(
        {
            "action_count": story_summary.get("action_count") or len(evidence_cards),
            "categories": categories,
            "call_graph_functions": call_graph_functions,
            "semantic_chain_summary": chain_summary,
            "sink_summary": sink_summary,
            "has_outbound_network": any(card.get("role") in {"outbound_client", "outbound_http_client"} for card in evidence_cards),
            "has_inbound_listener": any(card.get("role") in {"inbound_listener", "inbound_http_server"} for card in evidence_cards),
            "has_process_launch": any(card.get("category") == "process" for card in evidence_cards),
            "has_loader_activity": bool(loader_activity),
            "has_decoded_artifacts": bool(decoded_artifacts),
            "has_embedded_artifacts": bool(embedded_artifacts),
        }
    )


def compact_behavior_flow(story: Any, cards: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not isinstance(story, dict):
        return flow_from_cards(cards)
    card_index = index_cards(cards)
    flow = []
    for step in take(story.get("execution_flow"), MAX_FLOW_FUNCTIONS):
        if not isinstance(step, dict):
            continue
        function = step.get("function")
        actions = []
        for action in take(step.get("actions"), MAX_ACTIONS_PER_FUNCTION):
            if not isinstance(action, dict):
                continue
            category = normalize_category(action.get("category"))
            if category not in SYSTEM_CATEGORIES and action.get("kind") != "start_goroutine":
                continue
            compacted = compact_action(action)
            match = first_matching_card(card_index, function, action.get("kind"), action.get("target_api"))
            if match:
                compacted = merge_action_card(compacted, match)
            if function and compacted.get("function") in (None, "", "<unknown>"):
                compacted["function"] = function
            if compacted:
                actions.append(compacted)
        if actions:
            flow.append({"function": function, "actions": actions})
    return flow or flow_from_cards(cards)


def build_behavior_chains(
    behavior_flow: list[dict[str, Any]],
    cards: list[dict[str, Any]],
    graph: dict[str, Any],
    paths: dict[str, list[str]] | None = None,
) -> tuple[list[dict[str, Any]], set[tuple[Any, ...]]]:
    paths = paths or call_paths(graph)
    source_events = []
    for step in behavior_flow:
        if not isinstance(step, dict):
            continue
        for action in step.get("actions") or []:
            event = event_from_mapping(action, paths)
            if event:
                source_events.append(event)
    source_events.extend(event for event in (event_from_mapping(card, paths) for card in cards) if event)

    events = dedupe_events(source_events)[:MAX_CHAIN_EVENTS]
    add_event_links(events)
    if not events:
        return [], set()

    chain = prune_empty(
        {
            "chain_id": "chain_0",
            "entry": entry_function(graph, behavior_flow),
            "path": chain_path(events),
            "events": events,
        }
    )
    linked_keys = {event_key(event) for event in events}
    linked_keys.update(event_key(event) for event in source_events if covered_sparse_event(event, events))
    return [chain], linked_keys


def event_from_mapping(item: dict[str, Any], paths: dict[str, list[str]]) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        return None
    kind = event_kind(item)
    function = item.get("function")
    api = item.get("target_api") or item.get("api")
    args = event_arguments(item)
    event = prune_empty(
        {
            "event": kind,
            "function": function,
            "call_path": paths.get(str(function or "")),
            "api": api,
            "call": render_call(api, kind, args),
            "direction": event_direction(item),
            "args": args,
        }
    )
    return event if event.get("event") or event.get("call") else None


def event_arguments(item: dict[str, Any]) -> dict[str, Any]:
    args = {}
    for key in ("method", "url", "host", "ip", "listen_addr", "path", "library", "procedure"):
        if item.get(key) not in (None, "", [], {}):
            args[key] = item.get(key)
    if item.get("executable"):
        args["executable"] = item.get("executable")
    if item.get("argv"):
        args["argv"] = item.get("argv")
    if item.get("command_line"):
        args["command_line"] = item.get("command_line")
    if item.get("argv_provenance"):
        args["argv_provenance"] = item.get("argv_provenance")
    nested = item.get("arguments") if isinstance(item.get("arguments"), dict) else {}
    for key in ("method", "content_type", "flags", "mode", "api_shape", "memory_protection", "syscall_numbers"):
        if nested.get(key) not in (None, "", [], {}):
            args[key] = nested.get(key)
    if item.get("content"):
        args["content"] = item.get("content")
    if item.get("read_content"):
        args["read_content"] = item.get("read_content")
    if item.get("body"):
        args["body"] = item.get("body")
    return prune_empty(compact_value(args))


def event_kind(item: dict[str, Any]) -> Any:
    category = normalize_category(item.get("category"))
    return card_kind(item.get("kind"), category, item.get("role")) if category else item.get("kind")


def event_direction(item: dict[str, Any]) -> str | None:
    role = str(item.get("role") or "")
    if role.startswith("inbound"):
        return "inbound"
    if role.startswith("outbound"):
        return "outbound"
    return None


def render_call(api: Any, kind: Any, args: dict[str, Any]) -> str | None:
    name = str(api or kind or "")
    if not name:
        return None
    ordered_keys = (
        "method",
        "url",
        "content_type",
        "body",
        "path",
        "content",
        "executable",
        "argv",
        "library",
        "procedure",
        "listen_addr",
        "host",
        "ip",
        "flags",
        "mode",
        "memory_protection",
        "syscall_numbers",
    )
    parts = []
    for key in ordered_keys:
        if key not in args:
            continue
        value = args[key]
        if isinstance(value, dict):
            value = value.get("preview") or value.get("classification") or value.get("value") or value
        parts.append(f"{key}={jsonish(value)}")
        if len(parts) >= 5:
            break
    return f"{name}({', '.join(parts)})" if parts else f"{name}()"


def jsonish(value: Any) -> str:
    if isinstance(value, str):
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    if isinstance(value, list):
        return "[" + ", ".join(jsonish(item) for item in value[:8]) + "]"
    if isinstance(value, dict):
        preview = {key: value[key] for key in list(value)[:4]}
        return str(preview)
    return str(value)


def call_paths(graph: dict[str, Any]) -> dict[str, list[str]]:
    if not isinstance(graph, dict) or not graph:
        return {}
    entry = "main.main" if "main.main" in graph else next(iter(graph))
    paths = {entry: [entry]}
    queue = [entry]
    while queue:
        function = queue.pop(0)
        if len(paths.get(function, [])) >= 12:
            continue
        for target in graph_targets(graph.get(function)):
            if target not in graph or target in paths:
                continue
            paths[target] = paths[function] + [target]
            queue.append(target)
    return paths


def graph_targets(calls: Any) -> list[str]:
    targets = []
    for call in calls or []:
        target = call.get("target") if isinstance(call, dict) else getattr(call, "target", None)
        if isinstance(target, str) and target not in targets:
            targets.append(target)
    return targets


def entry_function(graph: dict[str, Any], behavior_flow: list[dict[str, Any]]) -> str:
    if isinstance(graph, dict) and "main.main" in graph:
        return "main.main"
    for step in behavior_flow or []:
        function = step.get("function") if isinstance(step, dict) else None
        if isinstance(function, str) and function:
            return function
    if isinstance(graph, dict) and graph:
        return str(next(iter(graph)))
    return "main.main"


def chain_path(events: list[dict[str, Any]]) -> list[str]:
    path = []
    for event in events:
        event_path = event.get("call_path")
        if isinstance(event_path, list) and event_path:
            for function in event_path:
                add_unique(path, function, 20)
            continue
        add_unique(path, event.get("function"), 20)
    return path


def add_event_links(events: list[dict[str, Any]]) -> None:
    written_paths: dict[str, str] = {}
    for index, event in enumerate(events):
        event["id"] = f"event_{index}"
        args = event.get("args") if isinstance(event.get("args"), dict) else {}
        if event.get("event") == "file_write" and isinstance(args.get("path"), str):
            written_paths[args["path"].lower()] = event["id"]
        executable = args.get("executable")
        if isinstance(executable, str) and executable.lower() in written_paths:
            event["uses"] = {"file_written_by": written_paths[executable.lower()]}


def dedupe_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    positions: dict[tuple[Any, ...], int] = {}
    for event in events:
        key = event_key(event)
        previous = positions.get(key)
        if previous is None:
            positions[key] = len(out)
            out.append(event)
            continue
        if event_quality(event) > event_quality(out[previous]):
            out[previous] = event
    return [event for event in out if not covered_sparse_event(event, out)]


def event_key(event: dict[str, Any]) -> tuple[Any, ...]:
    args = event.get("args") if isinstance(event.get("args"), dict) else {}
    content = args.get("content") if isinstance(args.get("content"), dict) else {}
    return (
        event.get("event"),
        event.get("function"),
        args.get("url"),
        args.get("path"),
        args.get("executable"),
        tuple(args.get("argv") or []),
        args.get("library"),
        args.get("procedure"),
        content.get("preview") or content.get("classification"),
    )


def event_quality(event: dict[str, Any]) -> int:
    args = event.get("args") if isinstance(event.get("args"), dict) else {}
    api = str(event.get("api") or "")
    kind = str(event.get("event") or "")
    score = 0
    if args:
        score += 10 + len(args)
    if api and api != kind and "." in api:
        score += 6
    if event.get("direction"):
        score += 2
    call = str(event.get("call") or "")
    if "(" in call and not call.endswith("()"):
        score += 3
    return score


def covered_sparse_event(event: dict[str, Any], events: list[dict[str, Any]]) -> bool:
    if event.get("args"):
        return False
    function = event.get("function")
    api = event.get("api")
    kind = event.get("event")
    for other in events:
        if other is event or other.get("function") != function or not other.get("args"):
            continue
        if other.get("event") == kind:
            return True
        if api and other.get("api") == api:
            return True
        if kind == "network_activity" and other.get("event") in {"network_request", "inbound_listener"}:
            return True
    return False


def flow_from_cards(cards: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for card in cards:
        function = str(card.get("function") or "<unknown>")
        grouped.setdefault(function, []).append(card_to_action(card))
    return [
        {"function": function, "actions": actions[:MAX_ACTIONS_PER_FUNCTION]}
        for function, actions in list(grouped.items())[:MAX_FLOW_FUNCTIONS]
    ]


def compact_action(action: dict[str, Any]) -> dict[str, Any]:
    role = action.get("network_role") or action.get("process_role") or action.get("filesystem_role")
    return prune_empty(
        {
            "kind": action.get("kind"),
            "category": normalize_category(action.get("category")),
            "target_api": action.get("target_api"),
            "role": neutralize_evaluator_text(role),
            "description": neutralize_evaluator_text(action.get("description")),
            "artifacts": [compact_artifact(item) for item in take(action.get("artifacts"), 4)],
        }
    )


def merge_action_card(action: dict[str, Any], card: dict[str, Any]) -> dict[str, Any]:
    for key in ("role", "target_api", "arguments", "url", "path", "executable", "argv", "content", "body"):
        if card.get(key) not in (None, [], {}) and action.get(key) in (None, [], {}):
            action[key] = card.get(key)
    return action


def card_to_action(card: dict[str, Any]) -> dict[str, Any]:
    return prune_empty(
        {
            "kind": card.get("kind"),
            "category": card.get("category"),
            "function": card.get("function"),
            "target_api": card.get("target_api"),
            "role": card.get("role"),
            "arguments": card.get("arguments"),
            "url": card.get("url"),
            "path": card.get("path"),
            "executable": card.get("executable"),
            "argv": card.get("argv"),
            "content": card.get("content"),
            "body": card.get("body"),
        }
    )


def cards_from_sinks(sink_args: Any) -> list[dict[str, Any]]:
    if not isinstance(sink_args, dict):
        return []
    cards = []
    for sink in take(sink_args.get("sinks"), MAX_CARDS):
        if not isinstance(sink, dict):
            continue
        category = normalize_category(sink.get("category"))
        if category not in SYSTEM_CATEGORIES:
            continue
        card = base_sink_card(sink, category)
        card.update(argument_fields_for_sink(sink, category))
        cards.append(prune_empty(card))
    return [card for card in cards if card]


def base_sink_card(sink: dict[str, Any], category: str) -> dict[str, Any]:
    role = first_role(sink, category)
    kind = card_kind(sink.get("kind"), category, role)
    return {
        "kind": kind,
        "category": category,
        "function": sink.get("function"),
        "target_api": sink.get("target"),
        "role": neutralize_evaluator_text(role),
        "operation": neutralize_evaluator_text(sink.get("operation_summary")),
        "evidence": compact_evidence(sink.get("evidence")),
    }


def first_role(sink: dict[str, Any], category: str) -> Any:
    direct_key = {
        "network": "network_role",
        "process": "process_role",
        "filesystem": "filesystem_role",
    }.get(category)
    if direct_key and sink.get(direct_key):
        return sink.get(direct_key)
    arg_roles = sink.get("arg_roles")
    if isinstance(arg_roles, dict):
        for key in ("network_role", "process_role", "filesystem_role"):
            values = arg_roles.get(key)
            if isinstance(values, list) and values:
                return values[0]
    return None


def argument_fields_for_sink(sink: dict[str, Any], category: str) -> dict[str, Any]:
    if category == "network":
        return network_fields(sink)
    if category == "process":
        return process_fields(sink)
    if category == "filesystem":
        return filesystem_fields(sink)
    if category in {"loader", "execution"}:
        return loader_fields(sink)
    return {"arguments": compact_args(sink)}


def network_fields(sink: dict[str, Any]) -> dict[str, Any]:
    http_args = sink.get("http_arguments") if isinstance(sink.get("http_arguments"), dict) else {}
    arg_roles = sink.get("arg_roles") if isinstance(sink.get("arg_roles"), dict) else {}
    url = extract_value(http_args.get("url")) or first(arg_roles.get("urls"))
    body = http_args.get("body") if isinstance(http_args.get("body"), dict) else {}
    out = {
        "url": url,
        "host": first(arg_roles.get("hosts")),
        "ip": first(arg_roles.get("ips")),
        "listen_addr": first(arg_roles.get("ports")) if first_role(sink, "network") == "inbound_listener" else None,
        "arguments": prune_empty(
            {
                "method": http_args.get("method"),
                "content_type": extract_value(http_args.get("content_type")),
            }
        ),
    }
    body_summary = body_summary_field(body)
    if body_summary:
        out["body"] = body_summary
    return out


def loader_fields(sink: dict[str, Any]) -> dict[str, Any]:
    loader_args = sink.get("loader_arguments") if isinstance(sink.get("loader_arguments"), dict) else {}
    arg_roles = sink.get("arg_roles") if isinstance(sink.get("arg_roles"), dict) else {}
    out = {
        "library": extract_value(loader_args.get("library")) or first(arg_roles.get("libraries")) or artifact_value(sink, {"dll_name", "file_name"}),
        "procedure": extract_value(loader_args.get("procedure")) or first(arg_roles.get("procedure_names")) or artifact_value(sink, {"windows_api_name", "procedure_name"}),
        "arguments": prune_empty(
            {
                "api_shape": loader_args.get("api_shape"),
                "memory_protection": loader_args.get("memory_protection"),
                "syscall_numbers": take(loader_args.get("syscall_numbers"), 6),
            }
        ),
        "artifacts": compact_artifacts(sink.get("artifacts")),
    }
    return out


def process_fields(sink: dict[str, Any]) -> dict[str, Any]:
    process_args = sink.get("process_arguments") if isinstance(sink.get("process_arguments"), dict) else {}
    arg_roles = sink.get("arg_roles") if isinstance(sink.get("arg_roles"), dict) else {}
    executable = extract_value(process_args.get("executable")) or first(arg_roles.get("commands"))
    argv = [extract_value(item) for item in take(process_args.get("argv"), 12)]
    argv = [item for item in argv if item not in (None, "")]
    out = {
        "executable": executable,
        "argv": argv,
        "command_line": process_args.get("command_line_preview"),
    }
    if process_args.get("argv_provenance"):
        out["argv_provenance"] = compact_value(process_args.get("argv_provenance"))
    elif process_args.get("argv_source"):
        out["argv_provenance"] = compact_value(process_args.get("argv_source"))
    return out


def filesystem_fields(sink: dict[str, Any]) -> dict[str, Any]:
    file_args = sink.get("file_arguments") if isinstance(sink.get("file_arguments"), dict) else {}
    arg_roles = sink.get("arg_roles") if isinstance(sink.get("arg_roles"), dict) else {}
    path = extract_value(file_args.get("path")) or first(arg_roles.get("filesystem_targets")) or first(arg_roles.get("paths"))
    data = file_args.get("data") if isinstance(file_args.get("data"), dict) else {}
    read_result = file_args.get("read_result") if isinstance(file_args.get("read_result"), dict) else {}
    out = {
        "path": path,
        "arguments": prune_empty(
            {
                "flags": file_args.get("flags"),
                "mode": file_args.get("mode"),
            }
        ),
    }
    content = content_summary_field(data)
    if content:
        out["content"] = content
    read_content = content_summary_field(read_result)
    if read_content:
        out["read_content"] = read_content
    return out


def compact_args(sink: dict[str, Any]) -> dict[str, Any]:
    args = {}
    for key in ("http_arguments", "process_arguments", "file_arguments", "loader_arguments", "arg_roles"):
        if sink.get(key):
            args[key] = compact_value(sink.get(key), 180)
    return args


def body_summary_field(body: dict[str, Any]) -> dict[str, Any]:
    return prune_empty(
        {
            "source": body.get("source"),
            "classification": body.get("classification"),
            "preview": body.get("preview"),
            "size": body.get("size"),
        }
    )


def content_summary_field(data: dict[str, Any]) -> dict[str, Any]:
    return prune_empty(
        {
            "classification": data.get("classification"),
            "preview": data.get("preview"),
            "size": data.get("size"),
            "source": data.get("source"),
            "source_kind": data.get("source_kind"),
            "magic": take(data.get("magic"), 6),
            "components": take(data.get("components"), 6),
        }
    )


def compact_decoded_artifacts(recovery: Any) -> list[dict[str, Any]]:
    if not isinstance(recovery, dict):
        return []
    decoded = recovery.get("decoded_artifacts")
    if not isinstance(decoded, list) or not decoded:
        decoded = recovery.get("xor_recovered_artifacts")
    out = []
    for item in take(decoded, 20):
        if not isinstance(item, dict):
            continue
        artifact = item.get("artifact") if isinstance(item.get("artifact"), dict) else {}
        classification = artifact.get("classification") if isinstance(artifact.get("classification"), dict) else {}
        out.append(
            prune_empty(
                {
                    "kind": decoded_artifact_kind(item, classification),
                    "function": item.get("function"),
                    "method": item.get("method"),
                    "transforms": take(item.get("transforms"), 6),
                    "artifact_type": item.get("artifact_type"),
                    "decoded_size": item.get("decoded_size"),
                    "sha256_prefix": item.get("sha256_prefix"),
                    "preview": item.get("decoded_preview") or classification.get("ascii_preview"),
                    "indicators": take(artifact.get("indicators"), 20),
                    "classification": prune_empty(
                        {
                            "type": classification.get("type"),
                            "mime_type": classification.get("mime_type"),
                            "signals": take(classification.get("signals"), 8),
                            "strings": take(classification.get("strings"), 12),
                            "magic_offsets": take(classification.get("magic_offsets"), 6),
                        }
                    ),
                    "source_summary": item.get("source_summary"),
                }
            )
        )
    return [item for item in out if item]


def decoded_artifact_kind(item: dict[str, Any], classification: dict[str, Any]) -> str:
    artifact_type = str(item.get("artifact_type") or classification.get("type") or "").lower()
    if artifact_type:
        return f"decoded_{artifact_type}"
    signals = " ".join(str(signal).lower() for signal in classification.get("signals") or [])
    if "pe" in signals:
        return "decoded_pe"
    if "elf" in signals:
        return "decoded_elf"
    if "url" in signals or item.get("indicators"):
        return "decoded_indicators"
    return "decoded_artifact"


def cards_from_decoded_artifacts(decoded_artifacts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    cards = []
    for item in decoded_artifacts:
        cards.append(
            prune_empty(
                {
                    "kind": item.get("kind") or "decoded_artifact",
                    "category": "decoded_artifact",
                    "function": item.get("function"),
                    "method": item.get("method"),
                    "decoded_size": item.get("decoded_size"),
                    "sha256_prefix": item.get("sha256_prefix"),
                    "indicators": item.get("indicators"),
                    "classification": item.get("classification"),
                    "evidence": ["decoded_artifact_recovered"],
                }
            )
        )
    return cards


def compact_loader_activity(loaders: Any) -> list[dict[str, Any]]:
    out = []
    for loader in take(loaders, 20):
        if not isinstance(loader, dict):
            continue
        out.append(
            prune_empty(
                {
                    "kind": loader.get("kind"),
                    "function": loader.get("function"),
                    "confidence": loader.get("confidence"),
                    "evidence": take(loader.get("evidence"), 12),
                    "allocation_constants": take(loader.get("allocation_constants"), 6),
                    "protection_constants": take(loader.get("protection_constants"), 6),
                    "called_transformer_count": len(loader.get("called_transformers") or []),
                }
            )
        )
    return [item for item in out if item]


def cards_from_loader_activity(loader_activity: list[dict[str, Any]]) -> list[dict[str, Any]]:
    cards = []
    for item in loader_activity:
        cards.append(
            prune_empty(
                {
                    "kind": item.get("kind") or "loader_activity",
                    "category": "loader",
                    "function": item.get("function"),
                    "confidence": item.get("confidence"),
                    "evidence": item.get("evidence"),
                    "arguments": {
                        "allocation_constants": item.get("allocation_constants"),
                        "protection_constants": item.get("protection_constants"),
                    },
                }
            )
        )
    return cards


def cards_from_runtime_decoding(runtime_decoding: Any, decoded_artifacts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not isinstance(runtime_decoding, dict):
        return []
    recovered_functions = {item.get("function") for item in decoded_artifacts if item.get("function")}
    cards = []
    for item in take(runtime_decoding.get("functions"), 50):
        if not isinstance(item, dict):
            continue
        decision = runtime_decoding_decision(item, recovered_functions)
        if not decision["include"]:
            continue
        cards.append(
            prune_empty(
                {
                    "kind": "runtime_decoding",
                    "category": "runtime_decoding",
                    "function": item.get("function"),
                    "classification": item.get("classification"),
                    "evidence": decision["evidence"],
                    "decoded_indicators": take(decision["indicators"], 12),
                    "consumed_by": take(decision["consumers"], 8),
                }
            )
        )
    return cards


def compact_runtime_decoding(runtime_decoding: Any, decoded_artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    if not isinstance(runtime_decoding, dict):
        return {}
    recovered_functions = {item.get("function") for item in decoded_artifacts if item.get("function")}
    functions = []
    recovered_indicators = []
    for item in take(runtime_decoding.get("functions"), 100):
        if not isinstance(item, dict):
            continue
        decision = runtime_decoding_decision(item, recovered_functions)
        if not decision["include"]:
            continue
        recovered_indicators.extend(decision["indicators"])
        functions.append(
            prune_empty(
                {
                    "function": item.get("function"),
                    "classification": item.get("classification"),
                    "evidence": decision["evidence"],
                    "decoded_indicators": take(decision["indicators"], 12),
                    "consumed_by": take(decision["consumers"], 8),
                }
            )
        )
    recovered_indicators = dedupe_indicator_objects(recovered_indicators)[:40]
    if not functions and not recovered_indicators:
        return {}
    return prune_empty(
        {
            "summary": runtime_decoding_summary(functions, recovered_indicators),
            "functions": functions[:20],
            "recovered_indicators": recovered_indicators,
        }
    )


def runtime_decoding_decision(item: dict[str, Any], recovered_functions: set[Any]) -> dict[str, Any]:
    indicators = [indicator for indicator in item.get("recovered_indicators") or [] if isinstance(indicator, dict)]
    consumed_indicators = [indicator for indicator in indicators if indicator_consumed_by_sink(indicator)]
    labels = set(item.get("feature_labels") or [])
    has_decoded_artifact = item.get("function") in recovered_functions
    has_explicit_decoder_output = "explicit_decoder_api" in labels and bool(indicators)
    include = bool(has_decoded_artifact or consumed_indicators or has_explicit_decoder_output)
    evidence = []
    if has_decoded_artifact:
        evidence.append("decoded_artifact_recovered")
    if consumed_indicators:
        evidence.append("decoded_value_consumed_by_sink")
    if has_explicit_decoder_output:
        evidence.append("explicit_decoder_api_output")
    consumers = dedupe_consumers(
        consumer
        for indicator in consumed_indicators
        for consumer in indicator.get("consumed_by") or []
        if isinstance(consumer, dict)
    )
    return {
        "include": include,
        "evidence": evidence,
        "indicators": consumed_indicators if consumed_indicators else indicators,
        "consumers": consumers,
    }


def indicator_consumed_by_sink(indicator: dict[str, Any]) -> bool:
    consumers = indicator.get("consumed_by")
    if not isinstance(consumers, list):
        return False
    for consumer in consumers:
        if not isinstance(consumer, dict):
            continue
        if consumer.get("sinks"):
            return True
        if consumer.get("chain_kind") in {"outbound_http", "outbound_network_client", "network_connect", "process_launch", "file_write", "file_read", "dynamic_loader"}:
            return True
    return False


def runtime_decoding_summary(functions: list[dict[str, Any]], indicators: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "function_count": len(functions),
        "recovered_indicator_count": len(indicators),
        "decoded_artifact_function_count": sum(
            1 for item in functions if "decoded_artifact_recovered" in (item.get("evidence") or [])
        ),
        "sink_consumed_value_count": sum(
            1 for item in functions if "decoded_value_consumed_by_sink" in (item.get("evidence") or [])
        ),
        "explicit_decoder_api_output_count": sum(
            1 for item in functions if "explicit_decoder_api_output" in (item.get("evidence") or [])
        ),
    }


def dedupe_indicator_objects(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    seen = set()
    for item in items:
        marker = (
            item.get("type") or item.get("kind"),
            item.get("value") or item.get("indicator") or item.get("text"),
            item.get("producer"),
            item.get("caller"),
        )
        if marker in seen:
            continue
        seen.add(marker)
        out.append(compact_value(item))
    return out


def dedupe_consumers(items: Any) -> list[dict[str, Any]]:
    out = []
    seen = set()
    for item in items:
        marker = (
            item.get("function"),
            item.get("chain_kind"),
            tuple((sink.get("kind"), sink.get("target")) for sink in item.get("sinks") or [] if isinstance(sink, dict)),
        )
        if marker in seen:
            continue
        seen.add(marker)
        out.append(compact_value(item))
    return out


def compact_embedded_artifacts(payloads: Any, classification: Any, payload_context: bool) -> list[dict[str, Any]]:
    out = []
    for payload in take(payloads, 20):
        if not isinstance(payload, dict):
            continue
        has_context = payload_context or payload.get("loaders") or payload.get("transformers") or payload.get("evidence")
        if not has_context:
            continue
        out.append(
            prune_empty(
                {
                    "kind": payload.get("kind"),
                    "confidence": payload.get("confidence"),
                    "classification": artifact_type_from_payload(payload),
                    "connected_to": take(payload.get("loaders") or payload.get("transformers"), 6),
                    "evidence": take(payload.get("evidence"), 8),
                }
            )
        )
    artifact_classification = classification if isinstance(classification, dict) else {}
    for item in take(artifact_classification.get("embedded_artifacts"), 5):
        if not isinstance(item, dict):
            continue
        cls = item.get("artifact_classification") if isinstance(item.get("artifact_classification"), dict) else {}
        if not payload_context and not cls.get("magic_offsets"):
            continue
        out.append(
            prune_empty(
                {
                    "kind": item.get("kind"),
                    "confidence": item.get("confidence"),
                    "classification": cls.get("type"),
                    "evidence": take(cls.get("signals"), 8),
                }
            )
        )
    return dedupe_cards([item for item in out if item])[:10]


def artifact_type_from_payload(payload: dict[str, Any]) -> Any:
    classification = payload.get("artifact_classification") if isinstance(payload.get("artifact_classification"), dict) else {}
    return classification.get("type") or payload.get("artifact_type")


def collect_indicators(
    evidence_cards: list[dict[str, Any]],
    decoded_artifacts: list[dict[str, Any]],
    semantic: dict[str, Any],
) -> dict[str, list[Any]]:
    indicators: dict[str, list[Any]] = {
        "urls": [],
        "domains": [],
        "ips": [],
        "paths": [],
        "commands": [],
        "registry_keys": [],
        "embedded_artifacts": [],
        "other": [],
    }
    for card in evidence_cards:
        add_indicator_from_card(indicators, card)
    for artifact in decoded_artifacts:
        add_unique(indicators["embedded_artifacts"], artifact.get("sha256_prefix"))
        for item in artifact.get("indicators") or []:
            add_indicator_object(indicators, item)
        classification = artifact.get("classification") if isinstance(artifact.get("classification"), dict) else {}
        for string in classification.get("strings") or []:
            add_string_indicator(indicators, string)
    runtime = semantic.get("runtime_decoding") if isinstance(semantic.get("runtime_decoding"), dict) else {}
    recovered_functions = {item.get("function") for item in decoded_artifacts if item.get("function")}
    concrete_runtime_indicators = []
    for item in take(runtime.get("functions"), 100):
        if isinstance(item, dict):
            decision = runtime_decoding_decision(item, recovered_functions)
            if decision["include"]:
                concrete_runtime_indicators.extend(decision["indicators"])
    for item in dedupe_indicator_objects(concrete_runtime_indicators)[:60]:
        add_indicator_object(indicators, item)
    return {key: values[:MAX_LIST_ITEMS] for key, values in indicators.items() if values}


def add_indicator_from_card(indicators: dict[str, list[Any]], card: dict[str, Any]) -> None:
    if card.get("url"):
        add_unique(indicators["urls"], card.get("url"))
    if card.get("host"):
        add_unique(indicators["domains"], card.get("host"))
    if card.get("ip"):
        add_unique(indicators["ips"], card.get("ip"))
    if card.get("path"):
        add_unique(indicators["paths"], card.get("path"))
    if card.get("command_line"):
        add_unique(indicators["commands"], card.get("command_line"))
    elif card.get("executable"):
        command = " ".join(str(part) for part in [card.get("executable"), *(card.get("argv") or [])] if part)
        add_unique(indicators["commands"], command)


def add_indicator_object(indicators: dict[str, list[Any]], item: Any) -> None:
    if isinstance(item, dict):
        value = item.get("value") or item.get("indicator") or item.get("text")
        kind = str(item.get("kind") or item.get("type") or "").lower()
    else:
        value = item
        kind = ""
    add_string_indicator(indicators, value, kind)


def add_string_indicator(indicators: dict[str, list[Any]], value: Any, kind: str = "") -> None:
    if not isinstance(value, str) or not value:
        return
    lower = value.lower()
    if kind in {"url", "uri"} or lower.startswith(("http://", "https://")):
        add_unique(indicators["urls"], value)
    elif kind in {"ip", "ipv4", "ipv6"}:
        add_unique(indicators["ips"], value)
    elif kind in {"path", "file_path"} or "\\" in value or value.startswith(("/", "./", "../")):
        add_unique(indicators["paths"], value)
    elif kind in {"domain", "hostname"} or (("." in value) and " " not in value and "/" not in value and "\\" not in value):
        add_unique(indicators["domains"], value)
    else:
        add_unique(indicators["other"], value)


def limitations(semantic: dict[str, Any], runtime_decoding: dict[str, Any]) -> list[str]:
    out = []
    for error in take(semantic.get("analysis_errors"), 20):
        out.append(str(error))
    sink_limitations = (semantic.get("sink_args") or {}).get("limitations") if isinstance(semantic.get("sink_args"), dict) else []
    for item in take(sink_limitations, 2):
        out.append(str(item))
    return dedupe_scalars(out, 20)


def compact_artifact(item: Any) -> dict[str, Any]:
    if not isinstance(item, dict):
        return {}
    return prune_empty({key: neutralize_evaluator_text(item.get(key)) for key in ("type", "value", "confidence", "kind")})


def compact_artifacts(items: Any) -> list[dict[str, Any]]:
    return [item for item in (compact_artifact(item) for item in take(items, 6)) if item]


def artifact_value(sink: dict[str, Any], types: set[str]) -> Any:
    for artifact in sink.get("artifacts") or []:
        if not isinstance(artifact, dict):
            continue
        if artifact.get("type") in types and artifact.get("value") not in (None, "", [], {}):
            return artifact.get("value")
    return None


def compact_evidence(items: Any) -> list[str]:
    out = []
    for item in take(items, 10):
        if not isinstance(item, str):
            continue
        if item.startswith(("description:", "tag:")):
            continue
        out.append(neutralize_evaluator_text(item))
    return dedupe_scalars(out, 8)


def extract_value(value: Any) -> Any:
    if isinstance(value, dict):
        return value.get("value") or value.get("preview") or value.get("label")
    return value


def first(value: Any) -> Any:
    if isinstance(value, list) and value:
        return value[0]
    if isinstance(value, str):
        return value
    return None


def normalize_category(value: Any) -> str:
    text = str(value or "").lower()
    if text == "execution":
        return "loader"
    if text == "persistence":
        return "filesystem"
    if text == "registry_or_persistence":
        return "registry"
    return text


def neutralize_evaluator_text(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    replacements = {
        "registry_or_persistence": "registry_or_autorun",
        "startup_or_persistence_location": "startup_or_autorun_location",
        "persistence_location_create": "startup_or_autorun_location_create",
        "persistence_locations": "startup_or_autorun_locations",
        "persistence_mechanism": "autorun_mechanism",
        "persistence": "autorun",
        "exfiltration": "data_transfer",
        "C2-like": "remote_control_like",
        "c2-like": "remote_control_like",
        "suspicious": "notable",
    }
    out = value
    for old, new in replacements.items():
        out = out.replace(old, new)
    return out


def category_for_card(card: dict[str, Any]) -> str | None:
    if card.get("category"):
        return str(card.get("category"))
    kind = str(card.get("kind") or "")
    for category in CARD_CATEGORY_ORDER:
        if category in kind:
            return category
    return None


def card_kind(kind: Any, category: str, role: Any) -> str:
    kind_text = str(kind or category)
    if category == "network":
        if role in {"inbound_listener", "inbound_http_server"}:
            return "inbound_listener"
        return "network_request" if kind_text in {"network_request", "http_get", "http_post", "http_request", "http_network"} or "http" in kind_text.lower() else "network_activity"
    if category == "process":
        return "process_launch"
    if category == "filesystem":
        return kind_text
    if category == "concurrency":
        return "goroutine_spawn" if kind_text == "start_goroutine" else kind_text
    return kind_text


def card_sort_key(card: dict[str, Any]) -> tuple[int, str, str, str]:
    category = str(card.get("category") or category_for_card(card) or "")
    return (
        CARD_CATEGORY_ORDER.get(category, 99),
        str(card.get("function") or ""),
        str(card.get("kind") or ""),
        str(card.get("target_api") or ""),
    )


def index_cards(cards: list[dict[str, Any]]) -> dict[tuple[Any, Any, Any], dict[str, Any]]:
    return {(card.get("function"), card.get("kind"), card.get("target_api")): card for card in cards}


def first_matching_card(index: dict[tuple[Any, Any, Any], dict[str, Any]], function: Any, kind: Any, target: Any) -> dict[str, Any] | None:
    direct = index.get((function, kind, target))
    if direct:
        return direct
    return next(
        (
            card
            for key, card in index.items()
            if key[0] == function and (key[1] == kind or key[2] == target)
        ),
        None,
    )


def dedupe_cards(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    out = []
    for item in items:
        marker = (
            item.get("kind"),
            item.get("function"),
            item.get("target_api"),
            item.get("url"),
            item.get("path"),
            item.get("executable"),
            item.get("sha256_prefix"),
        )
        if marker in seen:
            continue
        seen.add(marker)
        out.append(item)
    return out


def dedupe_scalars(items: list[Any], limit: int) -> list[Any]:
    seen = set()
    out = []
    for item in items:
        if item in (None, ""):
            continue
        marker = str(item)
        if marker in seen:
            continue
        seen.add(marker)
        out.append(item)
        if len(out) >= limit:
            break
    return out


def add_unique(items: list[Any], value: Any, limit: int | None = None) -> None:
    if value in (None, "", [], {}):
        return
    if limit is not None and len(items) >= limit:
        return
    if value not in items:
        items.append(compact_value(value))
