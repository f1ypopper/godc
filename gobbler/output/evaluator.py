"""Compact evaluator-facing Gobbler output projection."""

from __future__ import annotations

from pathlib import Path
from typing import Any

SCHEMA_VERSION = 2
MAX_FLOW_FUNCTIONS = 20
MAX_ACTIONS_PER_FUNCTION = 8
MAX_CARDS = 120
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
    "persistence",
    "registry_or_persistence",
}

CARD_CATEGORY_ORDER = {
    "loader": 0,
    "execution": 0,
    "process": 1,
    "network": 2,
    "filesystem": 3,
    "registry": 4,
    "persistence": 4,
    "registry_or_persistence": 4,
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
    evidence_cards = sorted(
        dedupe_cards(sink_cards + loader_cards + artifact_cards + decoder_cards),
        key=card_sort_key,
    )[:MAX_CARDS]
    indicators = collect_indicators(evidence_cards, decoded_artifacts, semantic)
    behavior_flow = compact_behavior_flow(semantic.get("behavior_story"), evidence_cards)
    embedded_artifacts = compact_embedded_artifacts(
        semantic.get("embedded_artifacts"),
        semantic.get("artifact_classification"),
        payload_context=bool(decoded_artifacts or loader_activity),
    )
    runtime_decoding = compact_runtime_decoding(semantic.get("runtime_decoding"), decoded_artifacts)

    output: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "output_profile": "evaluator",
        "binary": compact_binary_info(semantic),
        "execution_summary": execution_summary(
            semantic,
            evidence_cards,
            decoded_artifacts,
            embedded_artifacts,
            loader_activity,
            len(call_graph),
        ),
        "behavior_flow": behavior_flow,
        "evidence_cards": evidence_cards,
        "decoded_artifacts": decoded_artifacts,
        "embedded_artifacts": embedded_artifacts,
        "runtime_decoding": runtime_decoding,
        "loader_activity": loader_activity,
        "indicators": indicators,
        "limitations": limitations(semantic, runtime_decoding),
        "analysis_timing": compact_mapping(semantic.get("analysis_timing") or semantic.get("scanner_timing")),
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
            if compacted:
                actions.append(compacted)
        if actions:
            flow.append({"function": function, "actions": actions})
    return flow or flow_from_cards(cards)


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
            "role": role,
            "description": action.get("description"),
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
        "role": role,
        "operation": sink.get("operation_summary"),
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
    url = extract_value(http_args.get("url")) or first(arg_roles.get("urls")) or first(sink.get("strings"))
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
    executable = extract_value(process_args.get("executable")) or first(arg_roles.get("commands")) or first(sink.get("strings"))
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
    path = extract_value(file_args.get("path")) or first(arg_roles.get("filesystem_targets")) or first(arg_roles.get("paths")) or first(sink.get("strings"))
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
        labels = set(item.get("feature_labels") or [])
        indicators = item.get("recovered_indicators") or []
        strong = bool(indicators or item.get("function") in recovered_functions or labels.intersection({"explicit_decoder_api", "custom_decoder_candidate", "recovered_indicator"}))
        if not strong:
            continue
        cards.append(
            prune_empty(
                {
                    "kind": "runtime_decoding",
                    "category": "runtime_decoding",
                    "function": item.get("function"),
                    "classification": item.get("classification"),
                    "evidence": take(item.get("feature_labels"), 8),
                    "decoded_indicators": take(indicators, 12),
                }
            )
        )
    return cards


def compact_runtime_decoding(runtime_decoding: Any, decoded_artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    if not isinstance(runtime_decoding, dict):
        return {}
    recovered_functions = {item.get("function") for item in decoded_artifacts if item.get("function")}
    functions = []
    weak_candidate_count = 0
    for item in take(runtime_decoding.get("functions"), 100):
        if not isinstance(item, dict):
            continue
        labels = set(item.get("feature_labels") or [])
        indicators = item.get("recovered_indicators") or []
        strong = bool(indicators or item.get("function") in recovered_functions or labels.intersection({"explicit_decoder_api", "custom_decoder_candidate", "recovered_indicator"}))
        if not strong:
            weak_candidate_count += 1
            continue
        functions.append(
            prune_empty(
                {
                    "function": item.get("function"),
                    "classification": item.get("classification"),
                    "evidence": take(item.get("feature_labels"), 8),
                    "decoded_indicators": take(indicators, 12),
                    "consumed_by": take(item.get("consumed_by"), 8),
                }
            )
        )
    return prune_empty(
        {
            "summary": runtime_decoding.get("summary"),
            "functions": functions[:20],
            "recovered_indicators": take(runtime_decoding.get("recovered_indicators"), 40),
            "weak_candidate_count": weak_candidate_count,
            "note": "XOR, codec, or compression use alone is reported as weak unless a decoded artifact, recovered indicator, or downstream system interaction is visible.",
        }
    )


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
    for item in take(runtime.get("recovered_indicators"), 60):
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
    if runtime_decoding.get("weak_candidate_count"):
        out.append("Runtime decoding candidates without recovered artifacts are summarized as weak evidence.")
    sink_limitations = (semantic.get("sink_args") or {}).get("limitations") if isinstance(semantic.get("sink_args"), dict) else []
    for item in take(sink_limitations, 2):
        out.append(str(item))
    return dedupe_scalars(out, 20)


def compact_artifact(item: Any) -> dict[str, Any]:
    if not isinstance(item, dict):
        return {}
    return prune_empty({key: item.get(key) for key in ("type", "value", "confidence", "kind")})


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
        out.append(item)
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
    return text


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
        return "network_request" if "http" in kind_text.lower() else "network_activity"
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


def add_unique(items: list[Any], value: Any) -> None:
    if value in (None, "", [], {}):
        return
    if value not in items:
        items.append(compact_value(value))
