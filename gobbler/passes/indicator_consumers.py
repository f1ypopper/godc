from __future__ import annotations

from typing import Any


CONSUMER_CHAIN_KINDS = {
    "outbound_http",
    "outbound_network_client",
    "dynamic_loader",
    "process_start_attempt",
    "file_write",
    "file_read",
    "network_connect",
    "generated_identifier",
}


def attach_indicator_consumers(
    graph: dict[str, list[Any]], semantics: dict[str, Any]
) -> dict[str, Any]:
    runtime_decoding = semantics.get("runtime_decoding") or {}
    indicators = runtime_decoding.get("recovered_indicators") or []
    if not indicators:
        return semantics

    chain_by_function = index_consumer_chains(semantics)
    for indicator in indicators:
        consumers = []
        producer = indicator.get("producer")
        caller = indicator.get("caller")
        if producer:
            consumers.extend(consumers_for_function(producer, chain_by_function, "producer_function"))
        if caller:
            consumers.extend(consumers_for_sibling_calls(caller, graph, chain_by_function, producer))
            consumers.extend(consumers_for_function(caller, chain_by_function, "caller_function"))
        indicator["candidate_consumers"] = select_consumers(indicator, dedupe_consumers(consumers))
        indicator["consumed_by"] = []

    by_key = {
        indicator_key(indicator): indicator.get("candidate_consumers", [])
        for indicator in indicators
    }
    for item in runtime_decoding.get("functions") or []:
        for indicator in item.get("recovered_indicators") or []:
            indicator["candidate_consumers"] = by_key.get(indicator_key(indicator), [])
            indicator["consumed_by"] = []
    return semantics


def index_consumer_chains(semantics: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    indexed: dict[str, list[dict[str, Any]]] = {}
    for chain in (semantics.get("semantic_chains") or {}).get("chains") or []:
        if chain.get("kind") not in CONSUMER_CHAIN_KINDS:
            continue
        function = chain.get("function")
        if not function:
            continue
        indexed.setdefault(function, []).append(chain)
    return indexed


def consumers_for_sibling_calls(
    caller: str,
    graph: dict[str, list[Any]],
    chain_by_function: dict[str, list[dict[str, Any]]],
    producer: str | None,
) -> list[dict[str, Any]]:
    consumers = []
    for call in graph.get(caller, []) or []:
        if not getattr(call, "visible", True):
            continue
        target = call.target
        if target == producer:
            continue
        consumers.extend(consumers_for_function(target, chain_by_function, f"called_by_{caller}"))
    return consumers


def consumers_for_function(
    function: str,
    chain_by_function: dict[str, list[dict[str, Any]]],
    link_type: str,
) -> list[dict[str, Any]]:
    consumers = []
    for chain in chain_by_function.get(function, []) or []:
        sinks = chain.get("sinks") or []
        consumers.append(
            {
                "function": function,
                "chain_kind": chain.get("kind"),
                "confidence": "low",
                "relationship_status": "candidate",
                "unresolved": ["Shared function or caller does not establish indicator data flow to this sink."],
                "link_type": link_type,
                "sinks": sinks[:6],
                "literals": (chain.get("literals") or [])[:6],
            }
        )
    return consumers


def dedupe_consumers(consumers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped = []
    seen = set()
    for consumer in consumers:
        key = (
            consumer.get("function"),
            consumer.get("chain_kind"),
            tuple((sink.get("kind"), sink.get("target")) for sink in consumer.get("sinks", [])),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(consumer)
    deduped.sort(
        key=lambda item: (
            confidence_rank(item.get("confidence", "medium")),
            item.get("chain_kind", ""),
            item.get("function", ""),
        )
    )
    return deduped


def select_consumers(indicator: dict[str, Any], consumers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not consumers:
        return []
    indicator_type = indicator.get("type")
    preferred = [
        consumer
        for consumer in consumers
        if consumer_matches_indicator_type(consumer, indicator_type)
    ]
    selected = preferred if preferred else consumers
    selected.sort(
        key=lambda item: (
            consumer_kind_rank(item.get("chain_kind", ""), indicator_type),
            confidence_rank(item.get("confidence", "medium")),
            item.get("function", ""),
        )
    )
    return selected[:8]


def consumer_matches_indicator_type(consumer: dict[str, Any], indicator_type: str | None) -> bool:
    kind = consumer.get("chain_kind")
    if indicator_type in {"url", "domain", "path_or_url_fragment"}:
        return kind in {"outbound_http", "outbound_network_client", "network_connect"}
    if indicator_type in {"windows_path", "file_name_or_path"}:
        return kind in {"file_read", "file_write", "dynamic_loader"}
    if indicator_type == "command":
        return kind == "process_start_attempt"
    return True


def consumer_kind_rank(kind: str, indicator_type: str | None) -> int:
    if indicator_type in {"url", "domain", "path_or_url_fragment"}:
        return {
            "outbound_http": 0,
            "outbound_network_client": 1,
            "network_connect": 2,
            "file_write": 3,
            "file_read": 4,
        }.get(kind, 9)
    if indicator_type in {"windows_path", "file_name_or_path"}:
        return {
            "file_write": 0,
            "file_read": 1,
            "dynamic_loader": 2,
            "outbound_http": 3,
            "outbound_network_client": 4,
            "network_connect": 5,
        }.get(kind, 9)
    if indicator_type == "command":
        return {"process_start_attempt": 0}.get(kind, 9)
    return {
        "outbound_http": 0,
        "outbound_network_client": 1,
        "dynamic_loader": 2,
        "file_write": 2,
        "file_read": 3,
    }.get(kind, 9)


def indicator_key(indicator: dict[str, Any]) -> tuple[Any, ...]:
    return (
        indicator.get("type"),
        indicator.get("value"),
        indicator.get("producer"),
        indicator.get("caller"),
    )


def confidence_rank(confidence: str) -> int:
    return {"high": 0, "medium": 1, "low": 2}.get(confidence, 3)
