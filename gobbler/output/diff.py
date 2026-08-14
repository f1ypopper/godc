from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from gobbler.output.corpus_index import extract_sample_features


def diff_analysis_files(before_path: Path, after_path: Path) -> str:
    before = json.loads(before_path.read_text())
    after = json.loads(after_path.read_text())
    return diff_analysis_documents(before, after)


def diff_analysis_documents(before: dict[str, Any], after: dict[str, Any]) -> str:
    before_semantics = before.get("semantic_analysis") or {}
    after_semantics = after.get("semantic_analysis") or {}
    lines = ["Behavior output diff"]
    lines.extend(diff_features(before_semantics, after_semantics))
    lines.extend(diff_runtime_decoding(before_semantics, after_semantics))
    lines.extend(diff_semantic_chains(before_semantics, after_semantics))
    if len(lines) == 1:
        lines.append("  no semantic differences detected")
    return "\n".join(lines) + "\n"


def diff_features(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    before_features = set(extract_sample_features(before))
    after_features = set(extract_sample_features(after))
    added = sorted(after_features - before_features)
    removed = sorted(before_features - after_features)
    if not added and not removed:
        return []
    lines = ["  feature_changes:"]
    if added:
        lines.append(f"    added: {', '.join(added)}")
    if removed:
        lines.append(f"    removed: {', '.join(removed)}")
    return lines


def diff_runtime_decoding(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    before_items = index_runtime_decoding(before)
    after_items = index_runtime_decoding(after)
    added = sorted(set(after_items) - set(before_items))
    removed = sorted(set(before_items) - set(after_items))
    changed = sorted(
        function
        for function in set(before_items) & set(after_items)
        if before_items[function] != after_items[function]
    )
    if not added and not removed and not changed:
        return []
    lines = ["  runtime_decoding_changes:"]
    for function in added:
        lines.append(f"    added: {function} {after_items[function]}")
    for function in removed:
        lines.append(f"    removed: {function} {before_items[function]}")
    for function in changed:
        lines.append(f"    changed: {function} {before_items[function]} -> {after_items[function]}")
    return lines


def diff_semantic_chains(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    before_chains = index_semantic_chains(before)
    after_chains = index_semantic_chains(after)
    added = sorted(set(after_chains) - set(before_chains))
    removed = sorted(set(before_chains) - set(after_chains))
    if not added and not removed:
        return []
    lines = ["  semantic_chain_changes:"]
    for key in added[:30]:
        lines.append(f"    added: {after_chains[key]}")
    for key in removed[:30]:
        lines.append(f"    removed: {before_chains[key]}")
    return lines


def index_runtime_decoding(semantics: dict[str, Any]) -> dict[str, str]:
    indexed = {}
    for item in (semantics.get("runtime_decoding") or {}).get("functions") or []:
        indexed[item["function"]] = (
            f"classification={item.get('classification')} "
            f"confidence={item.get('confidence')} "
            f"evidence={','.join(item.get('evidence') or [])}"
        )
    return indexed


def index_semantic_chains(semantics: dict[str, Any]) -> dict[tuple[str, str, str], str]:
    indexed = {}
    for chain in (semantics.get("semantic_chains") or {}).get("chains") or []:
        sink_text = ",".join((sink.get("target") or "?") for sink in chain.get("sinks", [])[:4])
        key = (chain.get("kind", ""), chain.get("function", ""), sink_text)
        fields = ",".join(chain.get("related_fields") or [])
        suffix = f" fields=[{fields}]" if fields else ""
        indexed[key] = (
            f"{chain.get('kind')} function={chain.get('function')} "
            f"confidence={chain.get('confidence')} sinks=[{sink_text or '<none>'}]{suffix}"
        )
    return indexed
