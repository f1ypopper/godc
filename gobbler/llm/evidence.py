"""Model input budgeting and deterministic checks of cited factual support.

These checks validate references and typed claims, not natural-language intent.
"""
from __future__ import annotations

from copy import deepcopy
import json
from typing import Any


LOCAL_METADATA_KEYS = {"input_file", "input_path", "analysis_json", "verdict_json", "sample_name", "label", "ground_truth", "expected_verdict"}


def sanitize_evidence(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: sanitize_evidence(item) for key, item in value.items() if key not in LOCAL_METADATA_KEYS}
    if isinstance(value, list):
        return [sanitize_evidence(item) for item in value]
    return value


def prepare_prompt_evidence(evidence: dict[str, Any], max_chars: int) -> dict[str, Any]:
    """Fit complete JSON objects in budget; never truncate a fact or its ID.

    The catalog is authoritative. Redundant presentation views can be omitted;
    retained facts and their provenance remain intact. Every removal is counted.
    """
    if max_chars < 256:
        raise ValueError("Evidence budget must be at least 256 characters")
    out = sanitize_evidence(deepcopy(evidence))
    omitted: dict[str, int] = {}

    def rendered_size() -> int:
        return len(json.dumps(out, ensure_ascii=True, sort_keys=True, separators=(",", ":")))

    def note(key: str, count: int) -> None:
        omitted[key] = omitted.get(key, 0) + count
        out["prompt_omissions"] = dict(omitted)

    if rendered_size() <= max_chars:
        return out
    # Keep references in only one canonical representation under pressure.
    if isinstance(out.get("evidence_index"), dict):
        for key in ("behavior_chains", "unlinked_events", "decoded_artifacts", "embedded_artifacts", "runtime_decoding", "indicators"):
            if key in out:
                removed = out.pop(key)
                note(key, len(removed) if isinstance(removed, (dict, list)) else 1)
        for key in ("relationships", "ownership"):
            if rendered_size() > max_chars and key in out:
                removed = out.pop(key)
                note(key, len(removed) if isinstance(removed, (list, dict)) else 1)
        catalog = out["evidence_index"]
        for evidence_id in reversed(list(catalog)):
            if rendered_size() <= max_chars:
                break
            catalog.pop(evidence_id)
            note("evidence_facts", 1)
        # Relationships cannot be used when endpoints or supporting facts were omitted.
        if omitted.get("evidence_facts") and "relationships" in out:
            note("relationships", len(out.pop("relationships")))
    # Remove whole optional sections, preserving limitations until last.
    for key in list(out):
        if rendered_size() <= max_chars:
            break
        if key in {"schema_version", "output_profile", "evidence_index", "prompt_omissions", "limitations"}:
            continue
        removed = out.pop(key)
        note(key, len(removed) if isinstance(removed, (dict, list)) else 1)
    if rendered_size() > max_chars and "limitations" in out:
        note("limitations", len(out.pop("limitations")))
    if rendered_size() > max_chars:
        # Tiny budgets still get explicit absence and omission information.
        out = {"evidence_index": {}, "prompt_omissions": {"document_omitted": True, "reason": "evidence_budget_exhausted"}}
    return out


KIND_EVENTS = {
    "file_io": {"file_write", "file_read", "file_open", "file_create", "file_delete", "file_rename", "directory_create", "recursive_filesystem_walk", "permission_change", "stream_read"},
    "network": {"network_request", "network_activity", "inbound_listener", "network_connect", "network_listen", "http_get", "http_post", "http_request", "http_network"},
    "command_construction": {"command_constructed"},
    "process_execution": {"process_start_attempt"},
    "runtime_decoding": {"runtime_decoding", "runtime_string_materialization", "decoded_artifact"},
    "embedded_artifact": {"embedded_artifact", "embedded_static_artifact", "encoded_or_encrypted_embedded_artifact"},
    "dynamic_code_loading": {"reflective_pe_loader", "reflective_elf_loader", "dynamic_code_loader"},
    "memory_operation": {"memory_allocation", "memory_protection_change", "executable_memory_request"},
    "loader_candidate": {"pe_loader_candidate", "elf_loader_candidate", "dynamic_code_loader_candidate"},
    "registry": {"registry_access", "registry_write", "registry_read", "registry_create"},
    "concurrency": {"goroutine_spawn", "start_goroutine", "thread_creation"},
    "observation": {"dynamic_api_resolution", "dynamic_import_resolution", "dynamic_library_load",
                    "pe_header_parsing", "elf_header_parsing", "native_api_usage", "runtime_behavior_pattern"},
}


def validate_claims(result: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    """Fail closed on missing/incorrect IDs, wrong event types and unproved edges."""
    catalog = evidence.get("evidence_index") or {}
    if not isinstance(catalog, dict):
        catalog = {}
    edges = {edge.get("id"): edge for edge in evidence.get("relationships", []) if isinstance(edge, dict) and edge.get("id")}
    errors: list[str] = []
    behaviors = result.get("key_behaviors", [])
    if not isinstance(behaviors, list):
        behaviors = []
        errors.append("key_behaviors must be a list")
    if result.get("verdict") in {"dirty", "clean"} and not behaviors:
        errors.append("A decisive verdict requires cited behavior evidence")
    if result.get("verdict") == "clean" and (evidence.get("prompt_omissions") or evidence.get("projection_omissions")):
        errors.append("A clean verdict cannot rely on an incomplete evidence projection")
    checked = 0
    for index, claim in enumerate(behaviors):
        prefix = f"key_behaviors[{index}]"
        if not isinstance(claim, dict):
            errors.append(f"{prefix}: expected object")
            continue
        ids = claim.get("evidence_ids")
        events = claim.get("observed_events")
        if not isinstance(ids, list) or not ids or any(not isinstance(ref, str) or ref not in catalog for ref in ids):
            errors.append(f"{prefix}: missing or unknown evidence_ids")
            continue
        supported = {catalog[ref].get("event") for ref in ids if isinstance(catalog[ref], dict)}
        if not isinstance(events, list) or not events or any(not isinstance(event, str) or event not in supported for event in events):
            errors.append(f"{prefix}: observed_events are not supported by cited facts")
            continue
        kind = claim.get("kind")
        allowed = KIND_EVENTS.get(kind) if isinstance(kind, str) else None
        if allowed is None:
            errors.append(f"{prefix}: unsupported behavior kind")
        elif not all(event in allowed or (kind == "runtime_decoding" and event.startswith("decoded_")) for event in events):
            errors.append(f"{prefix}: behavior kind contradicts cited event types")
        if result.get("verdict") in {"clean", "dirty"}:
            for ref in ids:
                fact = catalog[ref]
                provenance = fact.get("provenance") or {}
                if fact.get("verification_status") == "legacy_unverified" or (isinstance(provenance, dict) and provenance.get("status") == "legacy_unverified"):
                    errors.append(f"{prefix}: legacy evidence requires reanalysis before a decisive verdict")
                if fact.get("projection_status") == "partial":
                    errors.append(f"{prefix}: cited fact was truncated")
                if kind == "dynamic_code_loading" and fact.get("relationship_status") != "verified":
                    errors.append(f"{prefix}: dynamic loading relationship is not verified")
        relationship_ids = claim.get("relationship_ids", [])
        if not isinstance(relationship_ids, list):
            errors.append(f"{prefix}: relationship_ids must be a list")
        else:
            for ref in relationship_ids:
                edge = edges.get(ref) if isinstance(ref, str) else None
                if not edge or edge.get("status") != "verified":
                    errors.append(f"{prefix}: relationship is not verified")
        checked += 1
    return {
        "status": "rejected" if errors else "references_checked",
        "checked_claims": checked,
        "errors": errors,
        "scope": "Evidence IDs, observed event types, and claimed verified relationships; natural-language intent is not mechanically validated.",
    }
