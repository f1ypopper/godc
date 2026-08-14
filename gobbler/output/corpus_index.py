from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from gobbler.utils.ownership import is_library_function


def build_feature_index(output_dir: Path) -> dict[str, Any]:
    samples = {}
    features: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for path in sorted(output_dir.glob("*.json")):
        if path.name in {"feature_index.json"}:
            continue
        try:
            document = json.loads(path.read_text())
        except Exception:
            continue
        semantics = document.get("semantic_analysis") or {}
        sample_features = extract_sample_features(semantics)
        if not sample_features:
            continue
        samples[path.stem] = {
            "json": path.name,
            "features": sorted(sample_features),
        }
        for feature, evidence in sample_features.items():
            features[feature].append(
                {
                    "sample": path.stem,
                    "confidence": evidence.get("confidence", "medium"),
                    "functions": evidence.get("functions", [])[:12],
                    "details": evidence.get("details", [])[:8],
                }
            )

    return {
        "version": 1,
        "sample_count": len(samples),
        "feature_count": len(features),
        "features": {feature: sorted(items, key=lambda item: item["sample"]) for feature, items in sorted(features.items())},
        "samples": dict(sorted(samples.items())),
    }


def write_feature_index(output_dir: Path) -> None:
    index = build_feature_index(output_dir)
    (output_dir / "feature_index.json").write_text(json.dumps(index, indent=2))
    (output_dir / "feature_index.txt").write_text(format_feature_index(index))


def extract_sample_features(semantics: dict[str, Any]) -> dict[str, dict[str, Any]]:
    features: dict[str, dict[str, Any]] = {}

    chains = (semantics.get("semantic_chains") or {}).get("chains") or []
    for chain in chains:
        kind = chain.get("kind")
        if not kind:
            continue
        if is_library_function(chain.get("function", "")):
            continue
        add_feature(
            features,
            feature_for_chain_kind(kind),
            chain.get("function"),
            chain.get("confidence", "medium"),
            chain_detail(chain),
        )

    runtime_decoding = semantics.get("runtime_decoding") or {}
    for indicator in runtime_decoding.get("recovered_indicators") or []:
        indicator_type = indicator.get("type") or "indicator"
        detail = indicator_detail(indicator)
        add_feature(
            features,
            "recovered_indicator",
            indicator.get("producer"),
            indicator.get("confidence", "medium"),
            detail,
        )
        add_feature(
            features,
            f"recovered_{indicator_type}",
            indicator.get("producer"),
            indicator.get("confidence", "medium"),
            detail,
        )

    for item in runtime_decoding.get("functions") or []:
        classification = item.get("classification")
        labels = set(item.get("feature_labels") or [])
        for label in sorted(labels):
            add_feature(
                features,
                label,
                item.get("function"),
                item.get("confidence", "medium"),
                classification,
            )
        if labels & {"explicit_decoder_api", "custom_decoder_candidate", "recovered_indicator"}:
            add_feature(
                features,
                "runtime_string_decoding",
                item.get("function"),
                item.get("confidence", "medium"),
                ",".join(sorted(labels)),
            )
        if item.get("decoder_calls"):
            decoder_details = ",".join(
                sorted(
                    {
                        f"{call.get('decoder', '?')}:{call.get('direction', 'unknown')}"
                        for call in item.get("decoder_calls", [])
                    }
                )
            )
            add_feature(
                features,
                "decoder_api_usage",
                item.get("function"),
                item.get("confidence", "medium"),
                decoder_details,
            )

    behavior_ir = semantics.get("behavior_ir") or {}
    functions = behavior_ir.get("functions") or {}
    for function, item in functions.items():
        library_function = is_library_function(function)
        tags = set(item.get("tags") or [])
        if "has_transform_loop" in tags and not library_function:
            add_feature(features, "transform_loop", function, "medium", "probable byte/data transform loop")
        for operation in item.get("flow") or []:
            kind = operation.get("kind")
            if library_function and kind not in {
                "process_launch",
                "dynamic_library_load",
                "dynamic_import_resolution",
            }:
                continue
            for feature in features_for_operation_kind(kind):
                add_feature(features, feature, function, "medium", operation.get("target"))

    if semantics.get("suspicious_data_blobs"):
        add_feature(
            features,
            "suspicious_static_data",
            "<reachable_component>",
            "medium",
            f"{len(semantics.get('suspicious_data_blobs') or [])} suspicious blobs",
        )

    return features


def add_feature(
    features: dict[str, dict[str, Any]],
    feature: str,
    function: str | None,
    confidence: str,
    detail: str | None = None,
) -> None:
    if not feature:
        return
    item = features.setdefault(
        feature,
        {
            "confidence": confidence,
            "functions": [],
            "details": [],
        },
    )
    if confidence_rank(confidence) > confidence_rank(item.get("confidence", "low")):
        item["confidence"] = confidence
    if function and function not in item["functions"]:
        item["functions"].append(function)
    if detail and detail not in item["details"]:
        item["details"].append(detail)


def feature_for_chain_kind(kind: str) -> str:
    return {
        "generated_identifier": "generated_identifier",
        "outbound_http": "outbound_http",
        "file_write": "file_write",
        "file_read": "file_read",
        "execution_or_loader": "execution_or_loader",
        "runtime_string_materialization": "runtime_string_materialization",
        "static_data_transform": "static_data_transform",
    }.get(kind, kind)


def features_for_operation_kind(kind: str | None) -> list[str]:
    return {
        "crypto_random": ["crypto_random"],
        "http_network": ["outbound_http"],
        "http_request": ["outbound_http"],
        "http_get": ["outbound_http"],
        "http_post": ["outbound_http"],
        "file_write": ["file_write"],
        "file_create": ["file_write"],
        "file_read": ["file_read"],
        "file_open": ["file_read"],
        "process_launch": ["process_launch", "execution_or_loader"],
        "dynamic_library_load": ["dynamic_loading", "execution_or_loader"],
        "dynamic_import_resolution": ["dynamic_loading", "execution_or_loader"],
        "dynamic_syscall_call": ["dynamic_syscall", "execution_or_loader"],
        "raw_syscall": ["raw_syscall"],
        "network_connect": ["network_connect"],
        "network_listen": ["network_listen"],
        "environment_read": ["environment_access"],
        "environment_write": ["environment_access"],
        "base64_decode_or_encode": ["decoder_api_usage"],
        "hex_decode_or_encode": ["decoder_api_usage"],
        "aes_crypto": ["crypto_api_usage"],
        "cipher_crypto": ["crypto_api_usage"],
        "chacha20_crypto": ["crypto_api_usage"],
    }.get(kind or "", [])


def chain_detail(chain: dict[str, Any]) -> str:
    sinks = chain.get("sinks") or []
    fields = chain.get("related_fields") or []
    pieces = []
    if sinks:
        pieces.append("sinks=" + ",".join((sink.get("target") or "?") for sink in sinks[:4]))
    if fields:
        pieces.append("fields=" + ",".join(fields[:8]))
    return " ".join(pieces)


def indicator_detail(indicator: dict[str, Any]) -> str:
    value = indicator.get("value") or ""
    consumers = []
    for consumer in indicator.get("consumed_by") or []:
        sinks = [
            sink.get("target")
            for sink in consumer.get("sinks", [])[:3]
            if sink.get("target")
        ]
        if sinks:
            consumers.append(f"{consumer.get('function')}->{','.join(sinks)}")
    if consumers:
        return f"{value} consumed_by={';'.join(consumers[:4])}"
    return value


def format_feature_index(index: dict[str, Any]) -> str:
    lines = [
        "Corpus feature index",
        f"  samples={index.get('sample_count', 0)} features={index.get('feature_count', 0)}",
    ]
    for feature, samples in (index.get("features") or {}).items():
        lines.append(f"  {feature}:")
        for sample in samples[:40]:
            functions = ", ".join(sample.get("functions") or [])
            details = "; ".join(sample.get("details") or [])
            suffix = ""
            if functions:
                suffix += f" functions=[{functions}]"
            if details:
                suffix += f" details=[{details}]"
            lines.append(
                f"    - {sample['sample']} confidence={sample.get('confidence', 'medium')}{suffix}"
            )
        if len(samples) > 40:
            lines.append(f"    ... {len(samples) - 40} more samples ...")
    return "\n".join(lines) + "\n"


def confidence_rank(confidence: str) -> int:
    return {"high": 3, "medium": 2, "low": 1}.get(confidence, 0)
