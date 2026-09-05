from typing import Any


from gobbler.utils.ownership import lookup_function_ownership


def rank_interesting_functions(graph: dict[str, list[Any]], semantics: dict[str, Any]) -> list[dict[str, Any]]:
    scores: dict[str, dict[str, Any]] = {}

    def add(function: str, points: int, reason: str) -> None:
        item = scores.setdefault(function, {"function": function, "score": 0, "reasons": []})
        item["score"] += points
        if reason not in item["reasons"]:
            item["reasons"].append(reason)

    for transformer in semantics.get("data_transformers") or []:
        add(transformer["function"], 25 if transformer["confidence"] == "high" else 15, "data_transformer")
        if transformer.get("input_sources"):
            add(transformer["function"], 15, "has_notable_static_data_source")

    for loader in semantics.get("loader_behaviors") or []:
        if loader["function"] == "<reachable_component>":
            for function in loader.get("functions", []):
                add(function, 20, f"participates_in_{loader['kind']}")
            continue
        add(loader["function"], 30 if loader["confidence"] == "high" else 15, loader["kind"])

    for payload in semantics.get("embedded_artifacts") or []:
        for function in payload.get("transformers", []):
            add(function, 25, "transforms_embedded_artifact")
        for loader in payload.get("loaders", []):
            if loader != "<reachable_component>":
                add(loader, 25, "passes_embedded_artifact_to_loader")

    dataflow = semantics.get("dataflow") or {}
    for function, facts in (dataflow.get("functions") or {}).items():
        if facts.get("value_flows"):
            add(function, min(20, 5 * len(facts["value_flows"])), "has_value_flows_from_constants")
        if facts.get("string_field_candidates"):
            add(function, 10, "reads_possible_struct_string_fields")
        if facts.get("slice_arg_candidates"):
            add(function, 10, "passes_slice_like_arguments")

    cfg = semantics.get("cfg") or {}
    for function, facts in (cfg.get("functions") or {}).items():
        loops = facts.get("probable_transform_loops") or []
        if loops:
            add(function, 20 + min(20, 5 * len(loops)), "has_probable_transform_loop")

    for function, calls in graph.items():
        for call in calls:
            target = call.target
            if "syscall" in target.lower():
                add(function, 10, f"calls_{target}")
            if any(marker in target for marker in ("crypto/", "chacha20", "github.com/ecies")):
                add(function, 10, f"calls_crypto:{target}")
            if any(marker in target for marker in ("os.WriteFile", "os/exec.Command", "path/filepath.Walk")):
                add(function, 10, f"calls_behavioral_api:{target}")

    for function, item in scores.items():
        ownership = lookup_function_ownership(function, semantics)
        item["ownership"] = ownership
        # Ownership supplies context only. Do not suppress dependency behavior
        # or reward unfamiliar symbols by assuming that they are application code.
        item["reasons"].append("ownership:" + ownership["classification"])

    ranked = sorted(scores.values(), key=lambda item: (-item["score"], item["function"]))
    for item in ranked:
        item["reasons"] = item["reasons"][:12]
    return ranked[:50]
