import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from gobbler.analyzer import Analyzer, Call, add_fallback_entry_graphs, call_to_dict
from gobbler.output.formatters import format_human_readable_report
from gobbler.passes.semantic import analyze_semantics


@dataclass
class AnalysisResult:
    graph: dict[str, list[Call]]
    semantics: dict[str, Any]
    serializable: dict[str, Any]


def analyze_binary(
    binary: Path,
    goresym: Path = Path("GoReSym"),
    entry: str = "main.main",
) -> AnalysisResult:
    analyzer = Analyzer(binary, goresym)
    graph = analyzer.build_reachable_graph(entry)
    add_fallback_entry_graphs(analyzer, graph)
    semantics = analyze_semantics(analyzer, graph)
    serializable = {
        "call_graph": {
            function: [call_to_dict(call) for call in calls if call.visible]
            for function, calls in graph.items()
        },
        "semantic_analysis": semantics,
    }
    return AnalysisResult(graph, semantics, serializable)


def write_analysis(result: AnalysisResult, output_dir: Path, sample_name: str) -> tuple[Path, Path]:
    return write_analysis_with_options(result, output_dir, sample_name)


def write_analysis_with_options(
    result: AnalysisResult,
    output_dir: Path,
    sample_name: str,
    output_profile: str = "full",
    compact_json: bool = False,
) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / f"{sample_name}.json"
    text_path = output_dir / f"{sample_name}.txt"
    serializable = serializable_for_profile(result.serializable, output_profile)
    if compact_json:
        json_text = json.dumps(serializable, separators=(",", ":"))
    else:
        json_text = json.dumps(serializable, indent=2)
    json_path.write_text(json_text)
    text_path.write_text(format_human_readable_report(result.graph, result.semantics))
    return json_path, text_path


def serializable_for_profile(document: dict[str, Any], output_profile: str) -> dict[str, Any]:
    if output_profile == "full":
        return document
    if output_profile != "evaluator":
        raise ValueError(f"unknown output profile: {output_profile}")
    semantics = document.get("semantic_analysis") or {}
    keep_semantic_keys = {
        "analysis_timing",
        "assessment_hints",
        "behavior_ir",
        "behavior_story",
        "data_transformers",
        "decryption_recovery",
        "embedded_payloads",
        "interesting_functions",
        "loader_behaviors",
        "pe_imports",
        "runtime_decoding",
        "scanner_timing",
        "semantic_chains",
        "suspicious_data_blobs",
    }
    return {
        "call_graph": document.get("call_graph", {}),
        "semantic_analysis": {
            key: value for key, value in semantics.items() if key in keep_semantic_keys
        },
        "output_profile": "evaluator",
    }
