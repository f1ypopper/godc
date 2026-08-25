import json
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from gobbler.analyzer import (
    DEFAULT_GORESYM_TIMEOUT,
    Analyzer,
    Call,
    add_fallback_entry_graphs,
    call_to_dict,
)
from gobbler.output.evaluator import build_evaluator_document
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
    goresym_timeout: float | None = DEFAULT_GORESYM_TIMEOUT,
) -> AnalysisResult:
    analyzer = Analyzer(binary, goresym, goresym_timeout=goresym_timeout)
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
    text = format_human_readable_report(result.graph, result.semantics)
    write_text_pair_atomically(json_path, json_text, text_path, text)
    return json_path, text_path


def write_text_pair_atomically(
    first_path: Path,
    first_text: str,
    second_path: Path,
    second_text: str,
) -> None:
    suffix = f".tmp.{uuid.uuid4().hex}"
    first_tmp = first_path.with_name(first_path.name + suffix)
    second_tmp = second_path.with_name(second_path.name + suffix)
    try:
        first_tmp.write_text(first_text)
        second_tmp.write_text(second_text)
        first_tmp.replace(first_path)
        second_tmp.replace(second_path)
    finally:
        for path in (first_tmp, second_tmp):
            try:
                path.unlink()
            except FileNotFoundError:
                pass


def serializable_for_profile(document: dict[str, Any], output_profile: str) -> dict[str, Any]:
    if output_profile == "full":
        return document
    if output_profile != "evaluator":
        raise ValueError(f"unknown output profile: {output_profile}")
    return build_evaluator_document(document)
