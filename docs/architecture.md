# Architecture

## Main Entry Points

- `gobbler.cli`: command-line interface for single analysis, batch analysis, diffs, corpus lookup, and viewer generation.
- `gobbler.pipeline`: high-level orchestration for analyzing one binary and writing output.
- `gobbler.analyzer`: PE parsing, GoReSym integration, disassembly, call graph construction, and lightweight argument/string recovery.
- `gobbler.passes.*`: semantic analysis passes.
- `scripts/analyze.py`: minimal direct script for analyzing every file in a directory.
- `scripts/eval.py`: minimal direct script for running LLM verdicts over analysis JSON files.
- `gobbler.passes.llm_verdict`: reusable LLM verdict pass used by `scripts/eval.py`.
- `gobbler.llm.provider`: replaceable LLM provider hook. Replace `complete_json()` to use another OpenAI-style or custom provider.
- `scripts/clean_corpus_builder.py`: clean corpus builder.

## Analysis Pipeline

The single-binary path is:

```text
gobbler.cli analyze
  -> gobbler.pipeline.analyze_binary
    -> Analyzer(binary, GoReSym)
      -> run GoReSym with -strings -d
      -> parse PE with LIEF
      -> disassemble functions with Capstone
      -> recover reachable call graph from entry point
      -> add fallback entry graphs
    -> analyze_semantics(analyzer, graph)
    -> write JSON + text output
```

`Analyzer` caches disassembly by function range and indexes Go function ranges and string ranges. That keeps repeated semantic passes from redisassembling the same function or doing linear address lookup for common operations.

## Call Graph

The call graph is reachable-user-behavior oriented. It starts from `main.main` by default and records visible calls after filtering runtime noise such as stack checks, GC-related calls, and compiler artifacts.

Each visible call can include:

- target function name
- target address when resolved
- direct/indirect call kind
- recovered string arguments
- argument register hints
- callback provenance when applicable

The call graph is useful for context, but the evaluator-facing output should rely more on `behavior_story`, `behavior_ir`, semantic chains, loaders, payloads, and recovered indicators.

## Semantic Passes

Current semantic passes include:

- `constants.py`: extracts referenced constants, byte arrays, string-like data, and large copy sources.
- `dataflow.py`: tracks simple value/data references and resolves array/blob sources.
- `behavior_ir.py`: turns calls and low-level operations into behavior operations.
- `semantic.py`: scans reachable functions for notable static data regions, data transformers, loader behavior, embedded artifacts, indirect calls, and PE imports.
- `runtime_decoding.py`: identifies likely runtime string/data decoders and recovered indicators.
- `decryption.py`: conservatively reconstructs decoded artifacts from XOR/base64/hex/gzip/zlib paths and identifies AES candidates.
- `artifact_classifier.py`: classifies notable static data, embedded artifact sources, and decoded artifacts with magic, entropy, strings, and optional Magika output.
- `go_types.py`: extracts package/type/receiver metadata from GoReSym and function symbols.
- `sink_args.py`: summarizes evaluator-facing system sinks, visible arguments/artifacts, and factual roles for process launches, network direction, filesystem directories, registry use, and persistence mechanisms.
- `semantic_chains.py`: connects sources, transformations, and sinks into factual behavior chains such as process launch, inbound network service, outbound network client, file access, and dynamic loader activity.
- `behavior_story.py`: builds an evaluator-facing behavior flow and narrative.
- `interesting.py`: scores user functions that are likely relevant to analysis.
- `behavior_graph.py`: builds graph-style behavior relationships for visualization and deeper review.
- `indicator_consumers.py`: maps recovered indicators to likely consumer functions or sinks.

## Output Profiles

`write_analysis_with_options()` supports two JSON profiles:

- `full`: complete analysis document.
- `evaluator`: smaller report used for eval and LLM verdicts. It keeps behavior, payload, decoding, loader, chain, timing, and assessment evidence while dropping lower-value debug sections.

The text report is always written from the full in-memory analysis.
