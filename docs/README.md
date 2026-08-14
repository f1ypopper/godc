# Gobbler Documentation

Gobbler is a static semantic analyzer for Go binaries. Its main goal is to turn a compiled Go executable into structured behavior evidence that a human analyst or LLM can use to decide whether the sample is clean, suspicious, or dirty.

The project currently supports x86-64 Go binaries in PE and ELF formats. It uses GoReSym for Go metadata, LIEF for binary parsing, Capstone for disassembly, and a set of local semantic passes to recover behavior-oriented facts.

## Documents

- [Architecture](architecture.md): how the analyzer is organized and how data flows through the project.
- [Usage](usage.md): commands for single binary analysis, batch analysis, feature indexes, viewer generation, and corpus lookup.
- [Output Format](output-format.md): the main JSON and text output sections.
- [LLM Verdicts and Eval](llm-and-eval.md): how OpenRouter verdicts work and how eval runs are produced.
- [Clean Corpus](clean-corpus.md): how the clean corpus is built and used.
- [Limitations](limitations.md): current analysis gaps and operational caveats.

## High-Level Flow

1. Gobbler runs GoReSym on the binary to recover Go functions, strings, and runtime metadata.
2. It disassembles reachable user functions with Capstone.
3. It builds a filtered call graph from `main.main` plus fallback entry roots.
4. It runs semantic passes that detect behavior: file/network/process APIs, data transformations, runtime decoding, embedded payloads, loader behavior, and recovered indicators.
5. It writes a JSON report and a human-readable text report.
6. Optional eval tooling sends a compact evaluator view of the JSON to an OpenRouter model and records verdicts, reasoning, indicators, behavioral summaries, token usage, cost, and metrics.
