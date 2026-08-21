# Output Format

Each analysis writes:

- `<sample>.json`: structured machine-readable analysis.
- `<sample>.txt`: human-readable behavior report.

## Top-Level JSON Shape

```json
{
  "call_graph": {},
  "semantic_analysis": {},
  "output_profile": "evaluator"
}
```

`output_profile` is present when the evaluator profile is used. Full output omits this marker and includes the complete semantic document.

## `call_graph`

The call graph maps function names to visible calls:

```json
{
  "main.main": [
    {
      "address": "0x...",
      "target": "os.Open",
      "target_address": "0x...",
      "kind": "direct",
      "string_args": ["..."],
      "arg_registers": {}
    }
  ]
}
```

The graph is filtered to reduce Go runtime noise. It is still lower-level than the behavior story and is best used for context or debugging.

## `semantic_analysis`

Important current sections:

- `binary_info`: parsed format, architecture, imagebase, and entry point.
- `imports`: generic import summary for PE or ELF when imports are present.
- `behavior_story`: evaluator-facing behavior flow. This is the closest field to “what the binary does”.
- `behavior_ir`: normalized behavior operations extracted from calls and low-level patterns.
- `semantic_chains`: connected source-transform-sink chains.
- `runtime_decoding`: likely runtime decoders and recovered indicators.
- `decryption_recovery`: conservative decoded artifact reconstruction for XOR/base64/hex/gzip/zlib outputs plus AES candidate information.
- `artifact_classification`: classifies notable static data and embedded artifact sources as PE, ELF, archive, script/text, or unknown binary; optionally includes Magika output when available.
- `go_types`: Go package/type metadata and receiver-type hints recovered from GoReSym and function symbols.
- `sink_args`: evaluator-facing summary of important system sinks and their visible strings, artifacts, arguments, and data sources.
- `data_transformers`: functions that likely transform byte/string/static data.
- `notable_data_blobs`: high-entropy, magic-containing, large-copy, or transformer-consumed data regions.
- `embedded_artifacts`: embedded static data tied to transformers or loader-relevant behavior.
- `loader_behaviors`: reflective loader, native API, dynamic import, executable memory, PE parsing, or ELF parsing behavior.
- `pe_imports`: PE import table summary from LIEF, kept as raw PE-specific context.
- `interesting_functions`: scored user functions relevant to behavior review.
- `assessment_hints`: short analysis hints for the evaluator.
- `analysis_timing` and `scanner_timing`: performance timings.

## Behavior Story

`behavior_story` is designed for a human or LLM to read quickly:

```json
{
  "purpose": "evaluator_facing_behavior_flow",
  "summary": {
    "action_count": 2,
    "network_action_count": 0,
    "filesystem_action_count": 0,
    "embedded_artifact_action_count": 1
  },
  "narrative": [
    "The binary contains embedded static data connected to transformation and loader-relevant code."
  ],
  "execution_flow": [
    {
      "function": "main.main",
      "actions": [
        {
          "kind": "network_request",
          "category": "network",
          "description": "makes an HTTP request",
          "artifacts": []
        }
      ]
    }
  ]
}
```

This section intentionally hides low-value array IDs and implementation details unless they explain recovered behavior.

## Sink Arguments

`sink_args` summarizes important system interactions and the concrete values visible near them:

```json
{
  "summary": {
    "sink_count": 3,
    "sinks_with_arg_roles": 3
  },
  "sinks": [
    {
      "function": "main.main",
      "category": "network",
      "kind": "http_get",
      "target": "net/http.Get",
      "operation_summary": "network http_get via net/http.Get (urls=https://example.com/a; hosts=example.com)",
      "arg_roles": {
        "urls": ["https://example.com/a"],
        "hosts": ["example.com"]
      }
    }
  ]
}
```

`arg_roles` groups recovered values by their use, such as URLs, hosts, paths, files, command parts, process targets, libraries, registry paths, and related static data sources. These are observations from recovered arguments and artifacts, not intent labels.

## Full vs Evaluator Output

The `full` profile is better for debugging the analyzer.

The `evaluator` profile is better for LLM/human verdicts. It keeps:

- behavior flow
- decoded/recovered artifacts
- embedded artifact and loader evidence
- chains and behavior IR
- notable static data regions
- timing
- assessment hints

The LLM verdict script applies an additional compact projection on top of evaluator JSON before prompting the model.
