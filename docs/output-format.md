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

- `behavior_story`: evaluator-facing behavior flow. This is the closest field to “what the binary does”.
- `behavior_ir`: normalized behavior operations extracted from calls and low-level patterns.
- `semantic_chains`: connected source-transform-sink chains.
- `runtime_decoding`: likely runtime decoders and recovered indicators.
- `decryption_recovery`: conservative XOR recovery and AES candidate information.
- `data_transformers`: functions that likely transform byte/string/payload data.
- `suspicious_data_blobs`: high-entropy, magic-containing, large-copy, or transformer-consumed data regions.
- `embedded_payloads`: payload-like blobs tied to transformers or loader behavior.
- `loader_behaviors`: reflective loader, native API, dynamic import, executable memory, or PE parsing behavior.
- `pe_imports`: PE import table summary from LIEF.
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
    "payload_action_count": 1
  },
  "narrative": [
    "The binary contains embedded payload-like data that is transformed and/or loaded."
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

## Full vs Evaluator Output

The `full` profile is better for debugging the analyzer.

The `evaluator` profile is better for LLM/human verdicts. It keeps:

- behavior flow
- decoded/recovered artifacts
- payload and loader evidence
- chains and behavior IR
- suspicious blobs
- timing
- assessment hints

The LLM verdict script applies an additional compact projection on top of evaluator JSON before prompting the model.

