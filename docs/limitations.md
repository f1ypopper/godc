# Current Limitations

## Static Analysis Scope

Gobbler is currently static. It does not execute samples. Dynamic behavior that only appears after environment checks, anti-analysis branches, remote configuration, or runtime-generated code may be missed.

## GoReSym Dependency

GoReSym is required for function metadata and strings. Samples can fail analysis when GoReSym cannot recover metadata or exits with an error.

Recent evals had dirty samples fail with:

```text
RuntimeError: GoReSym failed
```

Those are analysis failures, not clean/dirty model decisions.

## Architecture and Platform

The analyzer currently supports x86-64 PE and x86-64 ELF Go binaries. Other architectures, including ARM64 and LoongArch, are rejected because the disassembly and register tracking are x86-64-specific.

Mach-O is not currently supported.

## Dataflow Precision

The project intentionally uses pragmatic static dataflow, not full emulation. It can identify likely sources, transformations, sinks, and artifacts, but it may not always recover exact runtime values.

Examples:

- string construction through complex control flow may be missed
- heap object/struct field tracking is partial
- indirect calls may be classified but not fully resolved
- callback-heavy flows can lose ordering

## Decryption Recovery

XOR recovery is conservative. It probes likely byte sources and only reports outputs with strong artifact evidence.

AES support currently identifies candidates and API paths, but full AES decryption generally requires reconstructing key, mode, IV/nonce, and ciphertext arguments. That reconstruction is not complete.

## Embedded Payload Detection

Embedded payload detection is evidence-based. Strong signals include:

- payload magic such as MZ/PE/ELF
- high entropy
- large copy source
- consumption by transformer functions
- connection to loader behavior
- executable memory or dynamic import resolution

Incidental magic bytes in Go data sections are treated as weak evidence unless tied to behavior.

## LLM Verdict Reliability

The LLM layer is probabilistic and model-dependent. It should be treated as a verdict assistant, not the source of truth.

Known operational issues:

- malformed JSON responses
- model-specific sensitivity to benign process/network behavior
- false positives on admin/dev/security tools
- verdict drift between prompt versions

The eval pipeline records costs, tokens, duration, errors, and verdict records so prompt/model changes can be compared.
