# LLM Verdicts and Eval

Gobbler separates static analysis from LLM verdicting.

The analyzer produces JSON. The LLM verdict pass reads that JSON, builds a compact evaluator view, and asks an LLM provider for a strict JSON verdict. `scripts/eval.py` is the minimal directory-level script wrapper around `gobbler.passes.llm_verdict`.

## Provider Interface

The provider hook lives in:

```text
gobbler/llm/provider.py
```

Project code calls:

```python
complete_json(prompt, config, schema=None)
```

To use a different provider, replace or monkey-patch that one function so it returns `LLMResponse`:

```python
from gobbler.llm.provider import LLMResponse

def complete_json(prompt, config, schema=None):
    # call your OpenAI-style completions/chat endpoint here
    # schema is the verdict JSON schema and can be used as a tool/function schema
    return LLMResponse(
        text=response_text,
        parsed_json=parsed_verdict_or_none,
        usage=usage_dict,
        cost=estimated_cost,
        model=config.model,
        raw_response=raw_response_dict,
    )
```

The default implementation uses an OpenRouter/OpenAI-style chat completions endpoint via `requests`.

`scripts/eval.py` reads `LLM_KEY` and `OPENROUTER_MODEL` from the shell environment first, then falls back to the local `.env` file. It expects:

```dotenv
LLM_KEY=...
OPENROUTER_MODEL=google/gemini-2.5-flash-lite
```

## LLM Prompt Evidence

`gobbler.passes.llm_verdict` does not pass the entire Gobbler JSON directly. It builds a compact view containing:

- `behavior_story`
- `top_level_summary`
- `decryption_recovery`
- `behavior_operations`
- `semantic_chains`
- `runtime_decoding`
- `embedded_artifacts`
- `loader_behaviors`
- `notable_static_data`
- `behavior_strings`
- `top_interesting_functions`

The prompt asks the model to return valid JSON with:

- `verdict`: `clean`, `dirty`, or `unknown`
- `behavioral_summary`: short execution-flow summary starting from `main` or the earliest visible user entry point
- `reasoning`: short reasons
- `key_behaviors`: behavior entries with evidence
- `indicators`: URLs, domains, IPs, paths, commands, mutexes, embedded artifacts, and other artifacts
- `caveats`: uncertainty or limitations
- usage/cost fields copied from the OpenRouter response

The LLM verdict intentionally does not include a model confidence score.

## Directory Analysis

Analyze every file in a directory:

```bash
.venv/bin/python scripts/analyze.py data -o output/analysis --jobs 4
```

The script does not filter by extension. It assumes every direct file in the input directory is a valid executable.

## Directory Verdicts

Run LLM verdicts for every analysis JSON:

```bash
.venv/bin/python scripts/eval.py output/analysis -o output/verdicts --jobs 2
```

## Eval Outputs

The minimal scripts write flat output directories:

```text
output/analysis/<sample>.json
output/analysis/<sample>.txt
output/verdicts/<sample>.verdict.json
```

## Known LLM Operational Issue

Some models occasionally return malformed JSON even with JSON mode enabled. Current failures usually look like:

- `Unterminated string`
- `Expecting ',' delimiter`

A practical next improvement is adding a retry or JSON repair path in `gobbler.passes.llm_verdict`.
