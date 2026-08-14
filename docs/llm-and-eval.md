# LLM Verdicts and Eval

Gobbler separates static analysis from LLM verdicting.

The analyzer produces JSON. The LLM script reads that JSON, builds a compact evaluator view, and asks an OpenRouter model for a strict JSON verdict.

## One-Sample LLM Verdict

```bash
.venv/bin/python scripts/llm_verdict.py output/sample.json \
  --model google/gemini-2.5-flash-lite \
  --api-key-env OPENROUTER_KEY \
  --out output/sample.verdict.json
```

The script reads `.env` by default and looks up the variable named by `--api-key-env`.

The default variable is `OPENROUTER_API_KEY`, but this project has commonly used:

```bash
--api-key-env OPENROUTER_KEY
```

## LLM Prompt Evidence

`scripts/llm_verdict.py` does not pass the entire Gobbler JSON directly. It builds a compact view containing:

- `behavior_story`
- `top_level_summary`
- `decryption_recovery`
- `behavior_operations`
- `semantic_chains`
- `runtime_decoding`
- `embedded_payloads`
- `loader_behaviors`
- `suspicious_payload_blobs`
- `behavior_strings`
- `top_interesting_functions`

The prompt asks the model to return valid JSON with:

- `verdict`: `clean`, `suspicious`, `dirty`, or `unknown`
- `behavioral_summary`: short execution-flow summary starting from `main` or the earliest visible user entry point
- `reasoning`: short reasons
- `key_behaviors`: behavior entries with evidence
- `indicators`: URLs, domains, IPs, paths, commands, mutexes, payloads, and other artifacts
- `caveats`: uncertainty or limitations
- usage/cost fields copied from the OpenRouter response

The LLM verdict intentionally does not include a model confidence score.

## Full Eval

Run clean + dirty analysis and verdicts:

```bash
.venv/bin/python scripts/run_eval.py \
  --run-name full_after_change \
  --clean-dir corpus/clean/gomod \
  --clean-dir corpus/clean/synthetic \
  --dirty-dir data \
  --models google/gemini-2.5-flash-lite \
  --api-key-env OPENROUTER_KEY \
  --analysis-jobs 4 \
  --verdict-jobs 2 \
  --analysis-timeout 300 \
  --verdict-timeout 90
```

Limit to matching clean/dirty counts:

```bash
.venv/bin/python scripts/run_eval.py \
  --run-name eval_78_per_label \
  --clean-dir corpus/clean/gomod \
  --clean-dir corpus/clean/synthetic \
  --dirty-dir data \
  --models google/gemini-2.5-flash-lite \
  --api-key-env OPENROUTER_KEY \
  --analysis-jobs 4 \
  --verdict-jobs 2 \
  --analysis-timeout 300 \
  --verdict-timeout 90 \
  --limit-per-label 78
```

## Eval Outputs

Each run writes under `eval_runs/<run-name>/`:

```text
dataset.json
analysis_reports.json
eval_report.json
verdict_records.json
verdict_records.csv
analysis/<label>/<source>/*.json
analysis/<label>/<source>/*.txt
verdicts/<model>/<label>/*.verdict.json
```

`verdict_records.csv` is the easiest file for spreadsheet-style inspection. It includes sample label, verdict, behavioral summary, cost, token counts, duration, and error status.

## Metrics Convention

For current evals, `suspicious` is counted as dirty:

```text
dirty or suspicious -> predicted dirty
clean               -> predicted clean
unknown             -> excluded from decisive TP/TN/FP/FN counts
```

Useful metrics:

- TP: dirty sample predicted dirty/suspicious
- TN: clean sample predicted clean
- FP: clean sample predicted suspicious/dirty
- FN: dirty sample predicted clean
- FPR: `FP / (FP + TN)`
- FNR: `FN / (FN + TP)`
- TPR/recall: `TP / (TP + FN)`

## Known LLM Operational Issue

Some models occasionally return malformed JSON even with JSON mode enabled. Current failures usually look like:

- `Unterminated string`
- `Expecting ',' delimiter`

A practical next improvement is adding a retry or JSON repair path in `scripts/llm_verdict.py`.

