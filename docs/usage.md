# Usage

## Prerequisites

The current project expects:

- Python 3.11+
- `GoReSym` binary at `./GoReSym` by default
- Python packages used by the analyzer, notably `capstone` and `lief`
- An OpenRouter API key only when running LLM verdicts

Typical setup:

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install capstone lief
chmod +x GoReSym
```

## Analyze One Binary

```bash
.venv/bin/python -m gobbler.cli analyze data/sample.exe --out output
```

ELF x86-64 Go binaries can be analyzed the same way:

```bash
.venv/bin/python -m gobbler.cli analyze data/sample.elf --out output
```

Useful options:

```bash
--entry main.main
--goresym ./GoReSym
--output-profile full
--output-profile evaluator
--compact-json
--compare output/old.json
--index
```

Outputs:

```text
output/sample.json
output/sample.txt
```

## Batch Analyze a Directory

```bash
.venv/bin/python -m gobbler.cli batch data \
  --glob '*.exe' \
  --out output \
  --jobs 4 \
  --timeout 300
```

For ELF files:

```bash
.venv/bin/python -m gobbler.cli batch data \
  --glob '*.elf' \
  --out output_elf \
  --jobs 4 \
  --timeout 300
```

For evaluator-sized JSON:

```bash
.venv/bin/python -m gobbler.cli batch data \
  --glob '*.exe' \
  --out output \
  --jobs 4 \
  --timeout 300 \
  --output-profile evaluator \
  --compact-json
```

Batch output includes:

```text
output/<sample>.json
output/<sample>.txt
output/batch_report.json
output/feature_index.json
output/feature_index.txt
```

## Feature Index

List known indexed feature names:

```bash
.venv/bin/python -m gobbler.cli corpus list --out output
```

Find samples with a feature:

```bash
.venv/bin/python -m gobbler.cli corpus find runtime_decoding --out output
```

The feature index is mainly used to find samples that exhibit a behavior such as string decoding, embedded artifacts, loader behavior, network use, or process execution.

## Diff Two Analysis Outputs

```bash
.venv/bin/python -m gobbler.cli diff before.json after.json
```

Or write the diff:

```bash
.venv/bin/python -m gobbler.cli diff before.json after.json --out output/diff.txt
```

## Standalone Viewer

Generate the single-binary HTML viewer:

```bash
.venv/bin/python -m gobbler.cli viewer --out output/gobbler_viewer.html
```

Open the HTML file and load a Gobbler JSON output to inspect the report visually.
