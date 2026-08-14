# Clean Corpus

The clean corpus is used to estimate false positives and compare LLM/model behavior against known-benign Go binaries.

Current clean corpus locations:

```text
corpus/clean/gomod
corpus/clean/synthetic
```

## Synthetic Clean Samples

Synthetic samples are small local Go programs that intentionally exercise benign-but-suspicious-looking behavior:

- simple CLI
- file operations
- HTTP client
- process spawn
- crypto/encoding/compression
- updater-like flow

These are useful because they test whether the evaluator overreacts to common benign behaviors such as process creation, downloads, or crypto APIs.

## Go Module Clean Samples

The `gomod` provider builds real open-source Go command-line tools. These are better for evaluating real-world false positives because they include large dependency graphs, networking libraries, CLIs, updaters, dev tooling, and admin tools.

## Build Command

Use the corpus builder script:

```bash
.venv/bin/python scripts/clean_corpus_builder.py \
  --providers synthetic,gomod \
  --goos windows \
  --goarch amd64 \
  --target-count 100 \
  --timeout 300
```

Add `--force` to rebuild existing outputs:

```bash
--force
```

The builder writes:

```text
corpus/clean/manifest.jsonl
corpus/clean/synthetic/*.exe
corpus/clean/gomod/*.exe
```

## Notes

Some Go module builds fail due module path changes, Go version constraints, cross-compilation behavior, or upstream download limits. The manifest is the source of truth for what was successfully built.

The eval runner can use multiple clean dirs at once:

```bash
--clean-dir corpus/clean/gomod --clean-dir corpus/clean/synthetic
```

