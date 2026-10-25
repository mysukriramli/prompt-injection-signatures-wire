# 🛡️ Prompt Injection Signatures Wire

A zero-token, deterministic sanitization ruleset running entirely on GitHub Actions. It compiles regular expressions and YARA rules targeting prompt injection, instruction smuggling, chat-template breakout, and markdown data exfiltration.

## Token Impact
- **Tokens Burned on Defense**: 0 tokens (Filtering executes deterministically prior to LLM model evaluation).
- **Format**: Ready for Python `re`, Rust `regex`, or YARA engine integration.

## Machine Feeds
- [`v1/signatures.json`](public/v1/signatures.json) (Ruleset JSON)
- [`v1/signatures.yar`](public/v1/signatures.yar) (YARA-compatible rules)
- [`llms.txt`](public/llms.txt) (Token-efficient LLM digest)
- `signatures.parquet` (Columnar database snapshot)

## Architecture
- **Ruleset**: Deterministic AST and Regular Expressions
- **Database**: DuckDB + Parquet
- **Ledger**: Append-only Git-committed JSONL in `/data/history`
- **Edge CDN**: GitHub Pages (Fastly CDN)
