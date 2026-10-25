import os
import re
import json
import hashlib
import duckdb
from datetime import datetime, timezone

DB_FILE = "data/prompt_signatures.db"
HISTORY_DIR = "data/history"
EXPORT_DIR = "public"
API_DIR = os.path.join(EXPORT_DIR, "v1")

CANONICAL_SIGNATURES = [
    {
        "sig_id": "INJ-SYS-001",
        "category": "instruction_override",
        "severity": "CRITICAL",
        "pattern_type": "regex",
        "regex_rule": r"(?i)(?:ignore\s+(?:all\s+)?previous\s+(?:instructions|prompts|directives|context)|disregard\s+(?:all\s+)?prior\s+(?:rules|commands)|forget\s+(?:all\s+)?previous\s+instructions)",
        "description": "Direct imperative override targeting base system instructions."
    },
    {
        "sig_id": "INJ-TAG-002",
        "category": "delimiter_smuggling",
        "severity": "CRITICAL",
        "pattern_type": "regex",
        "regex_rule": r"(?i)<\s*(?:\|im_start\||\|im_end\||system|assistant|instruction|human|system_prompt)\s*>",
        "description": "Synthetic chat-template delimiter boundary injection."
    },
    {
        "sig_id": "INJ-EXF-003",
        "category": "markdown_data_exfiltration",
        "severity": "HIGH",
        "pattern_type": "regex",
        "regex_rule": r"(?i)!\[.*?\]\(https?:\/\/[^\s\)]+(?:\?|&)(?:token|key|secret|cookie|auth|pwd|data|leak)=.*?(?:\$|\{).*?\)",
        "description": "Zero-click markdown image embedding targeting data extraction via URL query parameters."
    },
    {
        "sig_id": "INJ-UNI-004",
        "category": "unicode_steganography",
        "severity": "HIGH",
        "pattern_type": "regex",
        "regex_rule": r"[\u200B-\u200D\uFEFF]{2,}",
        "description": "Consecutive zero-width unicode characters used to conceal injected text from tokenizers."
    },
    {
        "sig_id": "INJ-BIDI-005",
        "category": "bidi_override",
        "severity": "MEDIUM",
        "pattern_type": "regex",
        "regex_rule": r"[\u202A-\u202E\u2066-\u2069]",
        "description": "Bidirectional text control overrides altering perceived token layout and agent instruction flow."
    },
    {
        "sig_id": "INJ-JAIL-006",
        "category": "jailbreak_persona",
        "severity": "HIGH",
        "pattern_type": "regex",
        "regex_rule": r"(?i)(?:you\s+are\s+now\s+(?:DAN|unrestricted|jailbroken|an\s+unaligned\s+AI)|operate\s+without\s+(?:safety|moral|policy)\s+(?:guidelines|filters)|hypothetical\s+mode\s+enabled)",
        "description": "Roleplay jailbreak patterns attempting persona-based ethical guardrail circumvention."
    },
    {
        "sig_id": "INJ-TOOL-007",
        "category": "tool_call_forgery",
        "severity": "CRITICAL",
        "pattern_type": "regex",
        "regex_rule": r"(?i)(?:\{\s*\"name\"\s*:\s*\"(?:execute_command|bash|run_shell|write_file|delete_file)\"|call:(?:execute|shell|cmd)\()",
        "description": "Synthetic function-calling markup embedded in untrusted external text."
    },
    {
        "sig_id": "INJ-OBF-008",
        "category": "encoding_evasion",
        "severity": "MEDIUM",
        "pattern_type": "regex",
        "regex_rule": r"(?i)(?:base64\s+decode\s+this\s+instruction|rot13|execute\s+this\s+hex\s+string)",
        "description": "Secondary obfuscation wrapper forcing LLM to decode embedded payload before execution."
    }
]

def compute_hash(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()

def validate_regex_signatures(signatures: list) -> list:
    valid = []
    for sig in signatures:
        try:
            re.compile(sig["regex_rule"])
            valid.append(sig)
        except re.error as e:
            print(f"Compilation failure on {sig['sig_id']}: {e}")
    return valid

def generate_yara_rules(signatures: list) -> str:
    yara_lines = [
        "/*",
        " * Prompt Injection & Agent Override YARA Ruleset",
        f" * Generated UTC: {datetime.now(timezone.utc).isoformat()}",
        " */",
        ""
    ]
    for s in signatures:
        clean_rule_id = s["sig_id"].replace("-", "_")
        escaped_pattern = s["regex_rule"].replace("\\", "\\\\").replace('"', '\\"')
        rule_block = f"""rule {clean_rule_id} : {s['category']} {{
    meta:
        description = "{s['description']}"
        severity = "{s['severity']}"
    strings:
        $re = /{escaped_pattern}/
    condition:
        $re
}}
"""
        yara_lines.append(rule_block)
    return "\n".join(yara_lines)

def build_static_api(conn):
    os.makedirs(API_DIR, exist_ok=True)
    now_iso = datetime.now(timezone.utc).isoformat()

    cur = conn.execute("SELECT * FROM injection_signatures ORDER BY severity DESC, sig_id ASC")
    cols = [desc[0] for desc in cur.description]
    all_sigs = [dict(zip(cols, row)) for row in cur.fetchall()]

    with open(os.path.join(API_DIR, "signatures.json"), "w", encoding="utf-8") as f:
        json.dump({"metadata": {"updated_at": now_iso, "count": len(all_sigs)}, "signatures": all_sigs}, f, indent=2)

    with open(os.path.join(API_DIR, "signatures.yar"), "w", encoding="utf-8") as f:
        f.write(generate_yara_rules(all_sigs))

    lines = [
        "# Prompt Injection Signatures Wire",
        f"> Last Sync: {now_iso} UTC",
        "> Deterministic sanitization ruleset for autonomous agents (Zero LLM tokens burned for input triage).",
        "",
        "## Active Injection Detection Signatures"
    ]
    for s in all_sigs:
        lines.append(f"- **[{s['severity']}] {s['sig_id']}** ({s['category']}): {s['description']}\n  `Pattern: {s['regex_rule']}`")

    with open(os.path.join(EXPORT_DIR, "llms.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    html = f"""<!DOCTYPE html><html><head><title>Prompt Injection Signatures Wire</title></head>
    <body style='font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;line-height:1.6;padding:0 1rem;'>
    <h1>🛡️ Prompt Injection Signatures Wire</h1>
    <p>Deterministic regex and YARA signatures detecting prompt injection, instruction smuggling, and indirect agent overrides.</p>
    <h3>Machine Feeds</h3>
    <ul>
      <li><a href='v1/signatures.json'>/v1/signatures.json</a> (Machine JSON Ruleset)</li>
      <li><a href='v1/signatures.yar'>/v1/signatures.yar</a> (YARA-Compatible Rules)</li>
      <li><a href='llms.txt'>llms.txt</a> (Token-Efficient LLM Digest)</li>
      <li><a href='signatures.parquet'>signatures.parquet</a> (Columnar Parquet Snapshot)</li>
    </ul>
    <h3>Catalog of Defenses</h3>
    <table border="1" cellpadding="6" style="border-collapse:collapse;width:100%;text-align:left;">
      <tr><th>ID</th><th>Category</th><th>Severity</th><th>Description</th></tr>
      {"".join([f"<tr><td><strong>{s['sig_id']}</strong></td><td>{s['category']}</td><td>{s['severity']}</td><td>{s['description']}</td></tr>" for s in all_sigs])}
    </table>
    </body></html>"""
    with open(os.path.join(EXPORT_DIR, "index.html"), "w", encoding="utf-8") as f:
        f.write(html)

def run():
    os.makedirs("data", exist_ok=True)
    os.makedirs(HISTORY_DIR, exist_ok=True)
    os.makedirs(EXPORT_DIR, exist_ok=True)

    conn = duckdb.connect(DB_FILE)
    with open("schema.sql", "r", encoding="utf-8") as f:
        conn.execute(f.read())

    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    date_str = now.strftime("%Y-%m-%d")
    year_str = now.strftime("%Y")
    month_str = now.strftime("%m")

    month_dir = os.path.join(HISTORY_DIR, year_str, month_str)
    os.makedirs(month_dir, exist_ok=True)
    daily_history_file = os.path.join(month_dir, f"{date_str}.jsonl")

    verified_signatures = validate_regex_signatures(CANONICAL_SIGNATURES)

    conn.execute("BEGIN TRANSACTION")

    for s in verified_signatures:
        sig_id = s["sig_id"]
        cat = s["category"]
        sev = s["severity"]
        ptype = s["pattern_type"]
        rule = s["regex_rule"].replace("'", "''")
        desc = s["description"].replace("'", "''")

        content_hash = compute_hash(s)

        existing = conn.execute(f"SELECT content_hash FROM injection_signatures WHERE sig_id = '{sig_id}'").fetchone()

        if not existing:
            conn.execute(f"""
                INSERT INTO injection_signatures (
                    sig_id, category, severity, pattern_type,
                    regex_rule, description, content_hash, last_updated_utc
                ) VALUES (
                    '{sig_id}', '{cat}', '{sev}', '{ptype}',
                    '{rule}', '{desc}', '{content_hash}', '{now_iso}'
                )
            """)

            commit_id = conn.execute("SELECT nextval('seq_commit_id')").fetchone()[0]
            conn.execute(f"""
                INSERT INTO ledger (commit_id, timestamp_utc, operation, sig_id, category, detail)
                VALUES ({commit_id}, '{now_iso}', 'INIT_SIG', '{sig_id}', '{cat}', 'Signature baseline registered')
            """)

            entry = {
                "commit_id": commit_id, "timestamp_utc": now_iso, "operation": "INIT_SIG",
                "sig_id": sig_id, "category": cat, "severity": sev, "content_hash": content_hash
            }
            with open(daily_history_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")

        elif existing[0] != content_hash:
            conn.execute(f"""
                UPDATE injection_signatures SET
                    category = '{cat}',
                    severity = '{sev}',
                    pattern_type = '{ptype}',
                    regex_rule = '{rule}',
                    description = '{desc}',
                    content_hash = '{content_hash}',
                    last_updated_utc = '{now_iso}'
                WHERE sig_id = '{sig_id}'
            """)

            commit_id = conn.execute("SELECT nextval('seq_commit_id')").fetchone()[0]
            conn.execute(f"""
                INSERT INTO ledger (commit_id, timestamp_utc, operation, sig_id, category, detail)
                VALUES ({commit_id}, '{now_iso}', 'SIG_UPDATE', '{sig_id}', '{cat}', 'Signature pattern refined')
            """)

            entry = {
                "commit_id": commit_id, "timestamp_utc": now_iso, "operation": "SIG_UPDATE",
                "sig_id": sig_id, "category": cat, "severity": sev, "content_hash": content_hash
            }
            with open(daily_history_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")

    conn.execute("COMMIT")

    conn.execute(f"COPY (SELECT sig_id, category, severity, pattern_type, regex_rule, description, last_updated_utc FROM injection_signatures) TO '{EXPORT_DIR}/signatures.parquet' (FORMAT PARQUET)")
    build_static_api(conn)
    conn.close()

if __name__ == "__main__":
    run()
