CREATE SEQUENCE IF NOT EXISTS seq_commit_id START 1;

CREATE TABLE IF NOT EXISTS injection_signatures (
    sig_id VARCHAR PRIMARY KEY,
    category VARCHAR,
    severity VARCHAR,
    pattern_type VARCHAR,
    regex_rule VARCHAR,
    description VARCHAR,
    content_hash VARCHAR,
    last_updated_utc VARCHAR
);

CREATE TABLE IF NOT EXISTS ledger (
    commit_id BIGINT PRIMARY KEY,
    timestamp_utc VARCHAR,
    operation VARCHAR,
    sig_id VARCHAR,
    category VARCHAR,
    detail VARCHAR
);
