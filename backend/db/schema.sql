-- Schema for the device-trust collector. Applied idempotently at startup (store.migrate()).
-- One request = one row in each table, written in a single transaction.
--
--   collect_sessions     what the phone sent, plus request metadata (who, from where, when)
--   session_retrievals   what the server looked up for this session (history, request checks)
--   session_results      what the rules and the model decided
--
-- The older tables feature_reports, feature_model_results and device_assessments belong to
-- previous versions and are left untouched.

CREATE TABLE IF NOT EXISTS collect_sessions (
    id              UUID PRIMARY KEY,
    install_id      TEXT        NOT NULL,
    session_id      TEXT        NOT NULL,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    scan_time       TIMESTAMPTZ NOT NULL,           -- the phone's clock (device.scan_timestamp)
    action          TEXT        NOT NULL,
    client_ip       TEXT,
    net24           TEXT,                           -- /24 (IPv4) or /64 (IPv6) of client_ip
    user_agent      TEXT,
    payload_bytes   INTEGER     NOT NULL,
    app_version     INTEGER     NOT NULL,
    device          JSONB       NOT NULL,
    app             JSONB       NOT NULL,
    signals         JSONB       NOT NULL,
    unknown         JSONB       NOT NULL,
    failed_groups   JSONB       NOT NULL,
    UNIQUE (install_id, session_id)                 -- a retry of the same session is not a new row
);
CREATE INDEX IF NOT EXISTS collect_sessions_install_idx ON collect_sessions (install_id, received_at DESC);
CREATE INDEX IF NOT EXISTS collect_sessions_net_idx     ON collect_sessions (net24, received_at DESC);

CREATE TABLE IF NOT EXISTS session_retrievals (
    session_id      UUID PRIMARY KEY REFERENCES collect_sessions (id) ON DELETE CASCADE,
    server_signals  JSONB NOT NULL,                 -- catalogue signals the server computed (F299, F306, F329, ...)
    history         JSONB NOT NULL,                 -- summary of this install's earlier sessions
    checks          JSONB NOT NULL,                 -- configured identity checks (release manifest, signing cert)
    retrieval_ms    REAL  NOT NULL
);

CREATE TABLE IF NOT EXISTS session_results (
    session_id        UUID PRIMARY KEY REFERENCES collect_sessions (id) ON DELETE CASCADE,
    scored_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    rules_level       SMALLINT    NOT NULL,
    ml_level          SMALLINT,                     -- NULL when the model did not score
    final_level       SMALLINT    NOT NULL,
    risk_score        SMALLINT,                     -- 0-100, inside the band of final_level
    label             TEXT        NOT NULL,
    outcome           TEXT        NOT NULL,         -- allow | step_up | block
    assurance         TEXT        NOT NULL,         -- 'unverified': the payload is not signed or attested
    ml_mode           TEXT        NOT NULL,         -- enforce | shadow
    ml_status         TEXT        NOT NULL,         -- scored | insufficient_features | unavailable | error
    model_version     TEXT,
    model_data        TEXT,                         -- what the model was trained on (e.g. 'synthetic')
    feature_coverage  REAL,                         -- share of the model's features that were present
    reasons           JSONB       NOT NULL,
    features          JSONB       NOT NULL,         -- the exact feature vector the model saw (null = missing)
    ml                JSONB       NOT NULL,         -- anomaly percentile, head probabilities, explanation
    coverage          JSONB       NOT NULL,
    timings_ms        JSONB       NOT NULL
);
CREATE INDEX IF NOT EXISTS session_results_level_idx ON session_results (final_level, scored_at DESC);

-- Columns added after the first release (existing databases get them here; NULL for older rows).
ALTER TABLE session_results ADD COLUMN IF NOT EXISTS risk_score SMALLINT;
