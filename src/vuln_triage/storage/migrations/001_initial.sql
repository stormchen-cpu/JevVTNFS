-- Migration 001: Initial schema for vuln_triage

CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS imports (
    import_id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    kind TEXT NOT NULL,
    source_path TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    valid_count INTEGER NOT NULL,
    failed_count INTEGER NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS observations (
    observation_id TEXT PRIMARY KEY,
    import_id TEXT NOT NULL,
    source TEXT NOT NULL,
    source_finding_id TEXT,
    observed_at TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    package_name TEXT NOT NULL,
    package_version TEXT,
    vulnerability_id TEXT NOT NULL,
    asset_id TEXT,
    deployment_id TEXT,
    dependency_path TEXT,
    scanner_severity TEXT,
    raw_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(import_id) REFERENCES imports(import_id)
);

CREATE TABLE IF NOT EXISTS issues (
    issue_key TEXT PRIMARY KEY,
    asset_id TEXT,
    vulnerability_id TEXT NOT NULL,
    status TEXT NOT NULL, -- OPEN, RESOLVED, RISK_ACCEPTED
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS snapshots (
    snapshot_id TEXT PRIMARY KEY,
    snapshot_type TEXT NOT NULL, -- deployment, advisory
    identifier TEXT NOT NULL,     -- asset_id/deployment_id or advisory_id
    content_hash TEXT NOT NULL,
    data_json TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS triage_runs (
    run_id TEXT PRIMARY KEY,
    batch_id TEXT NOT NULL,
    observation_id TEXT NOT NULL,
    mode TEXT NOT NULL, -- shadow, active
    status TEXT NOT NULL, -- PENDING, RUNNING, SUCCEEDED, FAILED
    error_message TEXT,
    created_at TEXT NOT NULL,
    completed_at TEXT,
    FOREIGN KEY(observation_id) REFERENCES observations(observation_id)
);

CREATE TABLE IF NOT EXISTS decisions (
    decision_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    observation_id TEXT NOT NULL,
    occurrence_key TEXT NOT NULL,
    decision_key TEXT NOT NULL UNIQUE,
    fingerprint TEXT NOT NULL,
    assessment TEXT NOT NULL,
    priority TEXT NOT NULL,
    proposed_action TEXT NOT NULL,
    reason_codes_json TEXT NOT NULL,
    evidence_ids_json TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    expires_at TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(run_id) REFERENCES triage_runs(run_id),
    FOREIGN KEY(observation_id) REFERENCES observations(observation_id)
);

CREATE TABLE IF NOT EXISTS review_tasks (
    task_id TEXT PRIMARY KEY,
    decision_id TEXT NOT NULL,
    observation_id TEXT NOT NULL,
    status TEXT NOT NULL, -- OPEN, IN_REVIEW, RESOLVED
    assigned_to TEXT,
    resolution_notes TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(decision_id) REFERENCES decisions(decision_id),
    FOREIGN KEY(observation_id) REFERENCES observations(observation_id)
);

CREATE TABLE IF NOT EXISTS audit_events (
    audit_id TEXT PRIMARY KEY,
    decision_id TEXT NOT NULL,
    reviewer_id TEXT NOT NULL,
    reviewed_at TEXT NOT NULL,
    assessment TEXT NOT NULL,
    reason TEXT NOT NULL,
    evidence_ids_json TEXT NOT NULL,
    supersedes_id TEXT,
    FOREIGN KEY(decision_id) REFERENCES decisions(decision_id)
);

CREATE TABLE IF NOT EXISTS risk_acceptances (
    acceptance_id TEXT PRIMARY KEY,
    issue_key TEXT NOT NULL,
    scope TEXT NOT NULL,
    approved_by TEXT NOT NULL,
    reason TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(issue_key) REFERENCES issues(issue_key)
);

CREATE TABLE IF NOT EXISTS suppressions (
    suppression_id TEXT PRIMARY KEY,
    issue_key TEXT NOT NULL,
    occurrence_key TEXT NOT NULL,
    status TEXT NOT NULL, -- ACTIVE, EXPIRED, REVOKED
    reason TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    evidence_fingerprint TEXT NOT NULL,
    created_at TEXT NOT NULL,
    revoked_at TEXT,
    FOREIGN KEY(issue_key) REFERENCES issues(issue_key)
);

CREATE TABLE IF NOT EXISTS egress_events (
    event_id TEXT PRIMARY KEY,
    run_id TEXT,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    status TEXT NOT NULL, -- ALLOWED, BLOCKED, FAILED
    allowed_fields_json TEXT NOT NULL,
    stripped_fields_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- Indices for performance and idempotency lookups
CREATE INDEX IF NOT EXISTS idx_obs_source_finding ON observations(source, source_finding_id);
CREATE INDEX IF NOT EXISTS idx_decisions_occurrence ON decisions(occurrence_key);
CREATE INDEX IF NOT EXISTS idx_review_tasks_status ON review_tasks(status);
CREATE INDEX IF NOT EXISTS idx_suppressions_issue ON suppressions(issue_key, status);
