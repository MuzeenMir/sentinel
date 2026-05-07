-- SENTINEL Platform — PostgreSQL bootstrap
-- Runs once via docker-entrypoint-initdb.d on first container start.

BEGIN;

-- ─── Users ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id                  SERIAL PRIMARY KEY,
    username            VARCHAR(80)  UNIQUE NOT NULL,
    email               VARCHAR(120) UNIQUE NOT NULL,
    password_hash       VARCHAR(128) NOT NULL,
    role                VARCHAR(20)  NOT NULL DEFAULT 'viewer',
    status              VARCHAR(20)  DEFAULT 'active',
    tenant_id           BIGINT,
    mfa_secret          VARCHAR(32),
    mfa_enabled         BOOLEAN      DEFAULT FALSE,
    mfa_backup_codes    TEXT,
    created_at          TIMESTAMP    DEFAULT NOW(),
    last_login          TIMESTAMP,
    failed_login_attempts INT        DEFAULT 0,
    locked_until        TIMESTAMP
);

CREATE INDEX idx_users_tenant  ON users (tenant_id);
CREATE INDEX idx_users_status  ON users (status);

-- ─── Token blacklist (JWT revocation) ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS token_blacklist (
    id          SERIAL PRIMARY KEY,
    jti         VARCHAR(36) UNIQUE NOT NULL,
    revoked_at  TIMESTAMP DEFAULT NOW()
);

-- ─── Tenants ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tenants (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       VARCHAR(36) UNIQUE NOT NULL,
    name            VARCHAR(200) UNIQUE NOT NULL,
    display_name    VARCHAR(200),
    status          VARCHAR(20) NOT NULL DEFAULT 'active',
    plan            VARCHAR(50) NOT NULL DEFAULT 'professional',
    settings        TEXT        DEFAULT '{}',
    data_region     VARCHAR(50) DEFAULT 'us-east-1',
    retention_days  INT         DEFAULT 90,
    created_at      TIMESTAMP   NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP   NOT NULL DEFAULT NOW()
);

-- ─── Audit log ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_log (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       BIGINT,
    user_id         INT,
    action          VARCHAR(100) NOT NULL,
    resource_type   VARCHAR(50),
    resource_id     VARCHAR(100),
    details         JSONB,
    ip_address      INET,
    timestamp       TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_audit_tenant    ON audit_log (tenant_id);
CREATE INDEX idx_audit_user      ON audit_log (user_id);
CREATE INDEX idx_audit_timestamp ON audit_log (timestamp);
CREATE INDEX idx_audit_action    ON audit_log (action);

-- ─── Policy decisions ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS policy_decisions (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       BIGINT,
    policy_id       VARCHAR(100),
    action          VARCHAR(50),
    source_ip       INET,
    dest_ip         INET,
    confidence      FLOAT,
    model_version   VARCHAR(50),
    explanation     JSONB,
    created_at      TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_policy_tenant    ON policy_decisions (tenant_id);
CREATE INDEX idx_policy_created   ON policy_decisions (created_at);
CREATE INDEX idx_policy_policy_id ON policy_decisions (policy_id);

-- ─── Compliance assessments ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS compliance_assessments (
    id               BIGSERIAL PRIMARY KEY,
    tenant_id        BIGINT,
    framework        VARCHAR(50) NOT NULL,
    score            FLOAT,
    total_controls   INT,
    passed_controls  INT,
    failed_controls  INT,
    details          JSONB,
    assessed_at      TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_compliance_tenant    ON compliance_assessments (tenant_id);
CREATE INDEX idx_compliance_framework ON compliance_assessments (framework);
CREATE INDEX idx_compliance_assessed  ON compliance_assessments (assessed_at);

-- ─── Row-Level Security policies (disabled by default) ──────────────────────
-- Enable per-table with:  ALTER TABLE <table> ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_users ON users
    USING (tenant_id = current_setting('app.current_tenant_id', TRUE)::BIGINT);

CREATE POLICY tenant_isolation_audit ON audit_log
    USING (tenant_id = current_setting('app.current_tenant_id', TRUE)::BIGINT);

CREATE POLICY tenant_isolation_policy ON policy_decisions
    USING (tenant_id = current_setting('app.current_tenant_id', TRUE)::BIGINT);

CREATE POLICY tenant_isolation_compliance ON compliance_assessments
    USING (tenant_id = current_setting('app.current_tenant_id', TRUE)::BIGINT);

COMMIT;
