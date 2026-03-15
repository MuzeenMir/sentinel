-- ============================================================
-- SENTINEL Security Platform - Database Initialization Script
-- ============================================================
-- This script creates the necessary tables, indexes, and initial data
-- Auth tables (users, token_blacklist) are created by auth-service via SQLAlchemy

-- No extensions required (gen_random_uuid() is built-in in PostgreSQL 13+)

-- ============================================================
-- Table: network_logs
-- Stores all network traffic data for analysis
-- ============================================================
CREATE TABLE IF NOT EXISTS network_logs (
    id BIGSERIAL PRIMARY KEY,
    log_id UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    source_ip INET NOT NULL,
    destination_ip INET NOT NULL,
    source_port INTEGER CHECK (source_port >= 0 AND source_port <= 65535),
    destination_port INTEGER CHECK (destination_port >= 0 AND destination_port <= 65535),
    protocol VARCHAR(10) NOT NULL DEFAULT 'TCP',
    packet_size INTEGER CHECK (packet_size >= 0),
    bytes_sent BIGINT DEFAULT 0,
    bytes_received BIGINT DEFAULT 0,
    packets_count INTEGER DEFAULT 1,
    threat_level VARCHAR(20) DEFAULT 'LOW' CHECK (threat_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    is_threat BOOLEAN DEFAULT FALSE,
    detection_method VARCHAR(50),
    ai_confidence_score NUMERIC(5,4) CHECK (ai_confidence_score >= 0 AND ai_confidence_score <= 1),
    threat_type VARCHAR(50),
    raw_data JSONB,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- ============================================================
-- Table: threats
-- Detected threats and their investigation status
-- ============================================================
CREATE TABLE IF NOT EXISTS threats (
    id BIGSERIAL PRIMARY KEY,
    threat_id UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
    type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) DEFAULT 'MEDIUM' CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    status VARCHAR(30) DEFAULT 'new' CHECK (status IN ('new', 'investigating', 'mitigated', 'resolved', 'false_positive')),
    source_ip INET NOT NULL,
    dest_ip INET,
    source_port INTEGER,
    dest_port INTEGER,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    description TEXT,
    confidence NUMERIC(5,4) CHECK (confidence >= 0 AND confidence <= 1),
    detection_method VARCHAR(50),
    network_log_id BIGINT REFERENCES network_logs(id) ON DELETE SET NULL,
    details JSONB,
    mitigated_at TIMESTAMPTZ,
    resolved_at TIMESTAMPTZ,
    assigned_to VARCHAR(100),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- ============================================================
-- Table: firewall_policies
-- Firewall rules managed by DRL agent
-- ============================================================
CREATE TABLE IF NOT EXISTS firewall_policies (
    id BIGSERIAL PRIMARY KEY,
    policy_id UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
    policy_name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    source_cidr CIDR,
    destination_cidr CIDR,
    protocol VARCHAR(10) CHECK (protocol IN ('TCP', 'UDP', 'ICMP', 'ANY')),
    port_range VARCHAR(20),
    action VARCHAR(20) DEFAULT 'ALLOW' CHECK (action IN ('ALLOW', 'DENY', 'LOG', 'RATE_LIMIT')),
    priority INTEGER DEFAULT 100 CHECK (priority >= 0 AND priority <= 65535),
    is_active BOOLEAN DEFAULT TRUE,
    hit_count BIGINT DEFAULT 0,
    last_hit_at TIMESTAMPTZ,
    created_by VARCHAR(100),
    updated_by VARCHAR(100),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- ============================================================
-- Table: training_data
-- AI model training data derived from network logs
-- ============================================================
CREATE TABLE IF NOT EXISTS training_data (
    id BIGSERIAL PRIMARY KEY,
    log_id BIGINT REFERENCES network_logs(id) ON DELETE CASCADE,
    feature_vector JSONB NOT NULL,
    label VARCHAR(20) NOT NULL,
    is_anomaly BOOLEAN DEFAULT FALSE,
    model_version VARCHAR(20) NOT NULL,
    model_type VARCHAR(50),
    processed_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    feedback_score NUMERIC(5,4),
    feedback_notes TEXT
);

-- ============================================================
-- Table: rl_agent_states
-- DRL agent states and decisions for policy optimization
-- ============================================================
CREATE TABLE IF NOT EXISTS rl_agent_states (
    id BIGSERIAL PRIMARY KEY,
    state_id UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
    state_vector JSONB NOT NULL,
    action_taken VARCHAR(50) NOT NULL,
    reward_value NUMERIC(8,4) NOT NULL,
    q_value NUMERIC(8,4),
    episode_number INTEGER NOT NULL,
    step_number INTEGER NOT NULL,
    environment_state JSONB,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- ============================================================
-- Table: alerts
-- System alerts and incidents
-- ============================================================
CREATE TABLE IF NOT EXISTS alerts (
    id BIGSERIAL PRIMARY KEY,
    alert_id UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
    alert_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) DEFAULT 'INFO' CHECK (severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    status VARCHAR(20) DEFAULT 'new' CHECK (status IN ('new', 'acknowledged', 'resolved', 'ignored')),
    description TEXT NOT NULL,
    source_component VARCHAR(100),
    threat_id BIGINT REFERENCES threats(id) ON DELETE SET NULL,
    threat_score NUMERIC(5,2) CHECK (threat_score >= 0 AND threat_score <= 100),
    assigned_to VARCHAR(100),
    resolution_notes TEXT,
    correlation_id UUID,
    tags JSONB DEFAULT '[]',
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    acknowledged_at TIMESTAMPTZ,
    resolved_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- ============================================================
-- Table: compliance_assessments
-- Compliance framework assessment results
-- ============================================================
CREATE TABLE IF NOT EXISTS compliance_assessments (
    id BIGSERIAL PRIMARY KEY,
    assessment_id UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
    framework_id VARCHAR(50) NOT NULL,
    framework_name VARCHAR(100) NOT NULL,
    score NUMERIC(5,2) NOT NULL CHECK (score >= 0 AND score <= 100),
    status VARCHAR(20) DEFAULT 'non_compliant' CHECK (status IN ('compliant', 'non_compliant', 'partial')),
    controls_passed INTEGER DEFAULT 0,
    controls_failed INTEGER DEFAULT 0,
    controls_total INTEGER DEFAULT 0,
    details JSONB,
    assessed_by VARCHAR(100),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- ============================================================
-- Table: system_config
-- System configuration key-value store
-- ============================================================
CREATE TABLE IF NOT EXISTS system_config (
    id BIGSERIAL PRIMARY KEY,
    config_key VARCHAR(100) NOT NULL UNIQUE,
    config_value TEXT,
    config_type VARCHAR(20) DEFAULT 'string' CHECK (config_type IN ('string', 'number', 'boolean', 'json')),
    description TEXT,
    is_sensitive BOOLEAN DEFAULT FALSE,
    updated_by VARCHAR(100),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- ============================================================
-- Table: audit_logs
-- Audit trail for security compliance
-- ============================================================
CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGSERIAL PRIMARY KEY,
    event_id UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    user_id INTEGER,
    username VARCHAR(100),
    resource_type VARCHAR(50),
    resource_id VARCHAR(100),
    action VARCHAR(50) NOT NULL,
    old_value JSONB,
    new_value JSONB,
    ip_address INET,
    user_agent TEXT,
    status VARCHAR(20) DEFAULT 'success',
    error_message TEXT,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- ============================================================
-- INDEXES for optimal query performance
-- ============================================================

-- Network logs indexes
CREATE INDEX IF NOT EXISTS idx_network_logs_timestamp ON network_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_network_logs_source_ip ON network_logs(source_ip);
CREATE INDEX IF NOT EXISTS idx_network_logs_dest_ip ON network_logs(destination_ip);
CREATE INDEX IF NOT EXISTS idx_network_logs_threat ON network_logs(is_threat, threat_level);
CREATE INDEX IF NOT EXISTS idx_network_logs_composite ON network_logs(timestamp DESC, is_threat, threat_level);

-- Threats indexes
CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats(severity);
CREATE INDEX IF NOT EXISTS idx_threats_status ON threats(status);
CREATE INDEX IF NOT EXISTS idx_threats_timestamp ON threats(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_threats_source_ip ON threats(source_ip);
CREATE INDEX IF NOT EXISTS idx_threats_composite ON threats(severity, status, timestamp DESC);

-- Firewall policies indexes
CREATE INDEX IF NOT EXISTS idx_firewall_policies_priority ON firewall_policies(priority);
CREATE INDEX IF NOT EXISTS idx_firewall_policies_active ON firewall_policies(is_active) WHERE is_active = TRUE;

-- Alerts indexes
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_composite ON alerts(severity, status, created_at DESC);

-- Training data indexes
CREATE INDEX IF NOT EXISTS idx_training_data_model_version ON training_data(model_version);
CREATE INDEX IF NOT EXISTS idx_training_data_label ON training_data(label);

-- RL agent states indexes
CREATE INDEX IF NOT EXISTS idx_rl_agent_episode ON rl_agent_states(episode_number, step_number);

-- Audit logs indexes
CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_resource ON audit_logs(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(created_at DESC);

-- ============================================================
-- TRIGGERS for automatic timestamp updates
-- ============================================================

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_threats_updated_at
    BEFORE UPDATE ON threats
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_firewall_policies_updated_at
    BEFORE UPDATE ON firewall_policies
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_alerts_updated_at
    BEFORE UPDATE ON alerts
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_system_config_updated_at
    BEFORE UPDATE ON system_config
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================
-- Initial configuration values
-- ============================================================
INSERT INTO system_config (config_key, config_value, config_type, description) VALUES
    ('ai.model.version', '1.0.0', 'string', 'Current version of the AI threat detection model'),
    ('ai.confidence.threshold', '0.85', 'number', 'Minimum confidence threshold for threat detection'),
    ('drl.learning.rate', '0.001', 'number', 'Learning rate for the deep reinforcement learning algorithm'),
    ('drl.discount.factor', '0.99', 'number', 'Discount factor for future rewards'),
    ('firewall.default.action', 'ALLOW', 'string', 'Default action when no specific rule matches'),
    ('ids.sensitivity.level', 'MEDIUM', 'string', 'Sensitivity level for intrusion detection system'),
    ('alerts.retention.days', '90', 'number', 'Number of days to retain alerts'),
    ('logs.retention.days', '30', 'number', 'Number of days to retain network logs'),
    ('rate_limit.requests.per_minute', '100', 'number', 'API rate limit per minute')
ON CONFLICT (config_key) DO NOTHING;

-- ============================================================
-- Grant permissions (adjust as needed for your setup)
-- ============================================================
-- GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO sentinel;
-- GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO sentinel;