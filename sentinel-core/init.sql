-- Database initialization script for SENTINEL AI-based IDS System
-- This script creates the necessary tables and initial data for the system

-- Auth tables (users, token_blacklist) are created by auth-service via db.create_all()
-- Initial admin is created by auth-service on first start from ADMIN_USERNAME, ADMIN_PASSWORD, ADMIN_EMAIL in .env

-- Table for storing network traffic logs
CREATE TABLE IF NOT EXISTS network_logs (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    source_ip INET NOT NULL,
    destination_ip INET NOT NULL,
    source_port INTEGER,
    destination_port INTEGER,
    protocol VARCHAR(10),
    packet_size INTEGER,
    threat_level VARCHAR(20) DEFAULT 'LOW',
    is_threat BOOLEAN DEFAULT FALSE,
    detection_method VARCHAR(50),
    ai_confidence_score NUMERIC(5,4),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table for firewall policies managed by DRL
CREATE TABLE IF NOT EXISTS firewall_policies (
    id BIGSERIAL PRIMARY KEY,
    policy_name VARCHAR(100) NOT NULL UNIQUE,
    source_cidr INET,
    destination_cidr INET,
    protocol VARCHAR(10),
    port_range VARCHAR(20),
    action VARCHAR(20) DEFAULT 'ALLOW',
    priority INTEGER DEFAULT 100,
    is_active BOOLEAN DEFAULT TRUE,
    created_by VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table for AI model training data
CREATE TABLE IF NOT EXISTS training_data (
    id BIGSERIAL PRIMARY KEY,
    log_id BIGINT,
    feature_vector JSONB,
    label VARCHAR(20),
    is_anomaly BOOLEAN DEFAULT FALSE,
    model_version VARCHAR(20),
    processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (log_id) REFERENCES network_logs(id)
);

-- Table for DRL agent states and decisions
CREATE TABLE IF NOT EXISTS rl_agent_states (
    id BIGSERIAL PRIMARY KEY,
    state_vector JSONB,
    action_taken VARCHAR(50),
    reward_value NUMERIC(8,4),
    episode_number INTEGER,
    step_number INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table for system alerts and incidents
CREATE TABLE IF NOT EXISTS alerts (
    id BIGSERIAL PRIMARY KEY,
    alert_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) DEFAULT 'INFO',
    description TEXT,
    source_component VARCHAR(100),
    threat_score NUMERIC(5,2),
    resolved BOOLEAN DEFAULT FALSE,
    resolution_notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP NULL
);

-- Table for system configuration
CREATE TABLE IF NOT EXISTS system_config (
    id BIGSERIAL PRIMARY KEY,
    config_key VARCHAR(100) NOT NULL UNIQUE,
    config_value TEXT,
    description TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert some initial configuration values
INSERT INTO system_config (config_key, config_value, description) VALUES
('ai.model.version', '1.0.0', 'Current version of the AI threat detection model'),
('drl.learning.rate', '0.001', 'Learning rate for the deep reinforcement learning algorithm'),
('firewall.default.action', 'ALLOW', 'Default action when no specific rule matches'),
('ids.sensitivity.level', 'MEDIUM', 'Sensitivity level for intrusion detection system')
ON CONFLICT (config_key) DO NOTHING;

-- Create indexes for performance
CREATE INDEX idx_network_logs_timestamp ON network_logs(timestamp);
CREATE INDEX idx_network_logs_threat_level ON network_logs(threat_level);
CREATE INDEX idx_firewall_policies_priority ON firewall_policies(priority);
CREATE INDEX idx_alerts_severity ON alerts(severity, created_at);