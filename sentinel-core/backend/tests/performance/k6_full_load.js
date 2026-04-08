/**
 * SENTINEL Full-Surface k6 Load Test
 *
 * Covers all API Gateway endpoints across auth, threats, alerts, policies,
 * compliance, XAI, AI engine, and DRL engine categories.
 *
 * Stages:
 *   1. Ramp up     1 ->  50 VUs  (2 min)
 *   2. Steady      50 VUs        (5 min)
 *   3. Spike       50 -> 200 VUs (1 min)
 *   4. Ramp down   200 ->  0 VUs (1 min)
 *
 * Usage:
 *   k6 run --env BASE_URL=http://localhost:8080 k6_full_load.js
 *   k6 run --env BASE_URL=http://localhost:8080 --env AUTH_URL=http://localhost:5000 k6_full_load.js
 */

import http from 'k6/http';
import { check, group, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const BASE_URL  = __ENV.BASE_URL  || 'http://localhost:8080';
const AUTH_URL  = __ENV.AUTH_URL  || BASE_URL;
const ADMIN_USER = __ENV.ADMIN_USER || 'admin';
const ADMIN_PASS = __ENV.ADMIN_PASS || 'ChangeMe!2026';

// ---------------------------------------------------------------------------
// Custom metrics
// ---------------------------------------------------------------------------

const errorRate       = new Rate('sentinel_error_rate');
const authLatency     = new Trend('sentinel_auth_latency', true);
const threatLatency   = new Trend('sentinel_threat_latency', true);
const alertLatency    = new Trend('sentinel_alert_latency', true);
const policyLatency   = new Trend('sentinel_policy_latency', true);
const complianceLatency = new Trend('sentinel_compliance_latency', true);
const aiLatency       = new Trend('sentinel_ai_latency', true);
const drlLatency      = new Trend('sentinel_drl_latency', true);
const xaiLatency      = new Trend('sentinel_xai_latency', true);
const totalRequests   = new Counter('sentinel_total_requests');

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

export const options = {
  stages: [
    { duration: '2m',  target: 50  },   // ramp up
    { duration: '5m',  target: 50  },   // steady state
    { duration: '1m',  target: 200 },   // spike
    { duration: '1m',  target: 0   },   // ramp down
  ],
  thresholds: {
    http_req_duration:         ['p(95)<500'],
    sentinel_error_rate:       ['rate<0.01'],
    sentinel_auth_latency:     ['p(95)<300'],
    sentinel_threat_latency:   ['p(95)<500'],
    sentinel_alert_latency:    ['p(95)<500'],
    sentinel_policy_latency:   ['p(95)<500'],
    sentinel_compliance_latency: ['p(95)<1000'],
    sentinel_ai_latency:       ['p(95)<500'],
    sentinel_drl_latency:      ['p(95)<300'],
    sentinel_xai_latency:      ['p(95)<1000'],
  },
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function authHeaders(token) {
  return {
    headers: {
      'Content-Type':  'application/json',
      'Authorization': `Bearer ${token}`,
    },
  };
}

function record(res, metricTrend) {
  totalRequests.add(1);
  const isErr = res.status === 0 || res.status >= 400;
  errorRate.add(isErr);
  metricTrend.add(res.timings.duration);
}

function randomIP() {
  return `10.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 254) + 1}`;
}

function randomChoice(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

// ---------------------------------------------------------------------------
// Setup: authenticate once and share the token
// ---------------------------------------------------------------------------

export function setup() {
  const loginRes = http.post(
    `${AUTH_URL}/api/v1/auth/login`,
    JSON.stringify({ username: ADMIN_USER, password: ADMIN_PASS }),
    { headers: { 'Content-Type': 'application/json' } },
  );

  const token = loginRes.status === 200 ? loginRes.json('access_token') : '';
  if (!token) {
    console.warn('Setup: authentication failed, status=' + loginRes.status);
  }
  return { token };
}

// ---------------------------------------------------------------------------
// Default function: each VU iteration exercises one random scenario group
// ---------------------------------------------------------------------------

export default function (data) {
  const params = authHeaders(data.token);

  const scenario = Math.random();

  if (scenario < 0.10) {
    scenarioAuth(data, params);
  } else if (scenario < 0.25) {
    scenarioThreats(params);
  } else if (scenario < 0.40) {
    scenarioAlerts(params);
  } else if (scenario < 0.50) {
    scenarioPolicies(params);
  } else if (scenario < 0.60) {
    scenarioCompliance(params);
  } else if (scenario < 0.72) {
    scenarioAI(params);
  } else if (scenario < 0.84) {
    scenarioDRL(params);
  } else if (scenario < 0.92) {
    scenarioXAI(params);
  } else {
    scenarioMisc(params);
  }

  sleep(0.1 + Math.random() * 0.2);
}

// ---------------------------------------------------------------------------
// Scenario groups
// ---------------------------------------------------------------------------

function scenarioAuth(data, params) {
  group('auth', function () {
    // Token verification
    let res = http.post(`${BASE_URL}/api/v1/auth/verify`, null, params);
    check(res, { 'auth/verify 200': (r) => r.status === 200 });
    record(res, authLatency);

    // Profile
    res = http.get(`${BASE_URL}/api/v1/auth/profile`, params);
    check(res, { 'auth/profile 200': (r) => r.status === 200 });
    record(res, authLatency);

    // Refresh (requires refresh token, may return 422/401 with access token)
    res = http.post(`${BASE_URL}/api/v1/auth/refresh`, null, params);
    record(res, authLatency);

    // User listing (admin only)
    res = http.get(`${BASE_URL}/api/v1/auth/users?page=1&per_page=5`, params);
    record(res, authLatency);
  });
}

function scenarioThreats(params) {
  group('threats', function () {
    let res = http.get(`${BASE_URL}/api/v1/threats`, params);
    check(res, { 'threats list 2xx': (r) => r.status < 400 });
    record(res, threatLatency);

    res = http.get(`${BASE_URL}/api/v1/threats/1`, params);
    record(res, threatLatency);
  });
}

function scenarioAlerts(params) {
  group('alerts', function () {
    let res = http.get(`${BASE_URL}/api/v1/alerts?limit=20`, params);
    check(res, { 'alerts list 2xx': (r) => r.status < 400 });
    record(res, alertLatency);

    // Create alert
    const payload = JSON.stringify({
      type: randomChoice(['network_anomaly', 'brute_force', 'malware_detected', 'unauthorized_access']),
      severity: randomChoice(['low', 'medium', 'high', 'critical']),
      description: `k6 load test alert ${Date.now()}`,
      source: 'k6_load_test',
    });
    res = http.post(`${BASE_URL}/api/v1/alerts`, payload, params);
    check(res, { 'alert created': (r) => r.status === 201 || r.status === 200 });
    record(res, alertLatency);

    // Statistics
    res = http.get(`${BASE_URL}/api/v1/alerts/statistics`, params);
    record(res, alertLatency);
  });
}

function scenarioPolicies(params) {
  group('policies', function () {
    let res = http.get(`${BASE_URL}/api/v1/policies`, params);
    check(res, { 'policies list 2xx': (r) => r.status < 400 });
    record(res, policyLatency);

    // Create policy
    const payload = JSON.stringify({
      name: `k6-policy-${Date.now()}-${Math.floor(Math.random() * 9999)}`,
      action: randomChoice(['ALLOW', 'DENY', 'RATE_LIMIT']),
      source: `${randomIP()}/24`,
      destination: '10.0.0.0/8',
      protocol: 'TCP',
      port: Math.floor(Math.random() * 65535) + 1,
    });
    res = http.post(`${BASE_URL}/api/v1/policies`, payload, params);
    check(res, { 'policy created': (r) => r.status < 400 });
    record(res, policyLatency);
  });
}

function scenarioCompliance(params) {
  group('compliance', function () {
    let res = http.get(`${BASE_URL}/api/v1/frameworks`, params);
    check(res, { 'frameworks 2xx': (r) => r.status < 400 });
    record(res, complianceLatency);

    const fwk = randomChoice(['NIST', 'GDPR', 'HIPAA', 'PCI-DSS', 'SOC2']);

    res = http.get(`${BASE_URL}/api/v1/frameworks/${fwk}`, params);
    record(res, complianceLatency);

    const assessPayload = JSON.stringify({
      framework: fwk,
      policies: [],
      configurations: {},
    });
    res = http.post(`${BASE_URL}/api/v1/assess`, assessPayload, params);
    check(res, { 'assessment 2xx': (r) => r.status < 400 });
    record(res, complianceLatency);

    res = http.get(`${BASE_URL}/api/v1/reports/history?limit=5`, params);
    record(res, complianceLatency);
  });
}

function scenarioAI(params) {
  group('ai_engine', function () {
    // Single detection
    const detectPayload = JSON.stringify({
      traffic_data: {
        src_ip: randomIP(),
        dst_ip: '10.0.0.1',
        dst_port: randomChoice([22, 80, 443, 3306, 8080]),
        protocol: randomChoice(['TCP', 'UDP']),
        bytes_sent: Math.floor(Math.random() * 65535) + 64,
        bytes_recv: Math.floor(Math.random() * 65535) + 64,
        duration_ms: Math.floor(Math.random() * 30000),
        packets: Math.floor(Math.random() * 500) + 1,
      },
    });
    let res = http.post(`${BASE_URL}/api/v1/detect`, detectPayload, params);
    check(res, { 'detect 2xx': (r) => r.status < 400 });
    record(res, aiLatency);

    // Batch detection
    const batch = [];
    for (let i = 0; i < 5; i++) {
      batch.push({
        src_ip: randomIP(),
        dst_port: randomChoice([22, 80, 443]),
        protocol: 'TCP',
        bytes_sent: Math.floor(Math.random() * 65535) + 64,
        packets: Math.floor(Math.random() * 500) + 1,
      });
    }
    res = http.post(`${BASE_URL}/api/v1/detect/batch`, JSON.stringify({ traffic_batch: batch }), params);
    check(res, { 'detect/batch 2xx': (r) => r.status < 400 });
    record(res, aiLatency);
  });
}

function scenarioDRL(params) {
  group('drl_engine', function () {
    // Single decision
    const payload = JSON.stringify({
      detection_id: `det_${Date.now()}`,
      threat_score: Math.random(),
      threat_type: randomChoice(['brute_force', 'port_scan', 'malware', 'data_exfil']),
      source_ip: randomIP(),
      dest_ip: '10.0.0.1',
      dest_port: randomChoice([22, 80, 443]),
      protocol: 'TCP',
      asset_criticality: Math.floor(Math.random() * 5) + 1,
    });
    let res = http.post(`${BASE_URL}/api/v1/decide`, payload, params);
    check(res, { 'decide 2xx': (r) => r.status < 400 });
    record(res, drlLatency);

    // Action space
    res = http.get(`${BASE_URL}/api/v1/action-space`, params);
    record(res, drlLatency);

    // State space
    res = http.get(`${BASE_URL}/api/v1/state-space`, params);
    record(res, drlLatency);
  });
}

function scenarioXAI(params) {
  group('xai', function () {
    // Explain detection
    const explainPayload = JSON.stringify({
      detection_id: `det_${Date.now()}`,
      features: { bytes_sent: 5000, packets: 200, duration_ms: 1500 },
      prediction: { confidence: 0.92, is_threat: true },
      model_verdicts: {
        xgboost: { is_threat: true, confidence: 0.94 },
        lstm: { is_threat: true, confidence: 0.88 },
      },
    });
    let res = http.post(`${BASE_URL}/api/v1/explain/detection`, explainPayload, params);
    check(res, { 'explain/detection 2xx': (r) => r.status < 400 });
    record(res, xaiLatency);

    // Explain policy decision
    const policyPayload = JSON.stringify({
      decision_id: `drl_${Date.now()}`,
      action: randomChoice(['DENY', 'ALLOW', 'RATE_LIMIT', 'MONITOR']),
      state_features: { threat_score: 0.85, asset_criticality: 4 },
      confidence: 0.91,
    });
    res = http.post(`${BASE_URL}/api/v1/explain/policy`, policyPayload, params);
    check(res, { 'explain/policy 2xx': (r) => r.status < 400 });
    record(res, xaiLatency);

    // Audit trail
    res = http.get(`${BASE_URL}/api/v1/audit-trail?limit=10`, params);
    record(res, xaiLatency);
  });
}

function scenarioMisc(params) {
  group('misc', function () {
    // Health check
    let res = http.get(`${BASE_URL}/health`);
    check(res, { 'health 200': (r) => r.status === 200 });
    record(res, authLatency);

    // Statistics
    res = http.get(`${BASE_URL}/api/v1/stats`, params);
    check(res, { 'stats 2xx': (r) => r.status < 400 });
    record(res, authLatency);

    // Config (admin)
    res = http.get(`${BASE_URL}/api/v1/config`, params);
    record(res, authLatency);
  });
}
