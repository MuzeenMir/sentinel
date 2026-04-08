/**
 * SENTINEL DRL Engine Decision Benchmark (k6)
 *
 * Target: p95 < 50ms for single decision
 *
 * Usage:
 *   k6 run --env BASE_URL=http://localhost:5005 k6_drl_engine.js
 */
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:5005';
const AUTH_URL = __ENV.AUTH_URL || 'http://localhost:5000';
const ADMIN_USER = __ENV.ADMIN_USER || 'Santa';
const ADMIN_PASS = __ENV.ADMIN_PASS || 'Ggxr@123';

const decisionLatency = new Trend('decision_latency');
const errorRate = new Rate('errors');

export const options = {
  stages: [
    { duration: '10s', target: 50 },
    { duration: '30s', target: 200 },
    { duration: '30s', target: 500 },
    { duration: '10s', target: 0 },
  ],
  thresholds: {
    decision_latency: ['p(95)<50'],
    errors: ['rate<0.02'],
  },
};

export function setup() {
  const loginRes = http.post(`${AUTH_URL}/api/v1/auth/login`, JSON.stringify({
    username: ADMIN_USER,
    password: ADMIN_PASS,
  }), { headers: { 'Content-Type': 'application/json' } });
  return { token: loginRes.status === 200 ? loginRes.json('access_token') : '' };
}

export default function (data) {
  const headers = {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${data.token}`,
  };

  const threatTypes = ['brute_force', 'ddos', 'malware', 'port_scan', 'sql_injection'];
  const payload = JSON.stringify({
    detection_id: `perf-${Date.now()}-${Math.random().toString(36).substring(7)}`,
    threat_score: Math.random(),
    threat_type: threatTypes[Math.floor(Math.random() * threatTypes.length)],
    source_ip: `10.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`,
    dest_ip: '192.168.1.1',
    dest_port: [22, 80, 443, 3306, 5432][Math.floor(Math.random() * 5)],
    protocol: ['TCP', 'UDP'][Math.floor(Math.random() * 2)],
    severity: ['low', 'medium', 'high', 'critical'][Math.floor(Math.random() * 4)],
    confidence: 0.5 + Math.random() * 0.5,
  });

  const res = http.post(`${BASE_URL}/api/v1/decide`, payload, { headers });
  check(res, { 'decide 200': (r) => r.status === 200 });
  errorRate.add(res.status !== 200);
  decisionLatency.add(res.timings.duration);

  sleep(0.02);
}
