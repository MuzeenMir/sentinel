/**
 * SENTINEL API Gateway Performance Benchmark (k6)
 *
 * Target: 1000+ RPS at p95 < 200ms
 *
 * Usage:
 *   # Install k6: https://grafana.com/docs/k6/latest/set-up/install-k6/
 *   k6 run --env BASE_URL=http://localhost:8080 k6_api_gateway.js
 *   k6 run --env BASE_URL=http://localhost:8080 --vus 100 --duration 60s k6_api_gateway.js
 */
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const AUTH_URL = __ENV.AUTH_URL || 'http://localhost:5000';
const ADMIN_USER = __ENV.ADMIN_USER || 'Santa';
const ADMIN_PASS = __ENV.ADMIN_PASS || 'Ggxr@123';

const errorRate = new Rate('errors');
const latencyP95 = new Trend('latency_p95');

export const options = {
  stages: [
    { duration: '10s', target: 50 },
    { duration: '30s', target: 200 },
    { duration: '30s', target: 500 },
    { duration: '20s', target: 1000 },
    { duration: '10s', target: 0 },
  ],
  thresholds: {
    http_req_duration: ['p(95)<200'],
    errors: ['rate<0.01'],
  },
};

let token = '';

export function setup() {
  const loginRes = http.post(`${AUTH_URL}/api/v1/auth/login`, JSON.stringify({
    username: ADMIN_USER,
    password: ADMIN_PASS,
  }), { headers: { 'Content-Type': 'application/json' } });

  if (loginRes.status === 200) {
    return { token: loginRes.json('access_token') };
  }
  return { token: '' };
}

export default function (data) {
  const headers = {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${data.token}`,
  };

  // Health check (unauthenticated, fastest path)
  const healthRes = http.get(`${BASE_URL}/health`);
  check(healthRes, { 'health 200': (r) => r.status === 200 });
  errorRate.add(healthRes.status !== 200);
  latencyP95.add(healthRes.timings.duration);

  // Statistics endpoint (authenticated, aggregates downstream)
  const statsRes = http.get(`${BASE_URL}/api/v1/stats`, { headers });
  check(statsRes, { 'stats 200': (r) => r.status === 200 });
  errorRate.add(statsRes.status !== 200);
  latencyP95.add(statsRes.timings.duration);

  // Alerts listing (authenticated, proxied)
  const alertsRes = http.get(`${BASE_URL}/api/v1/alerts?limit=10`, { headers });
  check(alertsRes, { 'alerts 200': (r) => r.status === 200 });
  errorRate.add(alertsRes.status !== 200);

  // Threats listing (authenticated, proxied)
  const threatsRes = http.get(`${BASE_URL}/api/v1/threats`, { headers });
  check(threatsRes, { 'threats 200': (r) => r.status === 200 });
  errorRate.add(threatsRes.status !== 200);

  // Policies listing (authenticated, proxied)
  const policiesRes = http.get(`${BASE_URL}/api/v1/policies`, { headers });
  check(policiesRes, { 'policies 200': (r) => r.status === 200 });
  errorRate.add(policiesRes.status !== 200);

  sleep(0.1);
}
