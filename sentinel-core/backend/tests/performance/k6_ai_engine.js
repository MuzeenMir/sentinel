/**
 * SENTINEL AI Engine Inference Benchmark (k6)
 *
 * Target: p95 < 100ms for single detection
 *
 * Usage:
 *   k6 run --env BASE_URL=http://localhost:5003 k6_ai_engine.js
 */
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:5003';
const AUTH_URL = __ENV.AUTH_URL || 'http://localhost:5000';
const ADMIN_USER = __ENV.ADMIN_USER || 'Santa';
const ADMIN_PASS = __ENV.ADMIN_PASS || 'Ggxr@123';

const inferenceLatency = new Trend('inference_latency');
const errorRate = new Rate('errors');

export const options = {
  stages: [
    { duration: '10s', target: 20 },
    { duration: '30s', target: 100 },
    { duration: '30s', target: 200 },
    { duration: '10s', target: 0 },
  ],
  thresholds: {
    inference_latency: ['p(95)<100'],
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

function randomFeatures(n) {
  const arr = [];
  for (let i = 0; i < n; i++) {
    arr.push(Math.random() * 2 - 1);
  }
  return arr;
}

export default function (data) {
  const headers = {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${data.token}`,
  };

  // Single detection
  const payload = JSON.stringify({
    features: randomFeatures(50),
    source_ip: '192.168.1.' + Math.floor(Math.random() * 255),
    dest_ip: '10.0.0.1',
    protocol: 'TCP',
  });

  const res = http.post(`${BASE_URL}/api/v1/detect`, payload, { headers });
  check(res, { 'detect 200': (r) => r.status === 200 });
  errorRate.add(res.status !== 200);
  inferenceLatency.add(res.timings.duration);

  sleep(0.05);
}
