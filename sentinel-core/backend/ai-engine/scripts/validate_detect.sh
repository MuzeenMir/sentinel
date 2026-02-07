#!/usr/bin/env bash
# Validate AI engine prediction endpoint (service must be running).
# Usage: ./scripts/validate_detect.sh [BASE_URL]
# Example: ./scripts/validate_detect.sh http://localhost:5003

set -e
BASE_URL="${1:-http://localhost:5003}"
echo "Validating $BASE_URL/api/v1/detect ..."

resp=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/api/v1/detect" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer test-token" \
  -d '{"traffic_data":{"src_ip":"192.168.1.10","dst_ip":"10.0.0.5","src_port":54321,"dst_port":443,"protocol":"tcp","bytes_sent":1500,"bytes_recv":800,"packets_sent":10,"packets_recv":8,"duration_sec":2.5},"context":{}}')

body=$(echo "$resp" | head -n -1)
code=$(echo "$resp" | tail -n 1)

if [ "$code" != "200" ]; then
  echo "FAIL: expected HTTP 200, got $code"
  echo "$body" | python3 -m json.tool 2>/dev/null || echo "$body"
  exit 1
fi

if ! echo "$body" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'is_threat' in d and 'confidence' in d, 'missing fields'"; then
  echo "FAIL: response missing is_threat or confidence"
  echo "$body" | python3 -m json.tool 2>/dev/null || echo "$body"
  exit 1
fi

echo "OK: /api/v1/detect returned 200 with is_threat and confidence"
echo "$body" | python3 -m json.tool 2>/dev/null | head -20
