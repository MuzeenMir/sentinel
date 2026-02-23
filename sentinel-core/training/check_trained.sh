#!/usr/bin/env bash
# Quick check of what was trained and what's on disk. Run from repo root or sentinel-core.
set -euo pipefail
OUTPUT_DIR="${1:-backend/ai-engine/trained_models}"
CKPT="$OUTPUT_DIR/.training_checkpoint.json"
REPORT="$OUTPUT_DIR/training_report.json"

echo "=== Checkpoint (completed models) ==="
if [ -f "$CKPT" ]; then
  python3 -c "
import json
with open('$CKPT') as f:
  c = json.load(f)
done = c.get('completed', [])
print('Completed:', len(done), '/ 6')
print('Models:', ', '.join(done))
missing = set(['xgboost','isolation_forest','autoencoder','lstm','ensemble','drl']) - set(done)
if missing:
  print('Missing:', ', '.join(sorted(missing)))
"
else
  echo "No checkpoint at $CKPT"
fi

echo ""
echo "=== Artifacts on disk ==="
for name in xgboost isolation_forest autoencoder lstm ensemble drl; do
  dir="$OUTPUT_DIR/$name"
  if [ -d "$dir" ] && [ -n "$(ls -A "$dir" 2>/dev/null)" ]; then
    echo "  $name: OK ($(ls "$dir" 2>/dev/null | wc -l) files)"
  else
    echo "  $name: missing or empty"
  fi
done

echo ""
if [ -f "$REPORT" ]; then
  echo "=== Report summary ==="
  python3 -c "
import json
with open('$REPORT') as f:
  r = json.load(f)
print('Dataset:', r.get('dataset'))
print('Device:', r.get('device'))
print('Total time (min):', round(r.get('total_time_seconds', 0) / 60, 1))
"
fi
