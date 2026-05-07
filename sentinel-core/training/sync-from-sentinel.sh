#!/usr/bin/env bash
# Copy required, missing files from sentinel (EC2 copy) into sentinel.
# Run from repo root: ./sentinel-core/training/sync-from-sentinel.sh
# Uses rsync --ignore-existing so existing files in sentinel are never overwritten.

set -euo pipefail

LEGACY="${1:-$HOME/sentinel}"
SENTINEL="$(cd "$(dirname "$0")/../.." && pwd)"

if [ ! -d "$LEGACY" ]; then
  echo "ERROR: $LEGACY not found. Usage: $0 [path-to-sentinel]"
  exit 1
fi

echo "Syncing from $LEGACY -> $SENTINEL (missing files only)"
echo ""

# Paths that are gitignored but required (trained models, dataset data)
PATHS=(
  "sentinel-core/backend/ai-engine/trained_models"
  "sentinel-core/training/datasets/data"
)

for rel in "${PATHS[@]}"; do
  src="$LEGACY/$rel"
  dst="$SENTINEL/$rel"
  if [ ! -d "$src" ]; then
    echo "Skip (no source): $rel"
    continue
  fi
  mkdir -p "$dst"
  echo "Sync $rel ..."
  rsync -a --ignore-existing "$src/" "$dst/"
done

echo ""
echo "Done. Sentinel now has any missing files from sentinel."
