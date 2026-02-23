#!/usr/bin/env bash
# Copy required, missing files from senti (EC2 copy) into sentinel.
# Run from repo root: ./sentinel-core/training/sync-from-senti.sh
# Uses rsync --ignore-existing so existing files in sentinel are never overwritten.

set -euo pipefail

SENTI="${1:-$HOME/senti}"
SENTINEL="$(cd "$(dirname "$0")/../.." && pwd)"

if [ ! -d "$SENTI" ]; then
  echo "ERROR: $SENTI not found. Usage: $0 [path-to-senti]"
  exit 1
fi

echo "Syncing from $SENTI -> $SENTINEL (missing files only)"
echo ""

# Paths that are gitignored but required (trained models, dataset data)
PATHS=(
  "sentinel-core/backend/ai-engine/trained_models"
  "sentinel-core/training/datasets/data"
)

for rel in "${PATHS[@]}"; do
  src="$SENTI/$rel"
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
echo "Done. Sentinel now has any missing files from senti."
