#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Pull the entire sentinel folder from EC2 to ~/senti (full copy).
# Run from anywhere: ./sentinel-core/training/pull-full-sentinel.sh
#
# Uses same method as pull-models.sh: .sentinel-instance-ip and sentinel-training.pem
###############################################################################

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SENTINEL_CORE="$(cd "$(dirname "$0")/.." && pwd)"

# Key: same as pull-models.sh
KEY_FILE="${KEY_FILE:-}"
for d in "$REPO_ROOT" "$SENTINEL_CORE/training" "$SENTINEL_CORE" "$(pwd)"; do
  if [ -f "$d/sentinel-training.pem" ]; then
    KEY_FILE="$d/sentinel-training.pem"
    break
  fi
done
if [ -z "$KEY_FILE" ] || [ ! -f "$KEY_FILE" ]; then
  echo "ERROR: SSH key not found. Put sentinel-training.pem in repo root or set KEY_FILE."
  exit 1
fi

# Resolve public IP
PUBLIC_IP="${1:-}"
if [ -z "$PUBLIC_IP" ]; then
  if [ -f "$SENTINEL_CORE/.sentinel-instance-ip" ]; then
    PUBLIC_IP=$(cat "$SENTINEL_CORE/.sentinel-instance-ip" | tr -d '\r')
  fi
fi
if [ -z "$PUBLIC_IP" ] || [ "$PUBLIC_IP" = "None" ]; then
  echo "Usage: $0 [PUBLIC_IP]"
  echo "  Or set sentinel-core/.sentinel-instance-ip to the EC2 public IP."
  exit 1
fi

DEST="${2:-$HOME/senti}"
mkdir -p "$DEST"
echo "Pulling full sentinel from ${PUBLIC_IP} into $DEST ..."

if command -v rsync >/dev/null 2>&1; then
  rsync -avz --progress -e "ssh -i \"$KEY_FILE\" -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new" \
    "ubuntu@${PUBLIC_IP}:~/sentinel/" \
    "$DEST/"
else
  scp -i "$KEY_FILE" -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new -r \
    "ubuntu@${PUBLIC_IP}:~/sentinel/." \
    "$DEST/"
fi

echo "Done. Contents of $DEST:"
ls -la "$DEST"
