#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Pull the entire dragon-scale folder from EC2 to ~/dragon-scale (full copy).
# Run from anywhere: ./dragon-scale-core/training/pull-full-dragon-scale.sh
#
# Uses same method as pull-models.sh: .dragon-scale-instance-ip and dragon-scale-training.pem
###############################################################################

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DRAGON_SCALE_CORE="$(cd "$(dirname "$0")/.." && pwd)"

# Key: same as pull-models.sh
KEY_FILE="${KEY_FILE:-}"
for d in "$REPO_ROOT" "$DRAGON_SCALE_CORE/training" "$DRAGON_SCALE_CORE" "$(pwd)"; do
  if [ -f "$d/dragon-scale-training.pem" ]; then
    KEY_FILE="$d/dragon-scale-training.pem"
    break
  fi
done
if [ -z "$KEY_FILE" ] || [ ! -f "$KEY_FILE" ]; then
  echo "ERROR: SSH key not found. Put dragon-scale-training.pem in repo root or set KEY_FILE."
  exit 1
fi

# Resolve public IP
PUBLIC_IP="${1:-}"
if [ -z "$PUBLIC_IP" ]; then
  if [ -f "$DRAGON_SCALE_CORE/.dragon-scale-instance-ip" ]; then
    PUBLIC_IP=$(cat "$DRAGON_SCALE_CORE/.dragon-scale-instance-ip" | tr -d '\r')
  fi
fi
if [ -z "$PUBLIC_IP" ] || [ "$PUBLIC_IP" = "None" ]; then
  echo "Usage: $0 [PUBLIC_IP]"
  echo "  Or set dragon-scale-core/.dragon-scale-instance-ip to the EC2 public IP."
  exit 1
fi

DEST="${2:-$HOME/dragon-scale}"
mkdir -p "$DEST"
echo "Pulling full dragon-scale from ${PUBLIC_IP} into $DEST ..."

if command -v rsync >/dev/null 2>&1; then
  rsync -avz --progress -e "ssh -i \"$KEY_FILE\" -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new" \
    "ubuntu@${PUBLIC_IP}:~/dragon-scale/" \
    "$DEST/"
else
  scp -i "$KEY_FILE" -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new -r \
    "ubuntu@${PUBLIC_IP}:~/dragon-scale/." \
    "$DEST/"
fi

echo "Done. Contents of $DEST:"
ls -la "$DEST"
