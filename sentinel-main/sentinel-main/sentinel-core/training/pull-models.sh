#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Pull trained models (and optional files) from EC2 to your local machine.
# Run from the repository root: ./sentinel-core/training/pull-models.sh
#
# Requires: EC2 instance running, SSH key, and either:
#   - sentinel-core/.sentinel-instance-ip containing the public IP, or
#   - Pass the public IP as the first argument.
###############################################################################

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SENTINEL_CORE="$(cd "$(dirname "$0")/.." && pwd)"
REMOTE_BASE="ubuntu@__IP__:~/sentinel/sentinel-core"

# Key: same name as in ec2-provision (sentinel-training.pem). Prefer repo root or training dir.
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
    PUBLIC_IP=$(cat "$SENTINEL_CORE/.sentinel-instance-ip")
  fi
fi
if [ -z "$PUBLIC_IP" ] || [ "$PUBLIC_IP" = "None" ]; then
  echo "Usage: $0 [PUBLIC_IP]"
  echo "  Or set sentinel-core/.sentinel-instance-ip to the EC2 public IP."
  echo "  Get IP: aws ec2 describe-instances --instance-ids \$(cat sentinel-core/.sentinel-instance-id) --query 'Reservations[0].Instances[0].PublicIpAddress' --output text"
  exit 1
fi

TARGET_DIR="$SENTINEL_CORE/backend/ai-engine/trained_models"
REMOTE_PATH="ubuntu@${PUBLIC_IP}:~/sentinel/sentinel-core/backend/ai-engine/trained_models"

mkdir -p "$TARGET_DIR"
echo "Pulling trained models from ${PUBLIC_IP} into $TARGET_DIR ..."
# Copy contents of remote trained_models into local target (/. means contents only)
scp -i "$KEY_FILE" -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new -r "${REMOTE_PATH}/." "$TARGET_DIR/"
echo "Done. Contents of $TARGET_DIR:"
ls -la "$TARGET_DIR"
