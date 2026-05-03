#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Pull trained models (and optional files) from EC2 to your local machine.
# Run from the repository root: ./dragon-scale-core/training/pull-models.sh
#
# Requires: EC2 instance running, SSH key, and either:
#   - dragon-scale-core/.dragon-scale-instance-ip containing the public IP, or
#   - Pass the public IP as the first argument.
###############################################################################

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DRAGON_SCALE_CORE="$(cd "$(dirname "$0")/.." && pwd)"
REMOTE_BASE="ubuntu@__IP__:~/dragon-scale/dragon-scale-core"

# Key: same name as in ec2-provision (dragon-scale-training.pem). Prefer repo root or training dir.
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
    PUBLIC_IP=$(cat "$DRAGON_SCALE_CORE/.dragon-scale-instance-ip")
  fi
fi
if [ -z "$PUBLIC_IP" ] || [ "$PUBLIC_IP" = "None" ]; then
  echo "Usage: $0 [PUBLIC_IP]"
  echo "  Or set dragon-scale-core/.dragon-scale-instance-ip to the EC2 public IP."
  echo "  Get IP: aws ec2 describe-instances --instance-ids \$(cat dragon-scale-core/.dragon-scale-instance-id) --query 'Reservations[0].Instances[0].PublicIpAddress' --output text"
  exit 1
fi

TARGET_DIR="$DRAGON_SCALE_CORE/backend/ai-engine/trained_models"
REMOTE_PATH="ubuntu@${PUBLIC_IP}:~/dragon-scale/dragon-scale-core/backend/ai-engine/trained_models"

mkdir -p "$TARGET_DIR"
echo "Pulling trained models from ${PUBLIC_IP} into $TARGET_DIR ..."
# Copy contents of remote trained_models into local target (/. means contents only)
scp -i "$KEY_FILE" -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new -r "${REMOTE_PATH}/." "$TARGET_DIR/"
echo "Done. Contents of $TARGET_DIR:"
ls -la "$TARGET_DIR"
