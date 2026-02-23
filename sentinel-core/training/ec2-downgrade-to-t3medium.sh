#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Revert EC2 instance to t3.medium (e.g. after training on g4dn.2xlarge).
# Run from repo root: ./sentinel-core/training/ec2-downgrade-to-t3medium.sh
###############################################################################

SENTINEL_CORE="$(cd "$(dirname "$0")/.." && pwd)"
ID_FILE="$SENTINEL_CORE/.sentinel-instance-id"
REGION="${AWS_REGION:-us-east-1}"

if [ ! -f "$ID_FILE" ]; then
  echo "ERROR: $ID_FILE not found. Run from a repo that has provisioned the EC2 instance."
  exit 1
fi

INSTANCE_ID=$(cat "$ID_FILE" | tr -d '\r')
log() { echo "[$(date '+%H:%M:%S')] $*"; }

log "Stopping instance $INSTANCE_ID ..."
aws ec2 stop-instances --instance-ids "$INSTANCE_ID" --region "$REGION"
aws ec2 wait instance-stopped --instance-ids "$INSTANCE_ID" --region "$REGION"

log "Modifying instance type to t3.medium ..."
aws ec2 modify-instance-attribute \
  --instance-id "$INSTANCE_ID" \
  --instance-type '{"Value": "t3.medium"}' \
  --region "$REGION"

log "Starting instance ..."
aws ec2 start-instances --instance-ids "$INSTANCE_ID" --region "$REGION"
aws ec2 wait instance-running --instance-ids "$INSTANCE_ID" --region "$REGION"

PUBLIC_IP=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --region "$REGION" --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
echo "$PUBLIC_IP" > "$SENTINEL_CORE/.sentinel-instance-ip"
log "Instance is t3.medium. New public IP: $PUBLIC_IP"
log "SSH: ssh -i sentinel-training.pem ubuntu@$PUBLIC_IP"
