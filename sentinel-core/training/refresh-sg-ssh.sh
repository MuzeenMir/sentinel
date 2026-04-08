#!/usr/bin/env bash
# Refresh SSH access for your current IP and show instance reachability info.
# Run from your local machine: bash training/refresh-sg-ssh.sh
set -euo pipefail
REGION="${AWS_REGION:-us-east-1}"
SG_NAME="${SG_NAME:-sentinel-training-sg}"

echo "=== Current public IP ==="
MY_IP=$(curl -sS --max-time 5 https://checkip.amazonaws.com || echo "FAIL")
if [ "$MY_IP" = "FAIL" ]; then
  echo "Could not detect public IP. Check internet or run: curl -s https://checkip.amazonaws.com"
  exit 1
fi
echo "  $MY_IP"

echo ""
echo "=== Instance state and IP ==="
ID_FILE=".sentinel-instance-id"
if [ ! -f "$ID_FILE" ]; then
  echo "  No .sentinel-instance-id in $(pwd). Run from sentinel-core/."
  exit 1
fi
INSTANCE_ID=$(cat "$ID_FILE")
aws ec2 describe-instances \
  --instance-ids "$INSTANCE_ID" \
  --region "$REGION" \
  --query 'Reservations[0].Instances[0].{State:State.Name,PublicIP:PublicIpAddress,PrivateIP:PrivateIpAddress,SecurityGroups:SecurityGroups[*].GroupId}' \
  --output table

STATE=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --region "$REGION" --query 'Reservations[0].Instances[0].State.Name' --output text)
PUBLIC_IP=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --region "$REGION" --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)

if [ "$STATE" != "running" ]; then
  echo "  Instance is not running. Start it first."
  exit 1
fi
if [ "$PUBLIC_IP" = "None" ] || [ -z "$PUBLIC_IP" ]; then
  echo "  Instance has no public IP (e.g. in private subnet). Use EC2 Serial Console or Session Manager."
  exit 1
fi

echo ""
echo "=== Security group: allow SSH from $MY_IP ==="
SG_ID=$(aws ec2 describe-security-groups \
  --filters "Name=group-name,Values=${SG_NAME}" \
  --query 'SecurityGroups[0].GroupId' \
  --output text \
  --region "$REGION")
aws ec2 authorize-security-group-ingress \
  --group-id "$SG_ID" \
  --protocol tcp \
  --port 22 \
  --cidr "${MY_IP}/32" \
  --region "$REGION" 2>/dev/null && echo "  Rule added." || echo "  Rule already exists or added."

echo ""
echo "=== Try SSH ==="
echo "  ssh -i sentinel-training.pem -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new ubuntu@${PUBLIC_IP}"
echo ""
echo "If that fails:"
echo "  1. Your IP may change (VPN, different Wi-Fi). Re-run this script."
echo "  2. Outbound port 22 may be blocked (corporate/school). Try another network (e.g. phone hotspot)."
echo "  3. Temporarily allow all IPs (insecure): run with OPEN_ALL=1"

if [ "${OPEN_ALL:-0}" = "1" ]; then
  echo ""
  echo "=== Adding 0.0.0.0/0 on port 22 (INSECURE - remove after testing) ==="
  aws ec2 authorize-security-group-ingress \
    --group-id "$SG_ID" \
    --protocol tcp \
    --port 22 \
    --cidr "0.0.0.0/0" \
    --region "$REGION" 2>/dev/null && echo "  Added. Try SSH. Then remove: aws ec2 revoke-security-group-ingress --group-id $SG_ID --protocol tcp --port 22 --cidr 0.0.0.0/0 --region $REGION" || echo "  Rule may already exist."
fi
