#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# SENTINEL Training - EC2 Instance Provisioning
#
# Launches a t3.medium (cheap) instance for setup, downloads, and dependency
# installation.  After setup, use the upgrade commands at the bottom to switch
# to a GPU Spot Instance for actual training.
###############################################################################

REGION="${AWS_REGION:-us-east-1}"
KEY_NAME="${KEY_NAME:-sentinel-training}"
SG_NAME="${SG_NAME:-sentinel-training-sg}"
INSTANCE_NAME="sentinel-training"

SETUP_INSTANCE_TYPE="t3.medium"
VOLUME_SIZE_GB=150
VOLUME_TYPE="gp3"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

# ── Resolve AMI ──────────────────────────────────────────────────────────────
get_ubuntu_ami() {
    aws ec2 describe-images \
        --owners 099720109477 \
        --filters \
            "Name=name,Values=ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*" \
            "Name=state,Values=available" \
        --query 'sort_by(Images, &CreationDate)[-1].ImageId' \
        --output text \
        --region "${REGION}"
}

# ── Resolve security group ID ────────────────────────────────────────────────
get_sg_id() {
    aws ec2 describe-security-groups \
        --filters "Name=group-name,Values=${SG_NAME}" \
        --query 'SecurityGroups[0].GroupId' \
        --output text \
        --region "${REGION}"
}

# ── Launch instance ──────────────────────────────────────────────────────────
launch_instance() {
    local ami_id sg_id instance_id

    ami_id=$(get_ubuntu_ami)
    sg_id=$(get_sg_id)

    log "AMI:            ${ami_id}"
    log "Security Group: ${sg_id}"
    log "Instance Type:  ${SETUP_INSTANCE_TYPE}"
    log "Volume:         ${VOLUME_SIZE_GB} GB ${VOLUME_TYPE}"

    instance_id=$(aws ec2 run-instances \
        --image-id "${ami_id}" \
        --instance-type "${SETUP_INSTANCE_TYPE}" \
        --key-name "${KEY_NAME}" \
        --security-group-ids "${sg_id}" \
        --block-device-mappings "[{
            \"DeviceName\": \"/dev/sda1\",
            \"Ebs\": {
                \"VolumeSize\": ${VOLUME_SIZE_GB},
                \"VolumeType\": \"${VOLUME_TYPE}\",
                \"DeleteOnTermination\": true
            }
        }]" \
        --tag-specifications "[{
            \"ResourceType\": \"instance\",
            \"Tags\": [
                {\"Key\": \"Name\",  \"Value\": \"${INSTANCE_NAME}\"},
                {\"Key\": \"Project\", \"Value\": \"SENTINEL\"},
                {\"Key\": \"Purpose\", \"Value\": \"ML-Training\"}
            ]
        }]" \
        --metadata-options "HttpTokens=required,HttpPutResponseHopLimit=2,HttpEndpoint=enabled" \
        --query 'Instances[0].InstanceId' \
        --output text \
        --region "${REGION}")

    log "Instance launched: ${instance_id}"
    log "Waiting for instance to be running..."

    aws ec2 wait instance-running \
        --instance-ids "${instance_id}" \
        --region "${REGION}"

    local public_ip
    public_ip=$(aws ec2 describe-instances \
        --instance-ids "${instance_id}" \
        --query 'Reservations[0].Instances[0].PublicIpAddress' \
        --output text \
        --region "${REGION}")

    log ""
    log "========================================"
    log " Instance Ready!"
    log "========================================"
    log " Instance ID : ${instance_id}"
    log " Public IP   : ${public_ip}"
    log " SSH command :"
    log "   ssh -i ${KEY_NAME}.pem ubuntu@${public_ip}"
    log ""
    log " After SSH, run:"
    log "   bash sentinel-core/training/ec2-setup.sh"
    log "========================================"

    echo "${instance_id}" > .sentinel-instance-id
    echo "${public_ip}"   > .sentinel-instance-ip
}

# ── Upgrade to GPU Spot Instance ─────────────────────────────────────────────
print_upgrade_commands() {
    cat <<'UPGRADE'

# ──────────────────────────────────────────────────────────────────────────────
# UPGRADE TO GPU (run after setup is complete)
# ──────────────────────────────────────────────────────────────────────────────

INSTANCE_ID=$(cat .sentinel-instance-id)
REGION="${AWS_REGION:-us-east-1}"

# 1. Stop the instance
aws ec2 stop-instances --instance-ids "$INSTANCE_ID" --region "$REGION"
aws ec2 wait instance-stopped --instance-ids "$INSTANCE_ID" --region "$REGION"

# 2. Change to GPU instance type (g4dn.2xlarge = 8 vCPU; fits typical G/VT quota)
#    g4dn.2xlarge = 8 vCPU, 32GB RAM, 1x T4 16GB  (~$0.75/hr on-demand)
#    g4dn.4xlarge = 16 vCPU (requires higher quota)
aws ec2 modify-instance-attribute \
    --instance-id "$INSTANCE_ID" \
    --instance-type '{"Value": "g4dn.2xlarge"}' \
    --region "$REGION"

# 3. (Optional) Enable Spot pricing via Launch Template + Spot Fleet
#    For a simple approach, just start the on-demand instance:
aws ec2 start-instances --instance-ids "$INSTANCE_ID" --region "$REGION"
aws ec2 wait instance-running --instance-ids "$INSTANCE_ID" --region "$REGION"

# 4. Get new public IP (may change after stop/start)
aws ec2 describe-instances \
    --instance-ids "$INSTANCE_ID" \
    --query 'Reservations[0].Instances[0].PublicIpAddress' \
    --output text --region "$REGION"

# ──────────────────────────────────────────────────────────────────────────────
# SPOT INSTANCE ALTERNATIVE (cheaper, ~60-70% off)
# ──────────────────────────────────────────────────────────────────────────────

# Instead of modifying the existing instance, request a new Spot Instance.
# The EBS volume must be detached/reattached, so the simpler approach above
# (modify instance type) is recommended.
#
# To check current Spot pricing:
# aws ec2 describe-spot-price-history \
#     --instance-types g4dn.2xlarge \
#     --product-descriptions "Linux/UNIX" \
#     --start-time "$(date -u +%Y-%m-%dT%H:%M:%S)" \
#     --region "$REGION" \
#     --query 'SpotPriceHistory[0].SpotPrice' --output text

# ──────────────────────────────────────────────────────────────────────────────
# DOWNGRADE BACK (after training)
# ──────────────────────────────────────────────────────────────────────────────

# aws ec2 stop-instances --instance-ids "$INSTANCE_ID" --region "$REGION"
# aws ec2 wait instance-stopped --instance-ids "$INSTANCE_ID" --region "$REGION"
# aws ec2 modify-instance-attribute \
#     --instance-id "$INSTANCE_ID" \
#     --instance-type '{"Value": "t3.medium"}' \
#     --region "$REGION"
# aws ec2 start-instances --instance-ids "$INSTANCE_ID" --region "$REGION"

UPGRADE
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    log "=== SENTINEL EC2 Provisioning ==="
    launch_instance
    print_upgrade_commands
}

main "$@"
