#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# SENTINEL Training - AWS CLI Setup
#
# Run this on your LOCAL machine (Windows via Git Bash / WSL, or Linux/macOS)
# to install the AWS CLI and configure credentials before provisioning EC2.
###############################################################################

REGION="${AWS_REGION:-us-east-1}"
KEY_NAME="${KEY_NAME:-sentinel-training}"
SG_NAME="${SG_NAME:-sentinel-training-sg}"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

# ── 1. Install AWS CLI v2 ────────────────────────────────────────────────────
install_awscli() {
    if command -v aws &>/dev/null; then
        log "AWS CLI already installed: $(aws --version)"
        return
    fi

    case "$(uname -s)" in
        MINGW*|MSYS*|CYGWIN*)
            log "Download and run the MSI installer from:"
            log "  https://awscli.amazonaws.com/AWSCLIV2.msi"
            log "Then re-run this script."
            exit 1
            ;;
        Darwin*)
            log "Installing AWS CLI v2 for macOS..."
            curl -fsSL "https://awscli.amazonaws.com/AWSCLIV2.pkg" -o /tmp/AWSCLIV2.pkg
            sudo installer -pkg /tmp/AWSCLIV2.pkg -target /
            rm /tmp/AWSCLIV2.pkg
            ;;
        Linux*)
            log "Installing AWS CLI v2 for Linux..."
            curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscliv2.zip
            unzip -qo /tmp/awscliv2.zip -d /tmp
            sudo /tmp/aws/install --update
            rm -rf /tmp/aws /tmp/awscliv2.zip
            ;;
    esac

    log "AWS CLI installed: $(aws --version)"
}

# ── 2. Configure credentials ─────────────────────────────────────────────────
configure_credentials() {
    if aws sts get-caller-identity &>/dev/null; then
        log "AWS credentials already configured:"
        aws sts get-caller-identity --output table
        return
    fi

    if [ ! -t 0 ]; then
        log "ERROR: AWS credentials invalid or not set, and this script is not interactive."
        log "Run in your terminal: aws configure"
        log "Then run this script again: bash training/aws-setup.sh"
        exit 1
    fi

    log "Running 'aws configure'. You will need:"
    log "  - AWS Access Key ID"
    log "  - AWS Secret Access Key"
    log "  - Default region: ${REGION}"
    log "  - Default output format: json"
    echo ""
    aws configure
}

# ── 3. Create EC2 key pair ────────────────────────────────────────────────────
create_key_pair() {
    local key_file="${KEY_NAME}.pem"

    if aws ec2 describe-key-pairs --key-names "${KEY_NAME}" --region "${REGION}" &>/dev/null; then
        log "Key pair '${KEY_NAME}' already exists in ${REGION}."
        if [ ! -f "${key_file}" ]; then
            log "WARNING: Local key file '${key_file}' not found. If you lost it, delete the"
            log "  key pair in AWS and re-run: aws ec2 delete-key-pair --key-name ${KEY_NAME}"
        fi
        return
    fi

    log "Creating key pair '${KEY_NAME}'..."
    aws ec2 create-key-pair \
        --key-name "${KEY_NAME}" \
        --key-type ed25519 \
        --query 'KeyMaterial' \
        --output text \
        --region "${REGION}" > "${key_file}"

    chmod 400 "${key_file}"
    log "Key pair saved to ${key_file}  (keep this file safe!)"
}

# ── 4. Create security group ─────────────────────────────────────────────────
create_security_group() {
    if aws ec2 describe-security-groups \
        --filters "Name=group-name,Values=${SG_NAME}" \
        --region "${REGION}" \
        --query 'SecurityGroups[0].GroupId' \
        --output text 2>/dev/null | grep -q "sg-"; then
        log "Security group '${SG_NAME}' already exists."
        return
    fi

    local vpc_id
    vpc_id=$(aws ec2 describe-vpcs \
        --filters "Name=isDefault,Values=true" \
        --query 'Vpcs[0].VpcId' \
        --output text \
        --region "${REGION}")

    log "Creating security group in VPC ${vpc_id}..."
    local sg_id
    sg_id=$(aws ec2 create-security-group \
        --group-name "${SG_NAME}" \
        --description "SENTINEL training instance - SSH only" \
        --vpc-id "${vpc_id}" \
        --region "${REGION}" \
        --output text \
        --query 'GroupId')

    local my_ip
    my_ip=$(curl -fsSL https://checkip.amazonaws.com)

    aws ec2 authorize-security-group-ingress \
        --group-id "${sg_id}" \
        --protocol tcp \
        --port 22 \
        --cidr "${my_ip}/32" \
        --region "${REGION}"

    log "Security group ${sg_id} created. SSH allowed from ${my_ip}/32"
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    log "=== SENTINEL AWS Setup ==="
    install_awscli
    configure_credentials
    create_key_pair
    create_security_group
    log ""
    log "Setup complete. Next step:"
    log "  bash training/ec2-provision.sh"
}

main "$@"
