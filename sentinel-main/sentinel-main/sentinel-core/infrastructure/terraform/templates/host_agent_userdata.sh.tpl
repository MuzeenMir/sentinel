#!/bin/bash
# SENTINEL Host Agent bootstrap script
# Runs on Amazon Linux 2023 at first boot.
# Installs Docker, authenticates to ECR, and starts hids-agent and hardening-service.

set -euo pipefail
exec > >(tee /var/log/sentinel-bootstrap.log | logger -t sentinel-bootstrap -s 2>/dev/console) 2>&1

echo "=== SENTINEL Host Agent Bootstrap ==="
echo "Environment: ${environment}"
echo "Region: ${aws_region}"

# ── System packages ───────────────────────────────────────────────────────────
dnf update -y
dnf install -y docker aws-cli jq

# ── Docker ────────────────────────────────────────────────────────────────────
systemctl enable --now docker
usermod -aG docker ec2-user

# ── ECR login ─────────────────────────────────────────────────────────────────
aws ecr get-login-password --region ${aws_region} \
  | docker login --username AWS --password-stdin ${ecr_base_url}

# ── Fetch Redis auth token from Secrets Manager ───────────────────────────────
REDIS_AUTH=$(aws secretsmanager get-secret-value \
  --secret-id "${redis_secret_arn}" \
  --region ${aws_region} \
  --query 'SecretString' \
  --output text | jq -r '.auth_token // empty')

# ── Pull images ───────────────────────────────────────────────────────────────
docker pull "${hids_image}"
docker pull "${hardening_image}"

# ── Start hids-agent ──────────────────────────────────────────────────────────
docker run -d \
  --name sentinel-hids-agent \
  --restart unless-stopped \
  --privileged \
  --network host \
  -e KAFKA_BOOTSTRAP_SERVERS="${kafka_bootstrap}" \
  -e REDIS_URL="rediss://${redis_address}:6379" \
  $${REDIS_AUTH:+-e REDIS_PASSWORD="$$REDIS_AUTH"} \
  -e FIM_PATHS="/etc/passwd,/etc/shadow,/etc/sudoers,/etc/ssh/sshd_config" \
  -v /etc:/host/etc:ro \
  -v /var/log:/host/var/log:ro \
  -v /proc:/host/proc:ro \
  "${hids_image}"

# ── Start hardening-service ───────────────────────────────────────────────────
docker run -d \
  --name sentinel-hardening-service \
  --restart unless-stopped \
  --privileged \
  -e KAFKA_BOOTSTRAP_SERVERS="${kafka_bootstrap}" \
  -e REDIS_URL="rediss://${redis_address}:6379" \
  $${REDIS_AUTH:+-e REDIS_PASSWORD="$$REDIS_AUTH"} \
  -v /etc:/host/etc:rw \
  -v /proc:/host/proc:ro \
  "${hardening_image}"

# ── Configure CloudWatch agent for container logs ─────────────────────────────
dnf install -y amazon-cloudwatch-agent
cat > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json <<'CWCONFIG'
{
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {
            "file_path": "/var/log/sentinel-bootstrap.log",
            "log_group_name": "/sentinel/${environment}/host-agents/bootstrap",
            "log_stream_name": "{instance_id}"
          }
        ]
      }
    }
  }
}
CWCONFIG
systemctl enable --now amazon-cloudwatch-agent

echo "=== SENTINEL Host Agent Bootstrap complete ==="
