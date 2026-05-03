#!/usr/bin/env bash
# Add 48GB swap on EC2 to satisfy training memory needs. Run once on the instance: sudo bash ec2-add-swap.sh
set -euo pipefail
SWAP_SIZE_GB="${SWAP_SIZE_GB:-48}"
SWAP_FILE="${SWAP_FILE:-/swapfile}"

echo "Creating ${SWAP_SIZE_GB}GB swap at ${SWAP_FILE}..."
sudo fallocate -l "${SWAP_SIZE_GB}G" "${SWAP_FILE}"
sudo chmod 600 "${SWAP_FILE}"
sudo mkswap "${SWAP_FILE}"
sudo swapon "${SWAP_FILE}"
echo "${SWAP_FILE} none swap sw 0 0" | sudo tee -a /etc/fstab
echo "Swap enabled. Current memory:"
free -h
