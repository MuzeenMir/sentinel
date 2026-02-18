#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# SENTINEL Training - EC2 Instance Environment Setup
#
# Run this ON the EC2 instance after SSH.  Installs:
#   - System build dependencies
#   - Python 3.12 + venv
#   - NVIDIA driver + CUDA 12.1 (prepared for GPU upgrade)
#   - Project clone + Python deps + PyTorch w/ CUDA
###############################################################################

REPO_URL="${SENTINEL_REPO:-https://github.com/YOUR_ORG/sentinel.git}"
BRANCH="${SENTINEL_BRANCH:-main}"
PYTHON_VERSION="3.12"
CUDA_VERSION="12-1"
PROJECT_DIR="$HOME/sentinel"
VENV_DIR="$HOME/sentinel-venv"

log() { echo "[$(date '+%H:%M:%S')] $*"; }
section() { echo ""; log "═══ $* ═══"; }

# ── 1. System packages ───────────────────────────────────────────────────────
install_system_deps() {
    section "Installing system packages"
    sudo apt-get update -qq
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        build-essential gcc g++ make cmake \
        python3-dev python3-pip python3-venv \
        git curl wget unzip htop tmux \
        libgomp1 libssl-dev libffi-dev \
        software-properties-common

    # Add deadsnakes PPA for Python 3.12 if not already available
    if ! command -v "python${PYTHON_VERSION}" &>/dev/null; then
        sudo add-apt-repository -y ppa:deadsnakes/ppa
        sudo apt-get update -qq
        sudo apt-get install -y -qq \
            "python${PYTHON_VERSION}" \
            "python${PYTHON_VERSION}-venv" \
            "python${PYTHON_VERSION}-dev" \
            "python${PYTHON_VERSION}-distutils"
    fi

    log "Python $(python${PYTHON_VERSION} --version) installed."
}

# ── 2. NVIDIA driver + CUDA ──────────────────────────────────────────────────
install_nvidia_cuda() {
    section "Installing NVIDIA drivers and CUDA ${CUDA_VERSION}"

    if command -v nvidia-smi &>/dev/null; then
        log "NVIDIA driver already installed:"
        nvidia-smi --query-gpu=name,driver_version --format=csv,noheader || true
        return
    fi

    # Add NVIDIA CUDA repository
    local distro="ubuntu2404"
    local arch="x86_64"
    local keyring="/usr/share/keyrings/cuda-archive-keyring.gpg"

    wget -q "https://developer.download.nvidia.com/compute/cuda/repos/${distro}/${arch}/cuda-keyring_1.1-1_all.deb" \
        -O /tmp/cuda-keyring.deb
    sudo dpkg -i /tmp/cuda-keyring.deb
    rm /tmp/cuda-keyring.deb

    sudo apt-get update -qq
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        "cuda-toolkit-${CUDA_VERSION}" \
        cuda-drivers

    # Set up environment
    cat >> "$HOME/.bashrc" <<'EOF'
export PATH="/usr/local/cuda/bin:$PATH"
export LD_LIBRARY_PATH="/usr/local/cuda/lib64:${LD_LIBRARY_PATH:-}"
EOF
    export PATH="/usr/local/cuda/bin:$PATH"
    export LD_LIBRARY_PATH="/usr/local/cuda/lib64:${LD_LIBRARY_PATH:-}"

    log "CUDA toolkit installed. GPU will be available after switching to GPU instance type."
    log "Run 'nvidia-smi' after upgrading to g4dn.2xlarge to verify."
}

# ── 3. Clone project ─────────────────────────────────────────────────────────
clone_project() {
    section "Cloning SENTINEL project"

    if [ -d "${PROJECT_DIR}/.git" ]; then
        log "Project already cloned, pulling latest..."
        cd "${PROJECT_DIR}"
        git pull --ff-only
        cd -
        return
    fi

    git clone --branch "${BRANCH}" --depth 1 "${REPO_URL}" "${PROJECT_DIR}"
    log "Cloned to ${PROJECT_DIR}"
}

# ── 4. Python virtual environment + dependencies ─────────────────────────────
setup_python_env() {
    section "Setting up Python ${PYTHON_VERSION} virtual environment"

    "python${PYTHON_VERSION}" -m venv "${VENV_DIR}"
    source "${VENV_DIR}/bin/activate"

    pip install --upgrade pip setuptools wheel

    # Install training requirements (consolidated)
    if [ -f "${PROJECT_DIR}/sentinel-core/training/requirements.txt" ]; then
        pip install -r "${PROJECT_DIR}/sentinel-core/training/requirements.txt"
    else
        log "WARNING: training/requirements.txt not found, installing individual deps"
        pip install -r "${PROJECT_DIR}/sentinel-core/backend/ai-engine/requirements.txt"
        pip install -r "${PROJECT_DIR}/sentinel-core/backend/drl-engine/requirements.txt"
    fi

    # Install PyTorch with CUDA support (override the CPU-only version)
    pip install --force-reinstall \
        torch==2.1.0+cu121 \
        torchvision==0.16.0+cu121 \
        --extra-index-url https://download.pytorch.org/whl/cu121

    # Add venv activation to .bashrc
    if ! grep -q "sentinel-venv" "$HOME/.bashrc"; then
        echo "source ${VENV_DIR}/bin/activate" >> "$HOME/.bashrc"
    fi

    log "Python environment ready. Packages installed:"
    pip list --format=columns | head -30
}

# ── 5. Verify installation ───────────────────────────────────────────────────
verify() {
    section "Verifying installation"
    source "${VENV_DIR}/bin/activate"

    python -c "
import sys
print(f'Python:       {sys.version}')

import numpy as np
print(f'NumPy:        {np.__version__}')

import pandas as pd
print(f'Pandas:       {pd.__version__}')

import sklearn
print(f'scikit-learn: {sklearn.__version__}')

import xgboost
print(f'XGBoost:      {xgboost.__version__}')

import torch
print(f'PyTorch:      {torch.__version__}')
print(f'CUDA avail:   {torch.cuda.is_available()}')
if torch.cuda.is_available():
    print(f'GPU:          {torch.cuda.get_device_name(0)}')
    print(f'VRAM:         {torch.cuda.get_device_properties(0).total_mem / 1e9:.1f} GB')

import stable_baselines3
print(f'SB3:          {stable_baselines3.__version__}')
print()
print('All dependencies verified successfully.')
"

    log "Disk usage:"
    df -h / | tail -1

    log ""
    log "================================================"
    log " Setup complete!"
    log "================================================"
    log " Project:  ${PROJECT_DIR}"
    log " Venv:     ${VENV_DIR}"
    log ""
    log " Next steps:"
    log "   1. Download datasets:"
    log "      bash ${PROJECT_DIR}/sentinel-core/training/download_datasets.sh"
    log ""
    log "   2. Upgrade to GPU (from your LOCAL machine):"
    log "      See: training/ec2-provision.sh  (upgrade section)"
    log ""
    log "   3. Train models (after GPU upgrade):"
    log "      cd ${PROJECT_DIR}/sentinel-core"
    log "      python training/train_all.py \\"
    log "        --data-path training/datasets/data \\"
    log "        --dataset cicids2018 \\"
    log "        --device cuda"
    log "================================================"
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    log "=== SENTINEL EC2 Environment Setup ==="
    log "Instance type: $(curl -s http://169.254.169.254/latest/meta-data/instance-type 2>/dev/null || echo 'unknown')"
    log ""

    install_system_deps
    install_nvidia_cuda
    clone_project
    setup_python_env
    verify
}

main "$@"
