#!/usr/bin/env bash
set -euo pipefail
###############################################################################
# SENTINEL Training - Run on EC2 after dataset download (and optional GPU upgrade).
# Installs CUDA/deps if needed, then runs full training with GPU.
###############################################################################

PROJECT_DIR="${HOME}/sentinel"
VENV_DIR="${HOME}/sentinel-venv"
DATA_PATH="${PROJECT_DIR}/sentinel-core/training/datasets/data"
OUTPUT_PATH="${PROJECT_DIR}/sentinel-core/backend/ai-engine/trained_models"
DATASET="${SENTINEL_DATASET:-cicids2018}"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

# Use GPU if nvidia-smi works, else CPU
if command -v nvidia-smi &>/dev/null && nvidia-smi &>/dev/null; then
    DEVICE="cuda"
    log "GPU detected: $(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null || true)"
else
    DEVICE="cpu"
    log "No GPU detected; using CPU."
fi

# Ensure we're in project and venv is active
cd "${PROJECT_DIR}/sentinel-core"
if [ -f "${VENV_DIR}/bin/activate" ]; then
    source "${VENV_DIR}/bin/activate"
else
    log "ERROR: venv not found at ${VENV_DIR}. Run: bash sentinel-core/training/ec2-setup.sh"
    exit 1
fi

# Install CUDA-enabled PyTorch if we have GPU but torch is CPU-only
if [ "$DEVICE" = "cuda" ]; then
    if ! python -c "import torch; exit(0 if torch.cuda.is_available() else 1)" 2>/dev/null; then
        log "Installing PyTorch with CUDA support..."
        pip install --force-reinstall torch==2.2.2+cu121 torchvision==0.17.2+cu121 \
            --extra-index-url https://download.pytorch.org/whl/cu121
    fi
fi

if [ ! -d "${DATA_PATH}" ] || [ -z "$(ls -A "${DATA_PATH}" 2>/dev/null)" ]; then
    log "ERROR: No data at ${DATA_PATH}. Run: bash sentinel-core/training/download_datasets.sh"
    exit 1
fi

log "Starting training: dataset=${DATASET} device=${DEVICE} output=${OUTPUT_PATH}"
python training/train_all.py \
    --data-path "${DATA_PATH}" \
    --dataset "${DATASET}" \
    --device "${DEVICE}" \
    --output-path "${OUTPUT_PATH}"

log "Training finished. Models in ${OUTPUT_PATH}"
