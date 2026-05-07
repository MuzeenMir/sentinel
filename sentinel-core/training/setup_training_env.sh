#!/usr/bin/env bash
# =============================================================================
# SENTINEL Training Environment Setup
# Sets up a dedicated Python venv for local ML training.
# Hardware target: RTX 3050 (4GB VRAM), 16-core CPU, 14GB RAM
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
VENV_DIR="${SCRIPT_DIR}/.venv-training"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()  { echo -e "${BLUE}[SENTINEL]${NC} $*"; }
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[ERR]${NC} $*"; }

log "============================================="
log "  SENTINEL Local Training Environment Setup"
log "============================================="

# ── Check Python 3.10+ ───────────────────────────────────────────────────────
PYTHON=$(command -v python3.12 || command -v python3.11 || command -v python3.10 || command -v python3 || true)
if [[ -z "${PYTHON}" ]]; then
    err "Python 3.10+ is required. Install it and re-run."
    exit 1
fi
PY_VERSION=$("${PYTHON}" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
log "Using Python ${PY_VERSION} at ${PYTHON}"

# ── Create virtualenv ─────────────────────────────────────────────────────────
if [[ -d "${VENV_DIR}" ]]; then
    warn "Virtual env already exists at ${VENV_DIR}. Use --reinstall to rebuild."
    if [[ "${1:-}" == "--reinstall" ]]; then
        log "Removing existing venv..."
        rm -rf "${VENV_DIR}"
    fi
fi

if [[ ! -d "${VENV_DIR}" ]]; then
    log "Creating virtual environment at ${VENV_DIR}..."
    "${PYTHON}" -m venv "${VENV_DIR}"
fi

VENV_PYTHON="${VENV_DIR}/bin/python"
VENV_PIP="${VENV_DIR}/bin/pip"

# Upgrade pip/setuptools first
log "Upgrading pip and setuptools..."
"${VENV_PYTHON}" -m pip install --quiet --upgrade pip setuptools wheel

# ── Detect CUDA ───────────────────────────────────────────────────────────────
CUDA_VERSION=""
if command -v nvidia-smi &>/dev/null; then
    CUDA_VERSION=$(nvidia-smi --query-gpu=driver_version --format=csv,noheader 2>/dev/null | head -1 || true)
    log "NVIDIA driver detected: ${CUDA_VERSION}"

    # Detect CUDA toolkit version for PyTorch wheel selection
    if command -v nvcc &>/dev/null; then
        CUDA_TOOLKIT=$(nvcc --version 2>/dev/null | grep "release" | awk '{print $6}' | cut -d',' -f1 | sed 's/V//')
        log "CUDA toolkit: ${CUDA_TOOLKIT}"
    fi

    # RTX 3050 is Ampere (sm_86) — CUDA 12.4 wheels work with driver 590+
    TORCH_INDEX_URL="https://download.pytorch.org/whl/cu124"
    log "Installing PyTorch with CUDA 12.4 support..."
    "${VENV_PIP}" install --quiet \
        torch>=2.3 \
        torchvision>=0.18 \
        --index-url "${TORCH_INDEX_URL}"
else
    warn "No NVIDIA GPU detected — installing CPU-only PyTorch."
    TORCH_INDEX_URL="https://download.pytorch.org/whl/cpu"
    "${VENV_PIP}" install --quiet torch torchvision --index-url "${TORCH_INDEX_URL}"
fi

# ── Install training requirements ─────────────────────────────────────────────
log "Installing training requirements..."
"${VENV_PIP}" install --quiet -r "${SCRIPT_DIR}/requirements.txt"

# ── Verify GPU access in PyTorch ──────────────────────────────────────────────
log "Verifying PyTorch GPU access..."
"${VENV_PYTHON}" - <<'PYCHECK'
import torch
print(f"  PyTorch version : {torch.__version__}")
print(f"  CUDA available  : {torch.cuda.is_available()}")
if torch.cuda.is_available():
    print(f"  GPU name        : {torch.cuda.get_device_name(0)}")
    print(f"  VRAM            : {torch.cuda.get_device_properties(0).total_memory / 1e9:.1f} GB")
    print(f"  CUDA version    : {torch.version.cuda}")
else:
    print("  Training will run on CPU (slower)")
PYCHECK

# ── Verify XGBoost GPU ────────────────────────────────────────────────────────
log "Verifying XGBoost GPU access..."
"${VENV_PYTHON}" - <<'PYCHECK'
import xgboost as xgb
import numpy as np
try:
    X = np.random.rand(100, 10).astype(np.float32)
    y = np.random.randint(0, 2, 100)
    dtrain = xgb.DMatrix(X, label=y)
    params = {"tree_method": "hist", "device": "cuda", "max_depth": 3,
              "objective": "binary:logistic", "eval_metric": "logloss"}
    xgb.train(params, dtrain, num_boost_round=5, verbose_eval=False)
    print(f"  XGBoost version : {xgb.__version__}  CUDA OK")
except Exception as e:
    print(f"  XGBoost version : {xgb.__version__}  (CPU only: {e})")
PYCHECK

# ── Verify Stable-Baselines3 ─────────────────────────────────────────────────
log "Verifying Stable-Baselines3..."
"${VENV_PYTHON}" - <<'PYCHECK'
import stable_baselines3 as sb3
import gymnasium as gym
print(f"  Stable-Baselines3: {sb3.__version__}")
print(f"  Gymnasium        : {gym.__version__}")
PYCHECK

# ── Create training .env ──────────────────────────────────────────────────────
ENV_FILE="${SCRIPT_DIR}/.env.training"
if [[ ! -f "${ENV_FILE}" ]]; then
    log "Creating ${ENV_FILE}..."
    cat > "${ENV_FILE}" <<EOF
# SENTINEL Training Environment Variables
SENTINEL_TRAINING_DEVICE=cuda
SENTINEL_DATA_PATH=${SCRIPT_DIR}/datasets/data
SENTINEL_OUTPUT_PATH=${REPO_ROOT}/backend/ai-engine/trained_models
SENTINEL_MAX_ROWS=
SENTINEL_DATASET=cicids2018,cicids2017,unsw_nb15

# RAM-friendly batch sizes for 14GB system
SENTINEL_BATCH_SIZE_AUTOENCODER=256
SENTINEL_BATCH_SIZE_LSTM=64

# GPU memory tuning for RTX 3050 (4GB)
PYTORCH_CUDA_ALLOC_CONF=max_split_size_mb:512
EOF
    ok "Created ${ENV_FILE}"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
ok "============================================="
ok "  Training environment ready!"
ok "============================================="
echo ""
echo "  Activate:  source ${VENV_DIR}/bin/activate"
echo "  Train all: bash ${SCRIPT_DIR}/run_local_training.sh"
echo "  Datasets:  python ${SCRIPT_DIR}/download_datasets.py --all"
echo ""
