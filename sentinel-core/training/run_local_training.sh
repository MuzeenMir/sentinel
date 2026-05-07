#!/usr/bin/env bash
# =============================================================================
# SENTINEL Local Training Launcher
# Optimised for: RTX 3050 4GB VRAM · 16-core CPU · 14GB RAM
#
# Usage:
#   bash training/run_local_training.sh               # full pipeline, all datasets
#   bash training/run_local_training.sh --quick       # 500K rows, CPU-friendly test
#   bash training/run_local_training.sh --models xgboost isolation_forest
#   bash training/run_local_training.sh --dataset cicids2018
#   bash training/run_local_training.sh --resume      # continue after interruption
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
VENV_DIR="${SCRIPT_DIR}/.venv-training"
ENV_FILE="${SCRIPT_DIR}/.env.training"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
log()  { echo -e "${BLUE}[$(date +%H:%M:%S)]${NC} $*"; }
ok()   { echo -e "${GREEN}[$(date +%H:%M:%S)]${NC} ✓ $*"; }
warn() { echo -e "${YELLOW}[$(date +%H:%M:%S)]${NC} ⚠ $*"; }
err()  { echo -e "${RED}[$(date +%H:%M:%S)]${NC} ✗ $*"; exit 1; }

# ── Load .env.training if present ────────────────────────────────────────────
if [[ -f "${ENV_FILE}" ]]; then
    # shellcheck disable=SC2046
    export $(grep -v '^#' "${ENV_FILE}" | grep -v '^$' | xargs)
fi

# ── Defaults (overridable by env or CLI flags) ────────────────────────────────
DATASET="${SENTINEL_DATASET:-cicids2018,cicids2017,unsw_nb15}"
DATA_PATH="${SENTINEL_DATA_PATH:-${SCRIPT_DIR}/datasets/data}"
OUTPUT_PATH="${SENTINEL_OUTPUT_PATH:-${REPO_ROOT}/backend/ai-engine/trained_models}"
DEVICE="${SENTINEL_TRAINING_DEVICE:-cpu}"
MAX_ROWS="${SENTINEL_MAX_ROWS:-}"
MODELS=""
FORCE=""

# ── Parse CLI flags ───────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case $1 in
        --quick)
            MAX_ROWS=500000
            DATASET="cicids2018"
            DEVICE="cpu"
            MODELS="xgboost isolation_forest"
            warn "Quick mode: 500K rows, CIC-IDS-2018 only, CPU, XGBoost+IsoForest"
            shift ;;
        --dataset)
            DATASET="$2"; shift 2 ;;
        --models)
            shift
            MODELS=""
            while [[ $# -gt 0 && "${1:0:2}" != "--" ]]; do
                MODELS="${MODELS} ${1}"; shift
            done
            MODELS="${MODELS# }" ;;
        --max-rows)
            MAX_ROWS="$2"; shift 2 ;;
        --device)
            DEVICE="$2"; shift 2 ;;
        --output)
            OUTPUT_PATH="$2"; shift 2 ;;
        --resume)
            FORCE=""
            log "Resume mode: skipping already-completed models"
            shift ;;
        --force)
            FORCE="--force"
            warn "Force mode: will retrain all models from scratch"
            shift ;;
        --cpu)
            DEVICE="cpu"; shift ;;
        --gpu|--cuda)
            DEVICE="cuda"; shift ;;
        --help|-h)
            sed -n '2,18p' "$0"; exit 0 ;;
        *)
            err "Unknown flag: $1" ;;
    esac
done

# ── Resolve Python interpreter ────────────────────────────────────────────────
if [[ -x "${VENV_DIR}/bin/python" ]]; then
    PYTHON="${VENV_DIR}/bin/python"
    log "Using training venv: ${VENV_DIR}"
elif [[ -x "${REPO_ROOT}/sentinel-core/.venv/bin/python" ]]; then
    PYTHON="${REPO_ROOT}/sentinel-core/.venv/bin/python"
    warn "Training venv not found — using project venv. Run setup_training_env.sh first."
else
    PYTHON=$(command -v python3 || command -v python)
    warn "No venv found — using system Python at ${PYTHON}"
fi

# ── Check GPU availability ────────────────────────────────────────────────────
if [[ "${DEVICE}" == "cuda" ]]; then
    if ! command -v nvidia-smi &>/dev/null; then
        warn "nvidia-smi not found — falling back to CPU"
        DEVICE="cpu"
    else
        GPU_MEM=$(nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits 2>/dev/null | head -1 || echo "0")
        log "GPU detected: $(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | head -1) (${GPU_MEM} MB)"

        # RTX 3050 has 4096 MB — set conservative memory limits
        if [[ "${GPU_MEM}" -le 4096 ]]; then
            export PYTORCH_CUDA_ALLOC_CONF="max_split_size_mb:512,expandable_segments:True"
            warn "4GB GPU detected — applying conservative memory settings"
        fi
    fi
fi

# ── Verify datasets ───────────────────────────────────────────────────────────
log "Verifying datasets..."
IFS=',' read -ra DS_LIST <<< "${DATASET}"
for ds in "${DS_LIST[@]}"; do
    ds_dir="${DATA_PATH}/${ds}"
    if [[ ! -d "${ds_dir}" ]]; then
        warn "Dataset directory not found: ${ds_dir}"
    else
        n_csv=$(find "${ds_dir}" -name "*.csv" 2>/dev/null | wc -l)
        size=$(du -sh "${ds_dir}" 2>/dev/null | cut -f1 || echo "?")
        log "  ${ds}: ${n_csv} CSV files (${size})"
        if [[ "${n_csv}" -eq 0 ]]; then
            warn "  → No CSV files found. Run: python training/download_datasets.py --datasets ${ds}"
        fi
    fi
done

# ── Show training plan ────────────────────────────────────────────────────────
log ""
log "═══════════════════════════════════════════════"
log "  SENTINEL Training Plan"
log "═══════════════════════════════════════════════"
log "  Dataset    : ${DATASET}"
log "  Device     : ${DEVICE}"
log "  Max rows   : ${MAX_ROWS:-unlimited}"
log "  Models     : ${MODELS:-all}"
log "  Output     : ${OUTPUT_PATH}"
log "  Python     : ${PYTHON}"
log "═══════════════════════════════════════════════"
log ""

mkdir -p "${OUTPUT_PATH}"

# ── Build train_all.py arguments ──────────────────────────────────────────────
ARGS=(
    "${SCRIPT_DIR}/train_all.py"
    "--data-path" "${DATA_PATH}"
    "--dataset"   "${DATASET}"
    "--device"    "${DEVICE}"
    "--output-path" "${OUTPUT_PATH}"
)

[[ -n "${MAX_ROWS}" ]]      && ARGS+=("--max-rows" "${MAX_ROWS}")
[[ -n "${MODELS}" ]]        && ARGS+=("--models"   ${MODELS})
[[ -n "${FORCE}" ]]         && ARGS+=("--force")

# ── Run with memory monitoring ────────────────────────────────────────────────
START_TIME=$(date +%s)

log "Starting training pipeline..."
"${PYTHON}" "${ARGS[@]}"

END_TIME=$(date +%s)
ELAPSED=$(( END_TIME - START_TIME ))
MINUTES=$(( ELAPSED / 60 ))
SECONDS=$(( ELAPSED % 60 ))

ok ""
ok "═══════════════════════════════════════════════"
ok "  Training complete in ${MINUTES}m ${SECONDS}s"
ok "═══════════════════════════════════════════════"
ok "  Models saved to: ${OUTPUT_PATH}"
ok ""

# ── Show training report if present ──────────────────────────────────────────
REPORT="${OUTPUT_PATH}/training_report.json"
if [[ -f "${REPORT}" ]]; then
    log "Training report:"
    "${PYTHON}" - <<PYEOF
import json, sys
try:
    with open("${REPORT}") as f:
        r = json.load(f)
    print(f"  Dataset    : {r.get('dataset')}")
    print(f"  Device     : {r.get('device')}")
    print(f"  Total time : {r.get('total_time_seconds', 0) / 60:.1f} min")
    print(f"  Models     : {', '.join(r.get('models_trained', []))}")
    print()
    for name, m in r.get("metrics", {}).items():
        if isinstance(m, dict) and not m.get("error") and not m.get("skipped"):
            kv = {k: (f"{v:.4f}" if isinstance(v, float) else v)
                  for k, v in m.items() if k != "training_time_seconds"}
            print(f"  {name:20s}: {kv}")
except Exception as e:
    print(f"  Could not parse report: {e}")
PYEOF
fi
