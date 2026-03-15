#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# SENTINEL Training - Dataset Downloader
#
# Downloads and prepares cybersecurity intrusion-detection datasets:
#   1. CSE-CIC-IDS2018  (AWS Open Data - free S3 transfer in us-east-1)
#   2. CIC-IDS2017       (UNB / mirror)
#   3. UNSW-NB15          (UNSW Canberra)
###############################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="${SCRIPT_DIR}/datasets/data"

log() { echo "[$(date '+%H:%M:%S')] $*"; }
section() { echo ""; log "═══ $* ═══"; }

# ── CIC-IDS2018 ──────────────────────────────────────────────────────────────
download_cicids2018() {
    section "CIC-IDS2018 (AWS Open Data)"
    local dest="${DATA_DIR}/cicids2018"
    mkdir -p "${dest}"

    if [ -f "${dest}/.complete" ]; then
        log "Already downloaded. Remove ${dest}/.complete to re-download."
        return
    fi

    log "Syncing from s3://cse-cic-ids2018/ ..."
    log "Only downloading processed CSV files for ML training."

    aws s3 sync \
        "s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/" \
        "${dest}/" \
        --no-sign-request \
        --exclude "*" \
        --include "*.csv" \
        --region us-east-1

    local count
    count=$(find "${dest}" -name "*.csv" | wc -l)
    local size
    size=$(du -sh "${dest}" | cut -f1)
    log "Downloaded ${count} CSV files (${size})"

    touch "${dest}/.complete"
}

# ── CIC-IDS2017 ──────────────────────────────────────────────────────────────
download_cicids2017() {
    section "CIC-IDS2017"
    local dest="${DATA_DIR}/cicids2017"
    mkdir -p "${dest}"

    if [ -f "${dest}/.complete" ]; then
        log "Already downloaded. Remove ${dest}/.complete to re-download."
        return
    fi

    # The CIC-IDS2017 dataset is distributed as individual CSV files.
    # Primary source: UNB CIC website (requires manual download if this mirror is down).
    # Common mirror on Kaggle or direct URL.
    local base_url="https://iscxdownloads.cs.unb.ca/iscxdownloads/CIC-IDS-2017/GeneratedLabelledFlows"
    local files=(
        "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
        "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
        "Friday-WorkingHours-Morning.pcap_ISCX.csv"
        "Monday-WorkingHours.pcap_ISCX.csv"
        "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv"
        "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"
        "Tuesday-WorkingHours.pcap_ISCX.csv"
        "Wednesday-workingHours.pcap_ISCX.csv"
    )

    log "Downloading ${#files[@]} CSV files from UNB..."
    local failed=0
    for f in "${files[@]}"; do
        local encoded
        encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$f'))")
        if [ -f "${dest}/${f}" ]; then
            log "  [skip] ${f}"
            continue
        fi
        log "  [get]  ${f}"
        if ! wget -q --show-progress -O "${dest}/${f}" "${base_url}/${encoded}" 2>/dev/null; then
            log "  [WARN] Direct download failed for ${f}."
            log "         Try Kaggle: https://www.kaggle.com/datasets/cicdataset/cicids2017"
            ((failed++)) || true
        fi
    done

    if [ "$failed" -gt 0 ]; then
        log "WARNING: ${failed} file(s) could not be downloaded automatically."
        log "Manual download instructions:"
        log "  1. Visit https://www.unb.ca/cic/datasets/ids-2017.html"
        log "  2. Download the 'MachineLearningCVE' CSV files"
        log "  3. Place them in ${dest}/"
        log ""
        log "OR use Kaggle CLI:"
        log "  pip install kaggle"
        log "  kaggle datasets download -d cicdataset/cicids2017 -p ${dest}/ --unzip"
    else
        touch "${dest}/.complete"
    fi

    local size
    size=$(du -sh "${dest}" 2>/dev/null | cut -f1)
    log "CIC-IDS2017 directory: ${size}"
}

# ── UNSW-NB15 ────────────────────────────────────────────────────────────────
download_unsw_nb15() {
    section "UNSW-NB15"
    local dest="${DATA_DIR}/unsw_nb15"
    mkdir -p "${dest}"

    if [ -f "${dest}/.complete" ]; then
        log "Already downloaded. Remove ${dest}/.complete to re-download."
        return
    fi

    # UNSW-NB15 is available via direct download from the research site
    local base_url="https://unsw-my.sharepoint.com/:x:/g/personal"

    log "The UNSW-NB15 dataset requires manual download or Kaggle."
    log ""
    log "Option A - Kaggle (recommended):"
    log "  pip install kaggle"
    log "  kaggle datasets download -d mrwellsdavid/unsw-nb15 -p ${dest}/ --unzip"
    log ""
    log "Option B - Direct from UNSW:"
    log "  Visit: https://research.unsw.edu.au/projects/unsw-nb15-dataset"
    log "  Download the CSV files and place in: ${dest}/"
    log ""
    log "Required files:"
    log "  - UNSW-NB15_1.csv through UNSW-NB15_4.csv (training data)"
    log "  - UNSW_NB15_training-set.csv  (pre-split training set)"
    log "  - UNSW_NB15_testing-set.csv   (pre-split test set)"
    log "  - NUSW-NB15_features.csv      (feature descriptions)"

    # Attempt Kaggle download if kaggle CLI is available
    if command -v kaggle &>/dev/null; then
        log "Kaggle CLI found. Attempting download..."
        if kaggle datasets download -d mrwellsdavid/unsw-nb15 -p "${dest}/" --unzip 2>/dev/null; then
            touch "${dest}/.complete"
            local size
            size=$(du -sh "${dest}" | cut -f1)
            log "Downloaded UNSW-NB15 (${size})"
            return
        fi
        log "Kaggle download failed. Please configure kaggle API key."
    fi
}

# ── Manifest ──────────────────────────────────────────────────────────────────
create_manifest() {
    section "Creating dataset manifest"
    local manifest="${DATA_DIR}/MANIFEST.txt"

    {
        echo "SENTINEL Training Datasets"
        echo "Generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        echo "=========================================="
        echo ""

        for dataset_dir in "${DATA_DIR}"/*/; do
            local name
            name=$(basename "${dataset_dir}")
            local csv_count
            csv_count=$(find "${dataset_dir}" -name "*.csv" 2>/dev/null | wc -l)
            local size
            size=$(du -sh "${dataset_dir}" 2>/dev/null | cut -f1)
            local status="INCOMPLETE"
            [ -f "${dataset_dir}/.complete" ] && status="COMPLETE"

            echo "Dataset: ${name}"
            echo "  Status: ${status}"
            echo "  Files:  ${csv_count} CSV"
            echo "  Size:   ${size}"
            echo ""
        done

        echo "=========================================="
        echo "Total disk usage:"
        du -sh "${DATA_DIR}"
    } > "${manifest}"

    cat "${manifest}"
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    log "=== SENTINEL Dataset Downloader ==="
    log "Target directory: ${DATA_DIR}"
    log ""

    local dataset="${1:-all}"

    case "${dataset}" in
        cicids2018)  download_cicids2018 ;;
        cicids2017)  download_cicids2017 ;;
        unsw_nb15)   download_unsw_nb15 ;;
        all)
            download_cicids2018
            download_cicids2017
            download_unsw_nb15
            ;;
        *)
            echo "Usage: $0 [cicids2018|cicids2017|unsw_nb15|all]"
            exit 1
            ;;
    esac

    create_manifest

    log ""
    log "Dataset download complete. Next step:"
    log "  python training/train_all.py --data-path training/datasets/data --dataset cicids2018"
}

main "$@"
