#!/usr/bin/env bash
# =============================================================================
# SENTINEL Platform — Development Install Script
# =============================================================================
# Sets up the full development environment on a fresh Linux/macOS machine:
#   • Checks system prerequisites (Docker, Node.js, Python)
#   • Creates Python venvs for every backend service, training, Flink, & SDK
#   • Installs npm dependencies for the admin console frontend
#   • Generates a .env with randomised secrets from .env.example
# =============================================================================

set -euo pipefail

# ─── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ─── Helpers ──────────────────────────────────────────────────────────────────
info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
header()  { echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════${NC}"; \
            echo -e "${BOLD}${CYAN}  $*${NC}"; \
            echo -e "${BOLD}${CYAN}══════════════════════════════════════════${NC}"; }

ERRORS=()
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ─── Argument parsing ─────────────────────────────────────────────────────────
SKIP_HEAVY=false       # skip ai-engine / drl-engine / xai-service venvs (PyTorch is huge)
SKIP_FRONTEND=false
SKIP_VENVS=false
NO_COLOR=false

for arg in "$@"; do
  case $arg in
    --skip-heavy)    SKIP_HEAVY=true ;;
    --skip-frontend) SKIP_FRONTEND=true ;;
    --skip-venvs)    SKIP_VENVS=true ;;
    --no-color)      NO_COLOR=true ;;
    -h|--help)
      echo "Usage: $0 [options]"
      echo ""
      echo "Options:"
      echo "  --skip-heavy     Skip PyTorch-heavy venvs (ai-engine, drl-engine, xai-service)"
      echo "  --skip-frontend  Skip npm install for admin console"
      echo "  --skip-venvs     Skip all Python venv creation (only check system deps + .env)"
      echo "  --no-color       Disable colour output"
      echo "  -h, --help       Show this help"
      exit 0
      ;;
  esac
done

if $NO_COLOR; then
  RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; BOLD=''; NC=''
fi

# ─── Summary tracking ─────────────────────────────────────────────────────────
VENVS_CREATED=()
VENVS_UPDATED=()
VENVS_SKIPPED=()

# =============================================================================
# 1. SYSTEM PREREQUISITES
# =============================================================================
header "1 / 6  Checking system prerequisites"

# ── Python 3.10+ ──────────────────────────────────────────────────────────────
PYTHON_BIN=""
for candidate in python3.13 python3.12 python3.11 python3.10 python3; do
  if command -v "$candidate" &>/dev/null; then
    ver=$("$candidate" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    major=${ver%%.*}; minor=${ver##*.}
    if [[ $major -ge 3 && $minor -ge 10 ]]; then
      PYTHON_BIN="$candidate"
      success "Python $ver found  ($PYTHON_BIN)"
      break
    fi
  fi
done
if [[ -z "$PYTHON_BIN" ]]; then
  error "Python 3.10+ is required but not found."
  echo "  Ubuntu/Debian:  sudo apt install python3.12 python3.12-venv python3.12-dev"
  echo "  macOS:          brew install python@3.12"
  ERRORS+=("Python 3.10+ not found")
fi

# ── pip ───────────────────────────────────────────────────────────────────────
if [[ -n "$PYTHON_BIN" ]]; then
  if "$PYTHON_BIN" -m pip --version &>/dev/null; then
    success "pip found"
  else
    warn "pip not available for $PYTHON_BIN"
    echo "  Ubuntu/Debian:  sudo apt install python3-pip"
    ERRORS+=("pip not found for $PYTHON_BIN")
  fi
fi

# ── python3-venv / ensurepip ──────────────────────────────────────────────────
if [[ -n "$PYTHON_BIN" ]]; then
  if "$PYTHON_BIN" -m venv --help &>/dev/null; then
    success "python3-venv module found"
  else
    error "python3-venv module is missing."
    echo "  Ubuntu/Debian:  sudo apt install python3-venv  (or python3.12-venv)"
    ERRORS+=("python3-venv not found")
  fi
fi

# ── Docker ────────────────────────────────────────────────────────────────────
if command -v docker &>/dev/null; then
  DOCKER_VER=$(docker --version 2>/dev/null | grep -oP '[\d.]+' | head -1)
  success "Docker $DOCKER_VER found"
  # Check daemon is running
  if ! docker info &>/dev/null; then
    warn "Docker daemon is not running — start it before running 'docker compose up'."
  fi
else
  warn "Docker not found. The full stack runs via Docker Compose."
  echo "  Install: https://docs.docker.com/engine/install/"
fi

# ── Docker Compose ────────────────────────────────────────────────────────────
if docker compose version &>/dev/null 2>&1; then
  DC_VER=$(docker compose version --short 2>/dev/null || echo "v2+")
  success "Docker Compose $DC_VER found (plugin)"
elif command -v docker-compose &>/dev/null; then
  success "docker-compose found (standalone)"
  warn "Prefer Docker Compose v2 plugin (docker compose) over standalone docker-compose."
else
  warn "Docker Compose not found."
  echo "  Install: sudo apt install docker-compose-plugin  (or via Docker Desktop)"
fi

# ── Node.js 18+ ───────────────────────────────────────────────────────────────
NODE_BIN=""
if command -v node &>/dev/null; then
  NODE_VER=$(node --version | tr -d 'v')
  NODE_MAJOR=${NODE_VER%%.*}
  if [[ $NODE_MAJOR -ge 18 ]]; then
    NODE_BIN="node"
    success "Node.js v$NODE_VER found"
  else
    warn "Node.js v$NODE_VER found but v18+ is required."
    echo "  Install via nvm: https://github.com/nvm-sh/nvm"
    echo "  Or: sudo apt install nodejs  (ensure version ≥ 18)"
  fi
else
  warn "Node.js not found — required for the admin console frontend."
  echo "  Install via nvm: https://github.com/nvm-sh/nvm"
fi

# ── npm ───────────────────────────────────────────────────────────────────────
if [[ -n "$NODE_BIN" ]]; then
  if command -v npm &>/dev/null; then
    NPM_VER=$(npm --version)
    success "npm v$NPM_VER found"
  else
    warn "npm not found."
    ERRORS+=("npm not found")
  fi
fi

# ── git ───────────────────────────────────────────────────────────────────────
if command -v git &>/dev/null; then
  success "git $(git --version | awk '{print $3}') found"
else
  warn "git not found — needed for version control."
fi

# Abort early if critical tools are missing
if [[ ${#ERRORS[@]} -gt 0 ]]; then
  echo ""
  error "Critical prerequisites are missing:"
  for e in "${ERRORS[@]}"; do echo "  • $e"; done
  echo ""
  echo "Please install the above and re-run this script."
  exit 1
fi

# =============================================================================
# 2. ENVIRONMENT FILE
# =============================================================================
header "2 / 6  Setting up .env"

ENV_FILE="$SCRIPT_DIR/.env"
ENV_EXAMPLE="$SCRIPT_DIR/.env.example"

gen_secret() {
  # 64 hex characters — uses openssl if available, else /dev/urandom
  if command -v openssl &>/dev/null; then
    openssl rand -hex 32
  else
    tr -dc 'a-f0-9' </dev/urandom | head -c 64
  fi
}

gen_password() {
  # 24 alphanumeric characters
  if command -v openssl &>/dev/null; then
    openssl rand -base64 18 | tr -dc 'a-zA-Z0-9' | head -c 24
  else
    tr -dc 'a-zA-Z0-9' </dev/urandom | head -c 24
  fi
}

if [[ ! -f "$ENV_FILE" ]]; then
  info "Creating .env from .env.example with generated secrets..."
  cp "$ENV_EXAMPLE" "$ENV_FILE"

  # Replace placeholder secrets with real random values
  sed -i "s|change-this-to-a-random-64-char-string|$(gen_secret)|g" "$ENV_FILE"
  sed -i "s|change-this-db-password|$(gen_password)|g"              "$ENV_FILE"
  sed -i "s|change-this-grafana-password|$(gen_password)|g"         "$ENV_FILE"
  sed -i "s|generate-a-long-random-token|$(gen_secret)|g"           "$ENV_FILE"

  success ".env created with randomised secrets"
  warn "Review $ENV_FILE and update ADMIN_PASSWORD, ADMIN_EMAIL, and SMTP settings."
else
  success ".env already exists — skipping (delete it and re-run to regenerate)"
fi

# =============================================================================
# 3. PYTHON VIRTUAL ENVIRONMENTS — BACKEND SERVICES
# =============================================================================
header "3 / 6  Setting up Python virtual environments (backend services)"

BACKEND_DIR="$SCRIPT_DIR/backend"

# Heavy services that pull in PyTorch (warn user if --skip-heavy not set)
HEAVY_SERVICES=("ai-engine" "drl-engine" "xai-service")

create_venv() {
  local service_path="$1"
  local service_name
  service_name="$(basename "$service_path")"
  local req_file="$service_path/requirements.txt"
  local venv_dir="$service_path/.venv"

  if [[ ! -f "$req_file" ]]; then
    warn "[$service_name] No requirements.txt — skipping"
    VENVS_SKIPPED+=("$service_name")
    return
  fi

  # Heavy service guard
  if $SKIP_HEAVY; then
    for heavy in "${HEAVY_SERVICES[@]}"; do
      if [[ "$service_name" == "$heavy" ]]; then
        warn "[$service_name] Skipped (--skip-heavy)"
        VENVS_SKIPPED+=("$service_name (heavy — PyTorch)")
        return
      fi
    done
  fi

  if [[ -d "$venv_dir" ]]; then
    info "[$service_name] venv exists — updating packages..."
    "$venv_dir/bin/pip" install --quiet --upgrade pip
    "$venv_dir/bin/pip" install --quiet -r "$req_file"
    VENVS_UPDATED+=("$service_name")
  else
    info "[$service_name] Creating venv and installing packages..."
    "$PYTHON_BIN" -m venv "$venv_dir"
    "$venv_dir/bin/pip" install --quiet --upgrade pip
    "$venv_dir/bin/pip" install --quiet -r "$req_file"
    VENVS_CREATED+=("$service_name")
  fi
  success "[$service_name] Ready  →  $venv_dir"
}

if $SKIP_VENVS; then
  warn "Skipping all Python venv setup (--skip-venvs)"
else
  if $SKIP_HEAVY; then
    warn "Skipping heavy services (ai-engine, drl-engine, xai-service) — use --skip-heavy=false to include them"
  fi

  # Iterate over all backend service directories that have a requirements.txt
  while IFS= read -r req; do
    service_dir="$(dirname "$req")"
    # Skip nested test requirements
    if [[ "$service_dir" == *"/tests/"* ]]; then
      warn "Skipping test-only requirements: $req"
      continue
    fi
    create_venv "$service_dir"
  done < <(find "$BACKEND_DIR" -maxdepth 2 -name "requirements.txt" | sort)
fi

# =============================================================================
# 4. PYTHON VIRTUAL ENVIRONMENTS — TRAINING, FLINK & SDK
# =============================================================================
header "4 / 6  Setting up Python virtual environments (training / flink / sdk)"

if ! $SKIP_VENVS; then

  # ── Training pipeline ───────────────────────────────────────────────────────
  TRAINING_DIR="$SCRIPT_DIR/training"
  if [[ -f "$TRAINING_DIR/requirements.txt" ]]; then
    VENV_DIR="$TRAINING_DIR/.venv"
    if [[ -d "$VENV_DIR" ]]; then
      info "[training] venv exists — updating..."
      "$VENV_DIR/bin/pip" install --quiet --upgrade pip
      "$VENV_DIR/bin/pip" install --quiet -r "$TRAINING_DIR/requirements.txt"
      VENVS_UPDATED+=("training")
    else
      info "[training] Creating venv..."
      "$PYTHON_BIN" -m venv "$VENV_DIR"
      "$VENV_DIR/bin/pip" install --quiet --upgrade pip
      "$VENV_DIR/bin/pip" install --quiet -r "$TRAINING_DIR/requirements.txt"
      VENVS_CREATED+=("training")
    fi
    success "[training] Ready  →  $VENV_DIR"
    warn "[training] PyTorch (GPU) not installed — run training/setup_training_env.sh for CUDA-aware install."
  else
    warn "[training] No requirements.txt found at $TRAINING_DIR"
  fi

  # ── Apache Flink jobs ───────────────────────────────────────────────────────
  FLINK_DIR="$SCRIPT_DIR/stream-processing/flink-jobs"
  if [[ -f "$FLINK_DIR/requirements.txt" ]]; then
    VENV_DIR="$FLINK_DIR/.venv"
    if [[ -d "$VENV_DIR" ]]; then
      info "[flink-jobs] venv exists — updating..."
      "$VENV_DIR/bin/pip" install --quiet --upgrade pip
      "$VENV_DIR/bin/pip" install --quiet -r "$FLINK_DIR/requirements.txt"
      VENVS_UPDATED+=("flink-jobs")
    else
      info "[flink-jobs] Creating venv..."
      "$PYTHON_BIN" -m venv "$VENV_DIR"
      "$VENV_DIR/bin/pip" install --quiet --upgrade pip
      "$VENV_DIR/bin/pip" install --quiet -r "$FLINK_DIR/requirements.txt"
      VENVS_CREATED+=("flink-jobs")
    fi
    success "[flink-jobs] Ready  →  $VENV_DIR"
  else
    warn "[flink-jobs] No requirements.txt found at $FLINK_DIR"
  fi

  # ── Python SDK ──────────────────────────────────────────────────────────────
  SDK_DIR="$SCRIPT_DIR/sdk"
  if [[ -f "$SDK_DIR/pyproject.toml" ]]; then
    VENV_DIR="$SDK_DIR/.venv"
    if [[ -d "$VENV_DIR" ]]; then
      info "[sdk] venv exists — updating..."
      "$VENV_DIR/bin/pip" install --quiet --upgrade pip
      "$VENV_DIR/bin/pip" install --quiet -e "$SDK_DIR[dev]" 2>/dev/null || \
        "$VENV_DIR/bin/pip" install --quiet -e "$SDK_DIR"
      VENVS_UPDATED+=("sdk")
    else
      info "[sdk] Creating venv and installing in editable mode..."
      "$PYTHON_BIN" -m venv "$VENV_DIR"
      "$VENV_DIR/bin/pip" install --quiet --upgrade pip
      "$VENV_DIR/bin/pip" install --quiet -e "$SDK_DIR[dev]" 2>/dev/null || \
        "$VENV_DIR/bin/pip" install --quiet -e "$SDK_DIR"
      VENVS_CREATED+=("sdk")
    fi
    success "[sdk] Ready  →  $VENV_DIR"
  else
    warn "[sdk] No pyproject.toml found at $SDK_DIR"
  fi

fi  # end SKIP_VENVS

# =============================================================================
# 5. FRONTEND — npm install
# =============================================================================
header "5 / 6  Setting up frontend (admin console)"

FRONTEND_DIR="$SCRIPT_DIR/frontend/admin-console"

if $SKIP_FRONTEND; then
  warn "Skipping frontend setup (--skip-frontend)"
elif [[ -z "$NODE_BIN" ]]; then
  warn "Node.js not found — skipping frontend setup"
elif [[ ! -f "$FRONTEND_DIR/package.json" ]]; then
  warn "package.json not found at $FRONTEND_DIR — skipping"
else
  info "[admin-console] Running npm install..."
  npm --prefix "$FRONTEND_DIR" install --prefer-offline --no-fund --no-audit 2>&1 | \
    grep -v "^npm warn" || true
  success "[admin-console] npm packages installed"
fi

# =============================================================================
# 6. DOCKER IMAGES (optional pull)
# =============================================================================
header "6 / 6  Docker images"

if command -v docker &>/dev/null && docker info &>/dev/null; then
  info "Pulling infrastructure images (postgres, redis, kafka…)"
  # Pull only the infrastructure / third-party images to warm the Docker cache
  # — build of sentinel services happens via 'docker compose build'
  docker compose --project-directory "$SCRIPT_DIR" pull \
    postgres redis zookeeper kafka elasticsearch 2>&1 | \
    grep -E '(Pulling|pulled|already|error)' || true
  success "Infrastructure images pulled"
else
  warn "Docker daemon not running — skipping image pull."
  info "Run 'docker compose pull' manually when Docker is available."
fi

# =============================================================================
# SUMMARY
# =============================================================================
echo ""
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║          SENTINEL — Setup Complete                  ║${NC}"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""

if [[ ${#VENVS_CREATED[@]} -gt 0 ]]; then
  echo -e "${GREEN}  Venvs created (${#VENVS_CREATED[@]}):${NC}"
  for v in "${VENVS_CREATED[@]}"; do echo "    + $v"; done
fi
if [[ ${#VENVS_UPDATED[@]} -gt 0 ]]; then
  echo -e "${CYAN}  Venvs updated (${#VENVS_UPDATED[@]}):${NC}"
  for v in "${VENVS_UPDATED[@]}"; do echo "    ↻ $v"; done
fi
if [[ ${#VENVS_SKIPPED[@]} -gt 0 ]]; then
  echo -e "${YELLOW}  Venvs skipped (${#VENVS_SKIPPED[@]}):${NC}"
  for v in "${VENVS_SKIPPED[@]}"; do echo "    - $v"; done
fi

echo ""
echo -e "${BOLD}Next steps:${NC}"
echo ""
echo -e "  1.  Review / edit ${CYAN}.env${NC} (ADMIN_PASSWORD, ADMIN_EMAIL, SMTP settings)"
echo ""
echo -e "  2.  Start the full stack:"
echo -e "      ${CYAN}docker compose up -d${NC}"
echo ""
echo -e "  3.  Or start only infrastructure + run a service locally:"
echo -e "      ${CYAN}docker compose up -d postgres redis kafka${NC}"
echo -e "      ${CYAN}cd backend/auth-service${NC}"
echo -e "      ${CYAN}source .venv/bin/activate && python app.py${NC}"
echo ""
echo -e "  4.  Frontend dev server:"
echo -e "      ${CYAN}cd frontend/admin-console && npm run dev${NC}"
echo ""
echo -e "  5.  Training (GPU, optional):"
echo -e "      ${CYAN}cd training && bash setup_training_env.sh${NC}"
echo ""
echo -e "  Access points after 'docker compose up':"
echo -e "    Admin console →  ${CYAN}http://localhost:3000${NC}"
echo -e "    API gateway   →  ${CYAN}http://localhost:8080${NC}"
echo -e "    API docs      →  ${CYAN}http://localhost:8080/docs${NC}"
echo -e "    Grafana       →  ${CYAN}http://localhost:3001${NC}"
echo -e "    Prometheus    →  ${CYAN}http://localhost:9090${NC}"
echo -e "    Kibana        →  ${CYAN}http://localhost:5601${NC}"
echo ""
