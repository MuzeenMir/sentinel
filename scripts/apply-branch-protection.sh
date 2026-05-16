#!/usr/bin/env bash
# apply-branch-protection.sh — configure GitHub branch protection for SENTINEL `main`.
#
# WARNING: This script mutates GitHub settings on the canonical remote
# (github.com/MuzeenMir/sentinel). Do NOT run in CI; do NOT run without review.
# It is intentionally idempotent so it can be re-run to align drift.
#
# Requires: gh CLI authenticated with admin:repo_hook + repo scopes.
# Usage:
#   scripts/apply-branch-protection.sh [--dry-run] [--repo OWNER/REPO] [--branch main]
#
# Flags:
#   --dry-run   Print the JSON payload and `gh api` command; make no changes.
#   --repo      Override the target repo (default: MuzeenMir/sentinel).
#   --branch    Override the protected branch (default: main).
#
# Required status checks are sourced from .github/branch-protection.json and
# must exist in the repo before applying.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
BRANCH_PROTECTION_CONFIG="$REPO_ROOT/.github/branch-protection.json"

REPO="MuzeenMir/sentinel"
BRANCH="main"
DRY_RUN="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN="true"; shift ;;
    --repo)    REPO="$2"; shift 2 ;;
    --branch)  BRANCH="$2"; shift 2 ;;
    -h|--help)
      sed -n '1,30p' "$0" | grep -E '^#' | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

if ! command -v jq >/dev/null 2>&1; then
  echo "jq not installed" >&2
  exit 2
fi

if [[ ! -f "$BRANCH_PROTECTION_CONFIG" ]]; then
  echo "missing branch protection config: $BRANCH_PROTECTION_CONFIG" >&2
  exit 2
fi

mapfile -t REQUIRED_CHECKS < <(jq -r '.required_status_checks[]' "$BRANCH_PROTECTION_CONFIG")

if [[ "${#REQUIRED_CHECKS[@]}" -eq 0 ]]; then
  echo "branch protection config has zero required checks" >&2
  exit 2
fi

checks_json=$(printf '%s\n' "${REQUIRED_CHECKS[@]}" | jq -R . | jq -s 'map({context: ., app_id: -1})')

payload=$(jq -n --argjson checks "$checks_json" '{
  required_status_checks: {
    strict: true,
    checks: $checks
  },
  # false: preserves the Mir emergency-override path documented in the
  # ULTRAPLAN risk register. Phase 0 has a single reviewer (Marcus); locking
  # admins out entirely would deadlock if no reviewer is available.
  enforce_admins: false,
  required_pull_request_reviews: {
    dismiss_stale_reviews: true,
    require_code_owner_reviews: true,
    required_approving_review_count: 1,
    require_last_push_approval: true
  },
  restrictions: null,
  required_linear_history: true,
  allow_force_pushes: false,
  allow_deletions: false,
  block_creations: false,
  required_conversation_resolution: true,
  lock_branch: false,
  allow_fork_syncing: false,
  required_signatures: true
}')

echo "repo:   $REPO"
echo "branch: $BRANCH"
echo "payload:"
echo "$payload" | jq .

if [[ "$DRY_RUN" == "true" ]]; then
  echo
  echo "[dry-run] would run:"
  echo "  gh api -X PUT repos/$REPO/branches/$BRANCH/protection --input -"
  exit 0
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "gh CLI not installed" >&2
  exit 2
fi

if ! gh auth status >/dev/null 2>&1; then
  echo "gh CLI not authenticated. Run: gh auth login" >&2
  exit 2
fi

echo
read -r -p "Apply this protection to $REPO@$BRANCH? [y/N] " ans
if [[ ! "$ans" =~ ^[Yy]$ ]]; then
  echo "aborted"
  exit 1
fi

echo "$payload" | gh api \
  -X PUT \
  -H "Accept: application/vnd.github+json" \
  "repos/$REPO/branches/$BRANCH/protection" \
  --input -

echo "applied"

# Required signatures endpoint is separate from the main protection object on
# some API paths; ensure it's on.
gh api -X POST \
  -H "Accept: application/vnd.github+json" \
  "repos/$REPO/branches/$BRANCH/protection/required_signatures" >/dev/null || true

echo "required_signatures ensured"
