# Audit ledger tamper-evidence — activation runbook (D5-ops)

Activates **wedge #3**: nightly cosign-signed Merkle anchoring of the audit
ledger, plus the per-event hash chain (D4/SEC-08). Both the *publish* side
(`merkle-root-publish.yml`) and the *verify* side (`verify_audit_chain.py`) are
**dormant until the operational secrets below are set** — they are deliberately
not hard-coded.

## Current status (2026-06-26)

**DORMANT.** No repository Actions secrets are configured
(`gh secret list --repo MuzeenMir/sentinel` is empty), so:

- `AUDIT_DATABASE_URL` is unset → the nightly publishes **no** signed root.
- `AUDIT_COSIGN_IDENTITY_REGEXP` is unset → the verifier **fails closed**
  (refuses to trust any published root rather than blessing an unverified one).

Tamper-evidence is therefore **not active in production**. This runbook is the
hand-off to the maintainer (Mir) who holds the prod connection string.

---

## 1. Publish side — anchor the ledger nightly

`merkle-root-publish.yml` runs `03:17 UTC` daily (and on manual dispatch). It
needs one secret:

| Secret | Value | Notes |
|--------|-------|-------|
| `AUDIT_DATABASE_URL` | `postgresql://USER:PASS@HOST:5432/DBNAME` | **Read-only** role with `SELECT` on `audit_log`. Points at the **production** audit ledger DB. |

Set it as a repository (or environment) Actions secret:

```bash
gh secret set AUDIT_DATABASE_URL --repo MuzeenMir/sentinel
# paste the read-only connstring when prompted
```

**Verify activation** — manually dispatch and confirm a signed artifact:

```bash
gh workflow run merkle-root-publish.yml --repo MuzeenMir/sentinel
# then, on the run:
#   - the "Check audit DB configured" step must be green (no ::error)
#   - artifact "audit-root-<yesterday>" contains <date>.json + .json.sig + .json.pem
```

> After this change, a **manual dispatch with the secret still unset fails
> loudly** (red) instead of no-op'ing into a misleading green. The **scheduled**
> run stays soft (a `::warning`, not a daily red X) so a missing secret never
> blocks unrelated work — but prolonged dormancy is visible.

---

## 2. Verify side — auditors check the live DB against signed roots

Whoever audits the ledger (out-of-band, or a future scheduled verify job) runs
`sentinel-core/scripts/verify_audit_chain.py` and must pin the cosign signer
identity, or the verifier fails closed:

| Env | Value |
|-----|-------|
| `AUDIT_COSIGN_IDENTITY_REGEXP` | `^https://github\.com/MuzeenMir/sentinel/\.github/workflows/merkle-root-publish\.yml@refs/heads/main$` |
| `AUDIT_COSIGN_OIDC_ISSUER` | `https://token.actions.githubusercontent.com` *(default — no action needed)* |

The identity is the keyless-OIDC certificate SAN of the publishing workflow on
`main`. Example run:

```bash
export AUDIT_DATABASE_URL='postgresql://reader:...@HOST:5432/DBNAME'
export AUDIT_COSIGN_IDENTITY_REGEXP='^https://github\.com/MuzeenMir/sentinel/\.github/workflows/merkle-root-publish\.yml@refs/heads/main$'
python sentinel-core/scripts/verify_audit_chain.py \
  --published-dir ./audit-roots \
  --cert-identity-regexp "$AUDIT_COSIGN_IDENTITY_REGEXP"
```

`verify_audit_chain.py` checks, per tenant: the per-event hash chain (D4), the
daily Merkle root, and — when the identity regexp is set — the cosign signature
on each published root. **Without the regexp it reports every published root as
`identity_not_configured` and exits non-zero** (fail-closed by design).

---

## 3. Known follow-up (out of D5-ops scope)

There is **no scheduled verify workflow** yet — verification is currently manual.
A future hardening should add a scheduled job that runs `verify_audit_chain.py`
against the live DB + published roots and alerts on any chain break or signature
failure, so tamper-evidence is continuously *checked*, not just *published*.

---

## Checklist

- [ ] `AUDIT_DATABASE_URL` set (read-only prod audit-DB connstring)
- [ ] Manual `merkle-root-publish.yml` dispatch is green and produces a signed root
- [ ] `AUDIT_COSIGN_IDENTITY_REGEXP` documented/distributed to auditors
- [ ] First verifier run is clean (no chain breaks, signatures trusted)
- [ ] (follow-up) scheduled verify job added
