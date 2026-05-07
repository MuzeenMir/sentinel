# SENTINEL — Secrets Rotation Log

Record of secrets findings in git history and the state of each rotation. Real
secret values never land in this file; findings are identified by commit SHA,
path, and rule only.

Authoritative source for `.gitleaks.toml` allowlist additions and for anything
the Phase 0 secrets sweep surfaces. Future scans update this log in-place.

## 2026-04-19 — Phase 0 slice 4 full-history scan

Tool: `gitleaks v8.18.4` with `.gitleaks.toml` + `--log-opts="--all" --redact`.
Scope: 78 commits on `main` through `12968333` (fix(migrations)).
Command: `gitleaks detect --log-opts="--all" --config=.gitleaks.toml --redact`.

**Findings: 5.** 3 false positives, 2 real.

### Real — requires rotation

| # | Rule | File (historical) | Commit | Date | Status | Owner |
|---|---|---|---|---|---|---|
| 4 | `generic-api-key` | `sentinel-core/sentinelenv` line 5–6 (`SECRET_KEY=…`) | `cb03d3c2` | 2026-01-28 | **OPEN — rotate** | @MuzeenMir |
| 5 | `generic-api-key` | `sentinel-core/sentinelenv` line 9–10 (`…PASSWORD=…`) | `cb03d3c2` | 2026-01-28 | **OPEN — rotate** | @MuzeenMir |

**What happened.** A `.env`-style file named `sentinelenv` was committed into
`sentinel-core/` in late January 2026 and later removed from the working tree.
It remains reachable in reflog and on any fork/clone that existed before the
removal. `sentinelenv` and `sentinel_env/` are now in `.gitignore` (lines
19, 56–60 of `/.gitignore` at `HEAD`), but that does not invalidate history.

**Required actions (owner @MuzeenMir).**

1. **Rotate `SECRET_KEY`.** Treat as compromised. Regenerate wherever it was
   ever used (JWT signing, Flask session cookies, CSRF, anywhere env-loaded).
   Re-issue any long-lived JWTs signed under it.
2. **Rotate `POSTGRES_PASSWORD` / `ADMIN_PASSWORD`** or whichever `*_PASSWORD`
   was in that file. Update Postgres roles, any deployed services' env, and
   cycle all active DB sessions.
3. After rotation, update this log: move the row to **Resolved** with rotation
   date + method.
4. **Optional but recommended — history rewrite.** `git-filter-repo` to purge
   `sentinel-core/sentinelenv` across all refs, then force-push to the
   canonical remote (`github.com/MuzeenMir/sentinel`). This is destructive:
   every clone and fork must re-clone. **Do not execute without a written
   go-ahead from the repo owner.** See `scripts/history-purge.sh` scaffolding
   (to be written when the go-ahead lands).

Until rotation is confirmed, treat these credentials as burned.

### False positives — no rotation required

Library source code inside an accidentally-committed local virtualenv.
`sentinel_env/` is now gitignored (lines 19, 60 of `/.gitignore`) so no new
commits can reintroduce the venv. Allowlist tightened to stop future scans
from flagging library internals.

| # | Rule | File (historical) | Reason |
|---|---|---|---|
| 1 | `aws-access-token` | `sentinel_env/lib/python3.12/site-packages/PIL/ImageFont.py:1255` | Pillow source code regex collision (not a real key) |
| 2 | `generic-api-key` | `sentinel_env/lib/python3.12/site-packages/onnx/reference/ops/aionnxml/op_dict_vectorizer.py:42` | ONNX source code (`keys = …` literal) |
| 3 | `generic-api-key` | `sentinel_env/lib/python3.12/site-packages/onnxruntime/tools/symbolic_shape_infer.py:2198–2199` | ONNX Runtime source code |

Action taken: `.gitleaks.toml` allowlist extended to cover `sentinel_env/**`
(and the repo-root `venv/`, `.venv/`, `env/`) so future `gitleaks detect`
runs stop re-reporting these three. See that file for the pattern list.

### HEAD scan

`gitleaks detect --no-git --source . --config=.gitleaks.toml --redact` on
working tree at `12968333`: see `/tmp/gitleaks-head.json` (CI runs this on
every push; results visible in the `security` workflow).

## Rotation procedure (general)

1. Generate the new secret (cryptographically random for keys; password
   manager for user-facing). Never reuse.
2. Store the new value in the secrets manager of record (AWS Secrets Manager,
   HashiCorp Vault, or Kubernetes Secret — per environment). Do **not** put
   it in `.env` on any developer laptop; use local `.env.local` that is
   gitignored.
3. Re-deploy every service that reads the secret. For JWT signing keys,
   invalidate all outstanding tokens by bumping `JWT_KEY_ID`.
4. Update this log: row from `OPEN — rotate` to `Resolved <date> <method>`.
5. Re-run `gitleaks detect --no-git --source .` locally to verify the new
   value is not accidentally committed.

## Policy

- Every `gitleaks` finding gets a row in this file — false positives included,
  to avoid re-triaging.
- Rotation is the primary remedy; history rewrite is a coordinated operation
  that happens only when the owner approves it.
- New findings are added at the bottom of this file with a dated header.
- This log is tracked in git at `sentinel-core/docs/revamp/SECRETS-ROTATION-LOG.md`
  (post-flatten: `docs/revamp/SECRETS-ROTATION-LOG.md`).
