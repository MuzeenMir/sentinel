<!--
  SENTINEL PR template. Keep it honest — this is a checklist, not theatre.
  Conventional Commits in the title: <type>(<scope>): <subject>
  Example: feat(console): wire tenant switcher to console API
-->

## Summary

<!-- 1–3 sentences. What changes, why now. -->

## Phase / scope

- [ ] Phase 0 (stabilize)
- [ ] Phase 1 (consolidate)
- [ ] Phase 2+ (future)
- [ ] Not part of revamp — normal maintenance

## Type of change

- [ ] Feature
- [ ] Bug fix
- [ ] Refactor (no behavior change)
- [ ] Migration / DB schema
- [ ] CI / build / supply chain
- [ ] Docs
- [ ] Security

## Checklist

- [ ] Conventional Commit title with an allowed scope (`commitlint.config.js`)
- [ ] Pre-commit hooks passed locally (`pre-commit run --all-files`)
- [ ] Tests added / updated (or explicitly not required — say why)
- [ ] No secrets, tokens, keys, or `.env` values committed
- [ ] If migration: idempotent (`IF EXISTS` / `IF NOT EXISTS`), passes `scripts/fresh_db_check.sh`
- [ ] If touching LLM code: no LLM output reaches enforcement adapters (SAF-1 hard rule)
- [ ] If touching multi-tenant code: RLS test covers cross-tenant read returns zero rows (NFR-SEC-1)
- [ ] README / docs updated if behavior changed
- [ ] CODEOWNERS-mandated reviewer requested

## Two-person rule (check if it applies)

Required if this PR touches any of:

- [ ] OPA bundles (`/opa-bundles/**`)
- [ ] Model promotion (signed checkpoints, model registry)
- [ ] Helm prod values (`deploy/helm/**/values-prod.yaml`)
- [ ] Postgres RLS policies (`backend/migrations/**` touching RLS)
- [ ] Audit schema (`backend/_lib/audit/**` or audit table DDL)

If any box is checked, request a second reviewer from the security/infra CODEOWNERS.

## Test plan

- [ ] <!-- e.g. `pytest backend/auth-service/tests/` -->
- [ ] <!-- e.g. `npm run test` in `frontend/admin-console` -->
- [ ] <!-- e.g. `bash scripts/fresh_db_check.sh` -->

## Related

- Issue:
- ADR:
- Revamp doc: <!-- e.g. `docs/revamp/SDD-002.md §3.2` -->

---

<!--
  Reminder: squash-merge only on `main`. Signed commits required. Keep PR <500 lines where possible.
  If this PR spans multiple phases or scopes, split it.
-->
