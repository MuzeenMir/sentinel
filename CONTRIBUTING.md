# Contributing to SENTINEL

Thanks for your interest. This repo is mid-revamp (v1 → v2); please keep changes
scoped to the active workstream and read this whole page before opening a PR.

## Before you start

- **Bugs / features:** open an issue using the templates under
  `.github/ISSUE_TEMPLATE/`.
- **Questions / ideas:** use [Discussions](https://github.com/MuzeenMir/sentinel/discussions).
- **Security vulnerabilities:** do **not** open a public issue — follow
  [`SECURITY.md`](SECURITY.md).

## Branch and PR workflow

- Branch off `main`; keep one logical change per PR (aim for < 500 lines).
- Open a PR using the template (it auto-populates). Fill in the checklist
  honestly — it's a checklist, not theatre.
- `CODEOWNERS` gates review; request the mandated reviewer.
- **Squash-merge only** onto `main`. **Signed commits are required** on `main`
  (`git commit -S`).
- CI must be green before merge. Required checks include lint, typecheck, unit,
  security, build, and migrations.

## Commit messages

[Conventional Commits](https://www.conventionalcommits.org/) are enforced by
`commitlint.config.js`:

```
<type>(<scope>): <subject>
```

- **Types:** `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`,
  `build`, `ci`, `chore`, `revert`.
- **Scopes** track the v2 architecture plus repo concerns, e.g.
  `console | controller | analyzer | collector | agent | llm-gateway | lib |
  opa | helm | ci | docs | migrations | deps | repo`. See `commitlint.config.js`
  for the full allowlist; an unlisted scope fails the lint gate.
- Subject: lowercase, imperative, ≤ 100 chars (no trailing period, not
  Title-Case).

Example: `feat(console): wire tenant switcher to console API`

## Local checks

```bash
pre-commit install          # one-time
pre-commit run --all-files  # run all hooks before pushing
```

Service-specific tests live under each component; see the README for stack and
test commands (frontend: `npm run test` / `npm run lint` / `npm run type-check`
in `sentinel-core/frontend/admin-console/`).

## Hard project rules

These are non-negotiable and reviewers will block on them:

- **No secrets in source** — use env vars and `.env.example` placeholders only.
- **No LLM output reaches enforcement adapters** — write actions require human
  approval.
- Parameterized SQL; no `eval`/`exec` on untrusted input; auth + RBAC on APIs.
- Migrations must be idempotent (`IF EXISTS` / `IF NOT EXISTS`).
- Changes to OPA bundles, model promotions, Helm prod values, RLS policies, or
  audit schemas require the independent review gate (see the PR template and
  `ADR-011`).

## License

By contributing you agree your contributions are licensed under the project's
MIT license (see `LICENSE`).
