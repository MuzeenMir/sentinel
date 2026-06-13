# Security Policy

SENTINEL is a security platform under active v1 → v2 revamp. We take reports
seriously, but please read the honest scope note below before relying on it in
production.

## Reporting a vulnerability

**Do not open a public issue, PR, or Discussion for security problems.**

Report privately through GitHub:

1. Go to the [**Security advisories**](https://github.com/MuzeenMir/sentinel/security/advisories/new) page.
2. Click **Report a vulnerability** and fill in the advisory form.

This keeps the report private until a fix is available and coordinated.

If you cannot use GitHub advisories, you may instead open a minimal public issue
that says only *"requesting a private security contact"* — with **no details** —
and a maintainer will follow up with a private channel.

### What to include

- A description of the issue and the impact you believe it has.
- Steps to reproduce (a proof of concept helps, but is not required to report).
- Affected version / commit SHA and component (e.g. `console`, `controller`,
  `analyzer`, `collector`, `llm-gateway`).
- Any suggested remediation, if you have one.

### What to expect

This is a small, single-maintainer project. We aim to:

- **Acknowledge** your report within **5 business days**.
- Provide an initial **assessment** within **10 business days**.
- Keep you updated as we work toward a fix, and credit you in the advisory
  unless you ask otherwise.

These are good-faith targets, not contractual SLAs.

## Supported versions

Only the latest release line receives security fixes. Older tags are not
backported.

| Version | Supported |
| ------- | --------- |
| Latest `v1.1.x` release | ✅ |
| Older `v1.0.x` / pre-release | ❌ |

## Scope and honest status

This repository is **mid-revamp and not production-certified**. Several
security-relevant capabilities are v2 targets, not shipping guarantees — see the
README's "What does not yet ship" section. In particular, the following are
**not** yet complete and should not be assumed in a threat model:

- Multi-tenant isolation with Postgres row-level security (RLS).
- Signed, append-only audit logging enforced at the Postgres role level.
- SSO / SCIM and end-to-end signed (cosign) releases.
- Production-validated Terraform / Kubernetes deployment.

Reports about gaps in the above are welcome, but they are tracked as roadmap
work (see `sentinel-core/docs/revamp/`) rather than regressions.

## Safe harbor

We will not pursue or support action against researchers who:

- Make a good-faith effort to avoid privacy violations, data destruction, and
  service degradation.
- Only interact with systems/accounts they own or have explicit permission to test.
- Give us reasonable time to remediate before any public disclosure.

Thank you for helping keep SENTINEL and its users safe.
