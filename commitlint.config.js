// Conventional Commits for SENTINEL.
// Docs: https://www.conventionalcommits.org/
// Allowed scopes track the v2 target architecture plus repo-level concerns.

/** @type {import('@commitlint/types').UserConfig} */
module.exports = {
  extends: ['@commitlint/config-conventional'],
  rules: {
    'type-enum': [
      2,
      'always',
      [
        'feat',
        'fix',
        'docs',
        'style',
        'refactor',
        'perf',
        'test',
        'build',
        'ci',
        'chore',
        'revert',
      ],
    ],
    'scope-enum': [
      2,
      'always',
      [
        // v2 consolidated services
        'collector',
        'analyzer',
        'controller',
        'console',
        'agent',
        'llm-gateway',
        // v1 legacy (retained Phase 0–1; may be used during strangler-fig work)
        'api-gateway',
        'auth-service',
        'ai-engine',
        'xai-service',
        'alert-service',
        'policy-orchestrator',
        'compliance-engine',
        'drl-engine',
        'data-collector',
        'xdp-collector',
        'hardening-service',
        'firewall-adapters',
        // shared library (Phase 1)
        'lib',
        'lib-cim',
        'lib-tenancy',
        'lib-otel',
        'lib-audit',
        'lib-llm-client',
        // platform + infra
        'opa',
        'helm',
        'terraform',
        'deploy',
        'ci',
        'docker',
        'migrations',
        'deps',
        'tests',
        'contract-tests',
        'frontend',
        'proto',
        'observability',
        // meta
        'revamp',
        'docs',
        'adr',
        'sbom',
        'release',
        'repo',
      ],
    ],
    'scope-empty': [1, 'never'],
    'subject-case': [
      2,
      'never',
      ['sentence-case', 'start-case', 'pascal-case', 'upper-case'],
    ],
    'header-max-length': [2, 'always', 100],
    'body-max-line-length': [1, 'always', 120],
  },
};
