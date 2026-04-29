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
        // Rust crate modules (current OSS DNS-shield direction).
        'feed',
        'resolver',
        'blockpage',
        'tray',
        'installer',
        'service',
        // Meta / infra.
        'ci',
        'deps',
        'tests',
        'docs',
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
