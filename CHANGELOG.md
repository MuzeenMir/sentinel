# Changelog

## [1.2.0](https://github.com/MuzeenMir/sentinel/compare/v1.1.3...v1.2.0) (2026-05-30)


### Features

* **audit:** migrate audit_log Redis -&gt; PostgreSQL (T-031) ([#46](https://github.com/MuzeenMir/sentinel/issues/46)) ([944cd31](https://github.com/MuzeenMir/sentinel/commit/944cd315582fff222675919f15b1334206cff35d))
* **lib-tenancy:** wire sentinel_app runtime role + per-tx SET LOCAL (T-028) ([#41](https://github.com/MuzeenMir/sentinel/issues/41)) ([f07f0be](https://github.com/MuzeenMir/sentinel/commit/f07f0be57d203e639c3ed43e75e34446c29758cf))


### Bug Fixes

* **ci:** repair security dast bootstrap ([#45](https://github.com/MuzeenMir/sentinel/issues/45)) ([00e27d0](https://github.com/MuzeenMir/sentinel/commit/00e27d0c8f3d073f9e80e80303a78fd48e232975))
* **ci:** retry cosign installer in sbom-images ([#43](https://github.com/MuzeenMir/sentinel/issues/43)) ([ef47cf2](https://github.com/MuzeenMir/sentinel/commit/ef47cf293eac03d0d1e5ddc60e7bc15c9072eac8))
* **repo:** allow audit scope ([#47](https://github.com/MuzeenMir/sentinel/issues/47)) ([7eea8ea](https://github.com/MuzeenMir/sentinel/commit/7eea8eaf5dfbdb88905ce718365cff946737feed))


### Documentation

* **repo:** flip T-028 closure status + clean dragon-scale CLAUDE.md ([#44](https://github.com/MuzeenMir/sentinel/issues/44)) ([05593b4](https://github.com/MuzeenMir/sentinel/commit/05593b479d482f6cefca66001e772488cc7f6746))

## [1.1.3](https://github.com/MuzeenMir/sentinel/compare/v1.1.2...v1.1.3) (2026-05-24)


### Documentation

* **repo:** add QUICKSTART.md covering Win11 + Ubuntu 24 ([#39](https://github.com/MuzeenMir/sentinel/issues/39)) ([2815ecb](https://github.com/MuzeenMir/sentinel/commit/2815ecb1773fe69cd9357a63b6e09478690ef95c))

## [1.1.2](https://github.com/MuzeenMir/sentinel/compare/v1.1.1...v1.1.2) (2026-05-24)


### Documentation

* **repo:** phase-0 polish — refresh CLAUDE.md, supersede drift audit ([#36](https://github.com/MuzeenMir/sentinel/issues/36)) ([de18c53](https://github.com/MuzeenMir/sentinel/commit/de18c53bd00cb675b2081bd15888a8ac433cccfa))

## [1.1.1](https://github.com/MuzeenMir/sentinel/compare/v1.1.0...v1.1.1) (2026-05-23)


### Bug Fixes

* **migrations:** create users/audit_log base tables in 20260417_001 (T-030) ([#33](https://github.com/MuzeenMir/sentinel/issues/33)) ([6085027](https://github.com/MuzeenMir/sentinel/commit/6085027ad5b5d23ed1a1290a6a37a3b13dfe53fa))


### Documentation

* **migrations:** flip phase-0 closure review to all-green; add 2026-05-23 addendum ([#35](https://github.com/MuzeenMir/sentinel/issues/35)) ([bc8313c](https://github.com/MuzeenMir/sentinel/commit/bc8313c2c875edd3fdb5366945e062d9b6befa91))

## [1.1.0](https://github.com/MuzeenMir/sentinel/compare/v1.0.1...v1.1.0) (2026-05-23)


### Features

* **migrations:** add 20260417_002 sso/scim/mfa migration ([#28](https://github.com/MuzeenMir/sentinel/issues/28)) ([b22fd0b](https://github.com/MuzeenMir/sentinel/commit/b22fd0b7b32bdb173fe56c68f386ebf1aaa8f672))
* **migrations:** add 20260417_003 RLS + audit append-only role ([#29](https://github.com/MuzeenMir/sentinel/issues/29)) ([f495ef0](https://github.com/MuzeenMir/sentinel/commit/f495ef01fb5ef076d5cf037e11e1fe945d0b2dc6))
* **migrations:** land 20260417 consolidation migration (no-op vs current state) ([#27](https://github.com/MuzeenMir/sentinel/issues/27)) ([2e27f87](https://github.com/MuzeenMir/sentinel/commit/2e27f8742eb1fe81a6c8357b0cee7d7b61aec5cb))


### Bug Fixes

* **api-gateway:** fail closed when INTERNAL_SERVICE_TOKEN is empty ([#21](https://github.com/MuzeenMir/sentinel/issues/21)) ([9277913](https://github.com/MuzeenMir/sentinel/commit/927791358ad76ef1d10c51f7f3242c7ed9b15678))
* **api-gateway:** forward auth header and strip token in gateway proxies ([#23](https://github.com/MuzeenMir/sentinel/issues/23)) ([fee13a0](https://github.com/MuzeenMir/sentinel/commit/fee13a0aeabd345852aa3f50f86d6c65ba5c37ee))
* **api-gateway:** replace wildcard cors with an explicit fail-fast allowlist ([#22](https://github.com/MuzeenMir/sentinel/issues/22)) ([6fedf20](https://github.com/MuzeenMir/sentinel/commit/6fedf200d8444db096c9e2894e662673540d8b17))
* **tests:** add fresh_db_check.sh + CASCADE tenant_id drop in 20260313 downgrade ([#30](https://github.com/MuzeenMir/sentinel/issues/30)) ([0cd41dd](https://github.com/MuzeenMir/sentinel/commit/0cd41dd342c517e8c0b55c6e0a8a63a6a6e061af))


### Documentation

* **repo:** repoint phase 0 baseline plan and refresh status ([#25](https://github.com/MuzeenMir/sentinel/issues/25)) ([a3f8fe9](https://github.com/MuzeenMir/sentinel/commit/a3f8fe993a7c918d30455cef998ba6d117a5a45b))
* **revamp:** adopt phase 0 closure review ([2277e18](https://github.com/MuzeenMir/sentinel/commit/2277e1834c24995b34b0476346e8d7e5c78f6929))

## [1.0.1](https://github.com/MuzeenMir/sentinel/compare/v1.0.0...v1.0.1) (2026-05-17)


### Bug Fixes

* **deps:** repair container startup ([380063e](https://github.com/MuzeenMir/sentinel/commit/380063e64164f24687e73b037863303e6a5bee1d))
* **xdp-collector:** build xdp flow artifact ([#17](https://github.com/MuzeenMir/sentinel/issues/17)) ([219373f](https://github.com/MuzeenMir/sentinel/commit/219373fec525a2ba5ca3dfa6ee6989502f27093d))
* **xdp-collector:** default xdp profile to bridge services ([#14](https://github.com/MuzeenMir/sentinel/issues/14)) ([195c147](https://github.com/MuzeenMir/sentinel/commit/195c147bbdd1e38640cb92c01dc1be51e925ddae))

## 1.0.0 (2026-05-16)


### Bug Fixes

* **ci:** add compose-required env vars to e2e and integration CI ([4143529](https://github.com/MuzeenMir/sentinel/commit/41435296b552d2903bc733e7436bf7c7f05828cb))
* **security:** harden auth gateway compose and agent install ([5ee2457](https://github.com/MuzeenMir/sentinel/commit/5ee2457f44119090d277164294b0c707b1f79df6))
