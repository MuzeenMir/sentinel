# Changelog

## [1.8.1](https://github.com/MuzeenMir/sentinel/compare/v1.8.0...v1.8.1) (2026-06-26)


### Documentation

* **adr:** ADR-022 — downgrade review-gate independence claim (Codex/Kai retired) ([#94](https://github.com/MuzeenMir/sentinel/issues/94)) ([685fc6a](https://github.com/MuzeenMir/sentinel/commit/685fc6ac4163e4ed1bd9603dfc692c8be007f6ab))
* record audit Wave A–D closure + Phase-1 next-steps roadmap ([#95](https://github.com/MuzeenMir/sentinel/issues/95)) ([098cc05](https://github.com/MuzeenMir/sentinel/commit/098cc05372de41d8e9a32c5a65eff71074365260))

## [1.8.0](https://github.com/MuzeenMir/sentinel/compare/v1.7.3...v1.8.0) (2026-06-26)


### Features

* **audit:** per-event audit hash chain (D4, SEC-08) ([#90](https://github.com/MuzeenMir/sentinel/issues/90)) ([503624b](https://github.com/MuzeenMir/sentinel/commit/503624b3d9a482ac6a09fd9519491cd07d617948))

## [1.7.3](https://github.com/MuzeenMir/sentinel/compare/v1.7.2...v1.7.3) (2026-06-24)


### Bug Fixes

* header-only JWTs + fail-closed secrets + conftest cleanup (Wave D) ([#84](https://github.com/MuzeenMir/sentinel/issues/84)) ([e886688](https://github.com/MuzeenMir/sentinel/commit/e886688b95d02b588f3455bea2bfcabbfbecb6f7))


### Documentation

* correct SSO secret encryption-at-rest claim (SEC-05) ([#87](https://github.com/MuzeenMir/sentinel/issues/87)) ([b0f4928](https://github.com/MuzeenMir/sentinel/commit/b0f4928ebaf29117d9379045e4a07da57b5a38a0))

## [1.7.2](https://github.com/MuzeenMir/sentinel/compare/v1.7.1...v1.7.2) (2026-06-21)


### Bug Fixes

* audit Wave A remediation — make advertised controls actually enforce ([#77](https://github.com/MuzeenMir/sentinel/issues/77)) ([4d90ce0](https://github.com/MuzeenMir/sentinel/commit/4d90ce0ddef91a2b785d900cb7b477d5d0b9149e))
* **frontend:** npm audit fix — clear high/moderate advisories (security gate) ([#81](https://github.com/MuzeenMir/sentinel/issues/81)) ([40fe1ec](https://github.com/MuzeenMir/sentinel/commit/40fe1eced3d4021ad838b21f30c2c40972500cd0))
* **policy-orchestrator:** admin-gate /policies/auto-apply (SEC-04) ([#79](https://github.com/MuzeenMir/sentinel/issues/79)) ([51373eb](https://github.com/MuzeenMir/sentinel/commit/51373eb896d2242482fb3616f52db20ecac090f4))


### Documentation

* add 2026-06-19 read-only code audit of main @ v1.7.1 ([#76](https://github.com/MuzeenMir/sentinel/issues/76)) ([fa78148](https://github.com/MuzeenMir/sentinel/commit/fa78148c9b4508bf14f4dfdf1b600f9cc20f339d))
* sync CLAUDE.md + readme to shipped reality at v1.7.1 (DOC-01..06, ARC-02/03) ([#78](https://github.com/MuzeenMir/sentinel/issues/78)) ([1d46085](https://github.com/MuzeenMir/sentinel/commit/1d4608590ab4d9ea8d1d9a25780f5180576e0e9f))

## [1.7.1](https://github.com/MuzeenMir/sentinel/compare/v1.7.0...v1.7.1) (2026-06-12)


### Bug Fixes

* **console:** pin app tsconfig types to stop implicit [@types](https://github.com/types) scan breaking Docker build ([#73](https://github.com/MuzeenMir/sentinel/issues/73)) ([55eaca1](https://github.com/MuzeenMir/sentinel/commit/55eaca1942afb6b7b017e629e4f444b01d346b7d))

## [1.7.0](https://github.com/MuzeenMir/sentinel/compare/v1.6.0...v1.7.0) (2026-06-12)


### Features

* **audit:** auditor-facing ledger verification — cosign-gated verifier + console verdict page (Plan CLAUDE C7) ([#71](https://github.com/MuzeenMir/sentinel/issues/71)) ([19be56f](https://github.com/MuzeenMir/sentinel/commit/19be56f91e3b5984411ec1cc7ac2f0bb462de692))
* **llm-gateway:** broaden red-team gate with jailbreak + tool-output poisoning (C3) ([#68](https://github.com/MuzeenMir/sentinel/issues/68)) ([be69234](https://github.com/MuzeenMir/sentinel/commit/be69234c2449cc422d3b0abc67db21a2aed36b07))
* **llm-gateway:** inference provider abstraction + local self-host adapter (Plan CLAUDE C1) ([#66](https://github.com/MuzeenMir/sentinel/issues/66)) ([9084196](https://github.com/MuzeenMir/sentinel/commit/90841968097dc53b94db2c38ef07ed93eb9bed92))
* **llm-gateway:** model-quality eval gate with published thresholds (C2) ([#67](https://github.com/MuzeenMir/sentinel/issues/67)) ([b9c9a35](https://github.com/MuzeenMir/sentinel/commit/b9c9a3535bbb99f337f331126827b74eb23983db))
* **llm-gateway:** per-tenant inference quota + token budget (Plan CLAUDE C5) ([#70](https://github.com/MuzeenMir/sentinel/issues/70)) ([63ee04b](https://github.com/MuzeenMir/sentinel/commit/63ee04b5b4946d43cc26d112917f785999b2fe08))
* **llm-gateway:** reject citations whose source content was mutated (C4) ([#69](https://github.com/MuzeenMir/sentinel/issues/69)) ([8b4fc73](https://github.com/MuzeenMir/sentinel/commit/8b4fc73a2204e859856047fe20c4b969d72ba1cf))

## [1.6.0](https://github.com/MuzeenMir/sentinel/compare/v1.5.0...v1.6.0) (2026-06-06)


### Features

* **llm-gateway:** LLM analyst copilot — grounded, propose-only (wedge [#2](https://github.com/MuzeenMir/sentinel/issues/2)) ([#56](https://github.com/MuzeenMir/sentinel/issues/56)) ([0fd0456](https://github.com/MuzeenMir/sentinel/commit/0fd0456956669b5c30277b85aef803e4c5927d3c))

## [1.5.0](https://github.com/MuzeenMir/sentinel/compare/v1.4.0...v1.5.0) (2026-06-06)


### Features

* **opa:** add Rego detection evaluation ([#57](https://github.com/MuzeenMir/sentinel/issues/57)) ([e1396b6](https://github.com/MuzeenMir/sentinel/commit/e1396b6706f41b9e6509d5a70e414aa996aef253))


### Bug Fixes

* **ci:** harden supply-chain SBOM and xdp image build ([#63](https://github.com/MuzeenMir/sentinel/issues/63)) ([94bd399](https://github.com/MuzeenMir/sentinel/commit/94bd399e60202aea7173af77c3d67c236a1f986a))


### Documentation

* **repo:** reframe two-person rule as honest independent review gate (ADR-011) ([#55](https://github.com/MuzeenMir/sentinel/issues/55)) ([2775549](https://github.com/MuzeenMir/sentinel/commit/2775549d3978447f28573a9836931ddce55e6c72))

## [1.4.0](https://github.com/MuzeenMir/sentinel/compare/v1.3.0...v1.4.0) (2026-06-05)


### Features

* **ai-engine:** add detection-as-code registry ([#52](https://github.com/MuzeenMir/sentinel/issues/52)) ([a76ea76](https://github.com/MuzeenMir/sentinel/commit/a76ea76023f997d27281869532f49e092453f169))
* **api-gateway:** port gateway runtime to FastAPI ([#58](https://github.com/MuzeenMir/sentinel/issues/58)) ([c4aaa23](https://github.com/MuzeenMir/sentinel/commit/c4aaa237d32a8b15cee138b693359da22387e109))
* **api-gateway:** proxy authenticated copilot requests ([#61](https://github.com/MuzeenMir/sentinel/issues/61)) ([70d2e13](https://github.com/MuzeenMir/sentinel/commit/70d2e1365b1f70a7110c152a093ebc92799654c3))
* **api-gateway:** remove Flask runtime dependencies ([#59](https://github.com/MuzeenMir/sentinel/issues/59)) ([bb871d1](https://github.com/MuzeenMir/sentinel/commit/bb871d154ecea70338192320f793d3f9b792ee5f))
* **auth-service:** encrypt MFA TOTP secrets at rest (T-027) ([#51](https://github.com/MuzeenMir/sentinel/issues/51)) ([2b52275](https://github.com/MuzeenMir/sentinel/commit/2b52275aa1d8fcbc9563a7608c6ee118323ace27))


### Bug Fixes

* **ci:** clear June security advisory drift ([#60](https://github.com/MuzeenMir/sentinel/issues/60)) ([5c5871e](https://github.com/MuzeenMir/sentinel/commit/5c5871e5a0a98981ba42f391479add4183ec92fd))

## [1.3.0](https://github.com/MuzeenMir/sentinel/compare/v1.2.0...v1.3.0) (2026-05-30)


### Features

* **audit:** tamper-evident audit ledger — Merkle roots + verifier (wedge [#3](https://github.com/MuzeenMir/sentinel/issues/3)) ([#48](https://github.com/MuzeenMir/sentinel/issues/48)) ([5ea62de](https://github.com/MuzeenMir/sentinel/commit/5ea62de990062e4ad0f934207f433c536a5f0625))
* **policy-orchestrator:** reversible enforcement — TTL auto-rollback (wedge [#1](https://github.com/MuzeenMir/sentinel/issues/1)) ([#49](https://github.com/MuzeenMir/sentinel/issues/49)) ([04eb11b](https://github.com/MuzeenMir/sentinel/commit/04eb11bd00947f69edfdce8892c92d930ea09499))

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
