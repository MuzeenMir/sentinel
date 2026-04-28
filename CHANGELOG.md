# Changelog

## 1.0.0 (2026-04-28)


### Features

* **api-gateway,observability:** OTel pilot via OTLP gRPC → Tempo ([1c0b885](https://github.com/MuzeenMir/sentinel/commit/1c0b885e4a42bf382194aeaa5f4e7b2b645e085e))
* complete SAML validation, SCIM provisioning, and MFA persistence ([c79db17](https://github.com/MuzeenMir/sentinel/commit/c79db17bac736628950fcbb35b7fbe499920c22e))
* **drl:** default DRL engine to shadow mode end-to-end ([6d642c6](https://github.com/MuzeenMir/sentinel/commit/6d642c600e2af2491a808c74b9277a7784ad4d09))
* **frontend:** enterprise UI — tenant management, MFA setup wizard, SIEM config, upgraded audit log ([3d0dd2c](https://github.com/MuzeenMir/sentinel/commit/3d0dd2c28b5dadcf5dd81fbd252b106c495c01ac))
* integrate multi-tenancy across all services ([05c3df0](https://github.com/MuzeenMir/sentinel/commit/05c3df08e28a937740095b63cf1b044c6e377837))
* **repo:** rust skeleton (t1 pr-3) ([#8](https://github.com/MuzeenMir/sentinel/issues/8)) ([7d7cb86](https://github.com/MuzeenMir/sentinel/commit/7d7cb86e03c92319d138a37b39f9be843016db3a))
* SOC2 audit logging + backend test suite (Points 6 & 7) ([e2ba896](https://github.com/MuzeenMir/sentinel/commit/e2ba8964f6992289ce1954d800e091df467daa64))
* wire SIEM integration dispatcher into alert-service ([8154ea7](https://github.com/MuzeenMir/sentinel/commit/8154ea75e2fbde74f44cc33cadd5c10f90c4c6df))
* wire up eBPF build toolchain and fix Alembic migration chain ([78fb89a](https://github.com/MuzeenMir/sentinel/commit/78fb89a8cc448ca92390ff830c19c5783206f70f))


### Bug Fixes

* **ci,compose:** honor POSTGRES_DB env in postgres service ([c7c3892](https://github.com/MuzeenMir/sentinel/commit/c7c389219b63ca3e25b2769b2a913e218f88af35))
* **ci:** add alembic + SQLAlchemy to auth-service deps ([2824c62](https://github.com/MuzeenMir/sentinel/commit/2824c62caf6c228b81b6a1a53a3d48f02831af62))
* **ci:** correct backend Docker build context to sentinel-core/backend ([15409c6](https://github.com/MuzeenMir/sentinel/commit/15409c646e323087299fa56210468989a0e39760))
* **ci:** round 2 — lint format, semgrep CLI, sbom syft, e2e drl route, release seed ([0ad4afb](https://github.com/MuzeenMir/sentinel/commit/0ad4afb923d6a08c39c39c1ac76db8eabeb0b7e0))
* **ci:** round 3 — DRL gunicorn init, fresh-db race, sbom oci case ([f468d18](https://github.com/MuzeenMir/sentinel/commit/f468d180d8495aaf82c5e74c818f3f84658f3ecd))
* **ci:** round 4 — buildx provenance/load, paths-ignore, commitlint v20 ([#4](https://github.com/MuzeenMir/sentinel/issues/4)) ([261a106](https://github.com/MuzeenMir/sentinel/commit/261a106c01c6e174259723e26c3801adb4136c5e))
* **ci:** run sbom after build workflow_run, pull digests cross-run ([d231b98](https://github.com/MuzeenMir/sentinel/commit/d231b9804480b805c9cdd35a9da3c2040b012aff))
* **ci:** sanitize doc secret, install all service deps, align E2E tests with UI ([4132827](https://github.com/MuzeenMir/sentinel/commit/4132827f0d69aa070945067f9e53a8fb2960ea6c))
* **ci:** seed release-please with manifest + config for initial bootstrap ([eff3c40](https://github.com/MuzeenMir/sentinel/commit/eff3c40e651f626aa6585cbfae47370e441f0c7c))
* **ci:** unblock lint+typecheck gates on Phase 0 ([0b17025](https://github.com/MuzeenMir/sentinel/commit/0b1702564f1450b607f2a26f593cd22293d134e0))
* **ci:** unify Flask deps, persist authStore for E2E ([b424ae1](https://github.com/MuzeenMir/sentinel/commit/b424ae1586382c39013a52b64293a9b4e2bc4d06))
* **ci:** unify shared Python deps across backend services ([2585b96](https://github.com/MuzeenMir/sentinel/commit/2585b96b49bf898e610df2b80240aa76fea48c0e))
* **compose,docker:** align POSTGRES_DB name and ship audit_logger to services ([38d843d](https://github.com/MuzeenMir/sentinel/commit/38d843d73be970e60b9ef2a4c6436bfd85245abc))
* **e2e:** align alert triage HTTP verb with backend (POST, not PUT) ([0ee6379](https://github.com/MuzeenMir/sentinel/commit/0ee6379a6f11172f92061783a3bf8b1bb6fab161))
* **e2e:** match alerts list URLs carrying query params ([8e5a8bb](https://github.com/MuzeenMir/sentinel/commit/8e5a8bbfce033a4fd0ab6d5c65ce4f8a93167b38))
* **e2e:** render compliance details, scope DENY badge, isolate username text ([0b9604d](https://github.com/MuzeenMir/sentinel/commit/0b9604d97934a26a74dfecb439966df7aef3d84c))
* **e2e:** stabilize Playwright suite — proxy, selectors, UI mismatches ([25d6c2a](https://github.com/MuzeenMir/sentinel/commit/25d6c2a09eaab82139e20f6e3de1d18ae7c3958d))
* **migrations:** make enterprise_schema idempotent + drift-tolerant ([ecaf4cc](https://github.com/MuzeenMir/sentinel/commit/ecaf4cc0a43f70d37af8e1ba8cc3a2f827fd1a9b))
* **migrations:** Phase 0 slice 3 - idempotent revision 001 + verify roundtrip ([1296833](https://github.com/MuzeenMir/sentinel/commit/12968333f4c3ae12f34185ee60e7da4a410e61ca))
* **migrations:** seed default tenant with explicit tenant_id ([243481b](https://github.com/MuzeenMir/sentinel/commit/243481b39177f0397db191944a659fe191a0b05a))
* rescue 138 unique files from duplicate tree, clean git state ([c144af9](https://github.com/MuzeenMir/sentinel/commit/c144af955ef76b65820afa70f1946ea72ccf9ed6))
* resolve 28 failing backend tests + frontend lint & bundle splitting ([dcec061](https://github.com/MuzeenMir/sentinel/commit/dcec061dc3aa4f02e23eb6d668246ff58866c06b))
* resolve all 648 backend unit test failures ([c0ccc84](https://github.com/MuzeenMir/sentinel/commit/c0ccc847d7dfdc44d3ec874364256cc8c12aaf1e))
* resolve CI failures across frontend, backend, security-scan ([02c6c98](https://github.com/MuzeenMir/sentinel/commit/02c6c9822750aa90652fdaed461c841fce808cf8))
* **security:** clear pip-audit CVEs + scope semgrep to Phase 0 ([f483cd2](https://github.com/MuzeenMir/sentinel/commit/f483cd27ba4d83ef2636149aa3482ffe6c4d69fe))
* wire up missing gateway routes, align DB schema with ORM models ([5b069fc](https://github.com/MuzeenMir/sentinel/commit/5b069fcb9ce33cf676aba7bd639cdfa23adbce8d))


### Documentation

* add model governance docs + .gitignore hygiene + work log update ([352f68c](https://github.com/MuzeenMir/sentinel/commit/352f68cbe7d87a2690dca2f6f8ba729984626373))
* **agents:** canonical remote is MuzeenMir/sentinel ([73741c5](https://github.com/MuzeenMir/sentinel/commit/73741c5bc5711c8fa00627344b4253598abc4f9f))
* **repo:** add v1 archive notice pointing at archive/v1-python ([#5](https://github.com/MuzeenMir/sentinel/issues/5)) ([a72a694](https://github.com/MuzeenMir/sentinel/commit/a72a694bcd902177ddabdd12f51c82e722e9e55f))
* **revamp:** add phase 0/1 planning, SRS/SDD/SDP, git restructure ([8fe8a5e](https://github.com/MuzeenMir/sentinel/commit/8fe8a5e12994791ca3f382dc0608822da28a7bbd))
* **revamp:** defer git-flatten (Slice 6) past Phase 0 exit ([4374b29](https://github.com/MuzeenMir/sentinel/commit/4374b29008a5fde69e07e204b4f528db6e5fc71b))
* **revamp:** Phase 0 slice 1 - docs honesty + repo scaffolding ([a51d40d](https://github.com/MuzeenMir/sentinel/commit/a51d40d43aaad53462eae04fe246457e4a6621e7))
* seed DESIGN.md and TODOS.md, ignore .gstack/ ([#3](https://github.com/MuzeenMir/sentinel/issues/3)) ([f15b62d](https://github.com/MuzeenMir/sentinel/commit/f15b62d65bb56367949ea498fa05bd5c1b700f1f))
