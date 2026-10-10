# Changelog

## [0.5.0](https://github.com/savvagent/otto-platform/compare/v0.4.0...v0.5.0) (2026-10-10)


### Features

* add plan features and serve them to resource servers ([#31](https://github.com/savvagent/otto-platform/issues/31)) ([4e001e5](https://github.com/savvagent/otto-platform/commit/4e001e59931676602407fe71e0c3ef0461f11ccd)), closes [#30](https://github.com/savvagent/otto-platform/issues/30)

## [0.4.0](https://github.com/savvagent/otto-platform/compare/v0.3.0...v0.4.0) (2026-10-08)


### Features

* let users read their own account-level audit events ([#26](https://github.com/savvagent/otto-platform/issues/26)) ([0c51e7d](https://github.com/savvagent/otto-platform/commit/0c51e7dcd0f73dcab96c76b8d5a09e5182dcb195)), closes [#22](https://github.com/savvagent/otto-platform/issues/22)
* **otto-auth:** per-scope descriptions on the consent screen ([#24](https://github.com/savvagent/otto-platform/issues/24)) ([3298c41](https://github.com/savvagent/otto-platform/commit/3298c41ab7d1674f0ebe9c99bfd8d1f779f5a545)), closes [#20](https://github.com/savvagent/otto-platform/issues/20)


### Bug Fixes

* keep the lockfiles in step with release versions ([#28](https://github.com/savvagent/otto-platform/issues/28)) ([6006302](https://github.com/savvagent/otto-platform/commit/60063025029407bee6bf62eb5666624cfdcfa0b3)), closes [#27](https://github.com/savvagent/otto-platform/issues/27)
* **otto-auth:** bind registration ceremonies to the flow that started them ([#25](https://github.com/savvagent/otto-platform/issues/25)) ([a9d288c](https://github.com/savvagent/otto-platform/commit/a9d288c553005a5bb343a97eef44dd86192a4ba1)), closes [#21](https://github.com/savvagent/otto-platform/issues/21)

## [0.3.0](https://github.com/savvagent/otto-platform/compare/v0.2.1...v0.3.0) (2026-10-08)


### Features

* **otto-auth:** first-party console clients, org_hint, and admin downscoping ([#19](https://github.com/savvagent/otto-platform/issues/19)) ([7e0f4f8](https://github.com/savvagent/otto-platform/commit/7e0f4f801d45f60be9f62569cf21aaa8ed4bb2ba))
* **otto-resource:** member team lookup and member cache ([#18](https://github.com/savvagent/otto-platform/issues/18)) ([a220608](https://github.com/savvagent/otto-platform/commit/a220608fa269321e4b8777e1ba88c0ef0bbd659d)), closes [#3](https://github.com/savvagent/otto-platform/issues/3)
* **otto-web:** serve the identity HTTP surface ([#14](https://github.com/savvagent/otto-platform/issues/14)) ([2a00db8](https://github.com/savvagent/otto-platform/commit/2a00db8176167704201f2af7fa676480c719fda6))
* resource-server API (introspection, internal usage, lifecycle webhooks) ([#15](https://github.com/savvagent/otto-platform/issues/15)) ([3cd60b6](https://github.com/savvagent/otto-platform/commit/3cd60b68c576dee9ec8ef11f680e394828917324))
* **web:** platform console ([#17](https://github.com/savvagent/otto-platform/issues/17)) ([b7df223](https://github.com/savvagent/otto-platform/commit/b7df223e8543761ea33df3361f165c64727108fb))

## [0.2.1](https://github.com/savvagent/otto-platform/compare/v0.2.0...v0.2.1) (2026-10-07)


### Bug Fixes

* **otto-auth:** pin OIDC connections to validated addresses ([#12](https://github.com/savvagent/otto-platform/issues/12)) ([c7437af](https://github.com/savvagent/otto-platform/commit/c7437afdc63bc211f00f003868f7de208ae2341b)), closes [#7](https://github.com/savvagent/otto-platform/issues/7)

## [0.2.0](https://github.com/savvagent/otto-platform/compare/v0.1.0...v0.2.0) (2026-10-07)


### Features

* **otto-auth:** add a resource-server registry for multi-service tokens ([#10](https://github.com/savvagent/otto-platform/issues/10)) ([76d3f00](https://github.com/savvagent/otto-platform/commit/76d3f0080217d02a7b59496b0e9f43df5cd2b14c)), closes [#2](https://github.com/savvagent/otto-platform/issues/2)
* **otto-auth:** port enterprise OIDC federation and Cipher ([#8](https://github.com/savvagent/otto-platform/issues/8)) ([7bbaf98](https://github.com/savvagent/otto-platform/commit/7bbaf986f0452cbda453de42be68c02f62468868)), closes [#2](https://github.com/savvagent/otto-platform/issues/2)


### Bug Fixes

* **otto-auth:** port passkey ceremony owner check and make tenant role configurable ([#5](https://github.com/savvagent/otto-platform/issues/5)) ([f2d755d](https://github.com/savvagent/otto-platform/commit/f2d755d191a67b620f14d38b156eba8d9706ac38)), closes [#2](https://github.com/savvagent/otto-platform/issues/2)
* **otto-core:** stop unverified domain claims from blocking the real owner ([#11](https://github.com/savvagent/otto-platform/issues/11)) ([c408e0d](https://github.com/savvagent/otto-platform/commit/c408e0db370f3076a2fe31a88d34b42c52e7fa2a)), closes [#6](https://github.com/savvagent/otto-platform/issues/6) [#2](https://github.com/savvagent/otto-platform/issues/2)
