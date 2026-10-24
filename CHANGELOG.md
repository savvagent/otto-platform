# Changelog

## [0.12.1](https://github.com/savvagent/otto-platform/compare/v0.12.0...v0.12.1) (2026-10-24)


### Bug Fixes

* **otto-core:** retry lifecycle webhooks for about a day, as documented ([#110](https://github.com/savvagent/otto-platform/issues/110)) ([dc22a3f](https://github.com/savvagent/otto-platform/commit/dc22a3f585b85de7df4f57f95ffa2b0a4a938d4c))
* **otto-platform-server:** make the member-lookup cache test independent of wall-clock timing ([#111](https://github.com/savvagent/otto-platform/issues/111)) ([54ce9bd](https://github.com/savvagent/otto-platform/commit/54ce9bd8740d550c40347e4e47deda2d1cfbe27a))
* **otto-tenant:** rebuild when a migration is added ([#109](https://github.com/savvagent/otto-platform/issues/109)) ([72c2cf2](https://github.com/savvagent/otto-platform/commit/72c2cf28e3df8a8988297e2dcd45783ca07c568a)), closes [#71](https://github.com/savvagent/otto-platform/issues/71)
* **otto-tenant:** run the tenant-role probe on the connection Db::begin already holds ([#113](https://github.com/savvagent/otto-platform/issues/113)) ([98d07d5](https://github.com/savvagent/otto-platform/commit/98d07d58de9be8e2779cbcd9c98c329cf7287072))

## [0.12.0](https://github.com/savvagent/otto-platform/compare/v0.11.1...v0.12.0) (2026-10-24)


### Features

* **otto-billing:** bill only orgs that authorized the calling resource server ([#96](https://github.com/savvagent/otto-platform/issues/96)) ([1a2245b](https://github.com/savvagent/otto-platform/commit/1a2245b8aa135827ca39ffb2210cb91dab138bae))
* **otto-billing:** cancel Stripe billing when an org is deleted ([#99](https://github.com/savvagent/otto-platform/issues/99)) ([cae56fe](https://github.com/savvagent/otto-platform/commit/cae56fe0d31f1bf2f5baa83da13487ff42675595))
* **otto-cli:** add the otto command with MCP-style login ([#103](https://github.com/savvagent/otto-platform/issues/103)) ([a95af5b](https://github.com/savvagent/otto-platform/commit/a95af5bd5aa298f074e8ac170f19f5cbfccaab8e)), closes [#102](https://github.com/savvagent/otto-platform/issues/102)
* **otto-cli:** build otto for Linux, macOS and Windows ([#106](https://github.com/savvagent/otto-platform/issues/106)) ([84f1a6a](https://github.com/savvagent/otto-platform/commit/84f1a6a87aeffcb023dbfdfe704253631a85933c))
* **otto-flags-cli:** issue Otto Flags app keys from the terminal ([#107](https://github.com/savvagent/otto-platform/issues/107)) ([62b7cae](https://github.com/savvagent/otto-platform/commit/62b7cae8e6a83f56e9d40cb2776426983ea3cbc0))


### Bug Fixes

* **otto-auth:** close the remaining revocation races in PAT minting, code issuance and token revocation ([#98](https://github.com/savvagent/otto-platform/issues/98)) ([9b9c63f](https://github.com/savvagent/otto-platform/commit/9b9c63f70af021abc9853705bda5e86f11f8f504))
* **otto-billing:** record Stripe meter error reports as lost usage ([#97](https://github.com/savvagent/otto-platform/issues/97)) ([55898c4](https://github.com/savvagent/otto-platform/commit/55898c4613b1d26968b3583d6c813d98301f6fbb))

## [0.11.1](https://github.com/savvagent/otto-platform/compare/v0.11.0...v0.11.1) (2026-10-21)


### Bug Fixes

* **web:** move otto-tower links to the new host ([#93](https://github.com/savvagent/otto-platform/issues/93)) ([2434244](https://github.com/savvagent/otto-platform/commit/24342440d67a413bc1c065171602922bf33b61cb)), closes [#81](https://github.com/savvagent/otto-platform/issues/81)

## [0.11.0](https://github.com/savvagent/otto-platform/compare/v0.10.0...v0.11.0) (2026-10-21)


### Features

* rename otto-factory to otto-tower with guarded service and resource renames ([#92](https://github.com/savvagent/otto-platform/issues/92)) ([6726ce8](https://github.com/savvagent/otto-platform/commit/6726ce8c06a7123162dfb9f7857a1f013a6d8e73))

## [0.10.0](https://github.com/savvagent/otto-platform/compare/v0.9.2...v0.10.0) (2026-10-20)


### Features

* bill each otto service by its own value meters, with spend budgets ([#84](https://github.com/savvagent/otto-platform/issues/84)) ([919e01d](https://github.com/savvagent/otto-platform/commit/919e01d29e53f526c037ae69a093f2547eeed34f)), closes [#55](https://github.com/savvagent/otto-platform/issues/55) [#56](https://github.com/savvagent/otto-platform/issues/56) [#57](https://github.com/savvagent/otto-platform/issues/57) [#58](https://github.com/savvagent/otto-platform/issues/58) [#59](https://github.com/savvagent/otto-platform/issues/59) [#60](https://github.com/savvagent/otto-platform/issues/60) [#61](https://github.com/savvagent/otto-platform/issues/61) [#62](https://github.com/savvagent/otto-platform/issues/62) [#63](https://github.com/savvagent/otto-platform/issues/63) [#64](https://github.com/savvagent/otto-platform/issues/64) [#65](https://github.com/savvagent/otto-platform/issues/65) [#74](https://github.com/savvagent/otto-platform/issues/74)

## [0.9.2](https://github.com/savvagent/otto-platform/compare/v0.9.1...v0.9.2) (2026-10-15)


### Bug Fixes

* **otto-auth:** refuse a PAT that resolves to no scopes ([#53](https://github.com/savvagent/otto-platform/issues/53)) ([4cd6042](https://github.com/savvagent/otto-platform/commit/4cd60420d77714d3e71dfc3da528df11bc46d258)), closes [#52](https://github.com/savvagent/otto-platform/issues/52)

## [0.9.1](https://github.com/savvagent/otto-platform/compare/v0.9.0...v0.9.1) (2026-10-15)


### Bug Fixes

* **otto-auth:** refuse an authorization request that resolves to no scopes ([#51](https://github.com/savvagent/otto-platform/issues/51)) ([71f24f7](https://github.com/savvagent/otto-platform/commit/71f24f7c16e0e6c73312d4288a08c87e143a2f3d)), closes [#49](https://github.com/savvagent/otto-platform/issues/49)
* **otto-auth:** refuse an empty scope list at code issuance ([#48](https://github.com/savvagent/otto-platform/issues/48)) ([a6d03ac](https://github.com/savvagent/otto-platform/commit/a6d03ac6eae03090ca631a378bc8bcb7113d5dee)), closes [#46](https://github.com/savvagent/otto-platform/issues/46)

## [0.9.0](https://github.com/savvagent/otto-platform/compare/v0.8.0...v0.9.0) (2026-10-15)


### Features

* **otto-web:** let a person narrow a connector's scopes on the consent screen ([#45](https://github.com/savvagent/otto-platform/issues/45)) ([82b17dc](https://github.com/savvagent/otto-platform/commit/82b17dc0809c00c71273d8e43dd828742566e276)), closes [#43](https://github.com/savvagent/otto-platform/issues/43)

## [0.8.0](https://github.com/savvagent/otto-platform/compare/v0.7.0...v0.8.0) (2026-10-15)


### Features

* **web:** send agent-only services to their connect card, not their origin ([#42](https://github.com/savvagent/otto-platform/issues/42)) ([bd2212f](https://github.com/savvagent/otto-platform/commit/bd2212fdc50754fd8d68264f85d07fd25353dba9))

## [0.7.0](https://github.com/savvagent/otto-platform/compare/v0.6.1...v0.7.0) (2026-10-14)


### Features

* **web:** list otto-cxp among the otto services ([#39](https://github.com/savvagent/otto-platform/issues/39)) ([bae939f](https://github.com/savvagent/otto-platform/commit/bae939fb554c38a220904b1f9f9bd1ce5814800d))

## [0.6.1](https://github.com/savvagent/otto-platform/compare/v0.6.0...v0.6.1) (2026-10-12)


### Bug Fixes

* **web:** show the call count in the usage meter captions ([#37](https://github.com/savvagent/otto-platform/issues/37)) ([9d90b60](https://github.com/savvagent/otto-platform/commit/9d90b608659566f20c0f0c238c4990237a724eac))

## [0.6.0](https://github.com/savvagent/otto-platform/compare/v0.5.0...v0.6.0) (2026-10-12)


### Features

* **web:** market the otto-* services from otto.savvagent.com ([#35](https://github.com/savvagent/otto-platform/issues/35)) ([7b70e8a](https://github.com/savvagent/otto-platform/commit/7b70e8a156feb30a39289591755a16b82a51acae))

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
