# Alternatives to the otto name — why we are looking

> **Status:** RECORD (no decision)
> **Issue:** savvagent/otto-platform#126

## Goal

Record why we are exploring alternatives to `otto` as the shared name of the otto-* services (otto-tower, otto-flags, otto-cxp, the platform behind otto.savvagent.com, and `ottoctl`). This doc does not pick a new name, and it renames nothing.

We raised four concerns earlier but never wrote them down: trademark, searchability, domain availability and package-name availability. The findings below were checked again on **2026-10-30**. Registry and WHOIS results change over time, so re-check them before acting on any of this.

## Background: renames so far

- **otto-factory → otto-tower** (#81, `docs/specs/2026-10-21-otto-tower-rename-design.md`). We renamed this product because "factory" read as "dark factory" to engineers. That rename was not about "otto", but it gave us the machinery for a later one: resource-URI aliases with a sunset, guarded billing-slug renames, and new hosts that keep the old ones as aliases.
- **otto → ottoctl** (#114). The `otto` binary collided with a separate terminal coding agent that also installs a command named `otto` (it also ships `otto-*` provider and tool binaries). This is the first collision we actually hit, and the one that turned the concerns into work.

## Findings

### Trademark

These come from a desk search of third-party trademark databases, not the USPTO or EUIPO directly. They are not a clearance opinion.

- **Software in Class 9 or 42.** Several holders have registered OTTO for software:
  - TeleVet, Inc. (US Reg. 7517820, Class 9, registered 2024-09-24).
  - Otto, LLC (US Reg. 6515050, budgeting SaaS, Class 42, registered 2021).
  - DWFritz / OTTO Designworks (US Reg. 4882215, mobile calibration apps).
  - OTTO TECH SYSTEMS, filed by Otto Ladder Safety, Inc. (application pending).
- **Otto Group.** Otto GmbH & Co. KG, the German retail group, holds EU and US marks on "OTTO GROUP" and related names.
- **OTTO Motors.** Rockwell Automation sells autonomous mobile robots under the OTTO Motors name, with software called "OTTO Autonomy" and "OTTO Fleet Manager". It acquired the line through Clearpath Robotics in 2023 and has said it is keeping the branding. Our search found no record of the marks it holds.

**Why it matters:** "otto" is a crowded mark in exactly the classes our products fall into, which are downloadable software and SaaS. A suffix (`-tower`, `-flags`) narrows the conflict but does not remove it, and the shared "otto" family name is the part we would most want to protect.

### Searchability

- **Large, unrelated owners.** "otto" is a common given name and a common word. It is also the brand of a major European retailer (otto.de) and of an industrial-robotics line. These outrank a small developer-tools brand.
- **Other AI coding tools.** At least three are already called otto:
  - the `ottopilot` PyPI package (OttoAI, "a local-first, extensible coding agent"), which installs an `otto` command;
  - `@cmetech/otto` on npm, a terminal coding and operations assistant;
  - `kusold/otto` on GitHub, a Rust CLI that runs AI coding agents in a loop.

  These are the products a search for "otto agent", "otto cli" or "otto mcp" will mix ours up with.
- **Crowded registries.** npm search returns 359 packages for "otto", including the `@x-otto/*` family of coding and agent packages. A crates.io search for "otto" returns 59 crates.

**Why it matters:** we sell to developers and their agents, who find tools by name. A name that shares results with other agent tools in the same niche costs us discovery and confuses support.

### Domain availability

| Domain | State on 2026-10-30 |
|---|---|
| otto.com | Registered 1997, registrar Nameshield (a corporate brand registrar) |
| otto.io | Registered 2004, Nameshield |
| otto.ai | Registered 2017, 101domain |
| otto.sh | Registered 2003, Key-Systems |
| otto.dev | Registered, parked on Brandshelter name servers |
| ottoctl.com, ottoctl.dev, otto-tower.com, ottoflags.com | Unregistered |

**Why it matters:** every short otto domain is taken, mostly by brand-protection registrars, so we are unlikely to buy one. We live on `*.savvagent.com` subdomains: `otto.savvagent.com`, `otto-tower.savvagent.com`, `otto-flags.savvagent.com` and `otto-cxp.savvagent.com`. A compound name like `ottoctl` is available, but it only names the CLI.

### Package-name availability

| Registry | Name | State |
|---|---|---|
| crates.io | `otto` | Taken ("Release Rust crates with Otto from the terminal", published 2026-10-07) |
| crates.io | `otto-core` | Taken (same author, same date) |
| crates.io | `otto-auth`, `otto-billing`, `otto-client`, `otto-resource`, `otto-tenant`, `otto-web`, `otto-flags`, `otto-tower`, `otto-cxp`, `otto-platform`, `ottoctl` | Free |
| npm | `otto` | Taken (Otto.js) |
| npm | `otto-cli` | Taken ("AI-powered Git Release & Automation Tool") |
| npm | `@otto` scope | Unverified (npmjs.com refused the lookup); check by trying to create the org |
| npm | `ottoctl`, `otto-flags`, `otto-tower`, `otto-cxp` | Free |
| PyPI | `otto` | Taken (a WSGI publisher) |
| PyPI | `ottoctl`, `otto-flags` | Free |

**Why it matters:**
- **Our own crate name is already taken.** `otto-core` is the name of one of our crates and is taken on crates.io, so we cannot publish our workspace under its current names.
- **SDKs may have no clean namespace.** Unless we can get the `@otto` npm scope, SDKs for otto-flags and the other services would have to use a different scope or unscoped `otto-*` names that anyone can squat.
- **The free names may not stay free.** Two otto crates appeared on crates.io this month.

## What a rename would touch

These are the places "otto" appears today, so the size of any rename is visible before we pick a name:

- **Hosts and resource URIs.** These are the resource-URI audiences on every issued token:
  - `otto.savvagent.com`
  - `otto-tower.savvagent.com`
  - `otto-flags.savvagent.com`
  - `otto-cxp.savvagent.com`
  - `otto-factory.savvagent.com` (still an alias)

  The otto-tower alias mechanism covers resource servers. The platform's own issuer host is not covered.
- **MCP server names**, which become the tool prefixes agents see: `mcp__otto-tower__*`, `mcp__otto-flags__*`, `mcp__otto-cxp__*`. They are written into users' agent configs, permission allow-lists and skills.
- **Billing service slugs and meters**: `otto-tower/jobs_completed`, `otto-flags/evaluations`, `otto-cxp/*`. The tower rename found these to be the hardest identifiers to move once they exist in Stripe history. A guarded rename only works while no metered usage exists.
- **Token and secret prefixes**: `otto_platform_`, `otto_sso_`, `otto_ss_`, `otto_rs_`, `otto_factory_`. Secret scanners and existing credentials depend on them.
- **The CLI**: `ottoctl` and its `ottoctl flags` subcommands.
- **Crates**:
  - `otto-core`
  - `otto-auth`
  - `otto-billing`
  - `otto-client`
  - `otto-resource`
  - `otto-tenant`
  - `otto-web`
  - `otto-flags` (`crates/otto-flags-cli`)
  - `otto-platform-server`
- **Other internal identifiers**: about 15 `OTTO_*` environment variables, the Fly app `otto-platform`, and the `otto-platform-console` web package.

We could follow the otto-tower precedent: rename what users and agents see, and keep internal identifiers (crates, env vars, Fly apps, databases) unless they ship publicly. Publishing crates or SDKs would make the crate and package names user-visible.

## Open questions

1. **Scope of the rename:** the family name (replace "otto" everywhere) or only the colliding surfaces (the CLI is done; next would be published packages and SDKs)?
2. **Timing:** should we fix names before more billing meters record usage? Every new meter under `otto-*/` adds Stripe history to migrate.
3. **Legal check:** do we want a proper trademark clearance search on any candidate before committing, rather than another desk search?
4. **Candidate tests:** for any candidate, check the same four things at once: trademark in Classes 9 and 42, search results next to agent tooling, a short domain, and crates.io, npm and PyPI names plus an npm scope.

## Sources

- crates.io API (`/api/v1/crates/<name>`), npm registry (`registry.npmjs.org/<name>`), PyPI JSON API, and WHOIS/RDAP lookups, all queried 2026-10-30.
- Justia Trademarks, OTTO, Reg. 4882215: https://trademarks.justia.com/862/28/otto-86228949.html
- uspto.report, OTTO, Otto, LLC: https://uspto.report/TM/90333686
- Trademarkia, OTTO, TeleVet: https://www.trademarkia.com/otto-98012014
- uspto.report, OTTO TECH SYSTEMS: https://uspto.report/TM/90165393
- TrademarkElite, "otto group holding" EU mark: https://www.trademarkelite.com/europe/trademark/trademark-detail/018204044/otto-group-holding
- Robotics 24/7, Rockwell Automation on the OTTO Motors acquisition: https://www.robotics247.com/article/rockwell_automation_discusses_otto_motors_acquisition
- PyPI, ottopilot: https://pypi.org/project/ottopilot/
- GitHub, kusold/otto: https://github.com/kusold/otto
- pkgstats, @cmetech/otto: https://www.pkgstats.com/pkg:@cmetech/otto
