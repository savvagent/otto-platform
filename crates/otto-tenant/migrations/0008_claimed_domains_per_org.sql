-- Domain claims are unique per org, and only *verified* claims are unique
-- per domain (savvagent/otto-platform#6).
--
-- 0006 made `domain` the primary key, so the first org to claim a domain held
-- it whether or not it ever proved control. Any org could claim, say,
-- `bigcorp.com`, never verify it, and permanently block BigCorp from setting
-- up SSO. Now any number of orgs may hold a pending claim, the first to pass
-- DNS verification wins, and a verified claim blocks every other org from
-- claiming or verifying that domain until it is released.

ALTER TABLE claimed_domains DROP CONSTRAINT claimed_domains_pkey;
ALTER TABLE claimed_domains ADD PRIMARY KEY (org_id, domain);

-- At most one verified claim per domain. Routing (idp::resolve_for_domain)
-- reads only verified rows, so this is what keeps a domain routing to exactly
-- one org. Domains are stored lowercased (domains::normalize_domain).
CREATE UNIQUE INDEX claimed_domains_verified_domain_key
  ON claimed_domains (domain)
  WHERE verified_at IS NOT NULL;

-- The new primary key leads with org_id, which covers this index's lookups.
DROP INDEX claimed_domains_org_idx;
