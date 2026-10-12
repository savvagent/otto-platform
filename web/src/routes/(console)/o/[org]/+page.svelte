<script lang="ts">
  import { api } from '$lib/api';
  import { messageFor } from '$lib/errors';
  import { m } from '$lib/paraglide/messages';
  import { currentLocale } from '$lib/locale';
  import { useOrg } from '$lib/org.svelte';
  import { roleLabel } from '$lib/labels';
  import { SERVICES } from '$lib/services';
  import type { OrgMember, Team, UsageStatus } from '$lib/types';
  import Alert from '$lib/components/Alert.svelte';
  import Card from '$lib/components/Card.svelte';
  import Empty from '$lib/components/Empty.svelte';
  import Loading from '$lib/components/Loading.svelte';
  import Meter from '$lib/components/Meter.svelte';

  /**
   * The organization overview: who is in it, what plan it is on, how much of
   * the period's bucket has gone, and where to go to use the services it has.
   *
   * It owns identity and billing only. What an org *does* with a service (queues,
   * repositories, trackers) lives in that service's own console, which this page
   * links to from `SERVICES`.
   *
   * The three reads land as one value so a render never pairs one request's
   * member count with another's meter. They are plain `GET`s, not polled: nothing
   * here changes while nobody is touching the browser.
   */

  const org = useOrg();

  interface Overview {
    members: OrgMember[];
    teams: Team[];
    usage: UsageStatus;
  }

  let overview = $state<Overview | undefined>(undefined);
  let error = $state<string | undefined>(undefined);

  $effect(() => {
    const slug = org.slug;
    if (!slug) return;

    overview = undefined;
    error = undefined;

    void (async () => {
      try {
        const [members, teams, usage] = await Promise.all([
          api.members(slug),
          api.teams(slug),
          api.usage(slug)
        ]);
        // A fast navigation between two orgs can land the first fetch after the
        // second; applying it would show one org's numbers under the other's name.
        if (org.slug !== slug) return;
        overview = { members, teams, usage };
      } catch (e) {
        if (org.slug === slug) error = messageFor(e, m.overview_load_failed());
      }
    })();
  });

  const tiles = $derived(
    overview
      ? [
          { label: m.overview_tile_members(), value: overview.members.length, href: 'members' },
          { label: m.overview_tile_teams(), value: overview.teams.length, href: 'teams' }
        ]
      : []
  );
</script>

<div class="space-y-6">
  <div>
    <h1 class="text-lg font-semibold">{org.title}</h1>
    <p class="mt-0.5 text-sm text-faint">
      <code class="otto-mono">{org.slug}</code> · {m.overview_role_and_plan({
        role: org.role ? roleLabel(org.role) : '—',
        plan: org.org?.plan ?? '—'
      })}
    </p>
  </div>

  {#if error}
    <Alert>{error}</Alert>
  {:else if !overview}
    <Loading what={m.overview_loading()} />
  {:else}
    <div class="grid grid-cols-2 gap-3">
      {#each tiles as tile (tile.href)}
        <a class="otto-card px-4 py-3 transition hover:bg-raised" href="/o/{org.slug}/{tile.href}">
          <div class="text-2xl font-semibold text-ink">
            {tile.value.toLocaleString(currentLocale())}
          </div>
          <div class="mt-0.5 text-xs text-faint">{tile.label}</div>
        </a>
      {/each}
    </div>

    <div class="grid gap-6 lg:grid-cols-2">
      <Card title={m.overview_period_title()} description={m.overview_period_description()}>
        {#snippet actions()}
          <a class="text-xs text-muted underline hover:text-ink" href="/o/{org.slug}/usage">
            {m.overview_period_details()}
          </a>
        {/snippet}
        <Meter usage={overview.usage} compact />
      </Card>

      <Card title={m.overview_services_title()} description={m.overview_services_description()}>
        {#if SERVICES.length === 0}
          <Empty title={m.overview_services_empty_title()}>
            {m.overview_services_empty_hint()}
          </Empty>
        {:else}
          <ul class="flex flex-wrap gap-2">
            {#each SERVICES as service (service.url)}
              <li>
                <a
                  class="block rounded-md border border-edge px-3 py-1.5 text-sm text-muted transition hover:bg-raised hover:text-ink"
                  href={service.url}
                >
                  {service.name}
                </a>
              </li>
            {/each}
          </ul>
        {/if}
      </Card>
    </div>
  {/if}
</div>
