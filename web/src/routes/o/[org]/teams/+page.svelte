<script lang="ts">
  import { api } from '$lib/api';
  import { messageFor } from '$lib/errors';
  import { m } from '$lib/paraglide/messages';
  import { useOrg } from '$lib/org.svelte';
  import { slugPreview, person } from '$lib/format';
  import type { OrgMember, Team, TeamMember } from '$lib/types';
  import Alert from '$lib/components/Alert.svelte';
  import Button from '$lib/components/Button.svelte';
  import Card from '$lib/components/Card.svelte';
  import Empty from '$lib/components/Empty.svelte';
  import Field from '$lib/components/Field.svelte';
  import Loading from '$lib/components/Loading.svelte';

  /**
   * Teams — a grouping of members inside an org.
   *
   * The platform only records who is on which team. What a team scopes (a
   * service's repos, queues, projects) belongs to that service, which reads the
   * roster from here.
   */

  const org = useOrg();

  let teams = $state<Team[]>([]);
  let members = $state<OrgMember[]>([]);
  let rosters = $state<Record<string, TeamMember[]>>({});
  let expanded = $state<string | undefined>(undefined);
  let loading = $state(true);
  let error = $state<string | undefined>(undefined);
  let busy = $state<string | undefined>(undefined);

  let slug = $state('');
  let name = $state('');
  let creating = $state(false);
  let formError = $state<string | undefined>(undefined);

  $effect(() => {
    const org_ = org.slug;
    if (!org_) return;

    loading = true;
    error = undefined;

    void (async () => {
      try {
        const [t, m_] = await Promise.all([api.teams(org_), api.members(org_)]);
        if (org.slug !== org_) return;
        teams = t;
        members = m_;
      } catch (e) {
        error = messageFor(e, m.teams_error_load());
      } finally {
        loading = false;
      }
    })();
  });

  async function openTeam(team: Team) {
    if (expanded === team.slug) {
      expanded = undefined;
      return;
    }
    expanded = team.slug;
    await loadRoster(team.slug);
  }

  async function loadRoster(teamSlug: string) {
    try {
      rosters = { ...rosters, [teamSlug]: await api.teamMembers(org.slug, teamSlug) };
    } catch (e) {
      error = messageFor(e, m.teams_error_read());
    }
  }

  async function create(event: SubmitEvent) {
    event.preventDefault();
    creating = true;
    formError = undefined;
    try {
      await api.createTeam(org.slug, slugPreview(slug), name.trim());
      slug = '';
      name = '';
      teams = await api.teams(org.slug);
    } catch (e) {
      formError = messageFor(e, m.teams_error_create());
    } finally {
      creating = false;
    }
  }

  async function act(key: string, action: () => Promise<unknown>, teamSlug?: string) {
    busy = key;
    error = undefined;
    try {
      await action();
      teams = await api.teams(org.slug);
      if (teamSlug) await loadRoster(teamSlug);
    } catch (e) {
      error = messageFor(e, m.error_that_did_not_work());
    } finally {
      busy = undefined;
    }
  }

  /** Org members not already on the expanded team. */
  const candidates = $derived((teamSlug: string) => {
    const on = new Set((rosters[teamSlug] ?? []).map((m_) => m_.userId));
    return members.filter((m_) => !on.has(m_.id));
  });
</script>

<div class="space-y-5">
  <div>
    <h1 class="text-lg font-semibold">{m.teams_title()}</h1>
    <p class="mt-0.5 text-sm text-faint">
      {m.teams_subtitle()}
    </p>
  </div>

  {#if error}<Alert>{error}</Alert>{/if}

  {#if org.isAdmin}
    <Card title={m.teams_new_title()}>
      <form class="flex flex-wrap items-end gap-3" onsubmit={create}>
        <div class="w-44">
          <Field label={m.teams_field_slug()}>
            <input class="otto-input otto-mono" required bind:value={slug} />
          </Field>
        </div>
        <div class="min-w-48 flex-1">
          <Field label={m.teams_field_name()} hint={m.teams_field_name_hint()}>
            <input class="otto-input" bind:value={name} />
          </Field>
        </div>
        <div class="pb-0.5">
          <Button type="submit" pending={creating}>{m.teams_create()}</Button>
        </div>
      </form>
      {#if formError}<div class="mt-3"><Alert>{formError}</Alert></div>{/if}
    </Card>
  {/if}

  {#if loading && teams.length === 0}
    <Loading what={m.teams_loading()} />
  {:else if teams.length === 0}
    <Empty title={m.teams_empty_title()}>
      {m.teams_empty_body()}
    </Empty>
  {:else}
    <ul class="space-y-2">
      {#each teams as team (team.id)}
        <li class="otto-card">
          <div class="flex flex-wrap items-center gap-3 px-4 py-3">
            <div class="min-w-0 flex-1">
              <span class="otto-mono text-sm text-ink">{team.slug}</span>
              <p class="text-xs text-faint">{team.name}</p>
            </div>

            <button
              class="text-xs text-muted underline hover:text-ink"
              onclick={() => openTeam(team)}
              aria-expanded={expanded === team.slug}
            >
              {expanded === team.slug ? m.teams_hide_members() : m.teams_show_members()}
            </button>

            {#if org.isAdmin}
              <Button
                tone="danger"
                pending={busy === `${team.id}:delete`}
                onclick={() => act(`${team.id}:delete`, () => api.deleteTeam(org.slug, team.slug))}
              >
                {m.teams_delete()}
              </Button>
            {/if}
          </div>

          {#if expanded === team.slug}
            {@const roster = rosters[team.slug]}
            <div class="space-y-3 border-t border-edge/60 px-4 py-3">
              {#if !roster}
                <Loading what={m.teams_roster_loading()} />
              {:else if roster.length === 0}
                <p class="text-xs text-faint">{m.teams_roster_empty()}</p>
              {:else}
                <ul class="divide-y divide-edge/40">
                  {#each roster as member (member.userId)}
                    <li class="flex items-center gap-3 py-2 text-sm">
                      <span class="min-w-0 flex-1 truncate text-muted">
                        {person(member.name, member.email, member.label)}
                      </span>
                      {#if org.isAdmin}
                        <Button
                          tone="quiet"
                          pending={busy === `${team.id}:${member.userId}`}
                          onclick={() =>
                            act(
                              `${team.id}:${member.userId}`,
                              () => api.removeTeamMember(org.slug, team.slug, member.userId),
                              team.slug
                            )}
                        >
                          {m.teams_remove_member()}
                        </Button>
                      {/if}
                    </li>
                  {/each}
                </ul>
              {/if}

              {#if org.isAdmin && candidates(team.slug).length > 0}
                <label class="flex items-end gap-2">
                  <span class="sr-only">{m.teams_add_member_label({ team: team.slug })}</span>
                  <select
                    class="otto-input w-64"
                    value=""
                    onchange={(e) => {
                      const user = e.currentTarget.value;
                      e.currentTarget.value = '';
                      if (user) {
                        void act(
                          `${team.id}:add`,
                          () => api.addTeamMember(org.slug, team.slug, user),
                          team.slug
                        );
                      }
                    }}
                  >
                    <option value="">{m.teams_add_member_option()}</option>
                    {#each candidates(team.slug) as member (member.id)}
                      <option value={member.id}
                        >{person(member.name, member.email, member.label)}</option
                      >
                    {/each}
                  </select>
                </label>
              {/if}
            </div>
          {/if}
        </li>
      {/each}
    </ul>
  {/if}
</div>
