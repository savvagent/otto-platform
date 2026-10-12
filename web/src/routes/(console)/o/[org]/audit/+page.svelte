<script lang="ts">
  import { api } from '$lib/api';
  import { messageFor } from '$lib/errors';
  import { m } from '$lib/paraglide/messages';
  import { useOrg } from '$lib/org.svelte';
  import { absolute, relative } from '$lib/format';
  import type { AuditEvent } from '$lib/types';
  import Alert from '$lib/components/Alert.svelte';
  import Empty from '$lib/components/Empty.svelte';
  import Loading from '$lib/components/Loading.svelte';

  /**
   * The security log.
   *
   * Admin-only, unlike every other read in this console. Membership changes,
   * token issuance, and failed logins are exactly the trail an attacker holding
   * a low-privilege session would read before choosing whom to target — so the
   * server refuses a member, and this page is only in the sidebar for an admin.
   * The `403` is still the server's to give; hiding the link is a courtesy.
   *
   * **The rows themselves are not translated, and that is deliberate.** An
   * action is a stable identifier (`member.role_changed`), and the detail is
   * the server's JSON payload verbatim. A log read as evidence has to say the
   * same thing to everyone who reads it; only the chrome around it is prose.
   */

  const org = useOrg();

  let events = $state<AuditEvent[]>([]);
  let loading = $state(true);
  let error = $state<string | undefined>(undefined);

  $effect(() => {
    const slug = org.slug;
    if (!slug) return;

    loading = true;
    error = undefined;

    void (async () => {
      try {
        const found = await api.audit(slug, 200);
        if (org.slug !== slug) return;
        events = found;
      } catch (e) {
        error = messageFor(e, m.audit_error_load());
      } finally {
        loading = false;
      }
    })();
  });

  function detail(event: AuditEvent): string {
    const keys = Object.keys(event.detail ?? {});
    return keys.length > 0 ? JSON.stringify(event.detail) : '';
  }
</script>

<div class="space-y-5">
  <div>
    <h1 class="text-lg font-semibold">{m.audit_title()}</h1>
    <p class="mt-0.5 text-sm text-faint">
      {m.audit_subtitle({ org: org.title })}
    </p>
  </div>

  {#if error}
    <Alert>{error}</Alert>
  {:else if loading && events.length === 0}
    <Loading what={m.audit_loading()} />
  {:else if events.length === 0}
    <Empty title={m.audit_empty()} />
  {:else}
    <div class="otto-card overflow-x-auto">
      <table class="w-full text-sm">
        <thead class="border-b border-edge/60 text-left text-xs text-faint">
          <tr>
            <th class="px-4 py-2 font-medium">{m.audit_col_when()}</th>
            <th class="px-4 py-2 font-medium">{m.audit_col_action()}</th>
            <th class="px-4 py-2 font-medium">{m.audit_col_actor()}</th>
            <th class="px-4 py-2 font-medium">{m.audit_col_target()}</th>
            <th class="px-4 py-2 font-medium">{m.audit_col_detail()}</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-edge/40">
          {#each events as event (event.id)}
            <tr class="hover:bg-raised/40">
              <td class="px-4 py-2 whitespace-nowrap text-faint" title={absolute(event.createdAt)}>
                {relative(event.createdAt)}
              </td>
              <td class="otto-mono px-4 py-2 whitespace-nowrap text-ink">{event.action}</td>
              <td class="px-4 py-2 text-muted">{event.actorLabel ?? event.actorUserId ?? '—'}</td>
              <td class="px-4 py-2 text-muted">
                {event.targetType ? `${event.targetType} ${event.targetId ?? ''}` : '—'}
              </td>
              <td class="otto-mono max-w-64 truncate px-4 py-2 text-faint" title={detail(event)}>
                {detail(event)}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</div>
