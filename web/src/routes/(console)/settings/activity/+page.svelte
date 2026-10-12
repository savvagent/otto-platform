<script lang="ts">
  import { api } from '$lib/api';
  import { messageFor } from '$lib/errors';
  import { m } from '$lib/paraglide/messages';
  import { absolute, relative } from '$lib/format';
  import type { AuditEvent } from '$lib/types';
  import Alert from '$lib/components/Alert.svelte';
  import Empty from '$lib/components/Empty.svelte';
  import Loading from '$lib/components/Loading.svelte';

  /**
   * The account's own security activity: `GET /api/me/audit`.
   *
   * The account-level counterpart to an org's audit log (`/o/[org]/audit`),
   * for the events that happen outside any org — signing in and out, and
   * adding, renaming or removing a passkey. Without it, somebody with no org
   * yet had no way to see any of their own security history at all.
   *
   * **What is not here, and why.** Only rows this account is the actor of. A
   * failed sign-in that never identified an account belongs to nobody, so it
   * is shown to nobody; and anything done inside an org is that org's record,
   * which its admins read. The note under the table says so, so an empty or
   * short list is not mistaken for "nothing ever tried".
   *
   * No actor column: every row is yours. The rows themselves are not
   * translated, for the same reason as the org log — an action is a stable
   * identifier and the detail is the server's JSON verbatim.
   */

  let events = $state<AuditEvent[]>([]);
  let loading = $state(true);
  let error = $state<string | undefined>(undefined);

  $effect(() => {
    void (async () => {
      try {
        events = await api.myAudit(200);
      } catch (e) {
        error = messageFor(e, m.activity_error_load());
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

<svelte:head><title>{m.activity_page_title()}</title></svelte:head>

<div class="space-y-5">
  <div>
    <a class="text-xs text-faint hover:text-muted" href="/settings">← {m.activity_back()}</a>
    <h1 class="mt-1 text-lg font-semibold">{m.activity_title()}</h1>
    <p class="mt-0.5 text-sm text-faint">{m.activity_subtitle()}</p>
  </div>

  {#if error}
    <Alert>{error}</Alert>
  {:else if loading}
    <Loading what={m.activity_loading()} />
  {:else if events.length === 0}
    <Empty title={m.activity_empty()} />
  {:else}
    <div class="otto-card overflow-x-auto">
      <table class="w-full text-sm">
        <thead class="border-b border-edge/60 text-left text-xs text-faint">
          <tr>
            <th class="px-4 py-2 font-medium">{m.audit_col_when()}</th>
            <th class="px-4 py-2 font-medium">{m.audit_col_action()}</th>
            <th class="px-4 py-2 font-medium">{m.audit_col_target()}</th>
            <th class="px-4 py-2 font-medium">{m.activity_col_address()}</th>
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
              <td class="px-4 py-2 text-muted">
                {event.targetType ? `${event.targetType} ${event.targetId ?? ''}` : '—'}
              </td>
              <td class="otto-mono px-4 py-2 whitespace-nowrap text-muted">{event.ip ?? '—'}</td>
              <td class="otto-mono max-w-64 truncate px-4 py-2 text-faint" title={detail(event)}>
                {detail(event)}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}

  <p class="text-xs text-faint">{m.activity_scope_note()}</p>
</div>
