<script lang="ts">
  import { api } from '$lib/api';
  import { messageFor } from '$lib/errors';
  import { m } from '$lib/paraglide/messages';
  import { roleLabel } from '$lib/labels';
  import { useOrg } from '$lib/org.svelte';
  import { session } from '$lib/session.svelte';
  import { relative, person } from '$lib/format';
  import type { ClaimCode, CreatedInvite, Invite, OrgMember, Role } from '$lib/types';
  import Alert from '$lib/components/Alert.svelte';
  import Button from '$lib/components/Button.svelte';
  import Card from '$lib/components/Card.svelte';
  import CopyField from '$lib/components/CopyField.svelte';
  import Empty from '$lib/components/Empty.svelte';
  import Field from '$lib/components/Field.svelte';
  import Loading from '$lib/components/Loading.svelte';

  /**
   * Members and outstanding invitations.
   *
   * The roster is open to any member — who else is in your own org is not
   * privileged — while every button that changes something is admin-only. That
   * split is the server's; this page mirrors it so a member is not offered
   * controls that would fail, but the server is what enforces it.
   *
   * Two rules the server keeps and this page has to explain rather than
   * re-implement: only an owner may create or demote another owner, and the
   * last owner can be neither demoted nor removed. Both arrive as errors with
   * codes this bundle has sentences for.
   */

  const org = useOrg();

  let members = $state<OrgMember[]>([]);
  let invites = $state<Invite[]>([]);
  let loading = $state(true);
  let error = $state<string | undefined>(undefined);
  let busy = $state<string | undefined>(undefined);

  let inviteEmail = $state('');
  let inviteRole = $state<Role>('member');
  let inviting = $state(false);
  let inviteError = $state<string | undefined>(undefined);
  let minted = $state<CreatedInvite | undefined>(undefined);
  let claim = $state<ClaimCode | undefined>(undefined);

  $effect(() => {
    const slug = org.slug;
    const admin = org.isAdmin;
    if (!slug) return;

    loading = true;
    error = undefined;

    void (async () => {
      try {
        members = await api.members(slug);
        // Invitations are admin-only. A member asking for them gets a 403, and
        // spending a request to be told that on every page load is noise.
        invites = admin ? await api.invites(slug) : [];
      } catch (e) {
        error = messageFor(e, m.members_error_load());
      } finally {
        loading = false;
      }
    })();
  });

  async function reload() {
    members = await api.members(org.slug);
    if (org.isAdmin) invites = await api.invites(org.slug);
  }

  async function act(key: string, action: () => Promise<unknown>) {
    busy = key;
    error = undefined;
    try {
      await action();
      await reload();
      // Removing yourself changes your own memberships, and the org switcher in
      // the header reads them.
      await session.refresh();
    } catch (e) {
      error = messageFor(e, m.error_that_did_not_work());
    } finally {
      busy = undefined;
    }
  }

  async function invite(event: SubmitEvent) {
    event.preventDefault();
    inviting = true;
    inviteError = undefined;
    minted = undefined;
    try {
      // The code comes back here and nowhere else — only its hash is stored,
      // so it cannot be read back and must stay on screen until the admin has
      // actually delivered it.
      minted = await api.invite(org.slug, inviteEmail.trim(), inviteRole);
      inviteEmail = '';
      inviteRole = 'member';
      invites = await api.invites(org.slug);
    } catch (e) {
      inviteError = messageFor(e, m.members_error_invite());
    } finally {
      inviting = false;
    }
  }

  /**
   * Clear a member's passkeys and hold on to the code that comes back.
   *
   * Kept on screen until dismissed, because it is returned exactly once — only
   * its hash is stored, so an admin who navigates away has to reset again.
   */
  async function resetPasskeys(memberId: string) {
    busy = `${memberId}:reset`;
    error = undefined;
    claim = undefined;
    try {
      claim = await api.resetMemberPasskeys(org.slug, memberId);
    } catch (e) {
      error = messageFor(e, m.members_error_reset());
    } finally {
      busy = undefined;
    }
  }

  const roles: Role[] = ['owner', 'admin', 'member'];

  /**
   * The word for a role, for display only.
   *
   * `owner` / `admin` / `member` are wire values: they are what the `<option>`
   * carries and what `setMemberRole` sends. This translates the label beside
   * them and never the value itself.
   */
</script>

<div class="space-y-5">
  <div>
    <h1 class="text-lg font-semibold">{m.members_title()}</h1>
    <p class="mt-0.5 text-sm text-faint">
      {m.members_subtitle({ org: org.title })}
    </p>
  </div>

  {#if error}<Alert>{error}</Alert>{/if}

  {#if claim}
    <div class="space-y-3 rounded-lg border border-warn/40 bg-warn/5 p-4">
      <p class="text-sm text-ink">
        {m.members_claim_headline()}
        <span class="text-muted">{m.members_claim_caveat()}</span>
      </p>
      <CopyField label={m.members_copy_link()} value={claim.link} />
      <CopyField label={m.members_copy_code()} value={claim.code} />
      <p class="text-xs text-faint">
        {m.members_claim_note()}
      </p>
      <Button tone="quiet" onclick={() => (claim = undefined)}>{m.members_claim_done()}</Button>
    </div>
  {/if}

  {#if org.isAdmin}
    <Card title={m.members_invite_title()} description={m.members_invite_description()}>
      <form class="flex flex-wrap items-end gap-3" onsubmit={invite}>
        <div class="min-w-56 flex-1">
          <Field label={m.members_field_email()}>
            <input class="otto-input" type="email" required bind:value={inviteEmail} />
          </Field>
        </div>
        <div class="w-36">
          <Field label={m.members_field_role()}>
            <select class="otto-input" bind:value={inviteRole}>
              <option value="member">{m.members_role_member()}</option>
              <option value="admin">{m.members_role_admin()}</option>
              {#if org.isOwner}<option value="owner">{m.members_role_owner()}</option>{/if}
            </select>
          </Field>
        </div>
        <div class="pb-0.5">
          <Button type="submit" pending={inviting}>{m.members_invite_submit()}</Button>
        </div>
      </form>

      {#if inviteError}<div class="mt-3"><Alert>{inviteError}</Alert></div>{/if}
      {#if minted}
        <div class="mt-4 space-y-3 rounded-lg border border-ok/40 bg-ok/5 p-4">
          <p class="text-sm text-ink">
            {m.members_invite_minted_headline({ email: minted.email })}
            <span class="text-muted">{m.members_invite_minted_caveat()}</span>
          </p>
          <CopyField label={m.members_copy_link()} value={minted.link} />
          <CopyField label={m.members_copy_code()} value={minted.code} />
          <p class="text-xs text-faint">
            {m.members_invite_minted_note({ email: minted.email })}
          </p>
        </div>
      {/if}
    </Card>
  {/if}

  {#if loading && members.length === 0}
    <Loading what={m.members_loading()} />
  {:else}
    <Card title={m.members_roster_title()}>
      <ul class="divide-y divide-edge/40">
        {#each members as member (member.id)}
          {@const isMe = member.id === session.me?.user.id}
          <li class="flex flex-wrap items-center gap-3 py-2.5">
            <div class="min-w-0 flex-1">
              <div class="flex items-center gap-2 text-sm">
                <span class="text-ink">{person(member.name, member.email, member.label)}</span>
                {#if isMe}<span class="text-xs text-faint">{m.members_you()}</span>{/if}
                {#if member.disabledAt}
                  <span class="rounded-full border border-bad/50 px-2 py-0.5 text-xs text-bad">
                    {m.members_badge_disabled()}
                  </span>
                {/if}
              </div>
              <p class="text-xs text-faint">
                {m.members_row_meta({
                  email: member.email ?? member.label,
                  when: relative(member.joinedAt)
                })}
              </p>
            </div>

            {#if org.isAdmin}
              <select
                class="otto-input w-28"
                value={member.role}
                disabled={busy === member.id}
                onchange={(e) =>
                  act(member.id, () =>
                    api.setMemberRole(org.slug, member.id, e.currentTarget.value as Role)
                  )}
              >
                {#each roles as role (role)}
                  <!-- Only an owner may create or demote an owner; the server
                       refuses otherwise, and offering the option would be a
                       button that exists only to fail. -->
                  <option
                    value={role}
                    disabled={!org.isOwner && (role === 'owner' || member.role === 'owner')}
                  >
                    {roleLabel(role)}
                  </option>
                {/each}
              </select>

              <Button
                tone="quiet"
                pending={busy === `${member.id}:logout`}
                title={m.members_force_logout_title()}
                onclick={() =>
                  act(`${member.id}:logout`, () => api.forceLogout(org.slug, member.id))}
              >
                {m.members_force_logout()}
              </Button>

              <!-- The only assisted account recovery there is. No email means
                   no recovery link, so an admin is the last resort for someone
                   who has lost every device they registered. The code it
                   returns is what stops the emptied account being claimable by
                   whoever reaches registration first. -->
              {#if org.isOwner || member.role !== 'owner'}
                <Button
                  tone="quiet"
                  pending={busy === `${member.id}:reset`}
                  title={m.members_reset_title()}
                  onclick={() => {
                    if (
                      confirm(
                        m.members_reset_confirm({
                          who: member.email ?? member.label
                        })
                      )
                    ) {
                      resetPasskeys(member.id);
                    }
                  }}
                >
                  {m.members_reset_button()}
                </Button>
              {/if}
            {/if}

            {#if org.isAdmin || isMe}
              <Button
                tone="danger"
                pending={busy === `${member.id}:remove`}
                onclick={() =>
                  act(`${member.id}:remove`, () => api.removeMember(org.slug, member.id))}
              >
                {isMe ? m.members_leave() : m.members_remove()}
              </Button>
            {/if}
          </li>
        {/each}
      </ul>

      <p class="mt-3 text-xs text-faint">
        {m.members_roster_note()}
      </p>
    </Card>

    {#if org.isAdmin}
      <Card title={m.members_invites_title()}>
        {#if invites.length === 0}
          <Empty title={m.members_invites_empty()} />
        {:else}
          <ul class="divide-y divide-edge/40">
            {#each invites as pending (pending.id)}
              <li class="flex items-center gap-3 py-2.5 text-sm">
                <div class="min-w-0 flex-1">
                  <span class="text-ink">{pending.email}</span>
                  <p class="text-xs text-faint">
                    {m.members_invite_row_meta({
                      role: roleLabel(pending.role),
                      when: relative(pending.expiresAt)
                    })}
                  </p>
                </div>
                <Button
                  tone="quiet"
                  pending={busy === pending.id}
                  onclick={() => act(pending.id, () => api.revokeInvite(org.slug, pending.id))}
                >
                  {m.members_withdraw()}
                </Button>
              </li>
            {/each}
          </ul>
        {/if}
      </Card>
    {/if}
  {/if}
</div>
