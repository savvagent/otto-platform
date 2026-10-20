<script lang="ts">
  import { tick, untrack } from 'svelte';

  import { api } from '$lib/api';
  import {
    MAX_MONTHLY_BUDGET_CENTS,
    MIN_MONTHLY_BUDGET_CENTS,
    dollarsInput,
    formatCents,
    parseDollars,
    serviceName,
    type DollarsError
  } from '$lib/billing';
  import { messageFor } from '$lib/errors';
  import { currentLocale } from '$lib/locale';
  import { m } from '$lib/paraglide/messages';
  import type { ServiceBudget } from '$lib/types';
  import Alert from './Alert.svelte';
  import Button from './Button.svelte';

  /**
   * Set, change or remove one service's monthly budget, and its hard stop.
   *
   * For owners and admins only; the page renders a read-only summary for a
   * member instead, and the server answers a member's write with `403`
   * regardless.
   *
   * The amount is typed in dollars and sent as integer cents, parsed from
   * the string (`parseDollars`) so nothing passes through a float. A refused
   * amount is said next to the field (`aria-describedby`, `aria-invalid`) and
   * focus goes back to it. After a save or a removal focus moves to the
   * confirmation, a live region, so a keyboard or screen-reader user hears
   * that it worked and is not left on a button that may have just vanished.
   */
  interface Props {
    /** The org slug. */
    org: string;
    row: ServiceBudget;
    /** The service's row after a save or a removal. */
    onchange: (row: ServiceBudget) => void;
  }

  let { org, row, onchange }: Props = $props();

  const id = $derived(`budget-${row.service}`);
  const name = $derived(serviceName(row.service));

  let amount = $state(
    untrack(() => (row.budget ? dollarsInput(row.budget.monthlyBudgetCents) : ''))
  );
  let hardStop = $state(untrack(() => row.budget?.hardStop ?? false));
  let fieldError = $state<DollarsError | undefined>(undefined);
  let failure = $state<string | undefined>(undefined);
  let notice = $state<string | undefined>(undefined);
  let pending = $state<'save' | 'clear' | undefined>(undefined);

  let input = $state<HTMLInputElement | undefined>(undefined);
  let status = $state<HTMLElement | undefined>(undefined);

  const max = $derived(formatCents(MAX_MONTHLY_BUDGET_CENTS, currentLocale()));

  function fieldMessage(reason: DollarsError): string {
    switch (reason) {
      case 'empty':
        return m.budget_error_empty();
      case 'invalid':
        return m.budget_error_invalid();
      case 'too_small':
        return m.budget_error_too_small({
          min: formatCents(MIN_MONTHLY_BUDGET_CENTS, currentLocale())
        });
      case 'too_large':
        return m.budget_error_too_large({ max });
    }
  }

  async function announce(text: string) {
    notice = text;
    await tick();
    status?.focus();
  }

  async function save(event: SubmitEvent) {
    event.preventDefault();
    failure = undefined;
    notice = undefined;
    const parsed = parseDollars(amount);
    if (!parsed.ok) {
      fieldError = parsed.reason;
      await tick();
      input?.focus();
      return;
    }
    fieldError = undefined;
    pending = 'save';
    try {
      const updated = await api.setBudget(org, row.service, {
        monthlyBudgetCents: parsed.cents,
        hardStop
      });
      onchange(updated);
      amount = updated.budget ? dollarsInput(updated.budget.monthlyBudgetCents) : amount;
      hardStop = updated.budget?.hardStop ?? hardStop;
      await announce(m.budget_saved({ service: name }));
    } catch (e) {
      failure = messageFor(e, m.budget_save_failed());
    } finally {
      pending = undefined;
    }
  }

  async function clear() {
    failure = undefined;
    notice = undefined;
    fieldError = undefined;
    pending = 'clear';
    try {
      await api.clearBudget(org, row.service);
      onchange({ ...row, budget: null });
      amount = '';
      hardStop = false;
      await announce(m.budget_cleared({ service: name }));
    } catch (e) {
      failure = messageFor(e, m.budget_clear_failed());
    } finally {
      pending = undefined;
    }
  }
</script>

<form class="space-y-3" onsubmit={save} novalidate>
  <div>
    <label class="otto-label" for="{id}-amount">{m.budget_amount_label()}</label>
    <input
      bind:this={input}
      bind:value={amount}
      id="{id}-amount"
      name="amount"
      class="otto-input mt-1 w-full max-w-60"
      inputmode="decimal"
      autocomplete="off"
      aria-invalid={fieldError ? 'true' : undefined}
      aria-describedby={fieldError ? `${id}-error ${id}-hint` : `${id}-hint`}
    />
    <span id="{id}-hint" class="mt-1 block text-xs text-faint">
      {m.budget_amount_hint({ max })}
    </span>
    {#if fieldError}
      <span id="{id}-error" class="mt-1 block text-xs text-bad">{fieldMessage(fieldError)}</span>
    {/if}
  </div>

  <div class="flex items-start gap-2">
    <input
      bind:checked={hardStop}
      id="{id}-hard-stop"
      type="checkbox"
      role="switch"
      class="mt-0.5 size-4 accent-accent"
      aria-describedby="{id}-hard-stop-hint"
    />
    <div>
      <label class="text-sm text-ink" for="{id}-hard-stop">{m.budget_hard_stop_label()}</label>
      <span id="{id}-hard-stop-hint" class="block text-xs text-faint">
        {m.budget_hard_stop_hint()}
      </span>
    </div>
  </div>

  {#if failure}
    <Alert>{failure}</Alert>
  {/if}

  <div class="flex flex-wrap gap-2">
    <Button type="submit" pending={pending === 'save'} disabled={pending !== undefined}>
      {m.budget_save()}
    </Button>
    {#if row.budget}
      <Button
        tone="danger"
        pending={pending === 'clear'}
        disabled={pending !== undefined}
        onclick={clear}
      >
        {m.budget_clear()}
      </Button>
    {/if}
  </div>

  <p
    bind:this={status}
    tabindex="-1"
    role="status"
    class="text-sm text-ok outline-none"
    class:hidden={!notice}
  >
    {notice ?? ''}
  </p>
</form>
