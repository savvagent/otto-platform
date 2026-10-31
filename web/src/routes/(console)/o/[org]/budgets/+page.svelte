<script lang="ts">
  import { api } from '$lib/api';
  import { formatCents, serviceName } from '$lib/billing';
  import { messageFor } from '$lib/errors';
  import { day } from '$lib/format';
  import { currentLocale } from '$lib/locale';
  import { m } from '$lib/paraglide/messages';
  import { useOrg } from '$lib/org.svelte';
  import type { BudgetsResponse, ServiceBudget } from '$lib/types';
  import Alert from '$lib/components/Alert.svelte';
  import BudgetAlerts from '$lib/components/BudgetAlerts.svelte';
  import BudgetForm from '$lib/components/BudgetForm.svelte';
  import Card from '$lib/components/Card.svelte';
  import Empty from '$lib/components/Empty.svelte';
  import Loading from '$lib/components/Loading.svelte';
  import Meter from '$lib/components/Meter.svelte';

  /**
   * Monthly budgets, per service.
   *
   * Any member may read them; owners and admins set, change and remove them,
   * and turn each service's hard stop on or off. A member sees the same
   * figures with no form, and is told who can change them. The server
   * decides either way (`403` for a member's write): hiding the form is a
   * courtesy, not the control.
   *
   * Budgets are console-only by design. An agent reads its service's budget
   * through that service's `usage` tool and can never change it, because no
   * agent token authenticates here.
   */

  const org = useOrg();

  let view = $state<BudgetsResponse | undefined>(undefined);
  let error = $state<string | undefined>(undefined);

  $effect(() => {
    const slug = org.slug;
    if (!slug) return;

    view = undefined;
    error = undefined;

    void (async () => {
      try {
        const budgets = await api.budgets(slug);
        if (org.slug !== slug) return;
        view = budgets;
      } catch (e) {
        if (org.slug === slug) error = messageFor(e, m.budget_load_failed());
      }
    })();
  });

  function replace(row: ServiceBudget) {
    if (!view) return;
    view.services = view.services.map((s) => (s.service === row.service ? row : s));
  }
</script>

<div class="space-y-5">
  <div>
    <h1 class="text-lg font-semibold">{m.budget_title()}</h1>
    <p class="mt-0.5 text-sm text-faint">{m.budget_subtitle()}</p>
  </div>

  {#if error}
    <Alert>{error}</Alert>
  {:else if !view}
    <Loading what={m.budget_loading()} />
  {:else}
    <BudgetAlerts services={view.services} />

    {#if !org.isAdmin}
      <Alert tone="info">{m.budget_read_only()}</Alert>
    {/if}

    <p class="text-xs text-faint">{m.usage_period_since({ date: day(view.periodStart) })}</p>

    {#if view.services.length === 0}
      <Empty title={m.budget_empty_title()}>{m.budget_empty_hint()}</Empty>
    {:else}
      {#each view.services as row (row.service)}
        <Card title={serviceName(row.service)}>
          <div class="space-y-4">
            <div>
              <div class="sav-label">{m.usage_spend_label()}</div>
              <Meter usage={row} />
            </div>

            {#if org.isAdmin}
              <BudgetForm org={org.slug} {row} onchange={replace} />
            {:else}
              <dl class="grid grid-cols-2 gap-y-2 text-sm">
                <div>
                  <dt class="sav-label">{m.budget_value_label()}</dt>
                  <dd class="text-muted">
                    {row.budget
                      ? formatCents(row.budget.monthlyBudgetCents, currentLocale())
                      : m.budget_none()}
                  </dd>
                </div>
                <div>
                  <dt class="sav-label">{m.budget_hard_stop_label()}</dt>
                  <dd class="text-muted">
                    {row.budget?.hardStop ? m.budget_hard_stop_on() : m.budget_hard_stop_off()}
                  </dd>
                </div>
              </dl>
            {/if}
          </div>
        </Card>
      {/each}
    {/if}

    <p class="text-xs text-faint">{m.budget_resend_note()}</p>
  {/if}
</div>
