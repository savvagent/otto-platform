<script lang="ts">
  import { api } from '$lib/api';
  import { messageFor } from '$lib/errors';
  import { m } from '$lib/paraglide/messages';
  import { currentLocale } from '$lib/locale';
  import { useOrg } from '$lib/org.svelte';
  import { day } from '$lib/format';
  import type { UsageStatus } from '$lib/types';
  import Alert from '$lib/components/Alert.svelte';
  import Card from '$lib/components/Card.svelte';
  import Loading from '$lib/components/Loading.svelte';
  import Meter from '$lib/components/Meter.svelte';

  /**
   * The usage meter.
   *
   * Free to read, and readable by an org that has run out. The services an org
   * connects report their metered calls to the platform, which owns the plan and
   * the bucket, so this is the one figure every service draws against. Nothing
   * on this page charges anything: billing a customer for looking at what they
   * have been billed costs more in trust than it could ever earn.
   */

  const org = useOrg();

  let usage = $state<UsageStatus | undefined>(undefined);
  let loading = $state(true);
  let error = $state<string | undefined>(undefined);

  $effect(() => {
    const slug = org.slug;
    if (!slug) return;

    loading = true;
    error = undefined;

    void (async () => {
      try {
        const status = await api.usage(slug);
        if (org.slug !== slug) return;
        usage = status;
      } catch (e) {
        error = messageFor(e, m.usage_load_failed());
      } finally {
        loading = false;
      }
    })();
  });

  const free = $derived(usage ? usage.totalCalls - usage.billableUsed : 0);
</script>

<div class="space-y-5">
  <div>
    <h1 class="text-lg font-semibold">{m.usage_title()}</h1>
    <p class="mt-0.5 text-sm text-faint">{m.usage_subtitle()}</p>
  </div>

  {#if error}
    <Alert>{error}</Alert>
  {:else if !usage}
    <Loading what={m.usage_reading_meter()} />
  {:else}
    {#if usage.remaining === 0 && usage.hardStop}
      <Alert tone={usage.enforced ? 'error' : 'warn'}>
        {#if usage.enforced}
          {m.usage_out_enforced()}
        {:else}
          {m.usage_out_not_enforced()}
        {/if}
      </Alert>
    {:else if usage.warning}
      <Alert tone="warn">{m.usage_warning()}</Alert>
    {/if}

    <Card
      title={m.usage_period_title()}
      description={m.usage_period_since({ date: day(usage.periodStart) })}
    >
      <Meter {usage} />
    </Card>

    <div class="grid gap-3 sm:grid-cols-3">
      <div class="otto-card px-4 py-3">
        <div class="text-2xl font-semibold text-ink">
          {usage.totalCalls.toLocaleString(currentLocale())}
        </div>
        <div class="mt-0.5 text-xs text-faint">{m.usage_tile_recorded()}</div>
      </div>
      <div class="otto-card px-4 py-3">
        <div class="text-2xl font-semibold text-ink">
          {usage.billableUsed.toLocaleString(currentLocale())}
        </div>
        <div class="mt-0.5 text-xs text-faint">{m.usage_tile_billable()}</div>
      </div>
      <div class="otto-card px-4 py-3">
        <div class="text-2xl font-semibold text-muted">{free.toLocaleString(currentLocale())}</div>
        <div class="mt-0.5 text-xs text-faint">{m.usage_tile_free()}</div>
      </div>
    </div>

    <Card title={m.usage_why_title()}>
      <p class="text-sm text-muted">{m.usage_why_body()}</p>
      <p class="mt-3 text-sm text-muted">{m.usage_why_history()}</p>
      <dl class="mt-4 grid grid-cols-2 gap-y-2 text-sm sm:grid-cols-4">
        <div>
          <dt class="otto-label">{m.usage_field_plan()}</dt>
          <dd class="text-muted">{usage.plan}</dd>
        </div>
        <div>
          <dt class="otto-label">{m.usage_field_included()}</dt>
          <dd class="text-muted">{usage.includedOps.toLocaleString(currentLocale())}</dd>
        </div>
        <div>
          <dt class="otto-label">{m.usage_field_remaining()}</dt>
          <dd class="text-muted">{usage.remaining.toLocaleString(currentLocale())}</dd>
        </div>
        <div>
          <dt class="otto-label">{m.usage_field_over_bucket()}</dt>
          <dd class="text-muted">
            {usage.hardStop ? m.usage_over_stops() : m.usage_over_metered()}
          </dd>
        </div>
      </dl>
    </Card>
  {/if}
</div>
