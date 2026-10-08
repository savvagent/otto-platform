<script lang="ts">
  import type { UsageStatus } from '$lib/types';
  import { m } from '$lib/paraglide/messages';
  import { currentLocale } from '$lib/locale';

  /**
   * The usage meter.
   *
   * Two numbers matter and they are not the same one. `billableUsed` is what
   * counts against the bucket; `totalCalls` is every call the org made. The
   * gap between them is whatever a service chooses not to bill (a continuous
   * long poll would otherwise bill an idle agent tens of thousands of calls a
   * month), and a meter that showed only the billable figure would leave a
   * customer unable to reconcile it against what their agents actually did.
   *
   * The bar can exceed 100%. It is clamped for drawing and *not* for the
   * caption, because an org that has run over needs to see by how much.
   */
  interface Props {
    usage: UsageStatus;
    compact?: boolean;
  }

  let { usage, compact = false }: Props = $props();

  const fraction = $derived(usage.includedOps > 0 ? usage.billableUsed / usage.includedOps : 0);
  const percent = $derived(Math.round(fraction * 100));
  const width = $derived(Math.min(100, Math.max(0, percent)));
  const tone = $derived(fraction >= 1 ? 'bg-bad' : usage.warning ? 'bg-warn' : 'bg-accent');

  // An org over its bucket has `billableUsed > includedOps`, and `aria-valuenow`
  // above `aria-valuemax` is invalid ARIA — assistive tech may clamp it, report
  // it as the maximum, or ignore the meter. Clamp the machine-readable value and
  // put the real one in `aria-valuetext`, so going over is still announced
  // rather than rounded away. The caption and the percentage stay unclamped:
  // somebody over their allowance needs to see by how much.
  const ariaRange = $derived({
    'aria-valuenow': Math.min(usage.billableUsed, usage.includedOps),
    'aria-valuemin': 0,
    'aria-valuemax': usage.includedOps,
    'aria-valuetext': m.meter_aria_valuetext({
      used: usage.billableUsed.toLocaleString(currentLocale()),
      included: usage.includedOps.toLocaleString(currentLocale()),
      percent
    })
  });
</script>

<div>
  <div class="flex items-baseline justify-between gap-3">
    <span class="text-sm text-muted">
      {m.meter_billable_ratio({
        used: usage.billableUsed.toLocaleString(currentLocale()),
        included: usage.includedOps.toLocaleString(currentLocale())
      })}
    </span>
    <span class="text-xs text-faint">{percent}%</span>
  </div>

  <div
    class="mt-1.5 h-2 overflow-hidden rounded-full bg-raised"
    role="meter"
    {...ariaRange}
    aria-label={m.meter_aria_label()}
  >
    <div class="h-full rounded-full transition-all {tone}" style="width: {width}%"></div>
  </div>

  {#if !compact}
    <!--
      Three complete sentences rather than one sentence assembled from
      fragments. The counts pluralize independently, and a single sentence
      carrying both would need a variant per combination of categories — nine
      of them in Spanish, French and Italian — for a caption nobody reads
      twice.
    -->
    <p class="mt-2 text-xs text-faint">
      {m.meter_calls_recorded({ count: usage.totalCalls })}
      {m.meter_calls_billable({ count: usage.billableUsed })}
      {m.meter_unbilled_note()}
    </p>
  {/if}
</div>
