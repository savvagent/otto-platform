<script lang="ts">
  import { m } from '$lib/paraglide/messages';

  interface Props {
    /** What is being waited for. Callers pass a keyed message. */
    what?: string;
  }

  let { what = m.loading_default() }: Props = $props();
</script>

<div class="flex items-center gap-2 px-1 py-6 text-sm text-faint" role="status">
  <span
    class="size-3.5 animate-spin rounded-full border-2 border-current border-t-transparent"
    aria-hidden="true"
  ></span>
  {what}…
</div>
