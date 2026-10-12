<script lang="ts">
  import type { Snippet } from 'svelte';
  import type { HTMLAnchorAttributes } from 'svelte/elements';

  import { buttonClass, type ButtonSize, type ButtonTone } from './button';

  /**
   * A link that looks like a button: for an action that is a navigation —
   * "Create account", "See pricing", "Open the console".
   *
   * Still an `<a>`, so it can be opened in a new tab, works without
   * JavaScript, and is announced as a link. Any other anchor attribute
   * (`data-sveltekit-reload`, `hreflang`) is passed through.
   */
  interface Props extends Omit<HTMLAnchorAttributes, 'class' | 'children'> {
    href: string;
    tone?: ButtonTone;
    size?: ButtonSize;
    children: Snippet;
  }

  let { href, tone = 'primary', size = 'md', children, ...rest }: Props = $props();
</script>

<a {href} {...rest} class={buttonClass(tone, size)}>{@render children()}</a>
