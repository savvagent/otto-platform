<script lang="ts">
  import { currentLocale } from '$lib/locale';
  import { m } from '$lib/paraglide/messages';
  import { serviceLink, type Service } from '$lib/services';

  /**
   * A link to a Savvagent service from inside the console: the header's Services
   * nav, and the org home's Services card.
   *
   * **Where it goes is `serviceLink`'s call, not this component's.** A service
   * with a web console is a plain external link to it, as it always was. One
   * without — Savvagent Flags, Savvagent CXP — has nothing at its origin but a JSON 404,
   * so the link goes to its product page's connect card instead, which says
   * how to add it to an AI assistant.
   *
   * **That second link crosses into the marketing half, so it carries
   * `data-sveltekit-reload`**, for the reason the web README gives and
   * `ConsoleLink` follows the other way: a client-side route would carry the
   * console's locale getter onto a page whose language is its URL. It is
   * spelled in the console's current language, so a person reading the
   * console in Spanish lands on the Spanish page.
   *
   * **The difference shows before the click.** A connector gets a small
   * "Connector" badge, and an accessible name ("Savvagent CXP, connector") that
   * reads as a phrase rather than the two words run together; the badge is
   * hidden from assistive technology, which already hears it in the name.
   * The name starts with the visible text, so a voice-control user can say
   * what they see. The badge is `text-muted`, not `text-faint`: it is small
   * text that carries meaning, and faint falls under 4.5:1 on the card and on
   * the hover background.
   */
  interface Props {
    service: Service;
    /** `nav` for the header's quiet pills, `chip` for the org home's bordered ones. */
    variant: 'nav' | 'chip';
  }

  let { service, variant }: Props = $props();

  const link = $derived(serviceLink(service, currentLocale()));
</script>

<a
  href={link.href}
  class={variant === 'nav'
    ? 'group inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-muted transition hover:bg-raised hover:text-ink'
    : 'group flex items-center gap-1.5 rounded-md border border-edge px-3 py-1.5 text-sm text-muted transition hover:bg-raised hover:text-ink'}
  aria-label={link.kind === 'connector'
    ? m.service_connector_label({ name: service.name })
    : undefined}
  data-sveltekit-reload={link.kind === 'connector' ? '' : undefined}
>
  {service.name}
  {#if link.kind === 'connector'}
    <span
      aria-hidden="true"
      class="rounded border border-edge px-1 text-[0.6875rem] leading-4 font-medium text-muted group-hover:text-ink"
    >
      {m.service_connector_badge()}
    </span>
  {/if}
</a>
