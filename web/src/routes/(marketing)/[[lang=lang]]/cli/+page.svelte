<script lang="ts">
  import { m } from '$lib/paraglide/messages';
  import { SERVICES } from '$lib/services';
  import CopyField from '$lib/components/CopyField.svelte';
  import Seo from '$lib/components/Seo.svelte';

  import type { PageData } from './$types';

  /**
   * The `savctl` command-line tool: what it is, where to get it, how to run it
   * the first time.
   *
   * **Commands, URLs and file names are not messages.** They are the same in
   * every language and must stay copy-pasteable, so only the prose around them
   * is translated. The download links use GitHub's `latest/download` address,
   * which always names the newest release's asset, so no version is baked into
   * a prerendered file. They are external links: the prerender crawler only
   * follows same-origin ones.
   *
   * Prebuilt archives and the install steps mirror `docs/savctl.md`, which
   * is the source of truth; change them together.
   */
  let { data }: { data: PageData } = $props();

  const RELEASES = 'https://github.com/savvagent/otto-platform/releases/latest';
  const DOWNLOAD = `${RELEASES}/download`;
  const DOCS = 'https://github.com/savvagent/otto-platform/blob/main/docs/savctl.md';

  /** Platform names are names, so they are not translated. */
  const PLATFORMS = [
    { name: 'Linux x86_64', archive: 'savctl-x86_64-unknown-linux-musl.tar.gz' },
    { name: 'Linux arm64', archive: 'savctl-aarch64-unknown-linux-musl.tar.gz' },
    { name: 'macOS Apple silicon', archive: 'savctl-aarch64-apple-darwin.tar.gz' },
    { name: 'macOS Intel', archive: 'savctl-x86_64-apple-darwin.tar.gz' },
    { name: 'Windows x86_64', archive: 'savctl-x86_64-pc-windows-msvc.zip' }
  ];

  const UNIX_INSTALL = [
    'target=aarch64-apple-darwin',
    `base=${DOWNLOAD}`,
    'curl -fsSLO "$base/savctl-$target.tar.gz"',
    'curl -fsSLO "$base/SHA256SUMS"',
    'grep " savctl-$target.tar.gz\\$" SHA256SUMS | shasum -a 256 -c',
    'tar xzf "savctl-$target.tar.gz"',
    'install -m 0755 "savctl-$target/savctl" "savctl-$target/savctl-flags" ~/.local/bin/'
  ].join('\n');

  const WINDOWS_INSTALL = [
    `$base = "${DOWNLOAD}"`,
    'Invoke-WebRequest "$base/savctl-x86_64-pc-windows-msvc.zip" -OutFile savctl.zip',
    'Invoke-WebRequest "$base/SHA256SUMS" -OutFile SHA256SUMS',
    '(Get-FileHash savctl.zip -Algorithm SHA256).Hash',
    'Expand-Archive savctl.zip -DestinationPath .'
  ].join('\n');

  const FROM_SOURCE =
    'cargo install --locked --git https://github.com/savvagent/otto-platform savvagent-ctl savvagent-flags-cli';

  const why = [
    { title: () => m.cli_why_signin_title(), body: () => m.cli_why_signin_body() },
    { title: () => m.cli_why_secrets_title(), body: () => m.cli_why_secrets_body() },
    { title: () => m.cli_why_apps_title(), body: () => m.cli_why_apps_body() }
  ];

  const loginServices = SERVICES.flatMap((service) =>
    service.mcpUrl
      ? [{ name: service.name, command: `savctl login --resource ${service.mcpUrl}` }]
      : []
  );

  const ext = 'font-medium text-accent hover:underline';
</script>

<Seo title={m.cli_title()} description={m.cli_description()} path="/cli" lang={data.lang} />

<div class="flex flex-col gap-20 pb-10 sm:gap-24">
  <section aria-labelledby="cli-title" class="max-w-3xl pt-6">
    <p class="sav-label text-accent">{m.cli_eyebrow()}</p>
    <h1
      id="cli-title"
      class="mt-3 text-4xl font-semibold tracking-tight text-balance text-ink sm:text-5xl"
    >
      {m.cli_heading()}
    </h1>
    <p class="mt-6 text-lg text-pretty text-muted">{m.cli_lead()}</p>
  </section>

  <section aria-labelledby="why-title">
    <h2 id="why-title" class="text-2xl font-semibold tracking-tight text-ink">
      {m.cli_why_heading()}
    </h2>
    <ul role="list" class="mt-8 grid gap-8 md:grid-cols-3">
      {#each why as item, i (i)}
        <li class="border-l-2 border-accent/60 pl-4">
          <h3 class="font-semibold text-ink">{item.title()}</h3>
          <p class="mt-1.5 text-sm text-muted">{item.body()}</p>
        </li>
      {/each}
    </ul>
  </section>

  <section aria-labelledby="download-title" class="max-w-3xl">
    <h2 id="download-title" class="text-2xl font-semibold tracking-tight text-ink">
      {m.cli_download_heading()}
    </h2>
    <p class="mt-3 text-muted">{m.cli_download_intro()}</p>
    <ul role="list" aria-label={m.cli_download_list_label()} class="mt-6 grid gap-3 sm:grid-cols-2">
      {#each PLATFORMS as platform (platform.archive)}
        <li class="sav-card p-4">
          <a href="{DOWNLOAD}/{platform.archive}" class="block {ext}">{platform.name}</a>
          <span class="sav-mono mt-1 block text-xs text-muted">{platform.archive}</span>
        </li>
      {/each}
    </ul>
    <p class="mt-4 flex flex-wrap gap-x-4 gap-y-1 text-sm">
      <a href="{DOWNLOAD}/SHA256SUMS" class={ext}>{m.cli_download_checksums()}</a>
      <a href={RELEASES} class={ext}>{m.cli_download_releases()}</a>
    </p>
    <div class="mt-6">
      <p class="mb-2 text-sm text-muted">{m.cli_download_source()}</p>
      <CopyField value={FROM_SOURCE} />
    </div>
  </section>

  <section aria-labelledby="install-title" class="max-w-3xl">
    <h2 id="install-title" class="text-2xl font-semibold tracking-tight text-ink">
      {m.cli_install_heading()}
    </h2>
    <div class="mt-6 flex flex-col gap-8">
      <div>
        <h3 class="font-semibold text-ink">{m.cli_install_unix_heading()}</h3>
        <p class="mt-1.5 mb-3 text-sm text-muted">{m.cli_install_unix_note()}</p>
        <CopyField value={UNIX_INSTALL} />
      </div>
      <div>
        <h3 class="font-semibold text-ink">{m.cli_install_windows_heading()}</h3>
        <p class="mt-1.5 mb-3 text-sm text-muted">{m.cli_install_windows_note()}</p>
        <CopyField value={WINDOWS_INSTALL} />
      </div>
    </div>
  </section>

  <section aria-labelledby="unsigned-title" class="max-w-3xl">
    <h2 id="unsigned-title" class="text-2xl font-semibold tracking-tight text-ink">
      {m.cli_unsigned_heading()}
    </h2>
    <p class="mt-3 text-muted">{m.cli_unsigned_body()}</p>
    <div class="mt-5">
      <p class="mb-2 text-sm text-muted">{m.cli_unsigned_macos()}</p>
      <CopyField value="xattr -d com.apple.quarantine savctl" />
    </div>
    <p class="mt-5 text-sm text-muted">{m.cli_unsigned_windows()}</p>
  </section>

  <section aria-labelledby="first-title" class="max-w-3xl">
    <h2 id="first-title" class="text-2xl font-semibold tracking-tight text-ink">
      {m.cli_first_heading()}
    </h2>
    <p class="mt-3 text-muted">{m.cli_first_body()}</p>
    <div class="mt-5 flex flex-col gap-4">
      <CopyField value="savctl login" label={m.cli_first_label()} />
      {#if loginServices.length > 0}
        <p class="text-sm text-muted">{m.cli_first_services()}</p>
        {#each loginServices as service (service.name)}
          <CopyField value={service.command} label={service.name} />
        {/each}
      {/if}
    </div>
  </section>

  <section aria-labelledby="docs-title" class="max-w-3xl">
    <h2 id="docs-title" class="text-2xl font-semibold tracking-tight text-ink">
      {m.cli_docs_heading()}
    </h2>
    <p class="mt-3 text-muted">
      {m.cli_docs_body()}
      <a href={DOCS} class={ext}>{m.cli_docs_link()}</a>
    </p>
  </section>
</div>
