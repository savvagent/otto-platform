# The `savctl` command

`savctl` signs a developer in to Savvagent and runs per-app subcommands, so
a secret an app must not hand to an agent (for example otto-flags' `srv_` server
key) reaches a person's terminal with no model in the path.

## Install

Every [release](https://github.com/savvagent/otto-platform/releases/latest)
attaches a prebuilt `savctl` for each of these, with a `SHA256SUMS` file:

| Platform | Archive |
| --- | --- |
| Linux x86_64 | `savctl-x86_64-unknown-linux-musl.tar.gz` |
| Linux arm64 | `savctl-aarch64-unknown-linux-musl.tar.gz` |
| macOS Apple silicon | `savctl-aarch64-apple-darwin.tar.gz` |
| macOS Intel | `savctl-x86_64-apple-darwin.tar.gz` |
| Windows x86_64 | `savctl-x86_64-pc-windows-msvc.zip` |

The Linux binaries are static, so they run on any distribution. Each archive
holds `savctl` and `savctl-flags` (`.exe` on Windows) and the license, in a
directory named after the archive. Install both: `savctl flags` runs `savctl-flags`.

Linux and macOS. Set `target` to your platform's name from the table:

    target=aarch64-apple-darwin
    base=https://github.com/savvagent/otto-platform/releases/latest/download
    curl -fsSLO "$base/savctl-$target.tar.gz"
    curl -fsSLO "$base/SHA256SUMS"
    grep " savctl-$target.tar.gz\$" SHA256SUMS | shasum -a 256 -c
    tar xzf "savctl-$target.tar.gz"
    install -m 0755 "savctl-$target/savctl" "savctl-$target/savctl-flags" ~/.local/bin/   # or anywhere on PATH

Windows (PowerShell):

    $base = "https://github.com/savvagent/otto-platform/releases/latest/download"
    Invoke-WebRequest "$base/savctl-x86_64-pc-windows-msvc.zip" -OutFile savctl.zip
    Invoke-WebRequest "$base/SHA256SUMS" -OutFile SHA256SUMS
    (Get-FileHash savctl.zip -Algorithm SHA256).Hash   # compare with SHA256SUMS
    Expand-Archive savctl.zip -DestinationPath .
    # then move savctl.exe and savctl-flags.exe from savctl-x86_64-pc-windows-msvc\ to a directory on PATH

The binaries are not code-signed. The checksum shows the archive is the one the
release published.

- **macOS:** a file fetched with `curl` is not quarantined. If you download it in
  a browser instead, Gatekeeper blocks it. Run `xattr -d com.apple.quarantine savctl`
  once.
- **Windows:** SmartScreen may warn the first time. Choose *More info*, then
  *Run anyway*.

From source, with Rust 1.89 or later:

    cargo install --locked --git https://github.com/savvagent/otto-platform ottoctl otto-flags-cli

The packages keep their old names, `ottoctl` and `otto-flags-cli`, for now; they
install the `savctl` and `savctl-flags` binaries.

## Upgrading from `ottoctl`

`savctl` replaces `ottoctl`, and `savctl-flags` replaces `otto-flags`. Nothing
carries over: `savctl` keeps its credentials in a new directory (see [Where
credentials live](#where-credentials-live)), reads `SAVVAGENT_CONFIG_DIR` and
`SAVVAGENT_FLAGS_RESOURCE` instead of `OTTO_CONFIG_DIR` and
`OTTO_FLAGS_RESOURCE`, and runs `savctl-<app>` binaries, not `otto-<app>`.
Tokens issued before the switch no longer work anyway, so run `savctl login`
once. You can then delete the old `ottoctl` and `otto-flags` binaries and the
old `otto` config directory.

## Sign in

    savctl login [--force]
    savctl login --resource <uri> [--scope <scope>]... [--force]

With no `--resource`, `savctl` signs in to every Savvagent resource with one
browser consent screen. The screen lists each resource with its scopes. Untick
a resource to leave it out: it gets no access, and `savctl` reports it as left
out rather than as a failure. The resources are:

- `https://otto-tower.savvagent.com/mcp`
- `https://otto-flags.savvagent.com/mcp`
- `https://otto-cxp.savvagent.com/mcp`

For each it asks for the scopes the resource advertises, except opt-in issue
scopes (`<thing>:issue`), which are asked for only with `--scope`; consent
decides what is granted. A resource that already has a usable grant covering
those scopes opens no browser. If one resource fails, the grants for the others
are kept, the failure is named, and the exit status is non-zero. `--scope` goes
with `--resource`, since scopes belong to one resource server.

One consent screen for several resources is a Savvagent extension of RFC 8707: the
authorization server advertises `savvagent_authorize_resources_max` in its metadata,
accepts that many `resource` values on `/oauth/authorize`, and answers with a
`code` and its `resource` for each one you kept. Each code is an ordinary
single-resource code, so each token still has exactly one audience. The request
has one `scope` parameter, and each resource is asked for the requested scopes
it defines, so a scope name two resources share (such as `org:admin`) is asked
of both; the consent screen shows it under each, and you can untick it under
either. A resource you kept but whose every scope you may not grant (only
`org:admin`, as a member) is named in the callback as `refused_resource`, and
`savctl` reports it as a failure. Against a
server that does not advertise it, `savctl` signs in to each resource in turn,
one consent screen each.

If you ask for a scope the authorization server does not offer, `savctl` says
so and lists what it does offer, instead of opening a consent page that shows
only an error.

This is the flow an MCP client uses against `otto-auth`, with nothing new on the
server: read the resource's protected-resource metadata (RFC 9728), check the
authorization server's metadata names the issuer it was fetched for (RFC 8414),
register dynamically (RFC 7591, a public client), then authorization code with
PKCE S256 and a loopback redirect (`http://127.0.0.1:<port>/callback`). Your
browser opens the consent screen; the CLI also prints the URL in case it does not.

A token has one audience, so each resource gets its own grant. Running `savctl login`
again keeps a cached grant that is still usable (refreshing it if needed) and
already covers the scopes asked for, and opens no browser. Asking for a scope the
grant does not have, or passing `--force`, runs the browser flow again. A resource
with no grant triggers a consent screen the first time a `savctl-<app>` binary
asks for a token for it.

Remote or headless machines cannot complete a loopback redirect. There is no
device-code login yet.

## Where credentials live

`$SAVVAGENT_CONFIG_DIR`, else `$XDG_CONFIG_HOME/savvagent`, else
`~/.config/savvagent`. On Windows: `%SAVVAGENT_CONFIG_DIR%`, else
`%LOCALAPPDATA%\savvagent`, which does not roam.

Owner-only means mode `0600` for files and `0700` for directories on Linux and
macOS. On Windows it means an access list that grants your account full access,
inherits nothing, and grants no one else anything. Either way the permissions
are set as the entry is created.

- the directory is created owner-only if it does not exist; an existing
  directory is left as it is
- `credentials.json` is owner-only and holds the registered client id per
  authorization server and, per resource, the access token, refresh token and
  expiry. It is replaced by writing a new file and renaming it into place.
- `credentials.lock` is held while the file changes. Refresh holds it across the
  token request: otto-auth treats a refresh token presented twice as a replay and
  revokes every token the client holds, so two `savctl` processes must never
  refresh the same grant. A process that finds the lock taken waits up to 60
  seconds and then uses the other process's result.

Access tokens are refreshed when within 30 seconds of expiry. If a grant was
revoked or has expired, the command says to run `savctl login` again and removes
the dead grant.

## Subcommands

`savctl <app> <args>` runs `savctl-<app>` (`savctl-<app>.exe` on Windows) from `PATH`
with the same arguments. On Unix it replaces the `savctl` process, so Ctrl-C,
signals and the exit status are the app's own. Windows has no equivalent, so
`savctl` waits for the app, leaves Ctrl-C to it, and exits with its exit code. `<app>` is lowercase letters, digits and `-`. Only absolute `PATH`
entries are searched. If no such binary is found the error names the one it
looked for.

Any `savctl-<app>` on your `PATH` runs as you and can read the credentials file,
just as any `git-<cmd>` or `cargo-<cmd>` could. Install only ones you trust.

A `savctl-<app>` binary links the `otto-client` crate:

    let client = otto_client::Client::with_defaults()?;
    let token = client.token("https://flags.example/mcp").await?; // otto_client::Secret
    // ... call the app with token.expose() as a bearer token ...
    secret_from_app.deliver(&otto_client::Sink::Terminal)?;

## Otto Flags keys

    savctl flags app create <name> [--env <environment>]... [--out <file> [--overwrite]]
    savctl flags keys rotate --app <name-or-id> [--which server|client|both] [--out <file> [--overwrite]]

These issue an Otto Flags app's SDK keys. `app create` registers the app and
issues both keys. `keys rotate` replaces the server key by default, and the old
one stops working at once. Both need an owner or admin of the organization. They
sign in to `$SAVVAGENT_FLAGS_RESOURCE` (default `https://otto-flags.savvagent.com/mcp`)
with the `apps:admin` and `keys:issue` scopes. Any scopes already granted to the
cached sign-in are kept.

The server key (`srv_…`) goes to the terminal, or with `--out` to a new
owner-only file. The public client key (`sdk_…`) and the app's details are
printed on stderr. A copy of the server key anywhere else in the response is
replaced with `<redacted>`.

A rotation revokes the old key at once, so a key that was issued and then
couldn't be delivered would leave the app with no working one. To prevent
that, the command claims the destination before anything is issued:
- With `--out`, it creates the file, empty and owner-only, or with
  `--overwrite` a temporary file beside it.
- It refuses a piped stdout with no `--out`, an existing `--out` file without
  `--overwrite`, or a directory it can't write to.

In each of those cases it reports "Nothing was changed". If the command stops
before delivering, it removes what it created. Two failures can still lose the
key, and the error message says what happened and which rotation to run:
- the file write fails after the key was issued (for example, a full disk);
- the request was sent but no usable response came back, so the rotation may
  have happened anyway.

If otto-flags refuses because the sign-in lacks `keys:issue`, the error names
the scope and the `savctl login --resource … --scope apps:admin --scope keys:issue
--force` that grants it.

## Issuing secrets from a service

The convention for any otto-* service whose tools can return a secret (as
otto-flags does since savvagent/otto-flags#189):
- The service withholds the secret unless the token carries an explicit issue
  scope, named `<thing>:issue`.
- The issue scope is not in the resource's default scopes, so a client gets it
  only by asking and being granted it on the consent screen.
- The service's `savctl-<app>` binary asks for it and receives the secret through
  `otto_client::Client::call_tool` with the field named as secret. It claims
  the destination with `Sink::reserve` before the call and delivers with
  `Reservation::deliver` after it.

`call_tool` sends one JSON-RPC `tools/call` POST with the bearer token and no
session, which suits a stateless MCP server. A failure after the request was
sent is `Error::NoResponse`, distinct from `Error::Network`, because the tool
may have acted.

Registering the scope on the platform, with plain words for the consent screen.
`resource register` is idempotent: on an existing resource it replaces the name
and scopes, and keeps descriptions it is not given.

    otto-platform-server resource register https://otto-flags.savvagent.com/mcp \
      --name otto-flags \
      --scopes flags:read,flags:write,apps:admin,keys:issue \
      --default-scopes flags:read \
      --scope-description "keys:issue=Receive new secret server keys for your apps. Grant this only to the savctl command in your terminal, never to an AI assistant."

On Fly, run it through `fly ssh console -a otto-platform -C '…'`. Register the
scope before releasing a `savctl-flags` binary that asks for it. Until then the
authorization server refuses the sign-in with `invalid_scope`. `resource
describe` changes only the descriptions.

## Secrets

A secret an app returns should be wrapped in `otto_client::Secret`. It has no
readable `Display` or `Debug`, and its only way out is `deliver`:

- `Sink::Terminal` prints it on stdout only when stdout is a terminal. Piped or
  redirected output is refused, since that is how secrets end up in CI logs.
- `Sink::File { path, overwrite: false }` creates the file owner-only and
  refuses any existing path, a symlink included. With `overwrite: true` it
  writes a new owner-only file beside it and renames it into place, which replaces a symlink
  rather than writing through it.

Errors from this crate are built from fixed text, URLs, and the server's OAuth
`error` code and description with control characters removed and the length
capped. They never include a token, code, verifier, or the rest of a response
body.
