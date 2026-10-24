# The `otto` command

`otto` signs a developer in to an otto resource and runs per-app subcommands, so
a secret an app must not hand to an agent (for example otto-flags' `srv_` server
key) reaches a person's terminal with no model in the path.

## Install

Every [release](https://github.com/savvagent/otto-platform/releases/latest)
attaches a prebuilt `otto` for each of these, with a `SHA256SUMS` file:

| Platform | Archive |
| --- | --- |
| Linux x86_64 | `otto-x86_64-unknown-linux-musl.tar.gz` |
| Linux arm64 | `otto-aarch64-unknown-linux-musl.tar.gz` |
| macOS Apple silicon | `otto-aarch64-apple-darwin.tar.gz` |
| macOS Intel | `otto-x86_64-apple-darwin.tar.gz` |
| Windows x86_64 | `otto-x86_64-pc-windows-msvc.zip` |

The Linux binaries are static, so they run on any distribution. Each archive
holds `otto` and `otto-flags` (`.exe` on Windows) and the license, in a
directory named after the archive. Install both: `otto flags` runs `otto-flags`.

Linux and macOS. Set `target` to your platform's name from the table:

    target=aarch64-apple-darwin
    base=https://github.com/savvagent/otto-platform/releases/latest/download
    curl -fsSLO "$base/otto-$target.tar.gz"
    curl -fsSLO "$base/SHA256SUMS"
    grep " otto-$target.tar.gz\$" SHA256SUMS | shasum -a 256 -c
    tar xzf "otto-$target.tar.gz"
    install -m 0755 "otto-$target/otto" "otto-$target/otto-flags" ~/.local/bin/   # or anywhere on PATH

Windows (PowerShell):

    $base = "https://github.com/savvagent/otto-platform/releases/latest/download"
    Invoke-WebRequest "$base/otto-x86_64-pc-windows-msvc.zip" -OutFile otto.zip
    Invoke-WebRequest "$base/SHA256SUMS" -OutFile SHA256SUMS
    (Get-FileHash otto.zip -Algorithm SHA256).Hash   # compare with SHA256SUMS
    Expand-Archive otto.zip -DestinationPath .
    # then move otto.exe and otto-flags.exe from otto-x86_64-pc-windows-msvc\ to a directory on PATH

The binaries are not code-signed. The checksum shows the archive is the one the
release published.

- **macOS:** a file fetched with `curl` is not quarantined. If you download it in
  a browser instead, Gatekeeper blocks it. Run `xattr -d com.apple.quarantine otto`
  once.
- **Windows:** SmartScreen may warn the first time. Choose *More info*, then
  *Run anyway*.

From source, with Rust 1.89 or later:

    cargo install --locked --git https://github.com/savvagent/otto-platform otto-cli otto-flags-cli

## Sign in

    otto login --resource https://flags.example/mcp [--scope <scope>]... [--force]

This is the flow an MCP client uses against `otto-auth`, with nothing new on the
server: read the resource's protected-resource metadata (RFC 9728), check the
authorization server's metadata names the issuer it was fetched for (RFC 8414),
register dynamically (RFC 7591, a public client), then authorization code with
PKCE S256 and a loopback redirect (`http://127.0.0.1:<port>/callback`). Your
browser opens the consent screen; the CLI also prints the URL in case it does not.

A token has one audience, so each resource gets its own grant. Running `otto login`
again keeps a cached grant that is still usable (refreshing it if needed) and
already covers the scopes asked for, and opens no browser. Asking for a scope the
grant does not have, or passing `--force`, runs the browser flow again. A resource
with no grant triggers a consent screen the first time an `otto-<app>` binary
asks for a token for it.

Remote or headless machines cannot complete a loopback redirect. There is no
device-code login yet.

## Where credentials live

`$OTTO_CONFIG_DIR`, else `$XDG_CONFIG_HOME/otto`, else `~/.config/otto`. On
Windows: `%OTTO_CONFIG_DIR%`, else `%LOCALAPPDATA%\otto`, which does not roam.

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
  revokes every token the client holds, so two `otto` processes must never
  refresh the same grant. A process that finds the lock taken waits up to 60
  seconds and then uses the other process's result.

Access tokens are refreshed when within 30 seconds of expiry. If a grant was
revoked or has expired, the command says to run `otto login` again and removes
the dead grant.

## Subcommands

`otto <app> <args>` runs `otto-<app>` (`otto-<app>.exe` on Windows) from `PATH`
with the same arguments. On Unix it replaces the `otto` process, so Ctrl-C,
signals and the exit status are the app's own. Windows has no equivalent, so
`otto` waits for the app, leaves Ctrl-C to it, and exits with its exit code. `<app>` is lowercase letters, digits and `-`. Only absolute `PATH`
entries are searched. If no such binary is found the error names the one it
looked for.

Any `otto-<app>` on your `PATH` runs as you and can read the credentials file,
just as any `git-<cmd>` or `cargo-<cmd>` could. Install only ones you trust.

An `otto-<app>` binary links the `otto-client` crate:

    let client = otto_client::Client::with_defaults()?;
    let token = client.token("https://flags.example/mcp").await?; // otto_client::Secret
    // ... call the app with token.expose() as a bearer token ...
    secret_from_app.deliver(&otto_client::Sink::Terminal)?;

## Otto Flags keys

    otto flags app create <name> [--env <environment>]... [--out <file> [--overwrite]]
    otto flags keys rotate --app <name-or-id> [--which server|client|both] [--out <file> [--overwrite]]

These issue an Otto Flags app's SDK keys. `app create` registers the app and
issues both keys. `keys rotate` replaces the server key by default, and the old
one stops working at once. Both need an owner or admin of the organization. They
sign in to `$OTTO_FLAGS_RESOURCE` (default `https://otto-flags.savvagent.com/mcp`)
with the `apps:admin` and `keys:issue` scopes. Any scopes already granted to the
cached sign-in are kept.

The server key (`srv_…`) goes to the terminal, or with `--out` to a new
owner-only file. The public client key (`sdk_…`) and the app's details are
printed on stderr. Before anything is issued, the command checks that the key
can be delivered. It refuses a piped stdout with no `--out`, or an `--out`
file that exists without `--overwrite`, and reports "Nothing was changed". A
rotation that issued a key and then could not deliver it would otherwise leave
the app with no working server key. If writing fails after the key was issued,
the error says so and the key is not printed instead. Rotate again.

If otto-flags refuses because the sign-in lacks `keys:issue`, the error names
the scope and the `otto login --resource … --scope apps:admin --scope keys:issue
--force` that grants it.

## Issuing secrets from a service

The convention for any otto-* service whose tools can return a secret (as
otto-flags does since savvagent/otto-flags#189):
- The service withholds the secret unless the token carries an explicit issue
  scope, named `<thing>:issue`.
- The issue scope is not in the resource's default scopes, so a client gets it
  only by asking and being granted it on the consent screen.
- The service's `otto-<app>` binary asks for it and receives the secret through
  `otto_client::Client::call_tool` with the field named as secret. It delivers
  the secret with `Secret::deliver` after `Sink::check`.

`call_tool` sends one JSON-RPC `tools/call` POST with the bearer token and no
session, which suits a stateless MCP server.

Registering the scope on the platform, with plain words for the consent screen.
`resource register` is idempotent: on an existing resource it replaces the name
and scopes, and keeps descriptions it is not given.

    otto-platform-server resource register https://otto-flags.savvagent.com/mcp \
      --name otto-flags \
      --scopes flags:read,flags:write,apps:admin,keys:issue \
      --default-scopes flags:read \
      --scope-description "keys:issue=Receive new secret server keys for your apps. Grant this only to the otto command in your terminal, never to an AI assistant."

On Fly, run it through `fly ssh console -a otto-platform -C '…'`. Register the
scope before releasing an `otto-flags` binary that asks for it. Until then the
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
