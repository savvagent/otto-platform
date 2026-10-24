# The `otto` command

`otto` signs a developer in to an otto resource and runs per-app subcommands, so
a secret an app must not hand to an agent (for example otto-flags' `srv_` server
key) reaches a person's terminal with no model in the path.

Supported: Linux and macOS. Build from source: `cargo build --release -p otto-cli`
produces `target/release/otto`.

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

`$OTTO_CONFIG_DIR`, else `$XDG_CONFIG_HOME/otto`, else `~/.config/otto`:

- the directory is created `0700` if it does not exist; an existing directory is
  left as it is
- `credentials.json` is `0600` and holds the registered client id per
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

`otto <app> <args>` runs `otto-<app>` from `PATH` with the same arguments. On
Unix it replaces the `otto` process, so Ctrl-C, signals and the exit status are
the app's own. `<app>` is lowercase letters, digits and `-`. Only absolute `PATH`
entries are searched. If no such binary is found the error names the one it
looked for.

Any `otto-<app>` on your `PATH` runs as you and can read the credentials file,
just as any `git-<cmd>` or `cargo-<cmd>` could. Install only ones you trust.

An `otto-<app>` binary links the `otto-client` crate:

    let client = otto_client::Client::with_defaults()?;
    let token = client.token("https://flags.example/mcp").await?; // otto_client::Secret
    // ... call the app with token.expose() as a bearer token ...
    secret_from_app.deliver(&otto_client::Sink::Terminal)?;

## Secrets

A secret an app returns should be wrapped in `otto_client::Secret`. It has no
readable `Display` or `Debug`, and its only way out is `deliver`:

- `Sink::Terminal` prints it on stdout only when stdout is a terminal. Piped or
  redirected output is refused, since that is how secrets end up in CI logs.
- `Sink::File { path, overwrite: false }` creates the file `0600` and refuses any
  existing path, a symlink included. With `overwrite: true` it writes a new
  `0600` file beside it and renames it into place, which replaces a symlink
  rather than writing through it.

Errors from this crate are built from fixed text, URLs, and the server's OAuth
`error` code and description with control characters removed and the length
capped. They never include a token, code, verifier, or the rest of a response
body.
