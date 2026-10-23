# The `otto` command

`otto` signs a developer in to an otto resource and runs per-app subcommands, so
a secret an app must not hand to an agent (for example otto-flags' `srv_` server
key) reaches a person's terminal with no model in the path.

Supported: Linux and macOS. Build from source: `cargo build --release -p otto-cli`
produces `target/release/otto`.

## Sign in

    otto login --resource https://flags.example/mcp

This is the flow an MCP client uses against `otto-auth`, with nothing new on the
server: read the resource's protected-resource metadata (RFC 9728), register
dynamically (RFC 7591, a public client), then authorization code with PKCE S256
and a loopback redirect (`http://127.0.0.1:<port>/callback`). Your browser opens
the consent screen; the CLI also prints the URL in case it does not.

A token has one audience, so each resource gets its own grant. Running `otto login`
again for a resource replaces its grant. A resource with no grant triggers a
consent screen the first time an `otto-<app>` binary asks for a token for it.

Remote or headless machines cannot complete a loopback redirect. There is no
device-code login yet.

## Where credentials live

`$OTTO_CONFIG_DIR`, else `$XDG_CONFIG_HOME/otto`, else `~/.config/otto`:

- the directory is `0700`
- `credentials.json` is `0600` and holds the registered client id per
  authorization server and, per resource, the access token, refresh token and
  expiry.

Access tokens are refreshed when within 30 seconds of expiry. If a grant was
revoked or has expired, the command says to run `otto login` again and removes
the dead grant.

## Subcommands

`otto <app> <args>` runs `otto-<app>` from `PATH` with the same arguments and
exits with its status. `<app>` is lowercase letters, digits and `-`. If no such
binary is found the error names the one it looked for.

An `otto-<app>` binary links the `otto-client` crate:

    let client = otto_client::Client::with_defaults()?;
    let token = client.token("https://flags.example/mcp").await?; // otto_client::Secret
    // ... call the app with token.expose() as a bearer token ...
    secret_from_app.deliver(&otto_client::Sink::Terminal, &mut std::io::stdout())?;

## Secrets

A secret an app returns should be wrapped in `otto_client::Secret`. It has no
readable `Display` or `Debug`, and its only way out is `deliver`, to the terminal
or to a file the user names (created or narrowed to `0600` before anything is
written). Errors from this crate are built from fixed text, URLs and the server's
OAuth `error` code and description, never from a token, code or response body.
