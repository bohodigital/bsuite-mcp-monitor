# Authentication Health

`bs auth` verifies explicitly configured credential references. It is read-only:
it does not import, store, display, rotate, or log secret values.

Copy `auth.example.toml` to `~/.config/bsuite/auth.toml`, then run:

```bash
bs auth
bs auth --watch
bs auth --json
```

For a new host, use the intake wizard instead:

```bash
bs auth init
bs auth init --config ~/.config/bsuite/client-auth.toml
```

The wizard has templates for Cloudflare, GitHub CLI, generic HTTP, Umami HTTP,
Google/OAuth adapters, and generic command adapters. It asks for references,
purposes, URLs, environment-variable names, executable paths, and arguments.
It never asks for a token, password, OAuth client secret, or other secret value.
Use `--replace` only when intentionally replacing a profile.

Configuration lookup order is `bs auth --config PATH`, `BS_AUTH_CONFIG`, then
`~/.config/bsuite/auth.toml`. Authentication configuration rejects unknown
fields so a token cannot be accidentally added to the profile. A profile that
contains a command adapter or authenticated HTTP check must not be group or
world writable.

## Built-In Checks

- `cloudflare`: calls Cloudflare's read-only token verification endpoint using
  a token supplied through the configured environment variable.
- `github-cli`: runs `gh auth status` for the configured hostname.
- `http`: makes a GET request to an HTTPS endpoint, or a loopback HTTP health
  endpoint. It can send a Bearer token supplied through an environment variable.
- `command`: executes an operator-owned absolute executable without a shell.
  It must emit one normalized JSON object with `status` set to `healthy`,
  `warning`, `failed`, or `unknown`. It can optionally include a bounded
  `detail_code`, `expires_at`, and string `capabilities`; arbitrary detail text
  is discarded to prevent accidental credential disclosure. Existing read-only
  tools that emit only JSON `ok: true` or `ok: false` are also supported and
  are mapped to healthy or failed without retaining their payload.

Use `command` for Google, Umami API authorization, and custom workflows. The
operator owns the command, its credential source, and its least-privilege API
call. B-Suite captures only the normalized status, bounded detail, expiry, and
capability labels.

## Adapter Output

A command adapter writes exactly one JSON object to standard output. The
recommended result is:

```json
{
  "status": "healthy",
  "detail_code": "read_only_verified",
  "expires_at": "2027-01-01T00:00:00Z",
  "capabilities": ["read"]
}
```

`status` is one of `healthy`, `warning`, `failed`, or `unknown`. Existing
read-only utilities may instead return `{ "ok": true }` or `{ "ok": false }`.
B-Suite maps that to healthy or failed and discards all other payload fields.
Do not print a token, account identifier, request body, response body, or
free-form provider error in adapter output.

## Common Workflows

### Cloudflare Token

Use the Cloudflare template and supply the name of an environment variable that
contains the token in the process running B-Suite. The built-in check calls the
read-only token verification endpoint and reports active/failed plus expiry
when provided.

### GitHub CLI

Use the GitHub template. It runs `gh auth status --hostname HOST` and reports
only the result, not the account or token.

### Umami

Use the Umami HTTP template with a local or HTTPS health URL. For API-level
authentication, create a separate read-only command adapter. Do not use a
verification script that creates events or modifies analytics data as a health
probe.

### Google And Custom Providers

Use the Google/OAuth or custom-adapter template. Point it at an owner-managed
absolute executable that resolves its own credential reference and makes one
least-privilege verification request. Enter every argument individually in the
wizard; B-Suite does not invoke a shell.

## Credential Migration Boundary

Secret migration is intentionally not part of the public command yet. A future
importer will be developed privately with provider-specific migration tests. It
must use a named source and destination, avoid command-line secret arguments,
verify only reference metadata, and never write secret material to reports,
logs, or version control.

Usage history is only trustworthy when a broker emits a redacted access event.
Direct environment-variable use is shown as unobserved rather than guessed.
