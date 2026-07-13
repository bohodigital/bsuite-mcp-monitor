# Authentication Health

`bs auth` verifies explicitly configured credential references. It is read-only:
it does not import, store, display, rotate, or log secret values.

Copy `auth.example.toml` to `~/.config/bsuite/auth.toml`, then run:

```bash
bs auth
bs auth --watch
bs auth --json
```

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
  is discarded to prevent accidental credential disclosure.

Use `command` for Google, Umami API authorization, and custom workflows. The
operator owns the command, its credential source, and its least-privilege API
call. B-Suite captures only the normalized status, bounded detail, expiry, and
capability labels.

## Credential Migration Boundary

Secret migration is intentionally not part of the public command yet. A future
importer will be developed privately with provider-specific migration tests. It
must use a named source and destination, avoid command-line secret arguments,
verify only reference metadata, and never write secret material to reports,
logs, or version control.

Usage history is only trustworthy when a broker emits a redacted access event.
Direct environment-variable use is shown as unobserved rather than guessed.
