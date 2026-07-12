# Contributing

## Local Setup

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/python -m compileall -q bs
.venv/bin/python -m pip wheel --no-deps --wheel-dir dist .
```

Use `config.example.toml` for local MCP integration tests. Do not commit a
live configuration, service dump, credentials, private URL, or GeoLite database.

## Change Guidelines

- Keep collectors read-only and use argument arrays, never a shell.
- Keep Linux-specific assumptions documented.
- Run the compile and wheel-build checks before opening a pull request.
