from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from bs.auth_config import AuthCheck, AuthConfig, ConfigError, write_auth_config


Prompt = Callable[[str], str]


def _ask(prompt: Prompt, label: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    value = prompt(f"{label}{suffix}: ").strip()
    return value or default


def _required(prompt: Prompt, label: str, default: str = "") -> str:
    while not (value := _ask(prompt, label, default)):
        print("A value is required.")
    return value


def _metadata(prompt: Prompt, *, name: str, reference: str, purpose: str) -> tuple[str, str, str]:
    return (
        _required(prompt, "Check name", name),
        _required(prompt, "Credential reference", reference),
        _required(prompt, "Purpose", purpose),
    )


def _command(prompt: Prompt) -> tuple[str, ...]:
    executable = _required(prompt, "Absolute executable path")
    if not Path(executable).is_absolute():
        print("The executable path must be absolute.")
        return _command(prompt)
    # Collect arguments individually so the wizard never parses a shell command.
    args = [executable]
    print("Add one argument per prompt. Leave the argument prompt empty when finished.")
    while (value := _ask(prompt, "Argument")):
        args.append(value)
    return tuple(args)


def _cloudflare(prompt: Prompt) -> AuthCheck:
    name, reference, purpose = _metadata(prompt, name="cloudflare", reference="cloudflare-api", purpose="Verify Cloudflare API token health")
    return AuthCheck(name, "cloudflare", reference, purpose, environment_variable=_required(prompt, "Environment variable", "CLOUDFLARE_API_TOKEN"))


def _github(prompt: Prompt) -> AuthCheck:
    name, reference, purpose = _metadata(prompt, name="github", reference="github-cli", purpose="Verify GitHub CLI authentication")
    return AuthCheck(name, "github-cli", reference, purpose, hostname=_required(prompt, "GitHub hostname", "github.com"))


def _http(prompt: Prompt, *, umami: bool = False) -> AuthCheck:
    defaults = ("umami", "umami-service", "Verify Umami HTTP availability") if umami else ("http-service", "service-api", "Verify authenticated HTTP health")
    name, reference, purpose = _metadata(prompt, name=defaults[0], reference=defaults[1], purpose=defaults[2])
    url = _required(prompt, "Health URL")
    expected = _required(prompt, "Expected HTTP status", "200")
    try:
        expected_status = int(expected)
    except ValueError:
        print("Expected status must be an integer.")
        return _http(prompt, umami=umami)
    environment_variable = _ask(prompt, "Bearer-token environment variable (leave empty for unauthenticated health)")
    return AuthCheck(name, "http", reference, purpose, environment_variable=environment_variable, url=url, expected_status=expected_status)


def _adapter(prompt: Prompt, *, google: bool = False) -> AuthCheck:
    defaults = ("google-oauth", "google-oauth", "Verify Google OAuth with a read-only local adapter") if google else ("custom-adapter", "custom-credential", "Verify a custom credential with a read-only local adapter")
    name, reference, purpose = _metadata(prompt, name=defaults[0], reference=defaults[1], purpose=defaults[2])
    print("The adapter must emit JSON status or JSON ok and must not print secrets.")
    return AuthCheck(name, "command", reference, purpose, command=_command(prompt), timeout_seconds=float(_required(prompt, "Timeout seconds", "10")))


def run_auth_intake(path: Path, *, replace: bool, prompt: Prompt = input) -> int:
    print("B-Suite Auth Intake")
    print("This wizard records credential references only. Do not enter a token, password, or secret value.")
    print("Templates: 1 Cloudflare, 2 GitHub CLI, 3 HTTP, 4 Umami HTTP, 5 Google adapter, 6 Custom adapter.")
    checks: list[AuthCheck] = []
    while True:
        choice = _ask(prompt, "Template number (blank to finish)")
        if not choice:
            break
        builders = {"1": _cloudflare, "2": _github, "3": _http, "4": lambda value: _http(value, umami=True), "5": lambda value: _adapter(value, google=True), "6": _adapter}
        builder = builders.get(choice)
        if builder is None:
            print("Choose a template number from 1 through 6.")
            continue
        try:
            check = builder(prompt)
        except ValueError:
            print("Timeout must be a number.")
            continue
        if any(item.name == check.name for item in checks):
            print("Check names must be unique.")
            continue
        checks.append(check)
        print(f"Added {check.name} ({check.provider}).")
    if not checks:
        print("No checks were added; configuration was not written.")
        return 0
    try:
        write_auth_config(path, AuthConfig(tuple(checks)), replace=replace)
    except ConfigError as exc:
        print(f"bs: {exc}")
        return 2
    print(f"Wrote {len(checks)} credential reference checks to {path}.")
    print("Run `bs auth` to verify them.")
    return 0
