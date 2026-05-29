# SPDX-License-Identifier: MIT
"""Centralised security primitives for PyTangle.

Every subprocess invocation and outbound HTTP request in PyTangle is funnelled
through this module so that the hardening rules live in exactly one place and
are trivially auditable. See ``SECURITY.md`` for the rationale.
"""

from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
from collections.abc import Iterable, Mapping, Sequence
from html import escape as _html_escape
from urllib.parse import urlsplit

import requests
from requests.adapters import HTTPAdapter

__all__ = [
    "SafetyError",
    "CommandError",
    "SafeSession",
    "run_command",
    "validate_url",
    "is_valid_package_name",
    "is_valid_version",
    "safe_label",
]

# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #


class SafetyError(Exception):
    """Raised when an operation violates a security invariant."""


class CommandError(SafetyError):
    """Raised when a subprocess fails, is missing, or times out."""


# --------------------------------------------------------------------------- #
# Validation helpers
# --------------------------------------------------------------------------- #

# PEP 508 distribution name grammar.
_PACKAGE_NAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")
# Permissive PEP 440-ish version token: digits, dots, and the usual qualifiers.
_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+!_-]*$")
# Hard cap so a hostile name cannot blow up the terminal / HTML output.
_MAX_TOKEN_LEN = 128


def is_valid_package_name(name: object) -> bool:
    """Return True if *name* is a syntactically valid PEP 508 package name."""
    return (
        isinstance(name, str)
        and 0 < len(name) <= _MAX_TOKEN_LEN
        and bool(_PACKAGE_NAME_RE.match(name))
    )


def is_valid_version(version: object) -> bool:
    """Return True if *version* looks like a valid PEP 440 version string."""
    return (
        isinstance(version, str)
        and 0 < len(version) <= _MAX_TOKEN_LEN
        and bool(_VERSION_RE.match(version))
    )


def safe_label(value: object, *, max_len: int = _MAX_TOKEN_LEN) -> str:
    """Coerce *value* into an HTML-escaped, length-bounded label.

    Used for anything that ends up in the generated Pyvis HTML so that a
    malicious lockfile entry cannot inject markup or script.
    """
    text = "" if value is None else str(value)
    text = text.replace("\x00", "")
    if len(text) > max_len:
        text = text[: max_len - 1] + "…"
    return _html_escape(text, quote=True)


# --------------------------------------------------------------------------- #
# URL / SSRF validation
# --------------------------------------------------------------------------- #

# Only these hosts may ever be contacted.
ALLOWED_HOSTS: frozenset[str] = frozenset({"pypi.org", "api.osv.dev"})


def validate_url(url: str, *, allowed_hosts: Iterable[str] = ALLOWED_HOSTS) -> str:
    """Validate *url* against the SSRF allowlist; return it normalised.

    Enforces: HTTPS scheme, host in allowlist, no embedded credentials, no
    explicit non-default port, and rejects raw IP literals.
    """
    if not isinstance(url, str) or not url:
        raise SafetyError("URL must be a non-empty string")

    parts = urlsplit(url)
    if parts.scheme != "https":
        raise SafetyError(f"Refusing non-HTTPS URL: {url!r}")
    if parts.username or parts.password:
        raise SafetyError("Refusing URL with embedded credentials")

    host = parts.hostname
    if not host:
        raise SafetyError(f"URL has no host: {url!r}")

    # Reject raw IP literals outright — the allowlist is hostname-based and
    # IPs are a common SSRF pivot (e.g. 169.254.169.254, 127.0.0.1).
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass  # not an IP literal — good
    else:
        raise SafetyError(f"Refusing IP-literal host: {host!r}")

    if host.lower() not in {h.lower() for h in allowed_hosts}:
        raise SafetyError(f"Host {host!r} is not on the allowlist")

    # Disallow an explicit port; rely on the implicit HTTPS 443.
    if parts.port is not None and parts.port != 443:
        raise SafetyError(f"Refusing non-standard port: {parts.port}")

    return url


# --------------------------------------------------------------------------- #
# Hardened HTTP client
# --------------------------------------------------------------------------- #

DEFAULT_TIMEOUT = (5.0, 15.0)  # (connect, read) seconds
_MAX_RESPONSE_BYTES = 16 * 1024 * 1024  # 16 MiB hard cap


class SafeSession:
    """A ``requests`` session that enforces PyTangle's network policy.

    * HTTPS-only requests to allowlisted hosts (re-validated per request).
    * Redirects disabled (defends against redirect-to-internal SSRF).
    * Connect/read timeouts always applied.
    * Streamed responses with a hard size cap.
    """

    def __init__(
        self,
        *,
        allowed_hosts: Iterable[str] = ALLOWED_HOSTS,
        timeout: tuple[float, float] = DEFAULT_TIMEOUT,
        user_agent: str = "pytangle",
        max_retries: int = 2,
    ) -> None:
        self._allowed_hosts = frozenset(allowed_hosts)
        self._timeout = timeout
        self._session = requests.Session()
        self._session.headers.update(
            {"User-Agent": user_agent, "Accept": "application/json"}
        )
        adapter = HTTPAdapter(max_retries=max_retries)
        self._session.mount("https://", adapter)

    def get(self, url: str, **kwargs) -> requests.Response:
        return self._request("GET", url, **kwargs)

    def post_json(self, url: str, payload: object, **kwargs) -> requests.Response:
        return self._request("POST", url, json=payload, **kwargs)

    def _request(self, method: str, url: str, **kwargs) -> requests.Response:
        validate_url(url, allowed_hosts=self._allowed_hosts)
        kwargs.setdefault("timeout", self._timeout)
        # Security-critical defaults the caller must not override.
        kwargs["allow_redirects"] = False
        kwargs["stream"] = True
        resp = self._session.request(method, url, **kwargs)
        self._enforce_size_cap(resp)
        return resp

    @staticmethod
    def _enforce_size_cap(resp: requests.Response) -> None:
        declared = resp.headers.get("Content-Length")
        if declared is not None:
            try:
                if int(declared) > _MAX_RESPONSE_BYTES:
                    resp.close()
                    raise SafetyError("Response exceeds size cap")
            except ValueError:
                pass
        # Read with a cap even when Content-Length is absent/lying.
        content = resp.raw.read(_MAX_RESPONSE_BYTES + 1, decode_content=True)
        if len(content) > _MAX_RESPONSE_BYTES:
            resp.close()
            raise SafetyError("Response exceeds size cap")
        # Re-seat the consumed body so callers can use resp.json()/.content.
        resp._content = content
        resp._content_consumed = True  # type: ignore[attr-defined]

    def close(self) -> None:
        self._session.close()

    def __enter__(self) -> SafeSession:
        return self

    def __exit__(self, *exc) -> None:
        self.close()


# --------------------------------------------------------------------------- #
# Hardened subprocess runner
# --------------------------------------------------------------------------- #

# Minimal, predictable environment for child processes.
_SAFE_ENV_KEYS = ("PATH", "HOME", "LANG", "LC_ALL", "SYSTEMROOT", "TMPDIR")


def _scrubbed_env(extra: Mapping[str, str] | None) -> dict[str, str]:
    import os

    env = {k: os.environ[k] for k in _SAFE_ENV_KEYS if k in os.environ}
    env.setdefault("PATH", os.defpath)
    if extra:
        env.update({str(k): str(v) for k, v in extra.items()})
    return env


def run_command(
    args: Sequence[str],
    *,
    timeout: float = 60.0,
    cwd: str | None = None,
    check: bool = True,
    extra_env: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run an external command safely.

    Security guarantees:
      * ``shell=False`` always — *args* is a list, never a shell string.
      * The executable (``args[0]``) is resolved with :func:`shutil.which`;
        bare relative paths are rejected.
      * A wall-clock timeout is enforced.
      * The child runs with a scrubbed, minimal environment.
    """
    if isinstance(args, (str, bytes)):
        raise CommandError("args must be a list of strings, not a string")
    arg_list = [str(a) for a in args]
    if not arg_list:
        raise CommandError("No command provided")

    program = arg_list[0]
    resolved = shutil.which(program)
    if resolved is None:
        raise CommandError(f"Executable not found on PATH: {program!r}")

    try:
        proc = subprocess.run(  # noqa: S603 - hardened: shell=False, list args, scrubbed env
            [resolved, *arg_list[1:]],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            check=False,
            shell=False,
            env=_scrubbed_env(extra_env),
        )
    except subprocess.TimeoutExpired as exc:
        raise CommandError(f"Command timed out after {timeout}s: {program}") from exc
    except OSError as exc:
        raise CommandError(f"Failed to run {program}: {exc}") from exc

    if check and proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        raise CommandError(
            f"Command {program!r} exited with {proc.returncode}: {stderr[:500]}"
        )
    return proc
