"""Ephemeral GitHub authentication for inspecting private repositories.

Design goals (per the project's trust model):

* **Nothing is persisted.** repoc never writes a token to disk, a keyring, or an
  environment file. A token obtained here lives only in memory for the duration
  of a single ``repoc inspect`` run and is discarded on exit.
* **No secret in shell history or the process table.** The recommended paths are
  ``--login`` (GitHub's OAuth *device flow*, where you type a one-time code in
  the browser and repoc receives a short-lived token) and ``--token-stdin``
  (pipe a token in, so it never appears in ``argv``).

The device flow needs a public GitHub OAuth App *client id*. There is no secret
involved — the client id is safe to ship — but because every deployment should
use its own app, repoc reads it from the ``REPOC_GITHUB_CLIENT_ID`` environment
variable rather than hard-coding one. If it is unset, ``--login`` explains how to
register an app (or fall back to ``--token-stdin``).
"""

from __future__ import annotations

import os
import sys
import time

import httpx

DEVICE_CODE_URL = "https://github.com/login/device/code"
ACCESS_TOKEN_URL = "https://github.com/login/oauth/access_token"
DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"

# Read-only access is enough to inspect a private repo's metadata and contents.
DEFAULT_SCOPE = "repo:status read:org repo"

CLIENT_ID_ENV = "REPOC_GITHUB_CLIENT_ID"


class AuthError(RuntimeError):
    """Raised when interactive authentication cannot complete."""


def read_token_from_stdin() -> str:
    """Read a token piped on stdin. Never echoed, never stored."""

    if sys.stdin.isatty():
        raise AuthError(
            "--token-stdin expects a token on standard input, e.g. "
            "`echo $TOKEN | repoc inspect owner/repo --token-stdin`."
        )
    token = sys.stdin.readline().strip()
    if not token:
        raise AuthError("No token received on standard input.")
    return token


def resolve_client_id(client_id: str | None = None) -> str:
    client_id = client_id or os.environ.get(CLIENT_ID_ENV) or ""
    if not client_id:
        raise AuthError(
            "Interactive login needs a GitHub OAuth App client id.\n"
            f"Set {CLIENT_ID_ENV} to a public OAuth App's client id "
            "(https://github.com/settings/developers — enable 'Device Flow'),\n"
            "or skip login and pipe a fine-grained, read-only token instead:\n"
            "  echo $TOKEN | repoc inspect owner/repo --token-stdin"
        )
    return client_id


def device_login(
    *,
    client_id: str | None = None,
    scope: str = DEFAULT_SCOPE,
    prompt=print,
    timeout: float = 15.0,
) -> str:
    """Run GitHub's OAuth device flow and return a short-lived access token.

    The token is returned to the caller and never written anywhere by repoc.
    ``prompt`` is a callable used to show the user code / verification URL
    (defaults to ``print``; the CLI passes a Rich console printer).
    """

    client_id = resolve_client_id(client_id)

    with httpx.Client(timeout=timeout, headers={"Accept": "application/json"}) as client:
        start = _post(
            client,
            DEVICE_CODE_URL,
            {"client_id": client_id, "scope": scope},
        )
        device_code = start.get("device_code")
        user_code = start.get("user_code")
        verification_uri = start.get("verification_uri", "https://github.com/login/device")
        interval = int(start.get("interval", 5)) or 5
        expires_in = int(start.get("expires_in", 900)) or 900
        if not device_code or not user_code:
            raise AuthError("GitHub did not return a device code. Check the client id.")

        prompt(
            f"\nTo authorize repoc for this one run, open:\n  {verification_uri}\n"
            f"and enter the one-time code:  {user_code}\n"
            "Waiting for authorization (nothing will be saved to disk)...\n"
        )

        deadline = time.monotonic() + expires_in
        while time.monotonic() < deadline:
            time.sleep(interval)
            payload = _post(
                client,
                ACCESS_TOKEN_URL,
                {
                    "client_id": client_id,
                    "device_code": device_code,
                    "grant_type": DEVICE_GRANT,
                },
            )
            token = payload.get("access_token")
            if token:
                return token
            error = payload.get("error")
            if error == "authorization_pending":
                continue
            if error == "slow_down":
                interval += int(payload.get("interval", 5))
                continue
            if error in {"expired_token", "access_denied", "incorrect_device_code"}:
                raise AuthError(f"Authorization failed: {error}.")
            # Unknown error — surface GitHub's description if present.
            raise AuthError(
                f"Authorization failed: {payload.get('error_description', error or 'unknown error')}."
            )
        raise AuthError("Timed out waiting for device authorization.")


def _post(client: httpx.Client, url: str, data: dict[str, str]) -> dict:
    try:
        response = client.post(url, data=data)
    except httpx.HTTPError as exc:
        raise AuthError(f"Network error during authentication: {exc}") from exc
    try:
        return response.json()
    except ValueError as exc:
        raise AuthError("Unexpected non-JSON response from GitHub during authentication.") from exc
