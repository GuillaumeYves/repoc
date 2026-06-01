"""Ephemeral auth: device flow + stdin token, with nothing persisted."""

import httpx
import pytest

from repoc import auth


def test_resolve_client_id_errors_without_env(monkeypatch):
    monkeypatch.delenv(auth.CLIENT_ID_ENV, raising=False)
    with pytest.raises(auth.AuthError):
        auth.resolve_client_id()


def test_resolve_client_id_from_env(monkeypatch):
    monkeypatch.setenv(auth.CLIENT_ID_ENV, "Iv1.abc123")
    assert auth.resolve_client_id() == "Iv1.abc123"


def test_device_login_polls_until_token(monkeypatch):
    # Mock the HTTP transport so no real network call happens.
    calls = {"token": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/device/code"):
            return httpx.Response(
                200,
                json={
                    "device_code": "dc",
                    "user_code": "WXYZ-1234",
                    "verification_uri": "https://github.com/login/device",
                    "interval": 0,
                    "expires_in": 60,
                },
            )
        # access token endpoint: pending once, then success
        calls["token"] += 1
        if calls["token"] == 1:
            return httpx.Response(200, json={"error": "authorization_pending"})
        return httpx.Response(200, json={"access_token": "gho_secret"})

    transport = httpx.MockTransport(handler)
    real_client = httpx.Client

    def fake_client(*args, **kwargs):
        kwargs["transport"] = transport
        return real_client(*args, **kwargs)

    monkeypatch.setattr(auth.httpx, "Client", fake_client)
    monkeypatch.setattr(auth.time, "sleep", lambda *_: None)

    messages: list[str] = []
    token = auth.device_login(client_id="Iv1.abc", prompt=messages.append)

    assert token == "gho_secret"
    # The one-time user code is shown to the user.
    assert any("WXYZ-1234" in m for m in messages)


def test_device_login_raises_on_access_denied(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/device/code"):
            return httpx.Response(
                200,
                json={"device_code": "dc", "user_code": "AAAA", "interval": 0, "expires_in": 60},
            )
        return httpx.Response(200, json={"error": "access_denied"})

    transport = httpx.MockTransport(handler)
    real_client = httpx.Client
    monkeypatch.setattr(
        auth.httpx, "Client", lambda *a, **k: real_client(*a, **{**k, "transport": transport})
    )
    monkeypatch.setattr(auth.time, "sleep", lambda *_: None)

    with pytest.raises(auth.AuthError):
        auth.device_login(client_id="Iv1.abc", prompt=lambda *_: None)
