"""aiohttp middleware that protects the entire ComfyUI web application."""

from __future__ import annotations

import asyncio
import html
import logging
import os
import time
from collections import defaultdict, deque
from pathlib import Path
from urllib.parse import quote

from aiohttp import web

from .auth_core import (
    LDAPConfig,
    LDAPConfigError,
    SessionSigner,
    UserConfigError,
    load_ldap_config,
    load_or_create_secret,
    load_users,
    verify_credentials,
)
from .ldap_auth import authenticate_ldap

LOGGER = logging.getLogger("comfyui-auth")
PLUGIN_DIR = Path(__file__).resolve().parent
COOKIE_NAME = "comfyui_auth_session"
LOGIN_PATH = "/comfyui-auth/login"
LOGOUT_PATH = "/comfyui-auth/logout"
MAX_FORM_SIZE = 16 * 1024
_LOGGED_CONFIG_ERRORS: set[str] = set()


class LoginRateLimiter:
    """Small in-memory limiter to slow password guessing per remote address."""

    def __init__(self, attempts: int = 10, window_seconds: int = 300):
        self.attempts = attempts
        self.window_seconds = window_seconds
        self._entries: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str, now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        entries = self._entries[key]
        while entries and current - entries[0] > self.window_seconds:
            entries.popleft()
        if len(entries) >= self.attempts:
            return False
        entries.append(current)
        return True

    def clear(self, key: str) -> None:
        self._entries.pop(key, None)


def _users_path() -> Path:
    configured = os.environ.get("COMFYUI_AUTH_USERS_FILE")
    return Path(configured).expanduser().resolve() if configured else PLUGIN_DIR / "users.conf"


def _ldap_path() -> Path:
    configured = os.environ.get("COMFYUI_AUTH_LDAP_FILE")
    return Path(configured).expanduser().resolve() if configured else PLUGIN_DIR / "ldap.conf"


def _session_max_age() -> int:
    raw_value = os.environ.get("COMFYUI_AUTH_SESSION_MAX_AGE", "86400")
    try:
        value = int(raw_value)
    except ValueError:
        LOGGER.error("Invalid COMFYUI_AUTH_SESSION_MAX_AGE=%r; using 86400", raw_value)
        return 86_400
    return max(300, value)


def _load_users_for_request() -> tuple[dict[str, str], str | None]:
    path = _users_path()
    if not path.exists():
        return {}, f"User configuration file does not exist: {path}"
    try:
        return load_users(path), None
    except UserConfigError as exc:
        _log_config_error_once(str(exc))
        return {}, str(exc)


def _load_ldap_for_request() -> tuple[LDAPConfig | None, str | None]:
    path = _ldap_path()
    if not path.exists():
        return None, None
    try:
        return load_ldap_config(path), None
    except LDAPConfigError as exc:
        _log_config_error_once(str(exc))
        return None, str(exc)


def _log_config_error_once(message: str) -> None:
    if message not in _LOGGED_CONFIG_ERRORS:
        _LOGGED_CONFIG_ERRORS.add(message)
        LOGGER.error("%s", message)


def _authorized_identities(users: dict[str, str], ldap_config: LDAPConfig | None) -> set[str]:
    identities = set(users)
    if ldap_config:
        identities.update(f"{user}@{ldap_config.domain}" for user in ldap_config.whitelist)
    return identities


def _is_https(request: web.Request) -> bool:
    forced = os.environ.get("COMFYUI_AUTH_SECURE_COOKIE", "").strip().lower()
    if forced in {"1", "true", "yes", "on"}:
        return True
    # Do not trust X-Forwarded-Proto automatically: aiohttp only treats it as
    # authoritative when the deployment has configured a trusted proxy.
    return request.secure


def _client_key(request: web.Request) -> str:
    return request.remote or "unknown"


def _login_page(
    error: str | None = None,
    config_error: str | None = None,
    next_path: str | None = None,
    ldap_domain: str | None = None,
) -> web.Response:
    message = ""
    if config_error:
        message = f'<div class="error"><strong>Authentication is not configured.</strong><br>{html.escape(config_error)}</div>'
    elif error:
        message = f'<div class="error">{html.escape(error)}</div>'
    disabled = " disabled" if config_error else ""
    action = LOGIN_PATH
    if next_path:
        action += "?next=" + quote(_safe_next(next_path), safe="")
    login_prompt = "Sign in to continue"
    if ldap_domain:
        login_prompt = f"Sign in with ntid@{ldap_domain} to continue"
    body = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ComfyUI Login</title><style>
:root{{color-scheme:dark}}*{{box-sizing:border-box}}body{{margin:0;min-height:100vh;display:grid;place-items:center;background:#111318;color:#e7e9ee;font:15px system-ui,sans-serif}}
.card{{width:min(390px,calc(100% - 32px));padding:32px;border:1px solid #30333b;border-radius:14px;background:#1b1e24;box-shadow:0 18px 55px #0008}}
h1{{margin:0 0 8px;font-size:25px}}p{{margin:0 0 24px;color:#aeb3bd}}label{{display:block;margin:15px 0 6px;font-weight:600}}
input{{width:100%;padding:11px 12px;border:1px solid #444955;border-radius:7px;background:#101217;color:#fff;font:inherit}}input:focus{{outline:2px solid #6b8afd;border-color:transparent}}
button{{width:100%;margin-top:22px;padding:11px;border:0;border-radius:7px;background:#526ee8;color:white;font:700 15px system-ui;cursor:pointer}}button:disabled{{opacity:.45;cursor:not-allowed}}
.error{{margin:18px 0;padding:11px;border:1px solid #8d3e45;border-radius:7px;background:#3b2024;color:#ffd9dc;overflow-wrap:anywhere}}
</style></head><body><main class="card"><h1>ComfyUI</h1><p>{html.escape(login_prompt)}</p>{message}
<form method="post" action="{html.escape(action, quote=True)}" accept-charset="utf-8">
<label for="username">Username</label><input id="username" name="username" autocomplete="username" required autofocus{disabled}>
<label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required{disabled}>
<button type="submit"{disabled}>Sign in</button></form></main></body></html>"""
    return web.Response(
        text=body,
        content_type="text/html",
        headers={
            "Cache-Control": "no-store",
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
            "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
        },
    )


def _redirect_to_login(request: web.Request) -> web.Response:
    if request.method in {"GET", "HEAD"} and request.headers.get("Upgrade", "").lower() != "websocket":
        return web.HTTPFound(f"{LOGIN_PATH}?next={quote(request.path_qs, safe='')}")
    return web.json_response({"error": "authentication required", "login": LOGIN_PATH}, status=401)


def _safe_next(value: str | None) -> str:
    # Only permit local absolute paths, never scheme-relative/external URLs.
    if value and value.startswith("/") and not value.startswith("//") and "\r" not in value and "\n" not in value:
        return value
    return "/"


def build_auth_middleware(signer: SessionSigner):
    limiter = LoginRateLimiter()

    @web.middleware
    async def auth_middleware(request: web.Request, handler):
        users, users_error = _load_users_for_request()
        ldap_config, ldap_error = _load_ldap_for_request()
        config_error = None
        if not users and ldap_config is None:
            config_error = ldap_error or users_error or "No authentication provider is configured"

        if request.path == LOGIN_PATH:
            if request.method == "GET":
                return _login_page(
                    config_error=config_error,
                    next_path=request.query.get("next"),
                    ldap_domain=ldap_config.domain if ldap_config else None,
                )
            if request.method != "POST":
                raise web.HTTPMethodNotAllowed(request.method, ["GET", "POST"])
            if config_error:
                return _login_page(config_error=config_error, ldap_domain=ldap_config.domain if ldap_config else None)
            if request.content_length is not None and request.content_length > MAX_FORM_SIZE:
                raise web.HTTPRequestEntityTooLarge(max_size=MAX_FORM_SIZE, actual_size=request.content_length)
            client = _client_key(request)
            if not limiter.allow(client):
                return _login_page(
                    "Too many login attempts. Try again later.",
                    next_path=request.query.get("next"),
                    ldap_domain=ldap_config.domain if ldap_config else None,
                )
            try:
                form = await request.post()
            except (ValueError, web.HTTPException):
                return _login_page(
                    "Invalid login request.",
                    next_path=request.query.get("next"),
                    ldap_domain=ldap_config.domain if ldap_config else None,
                )
            username = str(form.get("username", ""))
            password = str(form.get("password", ""))
            authenticated_username: str | None = None
            ldap_identity = ldap_config.identity(username) if ldap_config else None
            if ldap_identity:
                local_user, ldap_username = ldap_identity
                if ldap_config.is_whitelisted(local_user):
                    if await asyncio.to_thread(authenticate_ldap, ldap_config, ldap_username, password):
                        authenticated_username = ldap_username
            elif verify_credentials(users, username, password):
                authenticated_username = username
            if authenticated_username is None:
                return _login_page(
                    "Invalid username or password.",
                    next_path=request.query.get("next"),
                    ldap_domain=ldap_config.domain if ldap_config else None,
                )
            limiter.clear(client)
            response = web.HTTPFound(_safe_next(request.query.get("next")))
            response.set_cookie(
                COOKIE_NAME,
                signer.create(authenticated_username),
                max_age=signer.max_age_seconds,
                httponly=True,
                secure=_is_https(request),
                samesite="Strict",
                path="/",
            )
            return response

        if request.path == LOGOUT_PATH:
            response = web.HTTPFound(LOGIN_PATH)
            response.del_cookie(COOKIE_NAME, path="/")
            return response

        username = signer.verify(request.cookies.get(COOKIE_NAME), _authorized_identities(users, ldap_config))
        if config_error or username is None:
            return _redirect_to_login(request)
        request["comfyui_auth_username"] = username
        return await handler(request)

    return auth_middleware


def install_auth_middleware() -> None:
    try:
        from server import PromptServer
    except ImportError as exc:
        raise RuntimeError("ComfyUI Auth must be loaded by ComfyUI (cannot import server.PromptServer)") from exc

    prompt_server = PromptServer.instance
    if prompt_server is None:
        raise RuntimeError("ComfyUI PromptServer is not initialized")
    app = prompt_server.app
    marker = "_comfyui_auth_installed"
    if getattr(app, marker, False):
        return
    signer = SessionSigner(load_or_create_secret(PLUGIN_DIR / ".session_secret"), _session_max_age())
    app.middlewares.insert(0, build_auth_middleware(signer))
    setattr(app, marker, True)
    LOGGER.info("Authentication middleware installed; users file: %s; LDAP file: %s", _users_path(), _ldap_path())
