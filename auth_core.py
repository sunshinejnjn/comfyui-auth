"""Configuration and signed-session helpers for ComfyUI Auth."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from base64 import urlsafe_b64decode, urlsafe_b64encode
from dataclasses import dataclass
from pathlib import Path
from typing import Collection, Mapping


class UserConfigError(ValueError):
    """Raised when users.conf cannot be used safely."""


class LDAPConfigError(ValueError):
    """Raised when ldap.conf exists but is invalid."""


class ApiKeysConfigError(ValueError):
    """Raised when apikeys.conf exists but is invalid."""


@dataclass(frozen=True)
class LDAPConfig:
    server: str
    search_base: str
    domain: str
    whitelist: frozenset[str]

    def identity(self, username: str) -> tuple[str, str] | None:
        """Return normalized ``(local user, UPN)`` for this LDAP domain."""
        local_user, separator, domain = username.rpartition("@")
        if not separator or not local_user or domain.casefold() != self.domain.casefold():
            return None
        normalized_user = local_user.casefold()
        return normalized_user, f"{normalized_user}@{self.domain}"

    def is_whitelisted(self, local_user: str) -> bool:
        return local_user.casefold() in self.whitelist


def password_sha256(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def load_users(path: Path) -> dict[str, str]:
    """Load ``username = sha256(password)`` records from *path*."""
    if not path.is_file():
        raise UserConfigError(f"User configuration file does not exist: {path}")

    users: dict[str, str] = {}
    errors: list[str] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise UserConfigError(f"Cannot read user configuration: {exc}") from exc

    for line_number, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if "=" not in line:
            errors.append(f"line {line_number}: missing '='")
            continue
        username, password_hash = (part.strip() for part in line.split("=", 1))
        if not username:
            errors.append(f"line {line_number}: username is empty")
        elif any(ord(char) < 32 for char in username):
            errors.append(f"line {line_number}: username contains a control character")
        elif username in users:
            errors.append(f"line {line_number}: duplicate username {username!r}")

        normalized_hash = password_hash.lower()
        if len(normalized_hash) != 64 or any(c not in "0123456789abcdef" for c in normalized_hash):
            errors.append(f"line {line_number}: password hash must be 64 hexadecimal characters")
        elif username and username not in users:
            users[username] = normalized_hash

    if errors:
        raise UserConfigError("Invalid user configuration (" + "; ".join(errors) + ")")
    if not users:
        raise UserConfigError(f"No users are configured in {path}")
    return users


def load_ldap_config(path: Path) -> LDAPConfig:
    """Load LDAP_SERVER, SEARCH_BASE and WHITELIST from an INI-like file."""
    if not path.is_file():
        raise LDAPConfigError(f"LDAP configuration file does not exist: {path}")
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise LDAPConfigError(f"Cannot read LDAP configuration: {exc}") from exc

    values: dict[str, str] = {}
    errors: list[str] = []
    allowed_keys = {"LDAP_SERVER", "SEARCH_BASE", "WHITELIST"}
    for line_number, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if "=" not in line:
            errors.append(f"line {line_number}: missing '='")
            continue
        key, value = (part.strip() for part in line.split("=", 1))
        key = key.upper()
        if key not in allowed_keys:
            errors.append(f"line {line_number}: unknown field {key!r}")
        elif key in values:
            errors.append(f"line {line_number}: duplicate field {key}")
        elif not value:
            errors.append(f"line {line_number}: {key} is empty")
        else:
            values[key] = value

    for key in sorted(allowed_keys - values.keys()):
        errors.append(f"missing required field {key}")

    domain = _domain_from_search_base(values.get("SEARCH_BASE", ""))
    if values.get("SEARCH_BASE") and not domain:
        errors.append("SEARCH_BASE must contain one or more DC components")

    whitelist = frozenset(
        user.strip().casefold()
        for user in values.get("WHITELIST", "").replace(";", ",").split(",")
        if user.strip()
    )
    if "WHITELIST" in values and not whitelist:
        errors.append("WHITELIST must contain at least one username")
    if any("@" in user for user in whitelist):
        errors.append("WHITELIST entries must be usernames without an @domain suffix")

    if errors:
        raise LDAPConfigError("Invalid LDAP configuration (" + "; ".join(errors) + ")")
    return LDAPConfig(
        server=values["LDAP_SERVER"],
        search_base=values["SEARCH_BASE"],
        domain=domain,
        whitelist=whitelist,
    )


def _domain_from_search_base(search_base: str) -> str:
    components: list[str] = []
    for component in search_base.split(","):
        key, separator, value = component.strip().partition("=")
        if separator and key.strip().casefold() == "dc" and value.strip():
            components.append(value.strip())
    return ".".join(components).casefold()


def verify_credentials(users: Mapping[str, str], username: str, password: str) -> bool:
    """Constant-time password comparison, including for unknown usernames."""
    expected = users.get(username, "0" * 64)
    supplied = password_sha256(password)
    valid = hmac.compare_digest(expected, supplied)
    return valid and username in users


def load_api_keys(path: Path) -> dict[str, str]:
    """Load API keys from an ``apikeys.conf`` file.

    Each entry is ``label = sha256(key)`` where ``label`` is an optional
    reference name; a bare 64-hex hash without ``=`` is also accepted (no
    label). Blank lines and lines beginning with ``#`` or ``;`` are ignored.
    Returns a mapping of {stored_key_hash: label}.
    """
    if not path.is_file():
        raise ApiKeysConfigError(f"API key configuration file does not exist: {path}")
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ApiKeysConfigError(f"Cannot read API key configuration: {exc}") from exc

    keys: dict[str, str] = {}
    errors: list[str] = []
    for line_number, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        label, separator, stored = line.partition("=")
        if separator:
            stored = stored.strip()
        else:
            label, stored = "", line
        label = label.strip()

        normalized = stored.lower()
        if len(normalized) != 64 or any(c not in "0123456789abcdef" for c in normalized):
            errors.append(f"line {line_number}: stored value must be 64 hexadecimal characters")
        elif normalized in keys:
            errors.append(f"line {line_number}: duplicate stored value")
        else:
            keys[normalized] = label

    if errors:
        raise ApiKeysConfigError(
            "Invalid API key configuration(" + "; ".join(errors) + ")"
        )
    if not keys:
        raise ApiKeysConfigError(f"No API keys are configured in {path}")
    return keys


def verify_api_key(api_key: str | None, keys: Mapping[str, str]) -> bool:
    """Return True if *api_key* matches one of the configured API keys.

    The presented key is hashed with :func:`password_sha256` and tested
    against the stored (hash) values; the input is always a fixed 64-character
    hex digest, so set membership is used instead of a linear scan.
    """
    if not api_key or not keys:
        return False
    return password_sha256(api_key) in keys


class SessionSigner:
    def __init__(self, secret: bytes, max_age_seconds: int = 86_400):
        if len(secret) < 32:
            raise ValueError("Session secret must contain at least 32 bytes")
        self.secret = secret
        self.max_age_seconds = max_age_seconds

    def create(self, username: str, now: int | None = None) -> str:
        payload = json.dumps(
            {"u": username, "iat": int(time.time() if now is None else now), "n": secrets.token_hex(8)},
            separators=(",", ":"),
        ).encode("utf-8")
        encoded = urlsafe_b64encode(payload).rstrip(b"=")
        signature = hmac.new(self.secret, encoded, hashlib.sha256).digest()
        return f"{encoded.decode('ascii')}.{urlsafe_b64encode(signature).rstrip(b'=').decode('ascii')}"

    def verify(self, token: str | None, users: Collection[str] | Mapping[str, str], now: int | None = None) -> str | None:
        if not token:
            return None
        try:
            encoded, supplied_signature = token.split(".", 1)
            expected_signature = hmac.new(self.secret, encoded.encode("ascii"), hashlib.sha256).digest()
            decoded_signature = _b64decode(supplied_signature)
            if not hmac.compare_digest(expected_signature, decoded_signature):
                return None
            payload = json.loads(_b64decode(encoded))
            username = payload["u"]
            issued_at = int(payload["iat"])
            current_time = int(time.time() if now is None else now)
            if not isinstance(username, str) or username not in users:
                return None
            if issued_at > current_time + 60 or current_time - issued_at > self.max_age_seconds:
                return None
            return username
        except (ValueError, TypeError, KeyError, json.JSONDecodeError, UnicodeError):
            return None


def load_or_create_secret(path: Path) -> bytes:
    """Load a persistent cookie-signing key, creating it with mode 0600."""
    try:
        secret = path.read_bytes()
    except FileNotFoundError:
        secret = secrets.token_bytes(48)
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            secret = path.read_bytes()
        else:
            with os.fdopen(descriptor, "wb") as output:
                output.write(secret)
    except OSError as exc:
        raise RuntimeError(f"Cannot read session secret {path}: {exc}") from exc
    if len(secret) < 32:
        raise RuntimeError(f"Session secret {path} is invalid; it must contain at least 32 bytes")
    return secret


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return urlsafe_b64decode(value + padding)
