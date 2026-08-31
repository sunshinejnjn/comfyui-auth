"""LDAP bind authentication based on ldap_auth_test.py."""

from __future__ import annotations

import logging

from .auth_core import LDAPConfig

LOGGER = logging.getLogger("comfyui-auth")


def authenticate_ldap(config: LDAPConfig, username: str, password: str) -> bool:
    """Authenticate by binding to LDAP with the user's full UPN."""
    if not password:
        return False
    try:
        import ldap3
    except ImportError:
        LOGGER.error("LDAP authentication requires the 'ldap3' Python package")
        return False

    try:
        server = ldap3.Server(config.server, use_ssl=True, get_info=None)
        connection = ldap3.Connection(server, user=username, password=password, auto_bind=True)
        try:
            return bool(connection.bound)
        finally:
            connection.unbind()
    except Exception as exc:
        LOGGER.warning("LDAP authentication failed for %s via %s: %s", username, config.server, exc)
        return False
