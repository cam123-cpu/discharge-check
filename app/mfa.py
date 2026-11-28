"""Two-factor sign-in: TOTP (RFC 6238) authenticator apps and single-use
recovery codes. Routes are added by register(app, ctx)."""
from __future__ import annotations

AUDIT_ACTIONS: dict[str, str] = {}


def register(app, ctx) -> None:
    pass
