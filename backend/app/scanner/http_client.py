"""Shared HTTP client factory for the passive scanner.

Enforces two protocol standards that eliminate common false positives:

* ``follow_redirects=True`` — all security-header, cookie and TLS parsing must
  operate on the *final* response after 301/302/303/307 redirects have been
  followed, never on an intermediate redirect hop.
* ``verify=True`` — TLS certificate chains are validated; failed handshakes are
  reported as a single informational finding instead of inventing fake
  "missing header" flags from an unreadable response.
"""

from __future__ import annotations

from typing import Any

import httpx

DEFAULT_TIMEOUT = 10.0
DEFAULT_USER_AGENT = "PhantomScan/1.0"


def build_http_client(
    *,
    timeout: float = DEFAULT_TIMEOUT,
    follow_redirects: bool = True,
    verify: bool = True,
    **kwargs: Any,
) -> httpx.AsyncClient:
    """Build a hardened :class:`httpx.AsyncClient`.

    Redirects are always followed and TLS certificates validated unless the
    caller explicitly opts out.
    """
    headers = dict(kwargs.pop("headers", {}) or {})
    headers.setdefault("User-Agent", DEFAULT_USER_AGENT)
    return httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=follow_redirects,
        verify=verify,
        headers=headers,
        **kwargs,
    )
