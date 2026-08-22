"""Cookie parsing utilities.

Replaces fragile manual string-splitting of ``Set-Cookie`` headers with
Python's standard-library :class:`http.cookies.SimpleCookie` parser so that
expiry dates and other attributes are never mistaken for cookie names.
"""

from __future__ import annotations

import re
from http.cookies import CookieError, SimpleCookie
from typing import Any

_ATTRIBUTE_KEYS = ("secure", "httponly", "samesite", "path", "expires", "max-age", "domain")

# Attribute names that must never be reported as cookie names, even if
# SimpleCookie fails and we fall back to manual parsing.
_NON_COOKIE_NAMES = frozenset(
    {"expires", "max-age", "maxage", "path", "domain", "secure", "httponly", "samesite", "comment", "priority"}
)

_COMMA_DATE_RE = re.compile(
    r"(?:^|,\s)(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),\s\d{2}\s(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s"
)


def _split_cookie_lines(header_value: str) -> list[str]:
    """Split a raw ``Set-Cookie`` header value into individual cookie strings.

    Multiple ``Set-Cookie`` headers may arrive joined with ``", "`` by an HTTP
    client.  Naively splitting on every comma breaks ``Expires=Wed, 21 Oct 2026
    07:28:00 GMT``, so comma-splits only occur where the following segment
    clearly begins a new cookie (``name=value`` whose name is not a known
    attribute and not preceded by an RFC 1123 date).
    """
    candidates = [part.strip() for part in header_value.split(",") if part.strip()]
    result: list[str] = []
    current = ""
    for part in candidates:
        looks_like_new_cookie = (
            re.match(r"^[^=;\s,]+=", part) is not None
            and part.split("=", 1)[0].strip().lower() not in _NON_COOKIE_NAMES
            and not _COMMA_DATE_RE.match(part)
        )
        if looks_like_new_cookie and current:
            result.append(current)
            current = part
        else:
            current = f"{current}, {part}" if current else part
    if current:
        result.append(current)
    return result


def parse_cookie_header(header_value: str) -> list[dict[str, Any]]:
    """Parse a ``Set-Cookie`` header value into structured cookie records.

    Returns a list of dicts with keys: ``name``, ``value``, ``secure``,
    ``httponly``, ``samesite``, ``path``, ``domain``, ``expires``,
    ``max_age``.  Expiry dates and other attributes are never returned as
    cookie names.
    """
    if not header_value:
        return []

    cookies: list[dict[str, Any]] = []
    for raw_cookie in _split_cookie_lines(header_value):
        try:
            jar = SimpleCookie()
            jar.load(raw_cookie)
        except (CookieError, TypeError, ValueError):
            jar = None

        if jar is not None and jar.keys():
            for key, morsel in jar.items():
                if str(key).strip().lower() in _NON_COOKIE_NAMES:
                    continue
                cookies.append(_morsel_record(str(key), morsel))
            continue

        # Fallback: never report attribute names (e.g. Expires) as cookies.
        for segment in raw_cookie.split(";")[:1]:
            name, _, value = segment.partition("=")
            name = name.strip()
            if not name or name.lower() in _NON_COOKIE_NAMES:
                continue
            cookies.append(
                {
                    "name": name,
                    "value": value.strip().strip('"'),
                    "secure": "secure" in raw_cookie.lower(),
                    "httponly": "httponly" in raw_cookie.lower(),
                    "samesite": _attribute_value(raw_cookie, "samesite") or "",
                    "path": _attribute_value(raw_cookie, "path") or "/",
                    "domain": _attribute_value(raw_cookie, "domain") or "",
                    "expires": _attribute_value(raw_cookie, "expires") or "",
                    "max_age": _attribute_value(raw_cookie, "max-age") or "",
                }
            )
    return cookies


def _morsel_record(name: str, morsel: Any) -> dict[str, Any]:
    def attr(key: str) -> str:
        try:
            return str(morsel.get(key) or "").strip()
        except AttributeError:
            return ""

    return {
        "name": name,
        "value": morsel.value,
        "secure": bool(attr("secure")),
        "httponly": bool(attr("httponly")),
        "samesite": attr("samesite") or "",
        "path": attr("path") or "/",
        "domain": attr("domain") or "",
        "expires": attr("expires") or "",
        "max_age": attr("max-age") or "",
    }


def _attribute_value(header_value: str, attribute: str) -> str:
    match = re.search(rf"(?:^|;\s*){attribute}\s*=\s*([^;]+)", header_value, re.IGNORECASE)
    return match.group(1).strip().strip('"') if match else ""
