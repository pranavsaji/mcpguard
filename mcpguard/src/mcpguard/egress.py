"""Outbound destinations a server's own source code contacts.

A tool-call policy only sees the calls the model proposes. A malicious server
can ignore its description and send data from inside its own process —
``postmark-mcp`` quietly BCC'd every email it sent. This module reads the
server's source (via :class:`~mcpguard.context.AnalysisContext`) and extracts:

* literal URLs passed to network calls (``fetch("https://…")``,
  ``requests.post("https://…")``, ``new WebSocket("wss://…")``…),
* hard-coded BCC recipients in mail-sending code.

Only the "text" view of each file is matched (comments blanked, strings kept;
see :mod:`mcpguard.source_mask`), so a commented-out call doesn't count. Used by
EGR01 (report) and the lockfile (a new destination since review is drift).
"""

from __future__ import annotations

import ipaddress
import os
from collections.abc import Iterator
from dataclasses import dataclass
from urllib.parse import urlparse

from .context import AnalysisContext
from .models import MCPServerSpec
from .patterns import (
    COLLECTOR_HOST_SUFFIXES,
    COLLECTOR_URL_RE,
    HIDDEN_RECIPIENT_RE,
    LOOPBACK_HOST_RE,
    NETWORK_CALL_URL_RE,
)
from .source_mask import mask_source

__all__ = ["Destination", "collector_reason", "egress_hosts", "iter_destinations"]


@dataclass(frozen=True, slots=True)
class Destination:
    """One outbound destination found in source."""

    kind: str  # "url" | "bcc"
    value: str  # the URL or the email address
    host: str  # hostname (URL) or domain (email)
    path: str
    line: int
    snippet: str


def _host(url: str) -> str | None:
    try:
        host = (urlparse(url).hostname or "").lower()
    except ValueError:
        return None
    # Template placeholders (``https://${host}/x``) aren't a fixed destination.
    if not host or any(c in host for c in "${}<>") or LOOPBACK_HOST_RE.match(host):
        return None
    return host


def iter_destinations(spec: MCPServerSpec, ctx: AnalysisContext) -> Iterator[Destination]:
    """Every literal outbound destination in ``spec``'s source, in file / line order."""
    for path, source in ctx.iter_source_files(spec):
        ext = os.path.splitext(path)[1].lower()
        text_lines = mask_source(source, ext).text.split("\n")
        raw_lines = source.split("\n")
        for index, line in enumerate(text_lines):
            if "://" in line:
                for match in NETWORK_CALL_URL_RE.finditer(line):
                    url = match.group("url")
                    host = _host(url)
                    if host:
                        yield Destination("url", url, host, path, index + 1, raw_lines[index])
            if "@" in line:
                for match in HIDDEN_RECIPIENT_RE.finditer(line):
                    addr = match.group("addr")
                    yield Destination(
                        "bcc", addr, addr.rsplit("@", 1)[1].lower(), path, index + 1, raw_lines[index]
                    )


def collector_reason(dest: Destination) -> str | None:
    """Why this destination is an exfiltration channel rather than an API, if it is."""
    if dest.kind == "bcc":
        return "hard-coded BCC recipient: every message the server sends is copied there"
    if COLLECTOR_URL_RE.search(dest.value):
        return "a chat webhook / bot endpoint that delivers data to whoever owns it"
    if any(dest.host == s or dest.host.endswith("." + s) for s in COLLECTOR_HOST_SUFFIXES):
        return "a request-collector / tunnel service built to receive arbitrary data"
    try:
        ip = ipaddress.ip_address(dest.host.strip("[]"))
    except ValueError:
        return None
    return "a hard-coded public IP address (no DNS, no certificate identity)" if ip.is_global else None


def egress_hosts(spec: MCPServerSpec, ctx: AnalysisContext) -> list[str]:
    """Sorted distinct destination hosts / mail domains in ``spec``'s source."""
    return sorted({d.host for d in iter_destinations(spec, ctx)})
