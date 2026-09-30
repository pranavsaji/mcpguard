"""OAuth authorization metadata of a remote MCP server (AUTH01).

The client side of MCP authorization consumes documents the *server* controls:
RFC 9728 protected-resource metadata names the authorization servers, and RFC
8414 authorization-server metadata names the endpoints the client will open and
post credentials to. CVE-2025-6514 (``mcp-remote``) was a client passing a
hostile ``authorization_endpoint`` to the OS — the server never had to be
"prompt injected". MCP 2026-07-28 hardened this side: authorization servers
SHOULD return ``iss`` (RFC 9207), clients MUST bind credentials to the issuer
that minted them, and Dynamic Client Registration is deprecated for Client ID
Metadata Documents.

:func:`discover` fetches the documents through an injected ``fetch_json`` (so
it's testable offline); :func:`analyze` is pure and returns the issues AUTH01
reports. The real fetcher (:func:`http_fetch_json`) never follows redirects,
caps response size and total time, resolves each host and refuses non-public
addresses, and only fetches authorization-server metadata from public ``https``
issuers (loopback too, when the MCP server itself is local) — at most
``MAX_ISSUERS`` of them. The scanner must not become an SSRF probe for a hostile
server. (A DNS answer that changes between the check and the connect is not
defended against; run ``--connect`` where the network itself is constrained.)
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse, urlunparse

from ..patterns import LOOPBACK_HOST_RE

__all__ = ["AuthIssue", "AuthMetadata", "analyze", "discover", "http_fetch_json", "scopes_of"]

FetchJson = Callable[[str], "dict[str, Any] | None"]

MAX_BYTES = 256 * 1024
MAX_ISSUERS = 5  # a hostile PRM can list thousands; only the first few are fetched
MAX_FETCHES = 16
DISCOVERY_BUDGET_SECONDS = 30.0
# Endpoint URL fields in RFC 8414 metadata that a client opens or sends secrets to.
ENDPOINT_FIELDS = (
    "authorization_endpoint", "token_endpoint", "registration_endpoint", "jwks_uri",
    "revocation_endpoint", "introspection_endpoint", "userinfo_endpoint",
    "device_authorization_endpoint", "pushed_authorization_request_endpoint",
)
# Characters with meaning to a shell or to `open` / `xdg-open` / `start`: never in a URL a
# client will launch (the CVE-2025-6514 payload shape).
_SHELL_META_RE = re.compile(r"[`$|;&<>\\\s\x00-\x1f\x7f]|\$\(")
_BROAD_SCOPE_RE = re.compile(
    r"^(?:\*|all|admin|root|superuser|full[_-]?access|owner)$|[:./](?:\*|admin|all)$", re.IGNORECASE
)


@dataclass(frozen=True)
class AuthMetadata:
    """What discovery found for one MCP endpoint."""

    server_url: str
    resource: str | None = None  # the resource identifier the PRM was fetched for
    resource_metadata_url: str | None = None
    resource_metadata: dict[str, Any] | None = None
    authorization_servers: dict[str, dict[str, Any] | None] = field(default_factory=dict)
    errors: tuple[str, ...] = ()

    @property
    def issuers(self) -> list[str]:
        return sorted(self.authorization_servers)


@dataclass(frozen=True)
class AuthIssue:
    severity: str  # critical | high | medium | low | info
    title: str
    field: str
    evidence: str
    remediation: str


# --------------------------------------------------------------------------- #
# Discovery                                                                   #
# --------------------------------------------------------------------------- #


def _well_known(base: str, suffix: str) -> list[str]:
    """RFC 8414 / 9728 well-known URLs: path-inserted first, then the origin."""
    parsed = urlparse(base)
    path = parsed.path.rstrip("/")
    origin = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
    urls = [f"{origin}/.well-known/{suffix}{path}"] if path else []
    urls.append(f"{origin}/.well-known/{suffix}")
    return urls


def discover(server_url: str, fetch_json: FetchJson) -> AuthMetadata | None:
    """Fetch the server's protected-resource and authorization-server metadata.

    Returns ``None`` when the server publishes no protected-resource metadata
    (it doesn't use MCP authorization).
    """
    errors: list[str] = []
    prm: dict[str, Any] | None = None
    prm_url = resource = None
    parsed = urlparse(server_url)
    for url in _well_known(server_url, "oauth-protected-resource"):
        try:
            prm = fetch_json(url)
        except (OSError, ValueError) as exc:
            errors.append(f"{url}: {exc}")
            continue
        if prm is not None:
            prm_url = url
            # The identifier this well-known URL stands for (RFC 9728 §3.1).
            suffix = url.split("/.well-known/oauth-protected-resource", 1)[1]
            resource = urlunparse((parsed.scheme, parsed.netloc, suffix, "", "", ""))
            break
    if prm is None:
        return AuthMetadata(server_url, errors=tuple(errors)) if errors else None

    local_server = _host_kind(server_url)[1] == "loopback"
    servers: dict[str, dict[str, Any] | None] = {}
    listed = prm.get("authorization_servers")
    issuers = [i for i in listed if isinstance(i, str)] if isinstance(listed, list) else []
    if len(issuers) > MAX_ISSUERS:
        errors.append(f"{len(issuers)} authorization servers listed; only the first {MAX_ISSUERS} checked")
    fetches, deadline = 0, time.monotonic() + DISCOVERY_BUDGET_SECONDS
    for issuer in issuers[:MAX_ISSUERS]:
        servers[issuer] = None
        if not _safe_to_fetch(issuer, local_server):
            continue  # reported by analyze(); never fetched
        for url in _well_known(issuer, "oauth-authorization-server") + _well_known(
            issuer, "openid-configuration"
        ):
            if fetches >= MAX_FETCHES or time.monotonic() > deadline:
                errors.append("discovery budget exhausted; remaining issuers not checked")
                return AuthMetadata(server_url, resource, prm_url, prm, servers, tuple(errors))
            fetches += 1
            try:
                doc = fetch_json(url)
            except (OSError, ValueError) as exc:
                errors.append(f"{url}: {exc}")
                continue
            if doc is not None:
                servers[issuer] = doc
                break
    return AuthMetadata(server_url, resource, prm_url, prm, servers, tuple(errors))


def _host_kind(url: str) -> tuple[str, str]:
    """``(scheme, "public" | "loopback" | "private" | "invalid")`` for a URL.

    Classifies by the host's *form*: trailing dots are dropped, and numeric shorthands
    that resolvers accept (``127.1``, ``2130706433``, ``0x7f.1``) are read as the address
    they denote. Name resolution is checked separately, at fetch time.
    """
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").rstrip(".")
    except ValueError:
        return "", "invalid"
    scheme = parsed.scheme.lower()
    if not host:
        return scheme, "invalid"
    if LOOPBACK_HOST_RE.match(host):
        return scheme, "loopback"
    ip = _as_ip(host)
    if ip is None:
        if re.fullmatch(r"[0-9a-fx.]+", host) and not re.search(r"\.[a-z]{2,}$", host):
            return scheme, "invalid"  # numeric-looking but not an address: don't guess
        return scheme, "private" if host.endswith((".internal", ".local", ".lan", ".localhost")) else "public"
    if ip.is_loopback:
        return scheme, "loopback"
    return scheme, "public" if ip.is_global else "private"


def _as_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    if re.fullmatch(r"(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+)){0,3}", host):
        try:  # the inet_aton shorthands curl, browsers, and getaddrinfo accept
            return ipaddress.IPv4Address(socket.inet_aton(host))
        except OSError:
            return None
    return None


def _safe_to_fetch(url: str, local_server: bool) -> bool:
    if _SHELL_META_RE.search(url):
        return False
    scheme, kind = _host_kind(url)
    if kind == "loopback":
        return local_server and scheme in ("http", "https")
    return scheme == "https" and kind == "public"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def _check_resolution(url: str, allow_loopback: bool) -> None:  # pragma: no cover - network
    """Refuse a host that resolves to a non-public address (metadata services, the LAN)."""
    host = (urlparse(url).hostname or "").rstrip(".")
    for info in socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP):
        ip = ipaddress.ip_address(str(info[4][0]).split("%", 1)[0])
        if ip.is_loopback and allow_loopback:
            continue
        if not ip.is_global:
            raise OSError(f"{host} resolves to non-public address {ip}; not fetched")


def http_fetch_json(
    url: str, timeout: float = 10.0, *, allow_loopback: bool = False
) -> dict[str, Any] | None:  # pragma: no cover - network
    """GET ``url`` as JSON. ``None`` on 404 / 405 / redirects; raises on other failures."""
    _check_resolution(url, allow_loopback)
    opener = urllib.request.build_opener(_NoRedirect)
    request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "mcpguard"})
    deadline = time.monotonic() + timeout
    try:
        with opener.open(request, timeout=timeout) as response:
            chunks: list[bytes] = []
            size = 0
            while size <= MAX_BYTES:  # bounded in bytes *and* wall time (no slow drip)
                if time.monotonic() > deadline:
                    raise OSError("metadata response too slow")
                chunk = response.read(16384)
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
            body = b"".join(chunks)
    except urllib.error.HTTPError as exc:
        if exc.code in (301, 302, 303, 307, 308, 404, 405, 410):
            return None
        raise OSError(f"HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise OSError(str(exc.reason)) from exc
    if len(body) > MAX_BYTES:
        raise ValueError("metadata document larger than 256 KB")
    data = json.loads(body.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("metadata document is not a JSON object")  # noqa: TRY004 - caught as a parse failure
    return data


# --------------------------------------------------------------------------- #
# Analysis                                                                    #
# --------------------------------------------------------------------------- #


def _norm(url: str) -> str:
    try:
        p = urlparse(url)
    except ValueError:
        return url
    return urlunparse((p.scheme.lower(), p.netloc.lower(), p.path.rstrip("/"), "", p.query, ""))


def scopes_of(meta: AuthMetadata) -> list[str]:
    """Scopes the protected resource advertises (``scopes_supported``)."""
    raw = (meta.resource_metadata or {}).get("scopes_supported")
    return sorted({s for s in raw if isinstance(s, str)}) if isinstance(raw, list) else []


def analyze(meta: AuthMetadata) -> list[AuthIssue]:
    """Every issue in ``meta``, most severe first within each document."""
    issues = list(_resource_issues(meta))
    for issuer, doc in sorted(meta.authorization_servers.items()):
        issues.extend(_issuer_issues(meta, issuer, doc))
    return issues


def _url_issues(url: object, where: str, meta: AuthMetadata, *, launched: bool) -> Iterator[AuthIssue]:
    """Scheme, shell-metacharacter, and private-address checks for one URL value."""
    local_server = _host_kind(meta.server_url)[1] == "loopback"
    if not isinstance(url, str) or not url:
        yield AuthIssue("medium", "Malformed URL in authorization metadata", where, repr(url)[:120],
                        "The value must be an absolute https URL.")
        return
    if _SHELL_META_RE.search(url):
        yield AuthIssue(
            "critical", "Shell metacharacters in an authorization URL (CVE-2025-6514 class)", where,
            url[:200],
            "A client that hands this URL to the OS (to open a browser) can run a command. Treat the "
            "server as hostile, and make sure mcp-remote is >= 0.1.16.",
        )
        return
    scheme, kind = _host_kind(url)
    if scheme in ("http", "https") and kind == "loopback" and not local_server:
        yield AuthIssue(
            "medium", "Authorization URL points at the client's own machine", where, url[:200],
            "A remote MCP server should not steer clients to localhost: it can drive local services "
            "with the user's browser session. Confirm this is intended.",
        )
        return
    if scheme not in ("http", "https"):
        yield AuthIssue(
            "critical" if launched else "high",
            f"Non-web URL scheme ({scheme or 'none'}:) in authorization metadata", where, url[:200],
            "Only https URLs are valid here; other schemes (javascript:, file:, custom handlers) are "
            "how a hostile server reaches the client's OS.",
        )
    elif scheme == "http" and kind != "loopback":
        yield AuthIssue("high", "Plaintext http authorization URL", where, url[:200],
                        "Authorization codes and tokens would cross the network in the clear. Use https.")
    elif kind == "private" and not local_server:
        yield AuthIssue(
            "medium", "Authorization URL points at a private network address", where, url[:200],
            "A public MCP server should not steer clients to internal hosts (SSRF / internal "
            "phishing). Confirm this is intended.",
        )
    elif kind == "invalid":
        yield AuthIssue("medium", "Malformed URL in authorization metadata", where, url[:200],
                        "The value must be an absolute https URL.")


def _resource_issues(meta: AuthMetadata) -> Iterator[AuthIssue]:
    for error in meta.errors[:3]:
        yield AuthIssue("info", "Authorization metadata could not be fetched", "discovery", error[:200],
                        "AUTH01 checks were incomplete for this server.")
    prm = meta.resource_metadata
    if prm is None:
        return
    declared = prm.get("resource")
    if meta.resource and isinstance(declared, str) and _norm(declared) != _norm(meta.resource):
        yield AuthIssue(
            "high", "Protected-resource metadata names a different resource", "resource",
            f"fetched for {meta.resource}, declares {declared}",
            "RFC 9728 §3.3: clients must reject metadata whose resource differs from the one they "
            "asked about. A mismatch lets one server hand out another's authorization setup.",
        )
    servers = prm.get("authorization_servers")
    if not isinstance(servers, list) or not servers:
        yield AuthIssue("low", "Protected-resource metadata lists no authorization server",
                        "authorization_servers", json.dumps(servers)[:120],
                        "Clients cannot start an authorization flow; check the server's auth setup.")
    for issuer in servers if isinstance(servers, list) else []:
        yield from _url_issues(issuer, "authorization_servers", meta, launched=False)
    broad = [s for s in scopes_of(meta) if _BROAD_SCOPE_RE.search(s)]
    if broad:
        yield AuthIssue(
            "low", "Server requests broad OAuth scopes", "scopes_supported", ", ".join(broad[:8]),
            "Ask only for the scopes the tools need. Pin the reviewed scope set with `mcpguard lock "
            "--connect`; a wider set later is flagged (MAN02).",
        )


def _issuer_issues(meta: AuthMetadata, issuer: str, doc: dict[str, Any] | None) -> Iterator[AuthIssue]:
    if doc is None:
        if _safe_to_fetch(issuer, _host_kind(meta.server_url)[1] == "loopback"):
            yield AuthIssue("info", "Authorization-server metadata not found", issuer, issuer,
                            "No RFC 8414 / OpenID metadata was published; AUTH01 skipped this issuer.")
        return
    declared = doc.get("issuer")
    if not isinstance(declared, str) or _norm(declared) != _norm(issuer):
        yield AuthIssue(
            "high", "Authorization-server metadata declares a different issuer", "issuer",
            f"listed as {issuer}, metadata says {declared!r}",
            "RFC 8414 §3.3: the issuer must match exactly, or a client can be mixed up between "
            "authorization servers and send one's code to another.",
        )
    for name in ENDPOINT_FIELDS:
        if name in doc:
            yield from _url_issues(doc[name], name, meta, launched=name == "authorization_endpoint")
    methods = doc.get("code_challenge_methods_supported")
    if not isinstance(methods, list) or "S256" not in methods:
        yield AuthIssue(
            "medium", "Authorization server does not advertise PKCE S256", "code_challenge_methods_supported",
            json.dumps(methods)[:120],
            "MCP clients must use PKCE with S256 and must refuse to proceed when the server doesn't "
            "advertise it: without it an intercepted code can be redeemed.",
        )
    if doc.get("authorization_response_iss_parameter_supported") is not True:
        yield AuthIssue(
            "low", "Authorization responses don't carry iss (RFC 9207)",
            "authorization_response_iss_parameter_supported", issuer,
            "MCP 2026-07-28 (SEP-2468): authorization servers should return iss so clients can detect "
            "authorization-server mix-up before redeeming a code.",
        )
    if "registration_endpoint" in doc and doc.get("client_id_metadata_document_supported") is not True:
        yield AuthIssue(
            "low", "Only deprecated Dynamic Client Registration is offered", "registration_endpoint", issuer,
            "MCP 2026-07-28 deprecates DCR for Client ID Metadata Documents; open registration lets any "
            "client impersonate a trusted app name on the consent screen.",
        )
