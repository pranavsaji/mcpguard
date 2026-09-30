"""Live-connection adapters for dynamic analysis.

A :class:`Connector` enumerates a *running* MCP server into an
:class:`~mcpguard.models.MCPManifest`. Two implementations ship:

* :class:`RecordedConnector` — returns a manifest handed to it. Pure and
  hermetic; used in tests and for replaying a previously captured enumeration.
* :class:`SdkConnector` — connects for real (STDIO, Streamable HTTP, or SSE)
  using the optional ``mcp`` SDK (install ``mcpguard[connect]``). Imported
  lazily so the core stays dependency-free.

Keeping connection behind this seam means dynamic rules never touch transport
details and stay unit-testable.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from typing import Any, Protocol, runtime_checkable

from ..models import MCPManifest, MCPPrompt, MCPResource, MCPServerSpec, MCPTool, Transport
from .oauth import AuthMetadata

__all__ = [
    "Connector",
    "RecordedConnector",
    "SdkConnector",
    "SdkStdioConnector",
    "build_connector",
    "enumerate_session",
]


@runtime_checkable
class Connector(Protocol):
    """Anything that can enumerate a live server into a manifest."""

    def fetch_manifest(self, spec: MCPServerSpec) -> MCPManifest: ...


class RecordedConnector:
    """A connector that replays a fixed manifest (test / offline replay)."""

    def __init__(self, manifest: MCPManifest, auth: AuthMetadata | None = None) -> None:
        self._manifest = manifest
        self._auth = auth

    def fetch_manifest(self, spec: MCPServerSpec) -> MCPManifest:
        return self._manifest

    def fetch_auth_metadata(self, spec: MCPServerSpec) -> AuthMetadata | None:
        return self._auth


def _field(obj: object, *names: str, default: Any = None) -> Any:
    """Read the first present attribute: the SDK renamed camelCase fields in 2.x."""
    for name in names:
        value = getattr(obj, name, None)
        if value is not None:
            return value
    return default


class SdkConnector:
    """Connect to a server via the ``mcp`` SDK and enumerate its full surface.

    Supports every transport a config can declare: STDIO (``command``),
    Streamable HTTP (``url``), and legacy SSE (``url`` ending in ``/sse`` or
    ``"type": "sse"``), passing any configured ``headers``. Enumerates tools,
    prompts, and resources (following pagination) plus server instructions.
    Works with both the 1.x and 2.x SDKs.

    Network/process side effects live here and nowhere else. Requires the
    optional ``connect`` extra; raises a clear error if the SDK is missing.
    """

    MAX_PAGES = 50

    def __init__(self, timeout: float = 30.0) -> None:
        self._timeout = timeout

    def fetch_auth_metadata(self, spec: MCPServerSpec) -> AuthMetadata | None:  # pragma: no cover - network
        """OAuth discovery (RFC 9728 / 8414) for a remote server or bridged URL (AUTH01)."""
        from ..rules.transport import remote_endpoints
        from .oauth import discover, http_fetch_json

        url = next((u for _, u in remote_endpoints(spec) if u.startswith(("https://", "http://"))), None)
        if url is None:
            return None
        from urllib.parse import urlparse

        from ..patterns import LOOPBACK_HOST_RE

        local = bool(LOOPBACK_HOST_RE.match(urlparse(url).hostname or ""))
        return discover(
            url, lambda u: http_fetch_json(u, timeout=min(self._timeout, 10.0), allow_loopback=local)
        )

    def fetch_manifest(self, spec: MCPServerSpec) -> MCPManifest:  # pragma: no cover - needs SDK + live server
        import anyio

        async def _run() -> MCPManifest:
            with anyio.fail_after(self._timeout):
                return await self._fetch(spec)

        result: MCPManifest = anyio.run(_run)
        return result

    async def _fetch(self, spec: MCPServerSpec) -> MCPManifest:  # pragma: no cover - needs SDK
        from mcp import ClientSession

        async with self._open_transport(spec) as streams:
            read, write = streams[0], streams[1]
            async with ClientSession(read, write) as session:
                init = await session.initialize()
                return await enumerate_session(session, init, max_pages=self.MAX_PAGES)

    @asynccontextmanager
    async def _open_transport(self, spec: MCPServerSpec) -> AsyncIterator[Sequence[Any]]:  # pragma: no cover - needs SDK
        if spec.command and spec.transport not in (Transport.HTTP, Transport.SSE):
            from mcp import StdioServerParameters
            from mcp.client.stdio import stdio_client

            params = StdioServerParameters(
                command=spec.command, args=list(spec.args), env=spec.env or None
            )
            async with stdio_client(params) as streams:
                yield streams
            return

        if not spec.url:
            raise ValueError(f"server {spec.name!r} has neither a command nor a url to connect to")

        if spec.transport is Transport.SSE:
            from mcp.client.sse import sse_client

            async with sse_client(spec.url, headers=spec.headers or None) as streams:
                yield streams
            return

        from mcp.client import streamable_http

        if hasattr(streamable_http, "streamable_http_client"):  # SDK 2.x
            from mcp.shared._httpx_utils import create_mcp_http_client

            async with (
                create_mcp_http_client(headers=spec.headers or None) as http_client,
                streamable_http.streamable_http_client(spec.url, http_client=http_client) as streams,
            ):
                yield streams
        else:  # SDK 1.x
            async with streamable_http.streamablehttp_client(  # type: ignore[attr-defined,unused-ignore]
                spec.url, headers=spec.headers or None
            ) as streams:
                yield streams


async def enumerate_session(session: Any, init: Any, *, max_pages: int = 50) -> MCPManifest:
    """Build a manifest from an initialized client session.

    Separated from transport setup so it can be tested against a fake session.
    Prompts and resources are only requested when the server advertises them.
    """
    capabilities = _field(init, "capabilities")
    tools = await _paginate(session.list_tools, "tools", max_pages)
    prompts = (
        await _paginate(session.list_prompts, "prompts", max_pages)
        if _field(capabilities, "prompts") is not None
        else []
    )
    resources = (
        await _paginate(session.list_resources, "resources", max_pages)
        if _field(capabilities, "resources") is not None
        else []
    )
    return MCPManifest(
        instructions=_field(init, "instructions", default="") or "",
        tools=tuple(_tool(t) for t in tools),
        prompts=tuple(
            MCPPrompt(
                name=p.name,
                description=p.description or "",
                arguments={
                    str(a.name): str(a.description or "")
                    for a in (_field(p, "arguments", default=[]) or [])
                },
            )
            for p in prompts
        ),
        resources=tuple(
            MCPResource(uri=str(r.uri), name=r.name or "", description=r.description or "")
            for r in resources
        ),
    )


def _tool(t: Any) -> MCPTool:
    annotations = _field(t, "annotations")
    if annotations is not None and not isinstance(annotations, dict):
        dump = getattr(annotations, "model_dump", None)
        annotations = dump(exclude_none=True) if callable(dump) else {}
    return MCPTool(
        name=t.name,
        description=t.description or "",
        input_schema=dict(_field(t, "input_schema", "inputSchema", default={}) or {}),
        title=_field(t, "title", default="") or "",
        annotations=dict(annotations or {}),
        output_schema=dict(_field(t, "output_schema", "outputSchema", default={}) or {}),
    )


async def _paginate(method: Any, attr: str, max_pages: int) -> list[Any]:
    """Collect every page of a ``list_*`` call, across SDK pagination signatures."""
    items: list[Any] = []
    result = await method()
    for _ in range(max_pages):
        items.extend(getattr(result, attr, None) or [])
        cursor = _field(result, "next_cursor", "nextCursor")
        if not cursor:
            break
        try:
            from mcp.types import PaginatedRequestParams

            result = await method(params=PaginatedRequestParams(cursor=cursor))
        except (ImportError, TypeError):
            result = await method(cursor=cursor)
    return items


# Backwards-compatible name: this connector used to support STDIO only.
SdkStdioConnector = SdkConnector


def build_connector() -> Connector:
    """Return the default live connector, or raise if the SDK is unavailable."""
    try:
        import mcp  # noqa: F401
    except ImportError as exc:  # pragma: no cover - exercised via monkeypatch in tests
        raise RuntimeError(
            "live --connect requires the MCP SDK. Install it with: pip install 'mcpguard[connect]'"
        ) from exc
    return SdkConnector()
