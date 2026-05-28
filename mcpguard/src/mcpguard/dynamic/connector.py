"""Live-connection adapters for dynamic analysis.

A :class:`Connector` enumerates a *running* MCP server into an
:class:`~mcpguard.models.MCPManifest`. Two implementations ship:

* :class:`RecordedConnector` — returns a manifest handed to it. Pure and
  hermetic; used in tests and for replaying a previously captured enumeration.
* :class:`SdkStdioConnector` — connects for real over STDIO using the optional
  ``mcp`` SDK (install ``mcpguard[connect]``). Imported lazily so the core stays
  dependency-free.

Keeping connection behind this seam means dynamic rules never touch transport
details and stay unit-testable.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..models import MCPManifest, MCPServerSpec, MCPTool

__all__ = ["Connector", "RecordedConnector", "SdkStdioConnector", "build_connector"]


@runtime_checkable
class Connector(Protocol):
    """Anything that can enumerate a live server into a manifest."""

    def fetch_manifest(self, spec: MCPServerSpec) -> MCPManifest: ...


class RecordedConnector:
    """A connector that replays a fixed manifest (test / offline replay)."""

    def __init__(self, manifest: MCPManifest) -> None:
        self._manifest = manifest

    def fetch_manifest(self, spec: MCPServerSpec) -> MCPManifest:
        return self._manifest


class SdkStdioConnector:
    """Connect to a local STDIO server via the ``mcp`` SDK and enumerate it.

    Network/process side effects live here and nowhere else. Requires the
    optional ``connect`` extra; raises a clear error if the SDK is missing.
    """

    def __init__(self, timeout: float = 30.0) -> None:
        self._timeout = timeout

    def fetch_manifest(self, spec: MCPServerSpec) -> MCPManifest:  # pragma: no cover - needs SDK + live server
        import anyio

        result: MCPManifest = anyio.run(self._fetch, spec)
        return result

    async def _fetch(self, spec: MCPServerSpec) -> MCPManifest:  # pragma: no cover - needs SDK
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        if not spec.command:
            raise ValueError(f"server {spec.name!r} has no command to launch over STDIO")

        params = StdioServerParameters(
            command=spec.command, args=list(spec.args), env=spec.env or None
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                init = await session.initialize()
                tools = await session.list_tools()
                instructions = getattr(init, "instructions", "") or ""
                return MCPManifest(
                    instructions=instructions,
                    tools=tuple(
                        MCPTool(
                            name=t.name,
                            description=t.description or "",
                            input_schema=dict(t.inputSchema or {}),
                        )
                        for t in tools.tools
                    ),
                )


def build_connector() -> Connector:
    """Return the default live connector, or raise if the SDK is unavailable."""
    try:
        import mcp  # noqa: F401
    except ImportError as exc:  # pragma: no cover - exercised via monkeypatch in tests
        raise RuntimeError(
            "live --connect requires the MCP SDK. Install it with: pip install 'mcpguard[connect]'"
        ) from exc
    return SdkStdioConnector()
