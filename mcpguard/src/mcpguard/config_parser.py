"""Parse MCP configuration / manifest files into :class:`MCPServerSpec` targets.

Supports the shapes seen in the wild:

* **Client configs** — Claude Desktop / Cursor (``mcpServers``) and VS Code
  (``servers``): a map of name -> ``{command, args, env}`` or ``{url}``.
* **Single server** — a bare ``{command, ...}`` or ``{url, ...}`` object.
* **Tool manifest** — ``{tools: [...], instructions, resources, prompts}`` as
  produced by enumerating a server; enables static metadata analysis offline.

A server entry may also embed a manifest inline (``tools`` / ``instructions``),
which is how fixtures and exported scans carry tool descriptions for analysis.
"""

from __future__ import annotations

import json
import os
from typing import Any

from .models import (
    MCPManifest,
    MCPPrompt,
    MCPResource,
    MCPServerSpec,
    MCPTool,
    Transport,
)
from .source_resolver import resolve_package_source

__all__ = ["ConfigError", "load_targets", "parse_config", "parse_manifest"]


class ConfigError(ValueError):
    """Raised when a config/manifest file cannot be understood."""


def load_targets(path: str) -> list[MCPServerSpec]:
    """Read ``path`` and return the MCP server targets it describes."""
    try:
        with open(path, encoding="utf-8") as handle:
            raw = handle.read()
    except OSError as exc:
        raise ConfigError(f"cannot read config file {path!r}: {exc}") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{path!r} is not valid JSON: {exc}") from exc
    except RecursionError as exc:
        raise ConfigError(f"{path!r} is nested too deeply to be an MCP config") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{path!r}: top-level JSON must be an object")
    return parse_config(data, base_dir=os.path.dirname(os.path.abspath(path)))


def parse_config(data: dict[str, Any], *, base_dir: str | None = None) -> list[MCPServerSpec]:
    """Dispatch a parsed JSON object to the right shape handler."""
    servers_map = data.get("mcpServers") or data.get("servers")
    if isinstance(servers_map, dict):
        return [
            _parse_server(name, entry, base_dir=base_dir)
            for name, entry in servers_map.items()
            if isinstance(entry, dict)
        ]

    # A bare manifest (tools/instructions but no launch info).
    if ("tools" in data or "instructions" in data) and "command" not in data and "url" not in data:
        name = str(data.get("name", "manifest"))
        return [MCPServerSpec(name=name, manifest=parse_manifest(data))]

    # A single inline server object.
    if "command" in data or "url" in data:
        return [_parse_server(str(data.get("name", "server")), data, base_dir=base_dir)]

    raise ConfigError(
        "unrecognized config: expected 'mcpServers'/'servers' map, a server "
        "object with 'command'/'url', or a manifest with 'tools'."
    )


def _parse_server(
    name: str, entry: dict[str, Any], *, base_dir: str | None
) -> MCPServerSpec:
    command = entry.get("command")
    raw_args = entry.get("args")
    args = tuple(str(a) for a in raw_args if a is not None) if isinstance(raw_args, list) else ()
    raw_env = entry.get("env")
    env = {str(k): str(v) for k, v in raw_env.items()} if isinstance(raw_env, dict) else {}
    url = entry.get("url")
    raw_headers = entry.get("headers")
    headers = (
        {str(k): str(v) for k, v in raw_headers.items()} if isinstance(raw_headers, dict) else {}
    )

    transport = _infer_transport(command, url, entry.get("type"))
    manifest = parse_manifest(entry) if ("tools" in entry or "instructions" in entry) else None
    source_path = _resolve_source(entry, command, args, base_dir)

    return MCPServerSpec(
        name=name,
        transport=transport,
        command=str(command) if command else None,
        args=args,
        env=env,
        url=str(url) if url else None,
        headers=headers,
        source_path=source_path,
        manifest=manifest,
    )


def _infer_transport(command: Any, url: Any, declared: Any) -> Transport:
    if isinstance(declared, str):
        try:
            return Transport(declared.lower())
        except ValueError:
            pass
    if command:
        return Transport.STDIO
    if isinstance(url, str):
        return Transport.SSE if url.rstrip("/").endswith("sse") else Transport.HTTP
    return Transport.UNKNOWN


def _resolve_source(
    entry: dict[str, Any], command: Any, args: tuple[str, ...], base_dir: str | None
) -> str | None:
    """Best-effort location of the server's source on disk for RCE analysis."""

    def _abs(p: str) -> str:
        return p if os.path.isabs(p) or base_dir is None else os.path.join(base_dir, p)

    # Explicit hints win.
    for key in ("source_path", "sourcePath", "cwd"):
        val = entry.get(key)
        if isinstance(val, str) and os.path.exists(_abs(val)):
            return _abs(val)

    # Otherwise: the first arg that points at an existing file/dir (e.g. server.py).
    for arg in args:
        candidate = _abs(arg)
        if os.path.exists(candidate) and os.path.splitext(candidate)[1]:
            return candidate

    # Finally: a copy of an npx/uvx-launched package already installed locally.
    return resolve_package_source(str(command) if command else None, args, base_dir)


def parse_manifest(data: dict[str, Any]) -> MCPManifest:
    """Build an :class:`MCPManifest` from a dict (tolerates camel/snake case)."""
    tools = tuple(_parse_tool(t) for t in _as_list(data.get("tools")))
    resources = tuple(
        MCPResource(
            uri=str(r.get("uri", "")),
            name=str(r.get("name", "")),
            description=str(r.get("description", "")),
        )
        for r in _as_list(data.get("resources"))
    )
    prompts = tuple(
        MCPPrompt(
            name=str(p.get("name", "")),
            description=str(p.get("description", "")),
            arguments={
                str(a.get("name", "")): str(a.get("description", ""))
                for a in _as_list(p.get("arguments"))
            },
        )
        for p in _as_list(data.get("prompts"))
    )
    ttl = data.get("ttlMs", data.get("ttl_ms"))
    scope = data.get("cacheScope", data.get("cache_scope"))
    return MCPManifest(
        instructions=str(data.get("instructions", "")),
        tools=tools,
        resources=resources,
        prompts=prompts,
        ttl_ms=ttl if isinstance(ttl, int) and not isinstance(ttl, bool) else None,
        cache_scope=scope if isinstance(scope, str) else "",
    )


def _parse_tool(data: dict[str, Any]) -> MCPTool:
    schema = data.get("inputSchema") or data.get("input_schema") or {}
    output = data.get("outputSchema") or data.get("output_schema") or {}
    annotations = data.get("annotations") or {}
    return MCPTool(
        name=str(data.get("name", "")),
        description=str(data.get("description", "")),
        input_schema=schema if isinstance(schema, dict) else {},
        title=str(data.get("title") or ""),
        annotations=annotations if isinstance(annotations, dict) else {},
        output_schema=output if isinstance(output, dict) else {},
    )


def _as_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]
