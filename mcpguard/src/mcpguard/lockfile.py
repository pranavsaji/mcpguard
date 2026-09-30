"""Reviewed-baseline lockfile ("tool pinning") for rug-pull detection.

``mcpguard lock`` records, per server, the launch line and the full manifest the
reviewer approved — every tool's description, title, annotations, and input /
output schemas, plus instructions, prompts, and resources — with a SHA-256 per
item. ``mcpguard scan --baseline mcpguard.lock.json`` then diffs the current
state against it (MAN01: manifest drift; MAN02: launch / inventory drift).

Hashing the *whole* tool object matters: pins that cover only the description
miss a rug pull that swaps the schema, adds a poisoned parameter, or flips
``readOnlyHint``. The file is deterministic (sorted keys, no timestamps) so it
diffs cleanly in code review.

Beside the manifest, an entry can pin what the server *reaches*: the outbound
hosts its source contacts (``egress``, when the source is on disk) and, with
``--connect``, the OAuth issuers and scopes it advertises (``auth``). MAN02
flags a new destination, a changed authorization server, or a wider scope set.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from .config_parser import ConfigError, parse_manifest
from .launchers import parse_launch
from .models import MCPManifest, MCPServerSpec, MCPTool
from .util import canonical_json

if TYPE_CHECKING:
    from .dynamic.oauth import AuthMetadata

__all__ = ["LOCK_VERSION", "LockEntry", "build_lock", "launch_identity", "load_lock", "tool_digest"]

LOCK_VERSION = 1


def _sha256(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8", "surrogatepass")).hexdigest()


def _tool_dict(tool: MCPTool) -> dict[str, object]:
    out: dict[str, object] = {"name": tool.name, "description": tool.description}
    if tool.title:
        out["title"] = tool.title
    if tool.input_schema:
        out["inputSchema"] = tool.input_schema
    if tool.output_schema:
        out["outputSchema"] = tool.output_schema
    if tool.annotations:
        out["annotations"] = tool.annotations
    return out


def tool_digest(tool: MCPTool) -> str:
    """SHA-256 over the complete tool definition."""
    return _sha256(_tool_dict(tool))


def manifest_dict(manifest: MCPManifest) -> dict[str, object]:
    """A manifest as plain JSON (the inverse of :func:`parse_manifest`)."""
    return {
        "instructions": manifest.instructions,
        "tools": [_tool_dict(t) for t in manifest.tools],
        "prompts": [
            {
                "name": p.name,
                "description": p.description,
                "arguments": [{"name": k, "description": v} for k, v in p.arguments.items()],
            }
            for p in manifest.prompts
        ],
        "resources": [
            {"uri": r.uri, "name": r.name, "description": r.description} for r in manifest.resources
        ],
    }


def launch_identity(spec: MCPServerSpec) -> str:
    """What the server *is*: its URL, or its launch line (command + args).

    Env values are excluded (secrets, machine-specific paths); env *names* are
    included, since adding e.g. ``NODE_OPTIONS`` changes what runs.
    """
    if spec.url and not spec.command:
        return spec.url
    env_names = ",".join(sorted(spec.env))
    return spec.command_line + (f" [env:{env_names}]" if env_names else "")


@dataclass(frozen=True)
class LockEntry:
    """One server's reviewed baseline."""

    launch: str
    manifest: MCPManifest | None
    package: str | None = None
    version: str | None = None
    egress: tuple[str, ...] | None = None  # None: source wasn't available at review
    auth_issuers: tuple[str, ...] | None = None  # None: not locked with --connect / no OAuth
    auth_scopes: tuple[str, ...] | None = None


def build_lock(
    specs: list[MCPServerSpec],
    manifests: dict[str, MCPManifest | None],
    *,
    generator: str,
    egress: Mapping[str, list[str]] | None = None,
    auth: Mapping[str, AuthMetadata | None] | None = None,
) -> dict[str, Any]:
    """Build the lockfile document for ``specs`` using ``manifests`` (by server name).

    ``egress`` maps a server to the hosts its source contacts (only servers whose
    source was read); ``auth`` to its discovered OAuth metadata.
    """
    from .dynamic.oauth import scopes_of

    servers: dict[str, object] = {}
    for spec in sorted(specs, key=lambda s: s.name):
        launch = parse_launch(spec.command, spec.args)
        entry: dict[str, object] = {"launch": launch_identity(spec)}
        if launch is not None and not launch.is_local:
            entry["package"] = launch.name
            if launch.version:
                entry["version"] = launch.version
        manifest = manifests.get(spec.name)
        if manifest is not None:
            entry["manifest_sha256"] = _sha256(manifest_dict(manifest))
            entry["tool_sha256"] = {t.name: tool_digest(t) for t in manifest.tools}
            entry["manifest"] = manifest_dict(manifest)
        if egress is not None and spec.name in egress:
            entry["egress"] = sorted(egress[spec.name])
        meta = auth.get(spec.name) if auth is not None else None
        if meta is not None and meta.resource_metadata is not None:
            entry["auth"] = {"issuers": meta.issuers, "scopes": scopes_of(meta)}
        servers[spec.name] = entry
    return {"mcpguard_lock": LOCK_VERSION, "generated_by": generator, "servers": servers}


def load_lock(path: str) -> dict[str, LockEntry]:
    """Read a lockfile into ``{server name: LockEntry}``.

    Raises :class:`ConfigError` on unreadable or malformed files, and when a
    recorded manifest no longer matches its own ``manifest_sha256`` — a
    hand-edited baseline must not silently become the new truth.
    """
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"cannot read baseline lockfile {path!r}: {exc}") from exc
    if not isinstance(data, dict) or data.get("mcpguard_lock") != LOCK_VERSION:
        raise ConfigError(f"{path!r} is not an mcpguard v{LOCK_VERSION} lockfile")
    servers = data.get("servers")
    if not isinstance(servers, dict):
        raise ConfigError(f"{path!r}: 'servers' must be an object")

    out: dict[str, LockEntry] = {}
    for name, raw in servers.items():
        if not isinstance(raw, dict):
            continue
        manifest = None
        if isinstance(raw.get("manifest"), dict):
            manifest = parse_manifest(raw["manifest"])
            recorded = raw.get("manifest_sha256")
            if recorded != _sha256(manifest_dict(manifest)):
                raise ConfigError(
                    f"{path!r}: baseline for server {name!r} fails its integrity hash "
                    "(edited by hand?). Re-create it with `mcpguard lock`."
                )
        raw_auth = raw.get("auth")
        auth: dict[str, Any] = raw_auth if isinstance(raw_auth, dict) else {}
        out[str(name)] = LockEntry(
            launch=str(raw.get("launch", "")),
            manifest=manifest,
            package=raw.get("package") if isinstance(raw.get("package"), str) else None,
            version=raw.get("version") if isinstance(raw.get("version"), str) else None,
            egress=_str_tuple(raw.get("egress")),
            auth_issuers=_str_tuple(auth.get("issuers")),
            auth_scopes=_str_tuple(auth.get("scopes")),
        )
    return out


def _str_tuple(value: object) -> tuple[str, ...] | None:
    if not isinstance(value, list):
        return None
    return tuple(str(v) for v in value if isinstance(v, str))
