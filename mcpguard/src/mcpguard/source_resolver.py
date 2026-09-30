"""Locate the installed source of a package-runner launched MCP server.

``npx -y @org/server`` and ``uvx mcp-server-x`` servers have no source next to
the config, so CMD01 would otherwise have nothing to scan. This module looks for
a copy the runner (or a package manager) has already installed on this machine:

* **npm** (``npx`` / ``bunx``): ``node_modules`` in the config directory and its
  ancestors, the ``npx`` cache (``~/.npm/_npx/*/node_modules``), and global
  ``node_modules`` roots.
* **PyPI** (``uvx`` / ``pipx``): uv tool environments, uv's ephemeral ``uvx``
  environments in its cache, and pipx venvs / its ``pipx run`` cache.

When the launch pins a version, only a copy of *that* version is accepted —
scanning a different version would report on code that never runs. Among
multiple candidates the most recently modified wins. Nothing is downloaded.
"""

from __future__ import annotations

import glob
import json
import os
import re
from collections.abc import Iterator, Mapping, Sequence

from .launchers import PackageLaunch, parse_launch

__all__ = ["resolve_package_source"]

# Global npm roots probed in addition to $NPM_CONFIG_PREFIX. Tests override this.
GLOBAL_NPM_ROOTS: tuple[str, ...] = (
    "/usr/local/lib/node_modules",
    "/opt/homebrew/lib/node_modules",
    "/usr/lib/node_modules",
)


def resolve_package_source(
    command: str | None,
    args: Sequence[str],
    base_dir: str | None,
    *,
    env: Mapping[str, str] | None = None,
) -> str | None:
    """Return a local directory holding the launched package's source, or ``None``."""
    launch = parse_launch(command, args)
    if launch is None or launch.is_local:
        return None
    env = os.environ if env is None else env
    if launch.ecosystem == "npm":
        return _newest(_npm_candidates(launch, base_dir, env))
    dist_info = _newest(_pypi_dist_infos(launch, env))
    if dist_info is None:
        return None
    return next((d for d in _top_level_dirs(dist_info) if os.path.isdir(d)), None)


def _newest(paths: Iterator[str]) -> str | None:
    existing = [p for p in dict.fromkeys(paths) if os.path.isdir(p)]
    return max(existing, key=_mtime) if existing else None


# --------------------------------------------------------------------------- #
# npm                                                                         #
# --------------------------------------------------------------------------- #


def _npm_candidates(
    launch: PackageLaunch, base_dir: str | None, env: Mapping[str, str]
) -> Iterator[str]:
    roots: list[str] = []
    if base_dir:
        current = os.path.abspath(base_dir)
        while True:
            roots.append(os.path.join(current, "node_modules"))
            parent = os.path.dirname(current)
            if parent == current:
                break
            current = parent
    home = _home(env)
    if home:
        roots.extend(sorted(glob.glob(os.path.join(home, ".npm", "_npx", "*", "node_modules"))))
    prefix = env.get("NPM_CONFIG_PREFIX") or env.get("npm_config_prefix")
    if prefix:
        roots.append(os.path.join(prefix, "lib", "node_modules"))
    roots.extend(GLOBAL_NPM_ROOTS)

    for root in roots:
        pkg_dir = os.path.join(root, *launch.name.split("/"))
        if _npm_version_ok(pkg_dir, launch.version):
            yield pkg_dir


def _npm_version_ok(pkg_dir: str, wanted: str | None) -> bool:
    manifest = os.path.join(pkg_dir, "package.json")
    if not os.path.isfile(manifest):
        return False
    if wanted is None:
        return True
    try:
        with open(manifest, encoding="utf-8") as handle:
            return str(json.load(handle).get("version", "")) == wanted
    except (OSError, ValueError):
        return False


# --------------------------------------------------------------------------- #
# PyPI                                                                        #
# --------------------------------------------------------------------------- #


def _normalize_dist(name: str) -> str:
    """PEP 503 / wheel dist-info normalization: runs of -_. become _."""
    return re.sub(r"[-_.]+", "_", name).lower()


def _pypi_dist_infos(launch: PackageLaunch, env: Mapping[str, str]) -> Iterator[str]:
    home = _home(env)
    envs: list[str] = []
    uv_tools = env.get("UV_TOOL_DIR") or (
        os.path.join(home, ".local", "share", "uv", "tools") if home else None
    )
    if uv_tools:
        envs.append(os.path.join(uv_tools, "*"))
    uv_cache = env.get("UV_CACHE_DIR") or (os.path.join(home, ".cache", "uv") if home else None)
    if uv_cache:
        envs.append(os.path.join(uv_cache, "archive-v0", "*"))
    pipx_home = env.get("PIPX_HOME") or (os.path.join(home, ".local", "pipx") if home else None)
    if pipx_home:
        envs.append(os.path.join(pipx_home, "venvs", "*"))
        envs.append(os.path.join(pipx_home, ".cache", "*"))

    dist = _normalize_dist(launch.name)
    for env_glob in envs:
        pattern = os.path.join(env_glob, "lib", "python*", "site-packages", "*.dist-info")
        for dist_info in sorted(glob.glob(pattern)):
            stem = os.path.basename(dist_info)[: -len(".dist-info")]
            name, _, version = stem.partition("-")
            if _normalize_dist(name) != dist:
                continue
            if launch.version is not None and version != launch.version:
                continue
            yield dist_info


def _top_level_dirs(dist_info: str) -> Iterator[str]:
    """Import-package directories a wheel installed, read from its RECORD."""
    site_packages = os.path.dirname(dist_info)
    try:
        with open(os.path.join(dist_info, "RECORD"), encoding="utf-8") as handle:
            paths = [line.split(",", 1)[0] for line in handle if line.strip()]
    except OSError:
        return
    seen: dict[str, None] = {}
    for path in paths:
        top, sep, _ = path.partition("/")
        if sep and not top.endswith((".dist-info", ".data")) and top not in ("..", "__pycache__"):
            seen.setdefault(top, None)
    for top in seen:
        yield os.path.join(site_packages, top)


def _home(env: Mapping[str, str]) -> str | None:
    return env.get("HOME") or env.get("USERPROFILE")


def _mtime(path: str) -> float:
    try:
        return os.path.getmtime(path)
    except OSError:
        return 0.0
