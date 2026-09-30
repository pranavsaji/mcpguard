"""Tests for locating installed npx / uvx / pipx package source (hermetic: temp dirs only)."""

from __future__ import annotations

import json
import os
from pathlib import Path

from mcpguard.config_parser import load_targets
from mcpguard.source_resolver import resolve_package_source


def _npm_package(root: Path, name: str, version: str) -> Path:
    pkg = root.joinpath("node_modules", *name.split("/"))
    (pkg / "dist").mkdir(parents=True)
    (pkg / "package.json").write_text(json.dumps({"name": name, "version": version}))
    (pkg / "dist" / "index.js").write_text("child_process.exec(cmd)\n")
    return pkg


def _wheel_install(env_dir: Path, dist: str, version: str, module: str) -> Path:
    site = env_dir / "lib" / "python3.12" / "site-packages"
    (site / module).mkdir(parents=True)
    (site / module / "server.py").write_text("import os\nos.system(cmd)\n")
    info = site / f"{dist}-{version}.dist-info"
    info.mkdir()
    (info / "RECORD").write_text(
        f"{module}/__init__.py,,\n{module}/server.py,,\n{info.name}/METADATA,,\n../../bin/x,,\n"
    )
    return site / module


class TestNpm:
    def test_finds_package_in_config_dir_ancestor(self, tmp_path: Path) -> None:
        pkg = _npm_package(tmp_path, "@scope/server", "1.2.3")
        nested = tmp_path / "a" / "b"
        nested.mkdir(parents=True)
        found = resolve_package_source("npx", ["-y", "@scope/server"], str(nested))
        assert found == str(pkg)

    def test_finds_package_in_npx_cache(self, isolated_install_locations: Path) -> None:
        cache = isolated_install_locations / ".npm" / "_npx" / "abc123"
        pkg = _npm_package(cache, "server-x", "0.4.0")
        assert resolve_package_source("npx", ["-y", "server-x@0.4.0"], None) == str(pkg)

    def test_pinned_version_must_match(self, tmp_path: Path) -> None:
        _npm_package(tmp_path, "server-x", "0.3.9")
        assert resolve_package_source("npx", ["-y", "server-x@0.4.0"], str(tmp_path)) is None

    def test_global_prefix_from_env(self, tmp_path: Path, monkeypatch) -> None:
        pkg = _npm_package(tmp_path / "prefix" / "lib", "server-x", "1.0.0")
        monkeypatch.setenv("NPM_CONFIG_PREFIX", str(tmp_path / "prefix"))
        assert resolve_package_source("npx", ["server-x"], None) == str(pkg)

    def test_newest_candidate_wins(self, tmp_path: Path, isolated_install_locations: Path) -> None:
        old = _npm_package(isolated_install_locations / ".npm" / "_npx" / "old", "srv", "1.0.0")
        new = _npm_package(isolated_install_locations / ".npm" / "_npx" / "new", "srv", "1.0.0")
        os.utime(old, (1_000_000, 1_000_000))
        assert resolve_package_source("npx", ["srv"], None) == str(new)


class TestPython:
    def test_finds_uv_tool_install_via_record(self, isolated_install_locations: Path) -> None:
        env_dir = isolated_install_locations / ".local" / "share" / "uv" / "tools" / "mcp-server-fetch"
        module = _wheel_install(env_dir, "mcp_server_fetch", "2025.4.7", "mcp_server_fetch")
        assert resolve_package_source("uvx", ["mcp-server-fetch"], None) == str(module)

    def test_finds_uvx_ephemeral_env_in_cache(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setenv("UV_CACHE_DIR", str(tmp_path / "uvcache"))
        env_dir = tmp_path / "uvcache" / "archive-v0" / "Xyz"
        module = _wheel_install(env_dir, "mcp_server_git", "1.0.0", "mcp_server_git")
        found = resolve_package_source("uvx", ["--from", "mcp-server-git==1.0.0", "mcp-server-git"], None)
        assert found == str(module)

    def test_module_name_may_differ_from_dist_name(self, isolated_install_locations: Path) -> None:
        env_dir = isolated_install_locations / ".local" / "pipx" / "venvs" / "weird"
        module = _wheel_install(env_dir, "weird_dist_name", "0.1.0", "actual_module")
        assert resolve_package_source("pipx", ["run", "weird-dist.name"], None) == str(module)

    def test_pinned_version_must_match(self, isolated_install_locations: Path) -> None:
        env_dir = isolated_install_locations / ".local" / "share" / "uv" / "tools" / "t"
        _wheel_install(env_dir, "mcp_server_fetch", "1.0.0", "mcp_server_fetch")
        assert resolve_package_source("uvx", ["mcp-server-fetch==2.0.0"], None) is None


class TestNotResolvable:
    def test_non_runner_commands_and_local_paths(self, tmp_path: Path) -> None:
        assert resolve_package_source("python", ["server.py"], str(tmp_path)) is None
        assert resolve_package_source("npx", ["./local"], str(tmp_path)) is None
        assert resolve_package_source(None, [], str(tmp_path)) is None

    def test_nothing_installed(self, tmp_path: Path) -> None:
        assert resolve_package_source("npx", ["-y", "@x/missing"], str(tmp_path)) is None
        assert resolve_package_source("uvx", ["missing"], None) is None


class TestConfigIntegration:
    def test_config_parser_attaches_resolved_source_and_cmd01_scans_it(self, tmp_path: Path) -> None:
        from mcpguard.scanner import scan_file

        _npm_package(tmp_path, "@scope/server", "1.2.3")
        config = tmp_path / "config.json"
        config.write_text(
            json.dumps({"mcpServers": {"s": {"command": "npx", "args": ["-y", "@scope/server@1.2.3"]}}})
        )
        (spec,) = load_targets(str(config))
        assert spec.source_path is not None and spec.source_path.endswith(os.path.join("@scope", "server"))

        (report,) = scan_file(str(config))
        cmd = [f for f in report.findings if f.rule_id == "CMD01"]
        # dist/ is scanned (no src/ sibling), and the sink is found.
        assert len(cmd) == 1 and cmd[0].location.path.endswith(os.path.join("dist", "index.js"))
