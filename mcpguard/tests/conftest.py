"""Shared fixtures.

The source resolver probes this machine's npm / uv / pipx install locations.
Point every one of them at an empty temporary home so results never depend on
what happens to be installed where the tests run.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mcpguard import source_resolver

_RESOLVER_ENV = ("UV_TOOL_DIR", "UV_CACHE_DIR", "PIPX_HOME", "NPM_CONFIG_PREFIX", "npm_config_prefix")


@pytest.fixture(autouse=True)
def isolated_install_locations(
    monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory
) -> Path:
    home = tmp_path_factory.mktemp("home")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("USERPROFILE", raising=False)
    for name in _RESOLVER_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(source_resolver, "GLOBAL_NPM_ROOTS", ())
    return home
