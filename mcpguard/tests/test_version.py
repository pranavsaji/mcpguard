"""One release, one version: the CLI, the package metadata, and the web engine agree."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from mcpguard import __version__

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT.parent / "mcpguard-web"


def test_package_metadata_matches() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text()
    assert re.search(r'^version = "([^"]+)"', pyproject, re.MULTILINE).group(1) == __version__  # type: ignore[union-attr]


@pytest.mark.skipif(not WEB.exists(), reason="web app not checked out beside the CLI")
def test_web_engine_matches() -> None:
    scan_ts = (WEB / "lib" / "scanner" / "scan.ts").read_text()
    assert re.search(r'ENGINE_VERSION = "([^"]+)"', scan_ts).group(1) == __version__  # type: ignore[union-attr]
