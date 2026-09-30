"""Analysis context shared across rules during a single scan.

Centralizes side-effecting work (reading source files from disk) behind a small,
mockable surface so individual rules stay pure and easy to unit-test. Source
reads are cached and size-capped to keep scans bounded.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .models import MCPManifest, MCPServerSpec

if TYPE_CHECKING:  # avoid an import cycle; only needed for typing
    from .ai import AIConfig
    from .dynamic.connector import Connector
    from .lockfile import LockEntry

# Extensions worth scanning for command-injection / RCE patterns.
SOURCE_EXTENSIONS: frozenset[str] = frozenset(
    {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".sh", ".rb", ".go"}
)
# Don't read absurdly large files into memory.
MAX_FILE_BYTES = 1_000_000
# Directories never worth walking.
SKIP_DIRS: frozenset[str] = frozenset(
    {".git", "node_modules", "__pycache__", ".venv", "venv", ".mypy_cache"}
)
# Build output: skipped only beside a ``src`` directory (where it merely duplicates
# the source). Installed npm packages often ship *only* ``dist/``, so it must be
# scanned there.
BUILD_DIRS: frozenset[str] = frozenset({"dist", "build"})


@dataclass
class AnalysisContext:
    """Per-scan shared state.

    Parameters
    ----------
    include_dynamic:
        Whether dynamic (live-connection) rules are permitted to run.
    connector:
        Live-connection adapter used to enumerate a running server. When set and
        ``include_dynamic`` is true, the scanner populates :attr:`live_manifest`.
    live_manifest:
        The manifest enumerated from the live server, if a connection was made.
    peers:
        Every server in the same config as ``(spec, effective manifest)``,
        including this one. Cross-server rules (shadowing, toxic flow) read it;
        a single-target scan sees only itself.
    baseline:
        The reviewed lockfile, ``{server name: LockEntry}``, when the scan was
        given ``--baseline``; ``None`` otherwise.
    ai:
        The AI judge configuration when the scan runs with ``--ai``; rules that
        consult it (AI01, FLOW01 roles, MAN01 drift) are no-ops without it.
    """

    include_dynamic: bool = False
    connector: Connector | None = None
    live_manifest: MCPManifest | None = None
    peers: tuple[tuple[MCPServerSpec, MCPManifest | None], ...] = ()
    baseline: dict[str, LockEntry] | None = None
    ai: AIConfig | None = None
    _source_cache: dict[str, list[tuple[str, str]]] = field(default_factory=dict, init=False)

    def effective_manifest(self, spec: MCPServerSpec) -> MCPManifest | None:
        """The manifest rules should analyze: live data if connected, else declared.

        This lets metadata rules (poisoning, hidden content, excessive agency)
        analyze whatever is most authoritative without knowing how it was sourced.
        """
        return self.live_manifest if self.live_manifest is not None else spec.manifest

    def baseline_for(self, spec: MCPServerSpec) -> LockEntry | None:
        """The reviewed baseline entry for ``spec``, if a lockfile was supplied."""
        return None if self.baseline is None else self.baseline.get(spec.name)

    def iter_source_files(self, spec: MCPServerSpec) -> Iterator[tuple[str, str]]:
        """Yield ``(path, text)`` for source files under ``spec.source_path``.

        Results are cached per ``source_path``. A missing path yields nothing.
        Files that are too large or undecodable are skipped silently.
        """
        root = spec.source_path
        if not root:
            return
        if root not in self._source_cache:
            self._source_cache[root] = list(self._scan(root))
        yield from self._source_cache[root]

    @staticmethod
    def _scan(root: str) -> Iterator[tuple[str, str]]:
        if os.path.isfile(root):
            text = AnalysisContext._read(root)
            if text is not None:
                yield root, text
            return
        for dirpath, dirnames, filenames in os.walk(root):
            has_src = "src" in dirnames
            dirnames[:] = [
                d for d in dirnames if d not in SKIP_DIRS and not (has_src and d in BUILD_DIRS)
            ]
            for name in filenames:
                if os.path.splitext(name)[1].lower() not in SOURCE_EXTENSIONS:
                    continue
                full = os.path.join(dirpath, name)
                text = AnalysisContext._read(full)
                if text is not None:
                    yield full, text

    @staticmethod
    def _read(path: str) -> str | None:
        try:
            if os.path.getsize(path) > MAX_FILE_BYTES:
                return None
            with open(path, encoding="utf-8", errors="replace") as handle:
                return handle.read()
        except OSError:
            return None
