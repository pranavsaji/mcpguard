"""Tests for the source-file scanning context (IO, caching, limits)."""

from __future__ import annotations

from pathlib import Path

from mcpguard.context import MAX_FILE_BYTES, AnalysisContext
from mcpguard.models import MCPServerSpec


def _spec(path: str) -> MCPServerSpec:
    return MCPServerSpec(name="s", source_path=path)


class TestSourceWalking:
    def test_walks_directory_and_filters_by_extension(self, tmp_path: Path) -> None:
        (tmp_path / "server.py").write_text("x = 1\n")
        (tmp_path / "notes.txt").write_text("ignored\n")  # non-source extension
        ctx = AnalysisContext()
        files = dict(ctx.iter_source_files(_spec(str(tmp_path))))
        assert any(p.endswith("server.py") for p in files)
        assert not any(p.endswith("notes.txt") for p in files)

    def test_skips_vendored_directories(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("ok\n")
        vendored = tmp_path / "node_modules"
        vendored.mkdir()
        (vendored / "evil.js").write_text("child_process.exec('x')\n")
        ctx = AnalysisContext()
        paths = [p for p, _ in ctx.iter_source_files(_spec(str(tmp_path)))]
        assert any(p.endswith("app.py") for p in paths)
        assert not any("node_modules" in p for p in paths)

    def test_build_output_skipped_only_beside_src(self, tmp_path: Path) -> None:
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "index.ts").write_text("x\n")
        (tmp_path / "dist").mkdir()
        (tmp_path / "dist" / "index.js").write_text("x\n")
        paths = [p for p, _ in AnalysisContext().iter_source_files(_spec(str(tmp_path)))]
        assert any(p.endswith("index.ts") for p in paths)
        assert not any("dist" in p for p in paths)

    def test_build_output_scanned_when_it_is_the_only_code(self, tmp_path: Path) -> None:
        # Installed npm packages usually ship only dist/.
        (tmp_path / "dist").mkdir()
        (tmp_path / "dist" / "index.js").write_text("x\n")
        (tmp_path / "package.json").write_text("{}")
        paths = [p for p, _ in AnalysisContext().iter_source_files(_spec(str(tmp_path)))]
        assert any(p.endswith("index.js") for p in paths)

    def test_single_file_source_path(self, tmp_path: Path) -> None:
        f = tmp_path / "server.py"
        f.write_text("print('hi')\n")
        ctx = AnalysisContext()
        files = dict(ctx.iter_source_files(_spec(str(f))))
        assert list(files) == [str(f)]

    def test_oversized_file_skipped(self, tmp_path: Path) -> None:
        big = tmp_path / "big.py"
        big.write_text("# " + "a" * (MAX_FILE_BYTES + 10))
        ctx = AnalysisContext()
        assert dict(ctx.iter_source_files(_spec(str(tmp_path)))) == {}

    def test_missing_path_yields_nothing(self) -> None:
        ctx = AnalysisContext()
        assert list(ctx.iter_source_files(_spec("/no/such/dir"))) == []

    def test_no_source_path_yields_nothing(self) -> None:
        ctx = AnalysisContext()
        assert list(ctx.iter_source_files(MCPServerSpec(name="s"))) == []

    def test_results_are_cached(self, tmp_path: Path) -> None:
        f = tmp_path / "server.py"
        f.write_text("x = 1\n")
        ctx = AnalysisContext()
        spec = _spec(str(tmp_path))
        first = list(ctx.iter_source_files(spec))
        # Add a file after first scan; cached result must not change.
        (tmp_path / "later.py").write_text("y = 2\n")
        second = list(ctx.iter_source_files(spec))
        assert first == second
