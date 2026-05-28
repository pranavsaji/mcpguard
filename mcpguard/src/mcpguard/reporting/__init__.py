"""Report rendering: dispatch a list of reports to a named output format."""

from __future__ import annotations

from ..models import Report, Severity
from .json_reporter import format_json
from .text import format_text

__all__ = ["render", "FORMATS", "format_text", "format_json"]

FORMATS: tuple[str, ...] = ("text", "json")


def render(
    reports: list[Report],
    *,
    fmt: str = "text",
    color: bool = False,
    threshold: Severity = Severity.HIGH,
    version: str = "0.0.0",
) -> str:
    """Render ``reports`` in ``fmt`` (``"text"`` or ``"json"``)."""
    if fmt == "text":
        return format_text(reports, color=color, threshold=threshold)
    if fmt == "json":
        return format_json(reports, threshold=threshold, version=version)
    raise ValueError(f"unknown format {fmt!r}; expected one of: {', '.join(FORMATS)}")
