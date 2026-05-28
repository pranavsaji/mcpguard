"""MCPGuard — a security scanner for Model Context Protocol (MCP) servers.

Public API surface. Import the common types from the top-level package::

    from mcpguard import scan_spec, Severity, Report
"""

from __future__ import annotations

from .config_parser import ConfigError, load_targets
from .models import (
    Category,
    Finding,
    Location,
    MCPManifest,
    MCPPrompt,
    MCPResource,
    MCPServerSpec,
    MCPTool,
    Report,
    Severity,
    Transport,
)
from .scanner import scan_file, scan_spec, scan_specs

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "Category",
    "ConfigError",
    "Finding",
    "Location",
    "MCPManifest",
    "MCPPrompt",
    "MCPResource",
    "MCPServerSpec",
    "MCPTool",
    "Report",
    "Severity",
    "Transport",
    "load_targets",
    "scan_file",
    "scan_spec",
    "scan_specs",
]
