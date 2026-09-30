"""Tests for SUP03 (publisher provenance), HDR01 (x-mcp-header), and CACHE01 (cache hints).

Each rule is checked on the attack shape it targets and on the benign lookalike
most likely to be confused with it: exact well-known names, typos inside a
trusted scope, git specs, valid nested header designations, private caching.
"""

from __future__ import annotations

from typing import Any

import pytest

from mcpguard.config_parser import parse_config, parse_manifest
from mcpguard.context import AnalysisContext
from mcpguard.models import Finding, MCPManifest, MCPServerSpec, MCPTool, Severity
from mcpguard.rules.base import Rule
from mcpguard.rules.protocol import CacheHintRule, HeaderMirroringRule
from mcpguard.rules.provenance import ProvenanceRule, edit_distance, skeleton
from mcpguard.scanner import scan_specs


def _run(rule: Rule, spec: MCPServerSpec) -> list[Finding]:
    return list(rule.analyze(spec, AnalysisContext()))


def _npx(pkg: str) -> MCPServerSpec:
    return MCPServerSpec(name="srv", command="npx", args=("-y", pkg))


# --------------------------------------------------------------------------- #
# SUP03                                                                       #
# --------------------------------------------------------------------------- #


class TestProvenance:
    @pytest.mark.parametrize(
        "pkg, scope",
        [
            ("@model-context-protocol/server-memory@1.0.0", "@model-context-protocol"),
            ("@modeIcontextprotocol/server-memory@1.0.0", "@modeicontextprotocol"),
            ("@modelcontextprotocoll/server-memory", "@modelcontextprotocoll"),
        ],
    )
    def test_scope_lookalikes_are_high(self, pkg: str, scope: str) -> None:
        [f] = _run(ProvenanceRule(), _npx(pkg))
        assert f.severity is Severity.HIGH
        assert f.title == "npm scope imitates a trusted MCP publisher"
        assert f"scope {scope} looks like @modelcontextprotocol" in f.evidence

    def test_name_lookalike_is_high(self) -> None:
        [f] = _run(ProvenanceRule(), _npx("mcp-rernote@0.1.30"))
        assert (f.severity, f.evidence) == (Severity.HIGH, "mcp-rernote looks like mcp-remote")

    def test_one_edit_typosquat_is_medium(self) -> None:
        [f] = _run(ProvenanceRule(), _npx("firecrawl-mpc@1.0.0"))
        assert (f.severity, f.confidence) == (Severity.MEDIUM, 0.6)
        assert f.evidence == "firecrawl-mpc vs firecrawl-mcp"

    def test_pypi_typosquat(self) -> None:
        spec = MCPServerSpec(name="srv", command="uvx", args=("mcp-server-fecth==1.0",))
        [f] = _run(ProvenanceRule(), spec)
        assert f.severity is Severity.MEDIUM

    @pytest.mark.parametrize(
        "pkg, brand, publisher",
        [
            ("postmark-mcp@1.0.16", "Postmark", "no verified package scope"),
            ("stripe-mcp-server", "Stripe", "@stripe"),
            ("@evil/github-mcp", "Github", "@github or @modelcontextprotocol"),
        ],
    )
    def test_brand_impersonation_is_low(self, pkg: str, brand: str, publisher: str) -> None:
        [f] = _run(ProvenanceRule(), _npx(pkg))
        assert (f.severity, f.confidence) == (Severity.LOW, 0.4)
        assert f.title == f"MCP package named after {brand} is not from its publisher"
        assert f.evidence.endswith(f"{brand} publishes under {publisher}")

    @pytest.mark.parametrize(
        "command, args",
        [
            ("npx", ("-y", "@modelcontextprotocol/server-memory@1.0.0")),  # exact well-known
            ("npx", ("-y", "@modelcontextprotocol/server-memroy")),  # typo in a trusted scope
            ("npx", ("-y", "@stripe/mcp@0.2.0")),  # brand under its own scope
            ("npx", ("-y", "mcp-remote@0.1.30")),
            ("uvx", ("mcp-server-fetch==2025.4.7",)),
            ("uvx", ("--from", "git+https://github.com/someone/github-mcp.git", "github-mcp")),
            ("uvx", ("awslabs.aws-documentation-mcp-server@1.0.0",)),  # AWS's own prefix
            ("npx", ("-y", "linear-regression-tool")),  # brand word without "mcp"
            ("npx", ("-y", "./local-server")),
            ("node", ("server.js",)),
        ],
    )
    def test_benign_launches_are_quiet(self, command: str, args: tuple[str, ...]) -> None:
        assert _run(ProvenanceRule(), MCPServerSpec(name="srv", command=command, args=args)) == []

    def test_helpers(self) -> None:
        assert skeleton("mcp-rernote") == skeleton("MCP_remote") == "mcpremote"
        assert skeleton("@modeIcontextprotocoI") == skeleton("@modelcontextprotocol")
        assert edit_distance("firecrawl-mcp", "firecrawl-mpc") == 1  # transposition
        assert edit_distance("kitten", "sitting") == 3
        assert edit_distance("abc", "abcdef", 2) == 3  # capped at limit + 1


# --------------------------------------------------------------------------- #
# HDR01                                                                       #
# --------------------------------------------------------------------------- #


def _hdr(properties: dict[str, Any]) -> list[Finding]:
    tool = MCPTool(name="t", input_schema={"type": "object", "properties": properties})
    return _run(HeaderMirroringRule(), MCPServerSpec(name="srv", manifest=MCPManifest(tools=(tool,))))


class TestHeaderMirroring:
    def test_valid_designations_including_nested_are_quiet(self) -> None:
        assert _hdr({
            "region": {"type": "string", "x-mcp-header": "Region"},
            "count": {"type": "integer", "x-mcp-header": "Count"},
            "opts": {"type": "object", "properties": {
                "tier": {"type": ["boolean", "null"], "x-mcp-header": "Tier"},
            }},
            "query": {"type": "string"},
        }) == []

    def test_control_characters_are_high(self) -> None:
        [f] = _hdr({"a": {"type": "string", "x-mcp-header": "X\r\nSet-Cookie: a=b"}})
        assert f.severity is Severity.HIGH
        assert f.evidence == "x-mcp-header='X\\r\\nSet-Cookie: a=b'"

    @pytest.mark.parametrize(
        "prop, problem",
        [
            ({"type": "string", "x-mcp-header": ""}, "must be a non-empty string"),
            ({"type": "string", "x-mcp-header": 7}, "must be a non-empty string"),
            ({"type": "string", "x-mcp-header": "Bad Header"}, "not an HTTP field-name token"),
            ({"type": "number", "x-mcp-header": "N"}, "type number cannot be mirrored"),
            ({"type": "object", "x-mcp-header": "O"}, "type object cannot be mirrored"),
            ({"x-mcp-header": "U"}, "declares no primitive type"),
            ({"type": [{}], "x-mcp-header": "D"}, "type {} cannot be mirrored"),  # no crash
        ],
    )
    def test_invalid_designations_are_medium(self, prop: dict[str, Any], problem: str) -> None:
        [f] = _hdr({"p": prop})
        assert f.severity is Severity.MEDIUM
        assert problem in f.evidence
        assert f.location.field == "param:p"

    def test_duplicate_names_are_case_insensitive(self) -> None:
        findings = _hdr({
            "a": {"type": "string", "x-mcp-header": "Region"},
            "b": {"type": "string", "x-mcp-header": "REGION"},
        })
        assert [f.location.field for f in findings] == ["param:b"]
        assert "duplicates the header name used by a" in findings[0].evidence

    @pytest.mark.parametrize(
        "prop, path",
        [
            ({"type": "array", "items": {"type": "string", "x-mcp-header": "T"}}, "properties.p.items"),
            ({"anyOf": [{"type": "string", "x-mcp-header": "M"}]}, "properties.p.anyOf[0]"),
        ],
    )
    def test_misplaced_designations(self, prop: dict[str, Any], path: str) -> None:
        [f] = _hdr({"p": prop})
        assert f.location.field == f"inputSchema.{path}"
        assert "not reachable from the schema root" in f.evidence

    def test_root_level_designation_is_misplaced(self) -> None:
        tool = MCPTool(name="t", input_schema={"type": "object", "x-mcp-header": "Root"})
        spec = MCPServerSpec(name="srv", manifest=MCPManifest(tools=(tool,)))
        [f] = _run(HeaderMirroringRule(), spec)
        assert f.location.field == "inputSchema.<root>"

    @pytest.mark.parametrize(
        "name, prop",
        [
            ("api_token", {"type": "string", "x-mcp-header": "Token"}),
            ("value", {"type": "string", "description": "The access token", "x-mcp-header": "Key"}),
        ],
    )
    def test_credentials_in_headers(self, name: str, prop: dict[str, Any]) -> None:
        [f] = _hdr({name: prop})
        assert f.title == "Credential-bearing parameter mirrored into an HTTP header"
        assert f.evidence == f"{name} -> Mcp-Param-{prop['x-mcp-header']}"


# --------------------------------------------------------------------------- #
# CACHE01                                                                     #
# --------------------------------------------------------------------------- #


def _cached(entry: dict[str, Any]) -> list[Finding]:
    [spec] = parse_config({"url": "https://mcp.example.com/mcp", "tools": [], **entry})
    return _run(CacheHintRule(), spec)


class TestCacheHints:
    def test_parse_manifest_reads_hints(self) -> None:
        m = parse_manifest({"tools": [], "ttlMs": 5000, "cacheScope": "private"})
        assert (m.ttl_ms, m.cache_scope) == (5000, "private")
        m = parse_manifest({"tools": [], "ttlMs": True, "cacheScope": 3})
        assert (m.ttl_ms, m.cache_scope) == (None, "")
        assert parse_manifest({"ttl_ms": 7, "cache_scope": "public"}).ttl_ms == 7

    @pytest.mark.parametrize(
        "entry, carrier",
        [
            ({"headers": {"Authorization": "Bearer ${T}"}}, "Authorization header"),
            ({"url": "https://mcp.example.com/mcp?api_key=abcdef123456"}, "credentials in the URL"),
        ],
    )
    def test_public_cache_of_authenticated_list(self, entry: dict[str, Any], carrier: str) -> None:
        [f] = _cached({"cacheScope": "public", **entry})
        assert f.severity is Severity.MEDIUM
        assert f.evidence == f"cacheScope=public; requests carry {carrier}"

    def test_bridge_header_argument_counts_as_auth(self) -> None:
        spec = MCPServerSpec(
            name="srv", command="npx",
            args=("-y", "mcp-remote@0.1.30", "https://x", "--header", "Authorization: Bearer ${T}"),
            manifest=MCPManifest(cache_scope="public"),
        )
        [f] = _run(CacheHintRule(), spec)
        assert f.evidence.endswith("Authorization header (bridge argument)")

    @pytest.mark.parametrize(
        "entry",
        [
            {"cacheScope": "public"},  # anonymous list: public caching is fine
            {"cacheScope": "private", "headers": {"Authorization": "Bearer ${T}"}},
            {"ttlMs": 60_000},
            {"ttlMs": 86_400_000},  # exactly 24h is not "past" it
        ],
    )
    def test_benign_hints_are_quiet(self, entry: dict[str, Any]) -> None:
        assert _cached(entry) == []

    @pytest.mark.parametrize(
        "ttl, shown", [(172_800_000, "~48h"), (88_200_000, "~24h"), (91_800_000, "~26h")]
    )
    def test_long_ttl_is_low_with_half_even_hours(self, ttl: int, shown: str) -> None:
        [f] = _cached({"ttlMs": ttl})
        assert f.severity is Severity.LOW
        assert f.evidence == f"ttlMs={ttl} ({shown})"

    def test_live_manifest_hints_are_used(self) -> None:
        spec = MCPServerSpec(name="srv", url="https://x", headers={"Authorization": "Bearer ${T}"})
        live = MCPManifest(cache_scope="public", ttl_ms=10**9)
        ctx = AnalysisContext(live_manifest=live)
        assert {f.severity for f in CacheHintRule().analyze(spec, ctx)} == {Severity.MEDIUM, Severity.LOW}


def test_rules_run_through_the_scanner() -> None:
    specs = [_npx("mcp-rernote@0.1.30")]
    ids = {f.rule_id for r in scan_specs(specs) for f in r.findings}
    assert "SUP03" in ids
