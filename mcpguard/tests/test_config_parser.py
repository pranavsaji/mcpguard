"""Tests for config/manifest parsing."""

from __future__ import annotations

import json

import pytest

from mcpguard.config_parser import ConfigError, load_targets, parse_config, parse_manifest
from mcpguard.models import Transport


class TestParseConfig:
    def test_claude_desktop_style_map(self) -> None:
        data = {
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
                    "env": {"FOO": "bar"},
                }
            }
        }
        specs = parse_config(data)
        assert len(specs) == 1
        spec = specs[0]
        assert spec.name == "filesystem"
        assert spec.transport is Transport.STDIO
        assert spec.command == "npx"
        assert spec.args == ("-y", "@modelcontextprotocol/server-filesystem", "/tmp")
        assert spec.env == {"FOO": "bar"}

    def test_vscode_style_servers_key(self) -> None:
        specs = parse_config({"servers": {"x": {"command": "python", "args": ["s.py"]}}})
        assert specs[0].name == "x" and specs[0].command == "python"

    def test_remote_url_infers_http_and_sse(self) -> None:
        http = parse_config({"mcpServers": {"r": {"url": "https://api.example/mcp"}}})[0]
        sse = parse_config({"mcpServers": {"r": {"url": "https://api.example/sse"}}})[0]
        assert http.transport is Transport.HTTP
        assert sse.transport is Transport.SSE

    def test_explicit_type_overrides_inference(self) -> None:
        spec = parse_config({"mcpServers": {"r": {"url": "https://x/y", "type": "sse"}}})[0]
        assert spec.transport is Transport.SSE

    def test_single_inline_server(self) -> None:
        specs = parse_config({"command": "python", "args": ["server.py"], "name": "solo"})
        assert len(specs) == 1 and specs[0].name == "solo"

    def test_env_values_coerced_to_str(self) -> None:
        spec = parse_config({"mcpServers": {"x": {"command": "c", "env": {"PORT": 8080}}}})[0]
        assert spec.env == {"PORT": "8080"}

    def test_inline_manifest_on_server_entry(self) -> None:
        data = {
            "mcpServers": {
                "x": {
                    "command": "python",
                    "tools": [{"name": "t", "description": "d"}],
                    "instructions": "be nice",
                }
            }
        }
        spec = parse_config(data)[0]
        assert spec.manifest is not None
        assert spec.manifest.tools[0].name == "t"
        assert spec.manifest.instructions == "be nice"

    def test_unrecognized_shape_raises(self) -> None:
        with pytest.raises(ConfigError, match="unrecognized config"):
            parse_config({"random": "junk"})


class TestParseManifest:
    def test_bare_manifest_document(self) -> None:
        data = {
            "instructions": "system instructions",
            "tools": [
                {
                    "name": "search",
                    "description": "Search.",
                    "inputSchema": {"properties": {"q": {"type": "string"}}},
                }
            ],
            "resources": [{"uri": "file://a", "description": "r"}],
            "prompts": [{"name": "p", "description": "pr"}],
        }
        specs = parse_config(data)
        assert len(specs) == 1
        manifest = specs[0].manifest
        assert manifest is not None
        assert manifest.tools[0].input_schema["properties"]["q"]["type"] == "string"
        assert manifest.resources[0].uri == "file://a"
        assert manifest.prompts[0].name == "p"

    def test_accepts_snake_case_input_schema(self) -> None:
        manifest = parse_manifest({"tools": [{"name": "t", "input_schema": {"x": 1}}]})
        assert manifest.tools[0].input_schema == {"x": 1}

    def test_parses_remote_server_headers(self) -> None:
        (spec,) = parse_config(
            {
                "servers": {
                    "remote": {
                        "type": "http",
                        "url": "https://mcp.example/mcp",
                        "headers": {"Authorization": "Bearer ${TOKEN}"},
                    }
                }
            }
        )
        assert spec.headers == {"Authorization": "Bearer ${TOKEN}"}
        assert parse_config({"url": "https://x.example/sse"})[0].headers == {}

    def test_tolerates_malformed_entries(self) -> None:
        manifest = parse_manifest({"tools": ["not-a-dict", {"name": "ok"}], "resources": "nope"})
        assert [t.name for t in manifest.tools] == ["ok"]
        assert manifest.resources == ()


class TestLoadTargets:
    def test_load_from_file(self, tmp_path) -> None:
        path = tmp_path / "config.json"
        path.write_text(json.dumps({"mcpServers": {"x": {"command": "python"}}}))
        specs = load_targets(str(path))
        assert specs[0].name == "x"

    def test_source_path_resolved_relative_to_config(self, tmp_path) -> None:
        (tmp_path / "server.py").write_text("print('hi')\n")
        path = tmp_path / "config.json"
        path.write_text(json.dumps({"mcpServers": {"x": {"command": "python", "args": ["server.py"]}}}))
        spec = load_targets(str(path))[0]
        assert spec.source_path is not None and spec.source_path.endswith("server.py")

    def test_missing_file_raises(self) -> None:
        with pytest.raises(ConfigError, match="cannot read"):
            load_targets("/nonexistent/path/config.json")

    def test_invalid_json_raises(self, tmp_path) -> None:
        path = tmp_path / "bad.json"
        path.write_text("{not json")
        with pytest.raises(ConfigError, match="not valid JSON"):
            load_targets(str(path))

    def test_non_object_top_level_raises(self, tmp_path) -> None:
        path = tmp_path / "arr.json"
        path.write_text("[1, 2, 3]")
        with pytest.raises(ConfigError, match="must be an object"):
            load_targets(str(path))
