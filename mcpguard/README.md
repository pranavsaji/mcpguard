# MCPGuard

**A security scanner for Model Context Protocol (MCP) servers — the `npm audit` for MCP.**

Agents are being wired to MCP servers with little to no security review. In early
2026, 40+ CVEs were disclosed against MCP implementations, and tool poisoning,
prompt injection, and STDIO-based RCE became systemic across the ecosystem.
MCPGuard scans an MCP server — from a config file, a tool manifest, or a live
connection — and produces a graded, CI-gating security report.

- **Zero-dependency core.** The scanner and CLI are pure Python stdlib. Portable,
  hermetic, fast. The live-connection feature is the only thing needing extras.
- **Pluggable rule engine.** Each detector is an independently-registered,
  unit-tested `Rule`. Adding one is a single module — nothing else changes.
- **CI-ready.** Stable JSON output and an exit-code gate (`--min-severity`).

## Install

```bash
pip install -e .                # static scanning (no third-party deps)
pip install -e ".[connect]"     # + live --connect support (MCP SDK)
pip install -e ".[dev]"         # + pytest, mypy, ruff
```

Requires Python ≥ 3.10.

## Usage

```bash
mcpguard scan path/to/mcp-config.json
mcpguard scan manifest.json --format json
mcpguard scan config.json --min-severity critical   # gate only on criticals
mcpguard scan config.json --connect                  # enumerate the live server
```

Exit codes: `0` clean · `1` a finding met/exceeded the gate · `2` usage/IO error.

### As a CI gate (GitHub Actions)

```yaml
- run: pip install mcpguard
- run: mcpguard scan .mcp/config.json --min-severity high --format json
  # job fails (exit 1) if any high/critical finding is present
```

## What it detects

| ID | Severity | Detects | Maps to |
|----|----------|---------|---------|
| **TP01** | High–Critical | Prompt injection / data-exfil directives in tool, parameter, and instruction text | OWASP LLM01 |
| **TP02** | Medium–High | Hidden content: zero-width / BiDi characters, HTML comments | OWASP LLM01 |
| **CAP01** | Medium–High | Dangerous capabilities (exec, shell, fs-write, network, creds, db) — excessive agency | OWASP Agentic |
| **CMD01** | High | RCE sinks in server source (`shell=True`, `os.system`, `eval`, `child_process.exec`, `curl \| sh`) | MCP STDIO RCE / CWE-78 |
| **SEC01** | High–Critical | Plaintext secrets in config `env` (vendor key formats + name/value heuristics) | CWE-798 |
| **SUP01** | Medium–High | Unpinned `npx`/`uvx` launches and remote fetch-and-run | MCP supply-chain / SLSA |
| **MAN01** | High | *(--connect)* Manifest drift / rug pull: live tools or descriptions differ from the reviewed baseline | MCP rug-pull |

Inputs accepted: Claude Desktop / Cursor (`mcpServers`) and VS Code (`servers`)
configs, a single inline server object, or a bare tool manifest
(`{tools, instructions, ...}`).

## Architecture

```
src/mcpguard/
  models.py         # immutable domain + finding types (the stable contract)
  patterns.py       # all detection signatures, curated in one place
  context.py        # per-scan shared state (source IO, live manifest)
  config_parser.py  # config/manifest JSON -> MCPServerSpec targets
  rules/
    base.py         # Rule ABC + self-registration registry
    *.py            # one module per detector (static)
  dynamic/
    connector.py    # live-connection adapters (Recorded / SDK-STDIO)
    drift.py        # MAN01 rug-pull / manifest-drift rule
  reporting/        # text (ANSI) + JSON reporters behind a dispatch
  scanner.py        # orchestration: run rules over targets, isolate failures
  cli.py            # argparse entry point + exit-code gate
```

Design principles: detection logic lives in stateless rules; side effects (file
IO, network) are isolated behind `AnalysisContext` / `Connector` seams; a
misbehaving rule degrades to an `INFO` finding instead of aborting the scan.

### Adding a rule

```python
from mcpguard.rules.base import Rule, register
from mcpguard.models import Category, Severity

@register
class MyRule(Rule):
    id = "MYRULE"
    title = "..."
    category = Category.SUPPLY_CHAIN
    default_severity = Severity.MEDIUM

    def analyze(self, target, ctx):
        if ...:
            yield self.finding(location=..., evidence=..., remediation=...)
```

Import it from `rules/__init__.py` and it's live — the scanner discovers it.

## Development

```bash
pytest --cov=mcpguard --cov-report=term-missing   # 124 tests, ~98% coverage
mypy            # strict, clean
ruff check .    # clean
```

## Status

Beta. Static rules are production-usable today; dynamic `--connect` enumerates
live STDIO servers via the MCP SDK. Roadmap: HTTP/SSE live transport, signature/
provenance verification (SUP01+), and per-rule allow-list tuning.

## License

MIT
