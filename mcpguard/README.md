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
pip install -e ".[claude]"      # + Claude AI judge (Jev needs no extra)
pip install -e ".[dev]"         # + pytest, mypy, ruff
```

Requires Python ≥ 3.10.

## Usage

```bash
mcpguard scan path/to/mcp-config.json
mcpguard scan manifest.json --format json
mcpguard scan config.json --min-severity critical   # gate only on criticals
mcpguard scan config.json --connect                  # enumerate the live server

mcpguard lock config.json --connect                  # pin reviewed state -> mcpguard.lock.json
mcpguard scan config.json --connect --baseline mcpguard.lock.json   # rug-pull check
mcpguard check-output result.json                    # indirect prompt injection in a tool result
mcpguard check-output --hook                         # as a Claude Code PostToolUse hook

mcpguard scan config.json --ai auto                  # + AI judge layer (Jev / Claude; keys in .env)
mcpguard redteam [--ai jev]                          # 122-case red-team suite: detection & FP rates
```

Claude Code hook (`.claude/settings.json`) — scan every MCP tool result before the model
acts on it:

```json
{"hooks": {"PostToolUse": [{"matcher": "mcp__.*",
  "hooks": [{"type": "command", "command": "mcpguard check-output --hook"}]}]}}
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
| **TP01** | High–Critical | Prompt injection / exfil directives anywhere in model-visible metadata — instructions, descriptions, titles, and *every* string in input/output schemas (names, enums, defaults, nested, `$defs`: full-schema poisoning), prompt arguments; base64-encoded payloads | OWASP LLM01 |
| **TP02** | Medium–Critical | Hidden content: zero-width / BiDi / invisible chars, Unicode Tag ASCII smuggling (decoded), variation-selector smuggling, ANSI escapes, HTML comments, whitespace padding | OWASP LLM01 |
| **TP03** | Medium–High | Tool shadowing: metadata naming another server's tools, shadowing / BCC directives, preference manipulation, cross-server name collisions, homoglyph tool names | OWASP LLM01 |
| **FLOW01** | Medium–High | Toxic flow / lethal trifecta across servers (untrusted input + private data + exfil sink; untrusted input + code exec) — exposure to indirect prompt injection | OWASP LLM01 / Agentic |
| **CAP01** | Medium–High | Dangerous capabilities (exec, shell, fs-write, network, creds, db); `readOnlyHint` on mutating tools | OWASP Agentic |
| **CMD01** | High | RCE sinks in server source (`shell=True`, `os.system`, `eval`, `child_process.exec`, `curl \| sh`), language-scoped, ignoring comments and string contents. Finds source via `source_path`/`cwd`, a script arg, or a locally installed npx/uvx/pipx package; emits an `INFO` note when it can't | MCP STDIO RCE / CWE-78 |
| **SEC01** | High–Critical | Plaintext secrets in `env`, `headers`, `args`, and `url` (20 vendor formats + name heuristics) | CWE-798 |
| **SUP01** | Low–High | Unpinned `npx`/`bunx`/`uvx`/`pipx` launches, container images without a digest, remote fetch-and-run | MCP supply-chain / SLSA |
| **SUP02** | Low–Critical | Known-vulnerable, malicious, or archived MCP packages (offline, source-cited advisories) and campaign IOCs | CWE-1395 |
| **CFG01** | Medium–High | Dangerous launch config: `LD_PRELOAD`/`NODE_OPTIONS` injection, TLS off, base-URL redirects, registry overrides, `sudo`, privileged containers / Docker socket, `/` or `~` roots, `0.0.0.0` binds | CWE-250 |
| **NET01** | Low–High | Plaintext HTTP to remote servers; deprecated HTTP+SSE | CWE-319 |
| **MAN01** | Medium–High | Manifest drift / rug pull vs the lockfile (or declared) baseline: any change to tools (description, schemas, annotations, title), instructions, prompts, resources | MCP rug-pull |
| **MAN02** | Medium–High | Launch drift vs the lockfile: command / package / version / image / URL / env-name changes, unreviewed servers | MCP rug-pull |
| **IPI01** | Low–Critical | *(check-output)* Injection, exfil, smuggling in tool **outputs** at run time | OWASP LLM01 (indirect) |
| **AI01** | High–Critical | *(--ai)* Semantic tool poisoning judged by Jev / Claude (paraphrase, other languages, obfuscation) | OWASP LLM01 |
| **IPI02** | High–Critical | *(--ai)* Semantic indirect prompt injection in tool outputs | OWASP LLM01 (indirect) |
| **AI02** | Medium–High | *(--ai)* AI review of server source for command injection, path traversal, SQLi, SSRF | CWE-78/22/89/918 |
| **AI03** | Medium–High | *(--ai)* Tool capability vs. the server's stated purpose; hidden behavior | OWASP Agentic |

Inputs accepted: Claude Desktop / Cursor (`mcpServers`) and VS Code (`servers`)
configs, a single inline server object, or a bare tool manifest
(`{tools, instructions, ...}`).

## Architecture

```
src/mcpguard/
  models.py         # immutable domain + finding types (the stable contract)
  patterns.py       # all detection signatures, curated in one place
  detectors.py      # pure text detectors shared by rules and the output guard
  advisories.py     # offline MCP package advisories (SUP02)
  lockfile.py       # reviewed-baseline lockfile for MAN01/MAN02
  guard.py          # IPI01/IPI02 tool-output guard + Claude Code hook protocol
  ai/               # optional AI judges: jev.py (stdlib HTTP), claude.py (Anthropic SDK), ensemble, cache
  redteam/          # red-team runner + cases.jsonl (122 attack / benign cases)
  context.py        # per-scan shared state (source IO, live manifest, peers, baseline)
  config_parser.py  # config/manifest JSON -> MCPServerSpec targets
  launchers.py      # npx/bunx/uvx/pipx argument parsing (package, pin)
  source_resolver.py # find locally installed npx/uvx/pipx package source
  source_mask.py    # blank comments/strings so CMD01 matches code only
  rules/
    base.py         # Rule ABC + self-registration registry
    *.py            # one module per detector (static)
  dynamic/
    connector.py    # live-connection adapters (Recorded / SDK: STDIO, HTTP, SSE)
    drift.py        # MAN01 manifest drift + MAN02 launch drift
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
pytest --cov=mcpguard --cov-report=term-missing
mypy            # strict, clean
ruff check .    # clean
```

## Status

Beta. Static rules are production-usable today; dynamic `--connect` enumerates
live servers over STDIO, Streamable HTTP, or SSE (with configured `headers`) via
the MCP SDK (1.x or 2.x). Roadmap: MCP 2026-07-28 stateless handshake, a live advisory
feed for SUP02, project-scoped agent settings, OAuth metadata checks, and per-rule
allow-list tuning.

## License

MIT
