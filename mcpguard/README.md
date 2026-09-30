# mcpguard

**A security scanner for Model Context Protocol (MCP) servers — the `npm audit` for MCP.**

Scan an MCP client config, a tool manifest, or a live server; get a graded,
framework-mapped report with a CI exit code. Three layers:

- **13 deterministic rules** — pure Python stdlib, offline, deterministic.
- **An optional AI judge** (`--ai`) — Jev (TypeSafe) and/or Claude, for paraphrased,
  translated, and obfuscated attacks, source-code flaws, and purpose mismatches.
- **A runtime guard** — scans tool *outputs* for indirect prompt injection; a Claude Code hook.

Full documentation, architecture, and measured red-team results:
[github.com/pranavsaji/mcpguard](https://github.com/pranavsaji/mcpguard).

## Install

```bash
pip install "mcpguard @ git+https://github.com/pranavsaji/mcpguard#subdirectory=mcpguard"

# from a clone
pip install -e .                # core (no third-party dependencies)
pip install -e ".[connect]"     # + live --connect enumeration (MCP SDK)
pip install -e ".[claude]"      # + Claude AI judge (Jev needs no extra)
pip install -e ".[dev]"         # + pytest, mypy, ruff
```

Requires Python ≥ 3.10.

## Usage

```bash
mcpguard scan config.json                        # text report; exit 1 on high/critical
mcpguard scan config.json -f json --min-severity critical
mcpguard scan config.json --connect              # enumerate live servers (STDIO / HTTP / SSE)
mcpguard scan config.json --ai auto              # + AI judge (keys from .env)

mcpguard lock config.json --connect              # pin the reviewed state -> mcpguard.lock.json
mcpguard scan config.json --baseline mcpguard.lock.json     # rug-pull / drift check

mcpguard check-output result.json                # indirect prompt injection in a tool result
mcpguard check-output --hook --ai jev            # as a Claude Code PostToolUse hook

mcpguard redteam [--ai jev]                      # 122-case red-team suite: detection & FP rates
```

Claude Code hook (`.claude/settings.json`):

```json
{"hooks": {"PostToolUse": [{"matcher": "mcp__.*",
  "hooks": [{"type": "command", "command": "mcpguard check-output --hook --ai jev"}]}]}}
```

AI judge keys (copy `.env.example` to `.env`): `TYPESAFE_API_KEY` for Jev,
`ANTHROPIC_API_KEY` for Claude. `--ai auto` uses every configured judge as an ensemble.

Exit codes: `0` clean · `1` gate failed · `2` usage / IO / credential error.

## Rules

| ID | Detects |
|----|---------|
| TP01 | Prompt injection / exfiltration anywhere in model-visible metadata, incl. every string and key in input/output schemas, and base64-encoded payloads |
| TP02 | Hidden content: invisible / BiDi chars, Unicode-tag ASCII smuggling (decoded), variation selectors, ANSI escapes, HTML comments, padding |
| TP03 | Tool shadowing, cross-server name collisions, homoglyph names, preference manipulation |
| FLOW01 | Toxic flow / lethal trifecta across servers (exposure to indirect prompt injection) |
| CAP01 | Excessive agency; `readOnlyHint` on tools that write or execute |
| CMD01 | RCE sinks in server source |
| SEC01 | Plaintext secrets in env, headers, args, and URLs (19 vendor formats) |
| SUP01 | Unpinned packages, undigested images, remote fetch-and-run |
| SUP02 | Known-vulnerable / malicious / archived MCP packages (33 advisories) and campaign IOCs |
| CFG01 | Dangerous launch config (`LD_PRELOAD`, `NODE_OPTIONS`, TLS off, `sudo`, privileged containers, `/` roots, …) |
| NET01 | Plaintext HTTP to remote servers; deprecated SSE |
| MAN01 / MAN02 | Rug pull: manifest and launch drift against the lockfile |
| AI01 / AI02 / AI03 | *(--ai)* Semantic poisoning · source review (CWE-78/22/89/918) · purpose vs. capability |
| IPI01 / IPI02 | *(check-output)* Injection in tool outputs; IPI02 with `--ai` |

## Library

```python
from mcpguard import scan_file, Severity
from mcpguard.ai import AIConfig, build_judge

reports = scan_file("mcp-config.json", ai=AIConfig(judge=build_judge("jev")))
failed = any(r.failed(Severity.HIGH) for r in reports)
```

## Development

```bash
pytest --cov=mcpguard     # 524 tests, 93% branch coverage
pytest -m live            # real Jev / Claude calls (needs keys)
mcpguard redteam          # detection / false-positive report
mypy                      # strict
ruff check .
```

## License

MIT
