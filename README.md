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

Fourteen independently registered rules plus a runtime guard, each mapped to a recognized
framework so findings survive a compliance conversation.

| ID | Severity | Detects | Maps to |
|----|----------|---------|---------|
| **TP01** | High–Critical | **Tool poisoning / prompt injection** across the *whole* metadata surface ("Full-Schema Poisoning"): server instructions; tool descriptions, titles, annotation titles; every string at any depth of the input **and output** schemas (every string and every non-keyword key: parameter names, descriptions, titles, defaults, enums, examples, `required`, `type`, `x-` extensions, `$defs`, `anyOf`…), parameter *names* that solicit secrets (`content_from_reading_ssh_id_rsa`) or open a covert channel (`sidenote`); prompt and prompt-argument text; resource text. Catches instruction override, concealment (`do not tell the user`, `do not mention that you…`), `<IMPORTANT>`-style pseudo-tags and chat-template tokens, tool-ordering hijacks ("call this tool first"), exfiltration (`read ~/.cursor/mcp.json`, `send … to https://…`, templated markdown-image beacons, conversation / system-prompt leaks), and **base64** that decodes to any of these. | OWASP LLM01 · MCP tool poisoning |
| **TP02** | Medium–Critical | **Hidden content.** Zero-width / BiDi / other invisible format characters; **Unicode Tag "ASCII smuggling"** (decoded into the evidence, critical if it hides a directive); variation-selector smuggling; **ANSI terminal escape sequences** (Trail of Bits line-jumping deception); HTML comments; whitespace padding that pushes text off-screen. | OWASP LLM01 |
| **TP03** | Medium–High | **Tool shadowing & spoofing** *(cross-server)*. A server's metadata naming another server's tool; shadowing directives ("when using the send_email tool, BCC…", "instead of calling…"); preference manipulation ("always use this tool", "other tools are deprecated"); tool-name collisions across servers; homoglyph (mixed-script) and non-spec tool names. | OWASP LLM01 · MCP tool shadowing |
| **FLOW01** | Medium–High | **Toxic flow / lethal trifecta** *(cross-server)* — the precondition for **indirect prompt injection**. Classifies every tool as untrusted-input, private-data, external-sink, or code-exec and flags configs where attacker-authored content (issues, email, web pages) can reach private data *and* an exfiltration path, or reach code execution — the GitHub-MCP / Supabase-MCP incident pattern. Falls back to known-server profiles when no manifest is available (medium). | OWASP LLM01 (indirect) · OWASP Agentic |
| **CAP01** | Medium–High | **Excessive agency.** Infers capability from tool name and description across six classes. Also flags **deceptive annotations**: `readOnlyHint: true` on a tool that writes, deletes, or executes (clients may auto-approve it). | OWASP Agentic — Excessive Agency |
| **CMD01** | High | **RCE sinks in server source.** When the server's source is locatable on disk: `shell=True`, `os.system`, `os.popen`, `eval`/`exec`, `child_process.exec`, `new Function`, `curl … \| sh`. Reported per file and line. | MCP STDIO RCE · CWE-78 |
| **SEC01** | High–Critical | **Plaintext secrets** in `env`, HTTP `headers` (`Authorization: Bearer <literal>`), launch `args` (`--api-key …`), and the server `url` (userinfo, `?api_key=`). 20 vendor formats (incl. OpenAI `sk-proj-`, Anthropic, GitHub fine-grained PATs, Stripe, Hugging Face, database URLs with passwords) plus name heuristics, with placeholder / `${VAR}` suppression. Evidence is redacted. | CWE-798 |
| **SUP01** | Low–High | **Supply-chain exposure.** Unpinned `npx`/`uvx`/`pipx`/`bunx` launches; container images not pinned by digest; fetch-and-execute of code from a URL / git ref at launch (a bridge's URL argument, e.g. `npx mcp-remote https://…`, is correctly *not* flagged). | MCP supply chain · SLSA |
| **SUP02** | Low–Critical | **Known-vulnerable, malicious, or archived packages** from an offline, source-cited advisory list: `mcp-remote` (CVE-2025-6514), MCP Inspector (CVE-2025-49596), `server-filesystem` (CVE-2025-53109/53110), `mcp-server-git` (CVE-2025-68143/4/5), `postmark-mcp` (malware), and more; plus IOCs from documented MCP campaigns (e.g. Deadbugz). Uses the pinned version, or the locally installed one. | CWE-1395 · MCP supply chain |
| **CFG01** | Medium–High | **Dangerous launch configuration.** Code-injecting env (`LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `NODE_OPTIONS=--require`), TLS verification disabled, LLM base-URL redirects (`ANTHROPIC_BASE_URL`), registry overrides (`--extra-index-url`: dependency confusion), `sudo`, containers with `--privileged` / Docker socket / host root / host namespaces / dangerous caps, filesystem servers rooted at `/` or `~`, binding to `0.0.0.0`. | CWE-250 · MCP local-server compromise |
| **NET01** | Low–High | **Insecure transport.** Plaintext `http://` to a non-loopback remote server (directly or via `mcp-remote`) — tokens and tool descriptions can be read or rewritten in transit; deprecated HTTP+SSE transport. | CWE-319 |
| **MAN01** | Medium–High | **Rug pull / manifest drift.** Diffs the current manifest (live via `--connect`, or declared) against the reviewed **lockfile** baseline: added / removed tools, and changed descriptions, input schemas, output schemas, titles, **annotations**, instructions, prompts, resources. | MCP rug pull |
| **MAN02** | Medium–High | **Launch / inventory drift** vs the lockfile: a server's command, package, version, image, URL, or env names changed since review (a supply-chain swap), and servers never reviewed at all. | MCP rug pull · supply chain |
| **IPI01** | Low–Critical | **Runtime guard for tool *outputs*** (`mcpguard check-output`, Claude Code hook). The same detectors applied to what tools return at run time — the only place indirect prompt injection and "Advanced Tool Poisoning" payloads (instructions in results / error messages) can be seen. | OWASP LLM01 (indirect) |
| **AI01** | High–Critical | *(--ai)* Semantic tool poisoning judged by Jev / Claude — paraphrased, translated, or obfuscated manipulation no keyword matches. | OWASP LLM01 |
| **IPI02** | High–Critical | *(--ai)* Semantic indirect prompt injection in tool outputs. | OWASP LLM01 (indirect) |
| **AI02** | Medium–High | *(--ai, CLI)* AI review of server source: tool input reaching shell / eval, unconfined paths, string-built SQL, unrestricted outbound URLs. | CWE-78 · 22 · 89 · 918 |
| **AI03** | Medium–High | *(--ai)* Tool capability vs. the server's stated purpose; hidden behavior behind a benign name. | OWASP Agentic — Excessive Agency |

### Attack-class coverage

| Attack class (2025–2026) | Where MCPGuard catches it |
|---|---|
| Tool poisoning (Invariant, Apr 2025) | TP01, TP02 |
| Full-Schema Poisoning (CyberArk, 2025) | TP01 (recursive schema walk incl. output schema, names, enums, defaults) |
| Advanced Tool Poisoning — payload in tool results / errors | IPI01 (runtime guard) |
| Rug pull / silent redefinition | MAN01 + MAN02 against `mcpguard lock` (full-object hashes, not just descriptions); SUP01 pinning |
| Tool shadowing / cross-server interference / name collision | TP03 |
| Tool squatting / homoglyph names / preference manipulation (MPMA) | TP03 |
| Indirect prompt injection (GitHub MCP, Supabase MCP) | FLOW01 (pre-deployment exposure), IPI01 (runtime) |
| Line jumping & ANSI terminal deception (Trail of Bits) | TP01 (pre-call directives), TP02 (ANSI) |
| ASCII smuggling (Unicode Tags), variation-selector smuggling | TP02, IPI01 |
| Malicious / vulnerable MCP packages | SUP02 |
| Supply-chain swap, unpinned `latest` | SUP01, MAN02 |
| Local server compromise (dangerous startup config) | CFG01, CMD01 |
| Credential exposure in configs | SEC01 |
| Token theft / MITM on remote servers | NET01, SEC01 |

**Out of scope** (runtime / client behavior a config scanner cannot observe): OAuth
confused-deputy and token-passthrough flaws inside a server, sampling / elicitation abuse
while a session runs, DNS rebinding of a server's own HTTP listener, and MCP Apps (`ui://`)
HTML content. FLOW01 identifies *exposure* to indirect injection; blocking it at run
time needs IPI01 plus human approval on sink tools.

> **Design bias: precision over recall.** A scanner in a CI gate that cries wolf gets
> the gate removed within a sprint. So placeholders are suppressed, secrets are matched
> on vendor formats before name heuristics, pagination "tokens" and `process.env` don't
> read as exfiltration, and inference-based rules (`CAP01`, `FLOW01`, `TP03` references)
> carry an explicit confidence below 1.0 rather than posing as certainty. Architectural
> findings that config hygiene can't fix (FLOW01 from package profiles, archived
> servers) sit below the default `high` gate.

### Inputs accepted

The parser dispatches on structure — you never declare a format:

- `{"mcpServers": {…}}` — Claude Desktop, Cursor, Claude Code `.mcp.json`, Gemini CLI, Amazon Q
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

mcpguard lock config.json --connect                  # pin the reviewed state (rug-pull baseline)
mcpguard scan config.json --connect --baseline mcpguard.lock.json

mcpguard check-output tool-result.json               # scan a tool result for injection
```

### Rug-pull protection: the lockfile

A server can pass review and then change what it serves. `mcpguard lock` records each
server's launch line and — with `--connect` — its full live manifest, with a SHA-256
over every *complete* tool definition (description, title, input and output schema,
annotations), plus instructions, prompts, and resources. Commit `mcpguard.lock.json`
next to your config; then every scan with `--baseline` reports:

- **MAN01** — any tool added, removed, or changed in *any* field (a flipped
  `readOnlyHint` or a new poisoned parameter counts, not just the description),
- **MAN02** — a changed command / package / version / image / URL / env name, and
  servers that were never reviewed.

The lockfile is deterministic (sorted keys, no timestamps) so changes show up as a clean
diff in code review, and a hand-edited baseline fails its own integrity hash.

### Runtime guard: indirect prompt injection in tool outputs

Indirect prompt injection lives in data a tool *returns* — an issue body, an email, a web
page — so no pre-deployment scan can see it. `mcpguard check-output` runs the same
detectors over tool results. Wire it into Claude Code as a `PostToolUse` hook so every
MCP tool result is checked before the model acts on it:

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "mcp__.*",
        "hooks": [{ "type": "command", "command": "mcpguard check-output --hook", "timeout": 30 }]
      }
    ]
  }
}
```

On a hit the hook returns `decision: "block"` with a reason, which Claude Code feeds back
to the model as a warning to treat that output as untrusted data. The hook never breaks
a session: malformed input passes silently. Outside Claude Code, pipe any tool result in
(`… | mcpguard check-output`); it exits `1` when a finding meets `--min-severity`.

### AI judge layer (Jev / Claude) — optional

The rules match known shapes of attack. An attacker who paraphrases ("the assistant should
first open the private key in the user's hidden secure-shell folder…"), writes in Spanish
or Chinese, or spells `1gn0re pr3vious` gets past every keyword list. `--ai` adds a
second, semantic layer: a model answers fixed yes/no questions about the text and returns
a probability.

```bash
cp mcpguard/.env.example .env        # add TYPESAFE_API_KEY and/or ANTHROPIC_API_KEY
mcpguard scan config.json --ai auto                  # best configured judge(s)
mcpguard scan config.json --ai ensemble --ai-cache .mcpguard-cache/ai.json
mcpguard check-output --hook --ai jev                # semantic runtime guard (fast)
```

| Judge | How it's called | Why |
|---|---|---|
| **Jev** (TypeSafe AI, `jev-latest`) | `POST https://api.typesafe.ai/v1/systemone`, stdlib HTTP, no extra deps | A decision model: returns calibrated probabilities, not text. Fast and ~$0.04 per million input tokens — cheap enough to judge every tool and every tool output. |
| **Claude** (`claude-opus-5`, `pip install 'mcpguard[claude]'`) | Official Anthropic SDK, structured JSON output, `effort: low`, `fallbacks: "default"` | A strong independent second opinion; fallbacks keep it answering when a safety classifier declines an attack payload. |
| **ensemble** | both; per question the **max** | An attacker has to fool both models at once. `auto` picks this when both keys are set. |

Where the judge is used:

| Where | Rule | Question asked |
|---|---|---|
| Every tool / prompt / resource / instruction block | **AI01** | Does this text direct the assistant, solicit secrets, demand secrecy, or steer other tools? |
| Server source code (CLI, files with a sink only) | **AI02** | Can tool input reach a shell / eval sink, an unconfined path, string-built SQL, or an unrestricted outbound URL? (CWE-78 / 22 / 89 / 918) |
| Each tool vs. the server's stated purpose | **AI03** | Does this tool exceed what the server says it's for (shell in a weather server), or hide behavior behind its name? |
| Every tool output (`check-output`, hook) | **IPI02** | Is this content trying to instruct an AI that reads it? (indirect prompt injection) |
| Toxic-flow classification | FLOW01 | Does this tool read third-party content / private data, send data out, execute code? — catches `lookup_ticket` / `notify_partner` that name heuristics can't (role threshold 0.6: a role is a description, not an alarm) |
| Rug-pull review | MAN01 | Does the changed text *add* instructions, data flows, or secrecy (vs. a wording fix)? |

Safety properties, because the judge is itself a model an attacker can talk to (TypeSafe
documents this for Jev; it holds for every LLM):

- **Additive only.** A judge adds or escalates findings; it never removes a deterministic
  one. The rules are the floor an attacker can't argue their way past.
- **Untrusted text is data.** It goes to Jev as a labelled field of structured state and to
  Claude inside a per-request nonce-delimited block; every question says so.
- **Fail visible.** A judge error is an `AI00` INFO finding (`--ai-fail-closed`: HIGH). The
  Claude Code hook falls back to the deterministic guard rather than break a session.
- **Opt-in triage only.** `check-output --ai-triage` lets a confident "benign" verdict
  (every answer ≤ 0.05) downgrade a *keyword-only* injection hit — e.g. a security article
  quoting "ignore previous instructions" — to LOW. Exfiltration, encoded, and smuggled
  content are never triaged.
- **No silent truncation.** Long outputs are judged in overlapping chunks; anything past
  the chunk budget is reported.
- **Circuit breaker.** A permanent judge failure (bad key, no credits) stops calls to that
  judge for the rest of the run and is reported once — a 300-tool config doesn't make 300
  doomed requests, and an ensemble keeps working on the healthy judge.
- **What leaves the machine.** Tool names, descriptions, schemas, server instructions, and
  the server's name / package / URL (credentials and query string stripped) — never env
  values or headers. AI02 sends source files, which may contain hardcoded secrets; it
  only runs when you point `--ai` at a config with `source_path`.

### AI judge in the web dashboard

The browser engine can't hold API keys, so the dashboard's **AI judge** toggle posts to a
server route, `POST /api/ai-scan`, which runs the deterministic scan plus AI01, AI03, and
AI-inferred toxic-flow roles (AI02 needs source files and MAN01 a lockfile: CLI only).
`GET /api/ai-scan` reports which judges are configured — never the keys.

- Keys: `mcpguard-web/.env.local`, or reuse `mcpguard/.env` / the repo-root `.env`
  (loaded by `next.config.ts` without overriding anything already set).
- **This route spends money.** Set `MCPGUARD_AI_ROUTE_TOKEN` and send it as a Bearer
  token; in production the route is closed without one unless you set
  `MCPGUARD_AI_ROUTE_PUBLIC=1`. Inputs are capped (256 KB, 300 tools).
- The same question catalog (`mcpguard-web/lib/ai/questions.json`) and the same rule logic
  run in both engines; a parity fixture holds the TypeScript AI rules to the Python output
  exactly.

### Red-team suite

`mcpguard redteam` runs 122 cases — 86 attacks across 13 categories and 36 *hard*
benign lookalikes (real official tool descriptions, security articles quoting attack
phrases, colored CLI output, flag emoji built from tag characters, safe versions of the
vulnerable source files, a terminal server that *should* run commands) — through each
layer and reports detection and false-positive rates:

```bash
mcpguard redteam                                  # deterministic layer (free)
mcpguard redteam --ai jev                         # + measure the Jev layer
mcpguard redteam --ai ensemble -f json            # machine-readable
mcpguard redteam --ai auto --min-recall 0.95 --max-fpr 0.10   # CI gate on quality
```

Measured 2026-09-30, live against `jev-1.13.0` (≈1 minute for the whole suite):

| Category | Attacks | Static | Jev alone | **Combined** |
|---|---|---|---|---|
| tool poisoning, hidden content, launch config, rug pull | 34 | 100% | — | **100%** |
| schema poisoning | 8 | 87.5% | 87.5% | **100%** |
| tool shadowing | 5 | 80% | 80% | **100%** |
| indirect injection (tool outputs) | 12 | 75% | 91.7% | **100%** |
| judge evasion | 3 | 66.7% | 100% | **100%** |
| toxic flow | 3 | 66.7% | 33.3% | **100%** |
| source review (command / SQL / path / SSRF) | 7 | 28.6% | 100% | **100%** |
| semantic evasion (paraphrase, Spanish / Chinese / German, leetspeak, spacing) | 10 | 0% | 100% | **100%** |
| purpose mismatch | 4 | 0% | 100% | **100%** |
| **Total** | **86** | **69.8%** | 73.3% | **100%** |

False positives on the 36 benign cases: 5.6% static, **8.3% combined** (3 cases): two
texts that *quote* "ignore previous instructions" (a security tool and a security
article — opt-in `--ai-triage` can downgrade the article when the judge is confident; Jev
scored it 0.33, so it correctly didn't), and the official `mcp-server-fetch` description,
which genuinely tells the model to set aside a prior instruction ("originally you… were
advised to refuse… this tool now grants you internet access") — Jev flags it at 0.94.
The Claude judge was not measured: the configured Anthropic account had no credits.

Every case's deterministic outcome is pinned (`expect_static`), so `pytest` fails on any
change — a new miss *or* a new false positive. Cases live in
`mcpguard/src/mcpguard/redteam/cases.jsonl`; `--cases your.jsonl` runs your own.

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
  Live server ──────▶ Connector ──▶ MCPManifest ──▶ AnalysisContext
  (STDIO/HTTP/SSE)      (optional)                     (+ all peers,
  mcpguard.lock.json ─────────────────────────────▶     baseline)
                                                            ▼
                                              ┌─── Rule registry ───┐
                                              │ TP01 TP02 TP03      │
                                              │ CAP01 FLOW01 CMD01  │
                                              │ SEC01 SUP01 SUP02   │
                                              │ CFG01 NET01         │
                                              │ MAN01 MAN02         │
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
  models.py         # immutable domain + finding types; full-schema text walker
  patterns.py       # every detection signature, curated in one place
  detectors.py      # pure text detectors shared by metadata rules and the output guard
  advisories.py     # offline, source-cited MCP package advisories (SUP02)
  context.py        # per-scan shared state: source IO, live manifest, peers, baseline
  config_parser.py  # config/manifest JSON → MCPServerSpec targets
  lockfile.py       # reviewed-baseline lockfile (tool pinning) for MAN01/MAN02
  guard.py          # IPI01 runtime guard for tool outputs (+ Claude Code hook protocol)
  rules/
    base.py         # Rule ABC + self-registration registry
    tool_poisoning.py  hidden_content.py  shadowing.py  toxic_flow.py
    excessive_agency.py  command_injection.py  secrets.py  pinning.py
    vulnerable_packages.py  launch_config.py  transport.py
  dynamic/
    connector.py    # live-connection adapters (Recorded / SDK: STDIO, HTTP, SSE)
    drift.py        # MAN01 manifest drift + MAN02 launch drift
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
network. That is what makes 94% branch coverage achievable rather than aspirational.

**4. A misbehaving rule degrades; it does not abort.** The scanner wraps each rule
invocation. An exception becomes an `INFO` finding with `confidence: 0.0` and the scan
continues. A failed live connection does the same. One broken detector must never deny
coverage of the others — in a CI gate, a crash that reads as "no findings" is worse
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

Seven configs in `samples/` exercise the full range end to end. They double as the fixture
set for the dashboard's demo buttons.

| File | What it demonstrates |
|---|---|
| `01-real-official-servers.json` | Real official servers as people actually configure them |
| `02-best-practice-pinned.json` | The same servers done right — pinned versions, `${ENV}` refs. Passes the gate; only architectural notes remain (FLOW01 medium, archived-server SUP02 low) |
| `03-hardcoded-secrets.json` | Live-looking keys pasted into `env` → SEC01 critical + SUP01 |
| `04-remote-fetch-launch.json` | `curl … \| bash` at launch → SUP01 high |
| `05-tool-poisoning-manifest.json` | The classic poisoning attack → TP01 ×5, TP02 ×2 |
| `06-excessive-agency-manifest.json` | Over-scoped tools → CAP01 |
| `07-shadowing-toxic-flow.json` | A 2025–26 multi-server attack chain → TP03 shadowing, TP02 ASCII smuggling (decoded), TP01 enum poisoning, SUP02 malware (`postmark-mcp`), FLOW01 lethal trifecta |

Key values in `03` are **fake but format-valid** (the AWS pair is the canonical AWS
documentation example). They exist to exercise `SEC01`; they are not credentials.

---

## Development

```bash
# Python engine
cd mcpguard
pytest --cov=mcpguard --cov-report=term-missing    # 524 tests (+2 live, skipped without keys)
pytest -m live                                     # real Jev / Claude calls (needs keys)
mcpguard redteam                                   # detection / false-positive report
mypy            # strict, clean

# Web
cd mcpguard-web
npm run test        # vitest — 174 tests, incl. exact Python/TS parity (rules + AI layer) and the AI route
npm run typecheck
npm run lint
npm run build
```

| Control | Standard held |
|---|---|
| Unit tests (Python) | 524 tests, incl. the 122-case red-team suite pinned case-by-case, and the AI layer against fake transports — every rule with true-positive *and* benign-lookalike cases, real-world attack payloads (Invariant, CyberArk FSP, shadowing, ASCII smuggling), lockfile round-trips and tamper checks, hook protocol, CLI exit codes. 94% branch coverage. |
| Hostile-input safety | ReDoS regression tests (2 MB adversarial inputs stay linear), malformed-config and deep-nesting tests, rule crashes keep partial findings, terminal-escape and lone-surrogate sanitization of the text report. |
| Cross-engine parity | `fixtures/attack_config.json` covers every browser rule; the TS engine must reproduce the Python engine's output on it *exactly* (every field, including evidence), enforced in both test suites. Regexes are translated through `pycompat.ts` so Unicode `\w`/`\b`, code-point counting, and case folding match Python. |
| Type checking | `mypy --strict`, clean, across the whole package. |
| Linting | `ruff`, 100-column line length. |
| Determinism | Sorted rule execution, stable finding sort. Byte-identical JSON across runs. |
| Bounded execution | 1 MB per-file cap, cached source reads, skipped vendor dirs, 30s connect timeout, 12s registry-proxy timeout. |

---

## Status and roadmap

**Beta.** The static rule set is production-usable today. `--connect` enumerates live
servers over STDIO, Streamable HTTP, and SSE through the MCP SDK (1.x or 2.x).

| Next | Rationale |
|---|---|
| MCP spec 2026-07-28 handshake in `--connect` | The new stateless `server/discover` flow replaces `initialize`; live enumeration depends on the SDK supporting it. |
| Live advisory feed (OSV / GHSA) for SUP02 | The offline list is deterministic but ages; an opt-in `--update-advisories` keeps it current. |
| Project-scoped agent settings | Scan `.claude/settings.json` (`enableAllProjectMcpServers`, hooks, `ANTHROPIC_BASE_URL`), `.cursor/`, `.gemini/`, `.amazonq/` — the auto-execution class behind several 2025–26 CVEs. |
| OAuth metadata checks in `--connect` | Flag non-HTTPS / private-IP / `javascript:` authorization endpoints (the `mcp-remote` CVE class) and missing issuer validation. |
| MCP Apps (`ui://`) resources | Inspect served HTML for credential forms and external scripts. |
| Per-rule allow-list tuning | A shell tool is not a finding in a shell server. Suppression *with justification* is what keeps a gate alive past its first quarter. |
| SARIF output | Puts findings in the GitHub code-scanning UI with no bespoke integration work. |

---

## License

MIT
