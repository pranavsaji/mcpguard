# Cybersecurity Project Ideas — Research Catalog & Build Plan

## Context

A researcher-grade scan of the current (2025–2026) cybersecurity landscape with
**10 strong, buildable project ideas** — each a *production-useful tool*, not a
toy demo — spanning four domains: **AI/LLM security, Blue team / SOC, AppSec /
supply chain, and Cloud / infra / crypto.**

This file is the deliverable: a ranked catalog with name, thesis, "why now"
(grounded in 2026 threat data), what it does, impact, complexity, stack, and a
minimal MVP scope for each — followed by a detailed build plan for the chosen
first project, **MCPGuard**.

### What the research established (2026 signal, with sources)

- **MCP is the year's hottest new attack surface.** 40+ CVEs disclosed against
  Model Context Protocol implementations Jan–Apr 2026; a "by-design" STDIO/
  subprocess flaw enables RCE; tool poisoning + indirect prompt injection are
  systemic across 9 of 11 MCP marketplaces (150M+ downloads affected).
- **Prompt injection is OWASP LLM01 for the 2nd edition running**, and the new
  *OWASP Top 10 for Agentic Applications* (Black Hat EU 2025) centers
  *excessive agency* — agents with more tools/permissions than they need.
- **Non-Human Identities are the consensus #1 cloud breach vector for 2026.**
  NHI-to-human ratio 45:1 (144:1 in cloud-native); GitGuardian found **29M new
  hardcoded secrets in 2025 (+34% YoY)**, 1.27M tied to AI services (+81%).
- **Software supply chain attacks keep accelerating** — 230+ malicious npm/PyPI
  packages confirmed in Feb 2026 alone; OSV malicious-package feed + typosquat/
  dependency-confusion detection are now table stakes.
- **99% of 2025 cloud breaches traced to misconfiguration**; over-permissioned
  IAM is a primary breach path.
- **Detection-as-code + continuous purple teaming** (Sigma in Git, Atomic Red
  Team in CI, ATT&CK coverage as a test suite) is the modern SOC standard.
- **Post-quantum migration clock is ticking** — NIST FIPS 203/204/205 final,
  NSA deadlines set; "harvest now, decrypt later" is active; building a
  **crypto inventory / CBOM** is the agonizing first step taking enterprises
  12–24 months.

Sources:
[MCP CVEs](https://dev.to/piiiico/mcp-security-vulnerabilities-in-2026-40-cves-and-counting-4pco) ·
[MCP RCE (Hacker News)](https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html) ·
[NSA MCP guidance](https://www.nsa.gov/Portals/75/documents/Cybersecurity/CSI_MCP_SECURITY.pdf) ·
[OWASP LLM Top 10 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/assets/PDF/OWASP-Top-10-for-LLMs-v2025.pdf) ·
[OWASP Agentic](https://www.promptfoo.dev/docs/red-team/owasp-agentic-ai/) ·
[NHI blind spot (CSO)](https://www.csoonline.com/article/4125156/why-non-human-identities-are-your-biggest-security-blind-spot-in-2026.html) ·
[Secrets Sprawl 2026](https://thehackernews.com/2026/03/the-state-of-secrets-sprawl-2026-9.html) ·
[OSV malicious pkgs](https://openssf.org/blog/2026/05/20/detecting-malicious-packages-using-the-osv-api/) ·
[Typosquatting tool](https://github.com/andrew/typosquatting) ·
[Open-source CSPM](https://www.sentinelone.com/cybersecurity-101/cloud-security/open-source-cspm/) ·
[Purple team detection lab](https://www.malviksecurity.com/blog/building-purple-team-detection-lab) ·
[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) ·
[PQC / CBOM 2026](https://www.gopher.security/news/nist-post-quantum-cryptography-standards-2026-migration)

---

## The 10 Ideas

Complexity = build effort to a *useful* MVP (1 = a weekend, 5 = months).
Impact = real defensive value + resume/portfolio signal in 2026.

### 1. MCPGuard — MCP server security scanner  ⭐ top pick
- **Domain:** AI/LLM security · **Impact:** 5/5 · **Complexity:** 3/5
- **Thesis:** Every team is bolting MCP servers onto agents with zero security
  review. Be the `npm audit` for MCP.
- **What it does:** Static + dynamic scan of an MCP server (config, manifest, or
  live endpoint). Flags: tool-description prompt injection / tool poisoning,
  STDIO command-injection / RCE surface, over-broad tool scopes (excessive
  agency), "rug-pull" mutable tool definitions, unpinned/unsigned servers,
  secrets in env. Outputs a risk report + CI gate.
- **Differentiator:** Maps findings to OWASP LLM Top 10 + Agentic Top 10 + the
  2026 MCP CVE classes. Ships as both CLI and a pre-flight check an agent runs
  before trusting a server.
- **Stack:** Python, MCP SDK, tree-sitter for static analysis, rules engine.
- **MVP:** Point it at an MCP server config → produce a graded report with the
  top poisoning/RCE/excessive-agency checks.

### 2. AgentSentry — runtime guardrail proxy for tool-using agents
- **Domain:** AI/LLM security · **Impact:** 5/5 · **Complexity:** 4/5
- **Thesis:** OWASP's top agentic risk is *excessive agency*; nothing enforces
  least-privilege at the tool-call boundary at runtime.
- **What it does:** Transparent proxy between agent and its tools/MCP servers.
  Enforces per-tool allow-lists, detects indirect prompt injection in retrieved
  content/tool outputs, requires human-approval for high-blast-radius actions,
  and produces a tamper-evident audit log of every tool call.
- **Differentiator:** Policy-as-code ("this agent may read but never delete";
  "no network egress to non-allowlisted hosts") + injection detection on the
  *data* flowing back into the model.
- **Stack:** Python/Go proxy, policy DSL (OPA/Rego or custom), small classifier
  for injection detection.
- **MVP:** Proxy that blocks a disallowed tool call and flags a planted
  injection string in a retrieved doc.

### 3. RedTeamLLM — automated LLM app red-teaming harness
- **Domain:** AI/LLM security · **Impact:** 4/5 · **Complexity:** 3/5
- **Thesis:** Teams ship LLM features with no adversarial testing.
- **What it does:** Library of attack templates (jailbreaks, prompt injection,
  data exfil, system-prompt leak, tool abuse) mapped to OWASP LLM Top 10; runs
  them against any chat/agent endpoint; scores pass/fail; regression-tests in
  CI. Think "Atomic Red Team for LLMs."
- **Differentiator:** Detection-as-code mindset applied to AI — coverage map of
  which OWASP risks you actually test.
- **Stack:** Python, pytest-style runner, pluggable target adapters.
- **MVP:** 15–20 attacks against an OpenAI/Anthropic endpoint → scored report.

### 4. DetectionForge — detection-as-code + purple-team CI pipeline
- **Domain:** Blue team / SOC · **Impact:** 5/5 · **Complexity:** 3/5
- **Thesis:** The modern SOC standard — Sigma rules in Git, validated by Atomic
  Red Team in CI, ATT&CK coverage as a test suite — has no clean open-source
  glue tying it together.
- **What it does:** Repo structure for Sigma detections; CI that (a) lints/tests
  rules, (b) fires the mapped Atomic Red Team technique in a sandbox, (c)
  confirms the detection triggers, (d) regenerates an ATT&CK coverage heatmap,
  (e) fails the build on regressions.
- **Differentiator:** Closes the loop *automatically* (emulate → detect →
  verify → report); identity-first techniques prioritized for 2026.
- **Stack:** Python, Sigma/pySigma, Atomic Red Team, GitHub Actions, ATT&CK
  Navigator layers.
- **MVP:** 5 Sigma rules + 5 atomics + a CI job that proves each rule fires.

### 5. PhishTriage — AI SOC alert / phishing triage copilot
- **Domain:** Blue team / SOC · **Impact:** 4/5 · **Complexity:** 2/5
- **Thesis:** Tier-1 analysts drown in repetitive triage; LLMs are genuinely
  good at enrichment + summarization.
- **What it does:** Ingests an alert or suspicious email (.eml), enriches
  (URLs/IPs/hashes against threat-intel APIs), reasons about verdict, drafts an
  analyst-ready summary + recommended action, assigns a confidence score.
- **Differentiator:** Grounded enrichment (no hallucinated verdicts) + explicit
  uncertainty; fits the WAT framework cleanly as a workflow + tools.
- **Stack:** Python, IOC enrichment APIs (VirusTotal/URLScan/AbuseIPDB), LLM.
- **MVP:** Drop in a phishing .eml → structured triage verdict + IOC table.

### 6. NHI-Sentinel — non-human identity & secrets-sprawl scanner
- **Domain:** Cloud/infra + AppSec · **Impact:** 5/5 · **Complexity:** 3/5
- **Thesis:** NHIs are the #1 projected 2026 cloud breach vector; 29M secrets
  leaked in 2025. This is the single hottest enterprise gap.
- **What it does:** Scans repos + cloud accounts to (a) detect leaked/hardcoded
  secrets (incl. AI-service keys), (b) build an inventory of non-human
  identities (service accounts, API keys, OAuth tokens, workload creds), (c)
  flag stale, over-privileged, or unrotated identities, (d) score governance
  gaps vs SOC2/NIST expectations.
- **Differentiator:** Goes beyond secret-scanning to *NHI governance* — owner,
  last-used, privilege, rotation age — the part everyone's missing.
- **Stack:** Python, git history scanning, entropy + provider-specific
  detectors, cloud IAM APIs (AWS/GCP/Azure read-only).
- **MVP:** Scan a repo's full git history + one cloud account → ranked NHI risk
  report.

### 7. DepFirewall — malicious-package install-time firewall
- **Domain:** AppSec / supply chain · **Impact:** 5/5 · **Complexity:** 3/5
- **Thesis:** 230+ malicious npm/PyPI packages in one month; CVE-based scanners
  miss typosquats, dependency confusion, and compromised maintainers.
- **What it does:** Pre-install hook (npm/pip) that checks each package against
  the OSV malicious feed, detects typosquatting (edit-distance vs popular
  names), dependency-confusion (public name shadowing a private one), and
  risky install scripts / network calls. Blocks or warns before code executes.
- **Differentiator:** Behavioral + name-based signals at *install time*, not a
  post-hoc SBOM scan; complements (doesn't duplicate) CVE SCA tools.
- **Stack:** Python/Node, OSV API, registry metadata, AST scan of install
  scripts.
- **MVP:** `pip install`/`npm install` wrapper that blocks a known-bad / obvious
  typosquat package.

### 8. ProvenancePipe — SBOM + SLSA provenance generator/verifier
- **Domain:** AppSec / supply chain · **Impact:** 4/5 · **Complexity:** 3/5
- **Thesis:** SBOMs are mandated (EO 14028, EU CRA) but most are generated and
  never *verified*; SLSA provenance adoption is low.
- **What it does:** Generates CycloneDX/SPDX SBOM for a build, attaches SLSA
  provenance attestation, and a verifier that checks an artifact's SBOM +
  provenance + signatures at deploy/admission time.
- **Differentiator:** The *verify-at-admission* half (Kubernetes admission
  controller / CI gate), which is where most setups stop short.
- **Stack:** Syft/Trivy, in-toto/SLSA, Sigstore cosign, optional K8s webhook.
- **MVP:** Build → SBOM + signed provenance → verifier passes/fails on tamper.

### 9. CryptoScout — crypto inventory (CBOM) + PQC-readiness scanner
- **Domain:** Crypto/infra · **Impact:** 4/5 · **Complexity:** 4/5
- **Thesis:** PQC migration's hardest first step is *finding* all crypto. NIST
  standards are final; the clock is real; "harvest now, decrypt later" is live.
- **What it does:** Scans source code, dependencies, and live TLS endpoints to
  inventory cryptographic usage; builds a CBOM (CycloneDX crypto-assets); flags
  quantum-vulnerable algorithms (RSA, ECDH/ECDSA, classic DH); prioritizes by
  data sensitivity; suggests hybrid/PQC migration paths.
- **Differentiator:** Bridges code + network views into one CBOM with a ranked
  migration roadmap — exactly the artifact enterprises are paying consultants
  12–24 months to produce.
- **Stack:** Python, tree-sitter/semgrep rules, TLS scanner, CycloneDX CBOM.
- **MVP:** Scan a repo + a list of TLS hosts → CBOM + quantum-risk ranking.

### 10. CloudLeastPriv — IAM least-privilege & misconfiguration analyzer
- **Domain:** Cloud/infra · **Impact:** 4/5 · **Complexity:** 3/5
- **Thesis:** 99% of 2025 cloud breaches were misconfiguration; over-permissioned
  IAM is the prime escalation path. Prowler/KICS exist but right-sizing IAM
  from *actual usage* is still hard.
- **What it does:** Reads IAM policies + cloud activity logs (CloudTrail), diffs
  granted vs *used* permissions, generates least-privilege policy
  recommendations, and flags classic misconfigs (public buckets, open ports,
  admin wildcards, unused roles).
- **Differentiator:** Usage-driven right-sizing (granted − used = remove), not
  just static policy linting.
- **Stack:** Python, AWS SDK (boto3), CloudTrail parsing, policy diffing.
- **MVP:** Point at one AWS account → "these roles can do X but only ever did
  Y" report + tightened policy JSON.

---

## At a glance

| # | Name | Domain | Impact | Complexity | Best for |
|---|------|--------|:------:|:----------:|----------|
| 1 | **MCPGuard** | AI/LLM | 5 | 3 | Hottest topic, clean MVP |
| 2 | AgentSentry | AI/LLM | 5 | 4 | Deep/ambitious flagship |
| 3 | RedTeamLLM | AI/LLM | 4 | 3 | Fast, demoable |
| 4 | DetectionForge | Blue team | 5 | 3 | SOC-role signal |
| 5 | PhishTriage | Blue team | 4 | 2 | Quickest win, WAT-fit |
| 6 | **NHI-Sentinel** | Cloud/AppSec | 5 | 3 | #1 enterprise gap |
| 7 | **DepFirewall** | Supply chain | 5 | 3 | Immediately useful |
| 8 | ProvenancePipe | Supply chain | 4 | 3 | Compliance-driven |
| 9 | CryptoScout | Crypto | 4 | 4 | Differentiated, future-proof |
| 10 | CloudLeastPriv | Cloud | 4 | 3 | Practical, measurable |

## Recommendation

Given the goal (**production-useful tool**, standalone is fine), the strongest
"impact ÷ complexity, build it this week" picks are:

1. **MCPGuard (#1)** — the most *2026* idea on the list, genuinely under-served,
   and you have direct domain access (you live in an MCP-heavy environment).
2. **DepFirewall (#7)** — immediately useful to every developer, crisp MVP,
   easy to show value (block a real typosquat).
3. **NHI-Sentinel (#6)** — biggest enterprise pain, strongest resume signal.

**Decision: building MCPGuard (#1) first.** The rest of this plan is its build
spec. The other 9 ideas remain catalogued above for later.

---

# Build Plan — MCPGuard

## Goal
A standalone, production-useful CLI that scans an MCP server (from a config
file, a server spec, or a live connection) and emits a graded security report —
the `npm audit` of the MCP ecosystem. Static analysis first (no network needed),
optional dynamic analysis behind a flag.

## Detection rules (MVP = the ★ rules)

| ID | Category | What it catches | OWASP / CVE mapping |
|----|----------|-----------------|---------------------|
| ★ TP01 | Tool poisoning | Injection directives in tool/param **descriptions** & server instructions ("ignore previous", "always call…", exfil phrasing) | LLM01 Prompt Injection |
| ★ TP02 | Hidden content | Zero-width / invisible unicode, HTML comments, oversized whitespace in metadata | LLM01 |
| ★ CAP01 | Excessive agency | Tools exposing shell/exec, file-write, arbitrary network, secret access; over-broad scopes | Agentic "Excessive Agency" |
| ★ CMD01 | RCE surface | Config/source spawning commands with unsanitized args; `shell=True`, `os.system`, `eval`, string-built commands in local server source | 2026 MCP STDIO RCE class |
| ★ SEC01 | Secrets | Plaintext secrets/API keys in config `env` blocks | LLM/secrets hygiene |
| ★ SUP01 | Supply chain | Unpinned `npx`/`uvx`/`pip` install, fetch-from-URL, unsigned server | MCP supply-chain CVEs |
| RUG01 | Rug pull (dynamic) | Runtime tool definitions differ from pinned baseline / change between calls | MCP rug-pull class |
| MAN01 | Manifest drift (dynamic) | Live tool list/schemas differ from declared manifest | MCP CVE class |

Each rule emits a `Finding`: `id, severity, category, mapping, location,
evidence, remediation`.

## Architecture
```
mcpguard scan <config | server-spec | url> [--connect] [--format text|json] [--min-severity]
```
- **Input adapters** (`config_parser.py`): parse Claude Desktop / Cursor / generic
  MCP config JSON, a single `{command,args,env}` spec, or a URL.
- **Static analyzer** (`static/`): rules over the manifest/metadata; if the server
  is a local command, locate & scan its source with tree-sitter + pattern rules.
- **Dynamic analyzer** (`dynamic/`, opt-in `--connect`): use the MCP SDK client to
  connect, enumerate tools/resources/prompts, run metadata rules on *live* data,
  snapshot definitions for rug-pull/drift comparison.
- **Rules registry** (`rules.py`) + **mappings** (`mappings.py`): OWASP LLM Top 10,
  OWASP Agentic Top 10, 2026 MCP CVE classes.
- **Reporters** (`report.py`): Rich console table + JSON; exit non-zero when any
  finding ≥ `--min-severity` (default `high`) for CI gating.

## Project layout
```
mcpguard/
  pyproject.toml            # uv/pip, entry point mcpguard = mcpguard.cli:app
  README.md
  src/mcpguard/
    cli.py                  # Typer app
    models.py               # Finding, Severity, Report
    config_parser.py
    static/{tool_poisoning,capabilities,command_injection,secrets,pinning}.py
    dynamic/{client,rugpull}.py
    rules.py                # rule registry / runner
    mappings.py
    report.py
  tests/
    fixtures/vulnerable_server/   # poisoned tool desc + exec tool + secret in env
    fixtures/clean_server/        # benign, well-scoped server
    fixtures/configs/             # sample MCP config JSON
    test_static.py test_dynamic.py test_cli.py
```

## Stack
Python 3.12 · `mcp` SDK · `typer` (CLI) · `rich` (output) · `tree-sitter` +
regex (static source scan) · `pytest` (tests). No paid APIs.

## Implementation order
1. Scaffold repo + `pyproject.toml` + `models.py` (Finding/Severity/Report).
2. `config_parser.py` + the 6 ★ static rules + `rules.py` runner.
3. `report.py` (Rich + JSON) + `cli.py` with exit-code gating.
4. Build vulnerable + clean fixtures; write unit tests per rule + e2e CLI test.
5. Add `--connect` dynamic analyzer (RUG01/MAN01) against the local fixture.
6. README with usage, rule catalog, and CI-gating example.

## Verification
- **Fixtures-as-tests:** assert the scanner flags every planted issue in
  `vulnerable_server` (poisoned description, exec capability, secret in env,
  unpinned install) and reports **clean** on `clean_server`.
- **Unit test per rule** (each detector in isolation) + **one e2e CLI test**
  producing both text and JSON, asserting the exit code.
- **Dynamic path:** spin up the local fixture server, run `--connect`, confirm
  enumeration + rug-pull baseline diff works.
- **Manual sanity:** run against 2–3 real public MCP servers; eyeball findings
  for false positives before calling it done.
