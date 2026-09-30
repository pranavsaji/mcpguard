# MCPGuard Web

The dashboard for **[MCPGuard](../README.md)** — scan Model Context Protocol (MCP) server
configs for tool poisoning, hidden text, tool shadowing, toxic flows, leaked secrets,
malicious packages, and dangerous launch configs, right in the browser.

- **Instant, local scanning.** A TypeScript port of the Python engine runs client-side.
  With the AI judge off, nothing leaves the browser.
- **Exact parity with the CLI.** `lib/scanner/engine.test.ts` holds the TypeScript
  engine to the Python engine's output — every field of every finding — on a shared
  attack fixture; `lib/ai/ai.test.ts` does the same for the AI layer.
- **Optional AI judge.** A server route runs Jev (TypeSafe) and/or Claude over tool
  metadata; keys stay on the server.
- **Registry browser.** Scan real servers from the official MCP registry in two clicks.

## Run

```bash
npm install
npm run dev        # http://localhost:3000
```

Other scripts: `npm run build`, `npm run test` (vitest, 189 tests), `npm run typecheck`,
`npm run lint`.

## Using it

1. Paste an MCP config (`mcpServers` for Claude Desktop / Cursor / Claude Code, `servers`
   for VS Code, a single server object, or a tool manifest), upload a `.json`, or pick
   one of the seven samples — from *Real official servers* to *Shadowing + toxic flow*.
2. Findings appear grouped by server with a PASS/FAIL gate, a severity summary (click a
   chip to filter), full-text filter, expandable evidence and remediation, framework
   mappings, and **Export JSON**.
3. Tick **AI judge** to re-scan on the server with Jev / Claude. The toggle is disabled
   when no judge is configured, asks for the route token when one is required, and
   reports which judge answered and any warnings (e.g. a judge with no credits).

## Detection in the browser

All config / manifest rules run client-side: **TP01** tool poisoning (full schema),
**TP02** hidden content (ASCII smuggling, ANSI, BiDi), **TP03** tool shadowing, **FLOW01**
toxic flows, **CAP01** excessive agency, **SEC01** secrets, **SUP01** pinning, **SUP02**
vulnerable / malicious packages, **SUP03** publisher impersonation / typosquats, **CFG01**
launch config, **NET01** transport, and the MCP 2026-07-28 surface: **HDR01**
`x-mcp-header` misuse and **CACHE01** `ttlMs` / `cacheScope` cache hints.

With the AI judge on, the server route adds **AI01** (semantic poisoning), **AI03**
(purpose vs. capability), and AI-inferred toxic-flow roles. Source review (**CMD01**,
**AI02**) and rug-pull checks (**MAN01**, **MAN02**) need the `mcpguard` CLI, which can
read server source and a lockfile.

## API

```bash
# Deterministic scan — same report schema as the CLI
curl -X POST http://localhost:3000/api/scan -H 'Content-Type: application/json' \
  -d '{"config": "<MCP config JSON as a string>", "gate": "high"}'

# Which AI judges are configured (names only)
curl http://localhost:3000/api/ai-scan

# AI scan (token-guarded; spends money)
curl -X POST http://localhost:3000/api/ai-scan -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $MCPGUARD_AI_ROUTE_TOKEN" \
  -d '{"config": "<MCP config JSON as a string>", "ai": "auto", "gate": "high"}'
```

The `ok` field and the `X-MCPGuard-OK` header carry the CI gate signal. `/api/ai-scan`
also returns an `ai` block (`judge`, `threshold`, `errors`).

## Configuration

AI judge keys are read **server-side only** — from `.env.local` here, or reused from
`../mcpguard/.env` or the repo-root `.env` (loaded by `next.config.ts` without overriding
anything already set).

| Variable | Purpose |
|---|---|
| `TYPESAFE_API_KEY` | Enables the Jev judge |
| `ANTHROPIC_API_KEY` | Enables the Claude judge |
| `MCPGUARD_AI_ROUTE_TOKEN` | Bearer token required by `/api/ai-scan` |
| `MCPGUARD_AI_ROUTE_PUBLIC` | `1` to allow `/api/ai-scan` without a token in production (not recommended) |

`/api/ai-scan` is **closed in production without a token**, and caps input at 256 KB and
300 tools — every call costs money.

## Architecture

```text
app/
  page.tsx                  # header + dashboard + rule catalog
  api/scan/route.ts         # POST /api/scan
  api/ai-scan/route.ts      # GET / POST /api/ai-scan (server-side AI layer)
  api/registry/route.ts     # GET /api/registry (official MCP registry proxy)
components/                 # Dashboard, FindingCard, RegistryBrowser, ServerInventory
lib/
  scanner/                  # TypeScript engine: parser, patterns, detectors, rules, scan
  ai/                       # judge.ts (ensemble, circuit breaker), jev.ts, claude.ts,
                            # aiScan.ts (AI01, AI03, flow roles), questions.json (shared)
  registry.ts  samples.ts  ui.ts
```

## Deploy (Vercel)

Standard Next.js app — `vercel`, or push to a connected repo. The deterministic scanner
needs no configuration. To enable the AI judge, set the keys **and**
`MCPGUARD_AI_ROUTE_TOKEN` in the project's environment variables.

Built with Next.js 16, React 19, Tailwind v4, and the Anthropic TypeScript SDK.
