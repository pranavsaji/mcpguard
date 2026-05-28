# MCPGuard Web

A beautiful, efficient dashboard for **MCPGuard** — scan Model Context Protocol
(MCP) server configs for tool poisoning, prompt injection, excessive agency,
leaked secrets, and supply-chain risk, right in the browser.

- **Instant, local scanning.** The rule engine is a pure-TypeScript port of the
  Python `mcpguard` engine and runs client-side — nothing is uploaded.
- **Parity-tested.** The TS engine is locked to the Python engine's output on the
  shared fixtures (`lib/scanner/engine.test.ts`).
- **API included.** `POST /api/scan` for programmatic / CI use.

## Run

```bash
npm install
npm run dev        # http://localhost:3000
```

Other scripts: `npm run build`, `npm run test` (vitest), `npm run typecheck`,
`npm run lint`.

## Using it

1. Paste an MCP config (Claude Desktop / Cursor `mcpServers`, VS Code `servers`,
   a single server object, or a tool manifest), upload a `.json`, or click
   **Vulnerable sample** / **Clean sample**.
2. Findings appear grouped by server with a PASS/FAIL gate, severity summary
   (click a chip to filter), full-text filter, expandable evidence + remediation,
   framework mappings, and **Export JSON**.

## API

```bash
curl -X POST http://localhost:3000/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"config": "<MCP config JSON as a string>", "gate": "high"}'
```

Returns the same report schema as the `mcpguard` CLI. The `ok` field and the
`X-MCPGuard-OK` response header carry the CI gate signal.

## Architecture

```
app/
  page.tsx            # header + dashboard + rule catalog
  api/scan/route.ts   # POST /api/scan (Web Request/Response)
components/
  Dashboard.tsx       # input, summary, filters, results (client)
  FindingCard.tsx     # expandable per-finding card
  SeverityBadge.tsx
lib/
  scanner/            # the TS engine: types, patterns, rules, configParser, scan
  ui.ts               # severity → Tailwind class map
  samples.ts          # sample configs
```

Detection coverage in the browser engine: **TP01** (tool poisoning), **TP02**
(hidden content), **CAP01** (excessive agency), **SEC01** (secrets), **SUP01**
(unpinned/remote launch). Source-level RCE (**CMD01**) and live rug-pull
(**MAN01**) checks run in the `mcpguard` CLI, which can read server source and
connect to a running server.

## Deploy (Vercel)

Standard Next.js app — `vercel` or push to a connected repo. No env vars or
backend services required; scanning is self-contained.

Built with Next.js 16, React 19, Tailwind v4.
