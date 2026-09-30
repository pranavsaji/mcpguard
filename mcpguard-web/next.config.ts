import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import type { NextConfig } from "next";

/**
 * AI judge keys may live beside the Python CLI (../mcpguard/.env) or at the repo
 * root (../.env), in addition to this app's own .env.local (which Next loads
 * first). Variables that are already set always win, and the keys are only read
 * by server routes — never sent to the browser (no NEXT_PUBLIC_ prefix).
 *
 * `@next/env`'s loadEnvConfig can't be used here: it returns its cached result
 * for the project dir, and forcing a reload resets process.env.
 */
function loadSiblingEnv(file: string): void {
  if (!existsSync(file)) return;
  for (const line of readFileSync(file, "utf8").split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || !trimmed.includes("=")) continue;
    const body = trimmed.startsWith("export ") ? trimmed.slice(7) : trimmed;
    const eq = body.indexOf("=");
    const key = body.slice(0, eq).trim();
    let value = body.slice(eq + 1).trim();
    if (value.length >= 2 && value[0] === value[value.length - 1] && (value[0] === '"' || value[0] === "'")) {
      value = value.slice(1, -1);
    }
    if (key && process.env[key] === undefined) process.env[key] = value;
  }
}

for (const file of [path.join(process.cwd(), "..", "mcpguard", ".env"), path.join(process.cwd(), "..", ".env")]) {
  loadSiblingEnv(file);
}

const nextConfig: NextConfig = {};

export default nextConfig;
