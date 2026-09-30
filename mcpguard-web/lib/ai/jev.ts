/**
 * Jev (TypeSafe AI) judge over `fetch` — same wire format as the Python
 * `mcpguard/ai/jev.py`, taken from TypeSafe's official SDK:
 *
 *   POST {TYPESAFE_BASE_URL | https://api.typesafe.ai}/v1/systemone
 *   Authorization: Bearer $TYPESAFE_API_KEY
 *   {"model", "state", "questions": {name: {"type": "noul", "instructions", "criteria": {"true", "false"}}}}
 *   -> {"model", "answers": {name: {"type": "noul", "noul": 0..1}}}
 */

import { type Content, type Judge, JudgeError, type Verdict, questionsFor } from "./judge";

const DEFAULT_BASE_URL = "https://api.typesafe.ai";
const RETRY_STATUSES = new Set([408, 429, 500, 502, 503, 504]);
const MAX_RETRIES = 2;
const MAX_RETRY_DELAY_MS = 5_000;

export interface JevOptions {
  apiKey?: string;
  model?: string;
  baseUrl?: string;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
  sleep?: (ms: number) => Promise<void>;
}

function retryDelayMs(headers: Headers, attempt: number): number {
  const ms = Number(headers.get("retry-after-ms"));
  if (Number.isFinite(ms) && headers.has("retry-after-ms")) return Math.min(ms, MAX_RETRY_DELAY_MS);
  const s = Number(headers.get("retry-after"));
  if (Number.isFinite(s) && headers.has("retry-after")) return Math.min(s * 1000, MAX_RETRY_DELAY_MS);
  return Math.min(500 * 2 ** attempt, MAX_RETRY_DELAY_MS);
}

export class JevJudge implements Judge {
  readonly name: string;
  readonly model: string;
  private readonly key: string;
  private readonly url: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;
  private readonly sleep: (ms: number) => Promise<void>;

  constructor(opts: JevOptions = {}) {
    const key = (opts.apiKey ?? process.env.TYPESAFE_API_KEY ?? "").trim();
    if (!key) throw new JudgeError("Jev needs TYPESAFE_API_KEY (set it in the server environment)", true);
    this.key = key;
    this.model = (opts.model ?? process.env.TYPESAFE_DEFAULT_MODEL ?? "jev-latest").trim();
    this.url = (opts.baseUrl ?? process.env.TYPESAFE_BASE_URL ?? DEFAULT_BASE_URL).replace(/\/+$/, "") + "/v1/systemone";
    this.timeoutMs = opts.timeoutMs ?? Number(process.env.MCPGUARD_JEV_TIMEOUT ?? 10) * 1000;
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.sleep = opts.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
    this.name = `jev:${this.model}`;
  }

  requestBody(surface: string, content: Content): Record<string, unknown> {
    const state = typeof content === "string"
      ? { content_under_review: content, content_origin: surface }
      : { ...content, content_origin: surface };
    const questions: Record<string, unknown> = {};
    for (const [name, q] of Object.entries(questionsFor(surface))) {
      questions[name] = { type: "noul", instructions: q.instructions, criteria: { true: q.yes, false: q.no } };
    }
    return { model: this.model, state, questions };
  }

  async judge(surface: string, content: Content): Promise<Verdict> {
    const body = JSON.stringify(this.requestBody(surface, content));
    let response: Response | null = null;
    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
      try {
        response = await this.fetchImpl(this.url, {
          method: "POST",
          body,
          headers: {
            Authorization: `Bearer ${this.key}`,
            "Content-Type": "application/json",
            Accept: "application/json",
            "User-Agent": "mcpguard-web",
          },
          signal: AbortSignal.timeout(this.timeoutMs),
        });
      } catch (err) {
        throw new JudgeError(`cannot reach TypeSafe API: ${err instanceof Error ? err.message : String(err)}`);
      }
      if (RETRY_STATUSES.has(response.status) && attempt < MAX_RETRIES) {
        await this.sleep(retryDelayMs(response.headers, attempt));
        continue;
      }
      break;
    }
    const res = response as Response;
    const raw = await res.text();
    if (res.status >= 400) {
      throw new JudgeError(`TypeSafe API returned HTTP ${res.status}: ${raw.slice(0, 200)}`, [400, 401, 402, 403, 404].includes(res.status));
    }
    let data: unknown;
    try {
      data = JSON.parse(raw);
    } catch {
      throw new JudgeError("TypeSafe API returned non-JSON");
    }
    const answers = (data as { answers?: unknown })?.answers;
    if (!answers || typeof answers !== "object") throw new JudgeError("TypeSafe API response has no 'answers'");
    const scores: Record<string, number> = {};
    for (const name of Object.keys(questionsFor(surface))) {
      const value = (answers as Record<string, { noul?: unknown }>)[name]?.noul;
      if (typeof value !== "number" || value < 0 || value > 1) {
        throw new JudgeError(`TypeSafe API answer '${name}' is missing or out of range`);
      }
      scores[name] = value;
    }
    const model = typeof (data as { model?: unknown }).model === "string" ? (data as { model: string }).model : this.model;
    return { scores, judge: `jev:${model}` };
  }
}
