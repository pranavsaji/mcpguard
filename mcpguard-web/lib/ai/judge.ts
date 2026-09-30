/**
 * AI judge layer for the web dashboard (server-side only — never import from a
 * client component: judges hold API keys). A TypeScript port of the Python
 * engine's `mcpguard/ai/base.py` + `__init__.py`: same questions (shared
 * `questions.json`), same additive-only / fail-visible rules, same ensemble
 * circuit breaker and chunking.
 */

import catalog from "./questions.json";

export interface Question {
  instructions: string;
  yes: string;
  no: string;
}

export type Surface = keyof typeof catalog.surfaces;
export type Content = string | Record<string, string>;

export const QUESTION_VERSION: string = catalog.version;
export const QUESTIONS: Record<string, Record<string, Question>> = catalog.surfaces;

export function questionsFor(surface: string): Record<string, Question> {
  const questions = QUESTIONS[surface];
  if (!questions) throw new JudgeError(`unknown judge surface '${surface}'`);
  return questions;
}

/** The judge could not answer. `permanent` failures (auth, billing) aren't retried this run. */
export class JudgeError extends Error {
  constructor(
    message: string,
    readonly permanent = false,
  ) {
    super(message);
    this.name = "JudgeError";
  }
}

export interface Verdict {
  /** question name -> probability that the answer is yes (0..1) */
  scores: Record<string, number>;
  judge: string;
}

export interface Judge {
  readonly name: string;
  judge(surface: string, content: Content): Promise<Verdict>;
}

/**
 * Ask several judges; per question take the max (default) or mean. A judge that
 * fails permanently is dropped for the rest of the run and recorded in `failures`.
 */
export class EnsembleJudge implements Judge {
  readonly name: string;
  readonly failures: string[] = [];
  private readonly disabled = new Set<string>();

  constructor(
    private readonly judges: Judge[],
    private readonly mode: "max" | "mean" = "max",
  ) {
    if (!judges.length) throw new JudgeError("ensemble needs at least one judge");
    this.name = `ensemble[${mode}](${judges.map((j) => j.name).join(", ")})`;
  }

  async judge(surface: string, content: Content): Promise<Verdict> {
    const live = this.judges.filter((j) => !this.disabled.has(j.name));
    const settled = await Promise.allSettled(live.map((j) => j.judge(surface, content)));
    const answers: Array<Record<string, number>> = [];
    const errors: string[] = [];
    settled.forEach((result, i) => {
      if (result.status === "fulfilled") {
        answers.push(result.value.scores);
        return;
      }
      const err = result.reason;
      const message = `${live[i].name}: ${err instanceof Error ? err.message : String(err)}`;
      errors.push(message);
      if (err instanceof JudgeError && err.permanent) {
        this.disabled.add(live[i].name);
        this.failures.push(`${message} (disabled for this run)`);
      }
    });
    if (!answers.length) {
      throw new JudgeError((errors.length ? errors : this.failures).join("; "), this.disabled.size === this.judges.length);
    }
    const scores: Record<string, number> = {};
    for (const q of Object.keys(questionsFor(surface))) {
      const values = answers.map((a) => a[q]).filter((v): v is number => typeof v === "number");
      if (values.length) {
        scores[q] = this.mode === "max" ? Math.max(...values) : values.reduce((a, b) => a + b, 0) / values.length;
      }
    }
    return { scores, judge: this.name };
  }
}

export const CHUNK_CHARS = 40_000;
export const MAX_CHUNKS = 12;

/** How a scan uses its judge (mirrors Python `AIConfig`). */
export class AIConfig {
  readonly errors: string[] = [];
  private dead = false;

  constructor(
    readonly judge: Judge,
    readonly threshold = 0.8,
    readonly roleThreshold = 0.6,
    readonly failClosed = false,
  ) {}

  /** Judge `content` (chunking long text); `null` and a recorded error on failure. */
  async ask(surface: string, content: Content): Promise<Verdict | null> {
    if (this.dead) return null; // after a permanent failure, stop calling this run
    try {
      if (typeof content === "string" && content.length > CHUNK_CHARS) return await this.askChunked(surface, content);
      return await this.judge.judge(surface, content);
    } catch (err) {
      this.errors.push(err instanceof Error ? err.message : String(err));
      this.dead = err instanceof JudgeError && err.permanent;
      return null;
    } finally {
      for (const failure of (this.judge as Partial<EnsembleJudge>).failures ?? []) {
        const note = `degraded: ${failure}`;
        if (!this.errors.includes(note)) this.errors.push(note);
      }
    }
  }

  private async askChunked(surface: string, text: string): Promise<Verdict> {
    const step = CHUNK_CHARS - 2_000;
    const starts: number[] = [];
    for (let i = 0; i < text.length; i += step) starts.push(i);
    const scores: Record<string, number> = {};
    for (const start of starts.slice(0, MAX_CHUNKS)) {
      const verdict = await this.judge.judge(surface, text.slice(start, start + CHUNK_CHARS));
      for (const [q, v] of Object.entries(verdict.scores)) scores[q] = Math.max(scores[q] ?? 0, v);
    }
    if (starts.length > MAX_CHUNKS) {
      this.errors.push(`text too long for the AI judge: judged the first ${MAX_CHUNKS} of ${starts.length} chunks`);
    }
    return { scores, judge: this.judge.name };
  }
}
