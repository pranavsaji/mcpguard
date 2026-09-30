/** Construct judges from the server environment (never from request input). */

import { ClaudeJudge } from "./claude";
import { JevJudge } from "./jev";
import { EnsembleJudge, type Judge, JudgeError } from "./judge";

export const AI_CHOICES = ["auto", "jev", "claude", "ensemble"] as const;
export type AIChoice = (typeof AI_CHOICES)[number];

/** Which judges have credentials configured (names only — never values). */
export function availableJudges(): { jev: boolean; claude: boolean } {
  return {
    jev: Boolean(process.env.TYPESAFE_API_KEY?.trim()),
    claude: Boolean(process.env.ANTHROPIC_API_KEY?.trim() || process.env.ANTHROPIC_AUTH_TOKEN?.trim()),
  };
}

/** Same semantics as the Python `build_judge`: `auto` = every configured judge, as an ensemble. */
export function buildJudge(choice: AIChoice): Judge {
  const available = availableJudges();
  switch (choice) {
    case "jev":
      return new JevJudge();
    case "claude":
      return new ClaudeJudge();
    case "ensemble":
      return new EnsembleJudge([new JevJudge(), new ClaudeJudge()]);
    case "auto": {
      const judges: Judge[] = [];
      if (available.jev) judges.push(new JevJudge());
      if (available.claude) judges.push(new ClaudeJudge());
      if (!judges.length) {
        throw new JudgeError("no AI judge configured on the server: set TYPESAFE_API_KEY and/or ANTHROPIC_API_KEY", true);
      }
      return judges.length === 1 ? judges[0] : new EnsembleJudge(judges);
    }
  }
}
