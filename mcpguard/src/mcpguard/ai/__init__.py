"""Optional AI judge layer (Jev and/or Claude). See :mod:`mcpguard.ai.base` for the design.

Nothing here runs unless a scan is given an :class:`AIConfig` (CLI: ``--ai``).
The deterministic scanner is unchanged and stays dependency-free.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field

from .base import (
    QUESTIONS,
    CachingJudge,
    EnsembleJudge,
    Judge,
    JudgeError,
    Verdict,
    find_dotenv,
    load_dotenv,
)

__all__ = [
    "AI_CHOICES",
    "QUESTIONS",
    "AIConfig",
    "CachingJudge",
    "EnsembleJudge",
    "Judge",
    "JudgeError",
    "Verdict",
    "build_judge",
    "find_dotenv",
    "load_dotenv",
]

AI_CHOICES = ("auto", "jev", "claude", "ensemble")

# Jev's state limit is ~32k tokens; ~40k characters per chunk stays well under it.
CHUNK_CHARS = 40_000
MAX_CHUNKS = 12


def build_judge(choice: str, *, cache_path: str | None = None) -> Judge:
    """Construct the judge named by ``choice`` from environment credentials.

    ``auto`` picks the best available: an ensemble of Jev + Claude when both are
    configured, otherwise whichever one is. ``ensemble`` requires both.
    """
    from .claude import ClaudeJudge
    from .jev import JevJudge

    def claude_configured() -> bool:
        return bool(os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"))

    judge: Judge
    if choice == "jev":
        judge = JevJudge()
    elif choice == "claude":
        judge = ClaudeJudge()
    elif choice == "ensemble":
        judge = EnsembleJudge([JevJudge(), ClaudeJudge()])
    elif choice == "auto":
        available: list[Judge] = []
        if os.environ.get("TYPESAFE_API_KEY"):
            available.append(JevJudge())
        if claude_configured():
            try:
                available.append(ClaudeJudge())
            except JudgeError:
                pass  # SDK not installed; Jev alone is fine
        if not available:
            raise JudgeError(
                "no AI judge configured: set TYPESAFE_API_KEY (Jev) and/or ANTHROPIC_API_KEY "
                "(Claude, needs `pip install 'mcpguard[claude]'`), e.g. in .env"
            )
        judge = available[0] if len(available) == 1 else EnsembleJudge(available)
    else:
        raise JudgeError(f"unknown --ai choice {choice!r}; expected one of {', '.join(AI_CHOICES)}")
    return CachingJudge(judge, cache_path)


@dataclass
class AIConfig:
    """How a scan uses its judge.

    ``threshold``: probability at/above which a judge answer becomes a finding.
    ``role_threshold``: probability at/above which a tool is *classified* into a
    toxic-flow role. Lower than ``threshold`` because a role is a description of
    what a tool does, not an alarm; the FLOW01 finding it feeds is still gated.
    ``fail_closed``: a judge failure is a HIGH finding (the gate fails) instead of INFO.
    ``triage``: in the output guard only, let a confident "benign" verdict downgrade a
    keyword-only injection hit to LOW. Off by default — see :mod:`mcpguard.guard`.
    """

    judge: Judge
    threshold: float = 0.8
    role_threshold: float = 0.6
    fail_closed: bool = False
    triage: bool = False
    errors: list[str] = field(default_factory=list)
    _dead: bool = field(default=False, repr=False)

    def ask(self, surface: str, content: str | Mapping[str, str]) -> Verdict | None:
        """Judge ``content``, chunking long text; ``None`` (and a recorded error) on failure.

        After a *permanent* failure (bad key, no credits) the judge is not called
        again this run: a 300-tool config shouldn't make 300 doomed requests.
        """
        if self._dead:
            return None
        try:
            if isinstance(content, str) and len(content) > CHUNK_CHARS:
                return self._ask_chunked(surface, content)
            return self.judge.judge(surface, content)
        except JudgeError as exc:
            self.errors.append(str(exc))
            self._dead = exc.permanent
            return None
        finally:
            self._collect_degradation()

    def _collect_degradation(self) -> None:
        """Surface ensemble members that dropped out, once each."""
        inner = getattr(self.judge, "inner", self.judge)
        for failure in getattr(inner, "failures", []):
            note = f"degraded: {failure}"
            if note not in self.errors:
                self.errors.append(note)

    def _ask_chunked(self, surface: str, text: str) -> Verdict:
        """Judge overlapping chunks and keep each question's maximum.

        Chunks overlap by 2k characters so a payload can't hide on a boundary.
        Text beyond ``MAX_CHUNKS`` chunks is not judged; that is reported, never silent.
        """
        step = CHUNK_CHARS - 2_000
        starts = list(range(0, len(text), step))
        scores: dict[str, float] = {}
        judged = starts[:MAX_CHUNKS]
        for start in judged:
            verdict = self.judge.judge(surface, text[start : start + CHUNK_CHARS])
            for name, value in verdict.scores.items():
                scores[name] = max(scores.get(name, 0.0), value)
        if len(starts) > MAX_CHUNKS:
            self.errors.append(
                f"text too long for the AI judge: judged the first {MAX_CHUNKS} of "
                f"{len(starts)} chunks"
            )
        return Verdict(scores=scores, judge=self.judge.name)
