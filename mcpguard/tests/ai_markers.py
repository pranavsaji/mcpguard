"""A deterministic fake judge shared (by specification) with the TS engine's parity test.

Each question scores 0.95 when its marker word appears in the content, else 0.01.
The TS twin lives in mcpguard-web/lib/ai/ai.test.ts — keep them identical.
"""

from __future__ import annotations

from collections.abc import Mapping

from mcpguard.ai import Verdict
from mcpguard.ai.base import QUESTIONS

MARKERS = {
    "injection": "EVIL", "exfiltration": "STEAL", "concealment": "HIDE", "tool_steering": "STEER",
    "untrusted_input": "UNTRUSTED", "private_data": "PRIVATE", "external_sink": "SINK",
    "code_exec": "EXECUTES", "excessive": "EXCESS", "mismatch": "MISMATCH",
}


class MarkerJudge:
    name = "marker"

    def judge(self, surface: str, content: str | Mapping[str, str]) -> Verdict:
        text = content if isinstance(content, str) else "\n".join(content.values())
        return Verdict({q: 0.95 if MARKERS.get(q, "\x00") in text else 0.01 for q in QUESTIONS[surface]},
                       judge=self.name)
