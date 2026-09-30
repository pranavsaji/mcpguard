"""Jev (TypeSafe AI) judge — a "System One" decision model over plain HTTP.

Jev answers typed questions about a piece of state and returns probabilities
instead of text, which is exactly the shape a security gate wants: fast, cheap
(~$0.04 per million input tokens), and calibrated enough to threshold.

Wire format (from TypeSafe's official ``typesafe-sdk-python``)::

    POST {TYPESAFE_BASE_URL or https://api.typesafe.ai}/v1/systemone
    Authorization: Bearer $TYPESAFE_API_KEY
    {"model": "jev-latest", "state": <text | object>,
     "questions": {"<name>": {"type": "noul", "instructions": "...",
                              "criteria": {"true": "...", "false": "..."}}}}
    -> {"model": "jev-1.13.0", "usage": {...},
        "answers": {"<name>": {"type": "noul", "noul": 0.97}}}

Implemented with the standard library so the core (and the Claude Code hook)
stays dependency-free. Retries 408 / 429 / 5xx with ``retry-after`` like the SDK.

Environment: ``TYPESAFE_API_KEY`` (required), ``TYPESAFE_DEFAULT_MODEL``
(default ``jev-latest``), ``TYPESAFE_BASE_URL``, ``MCPGUARD_JEV_TIMEOUT`` (s).
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from typing import Any

from .base import JudgeError, Verdict, questions_for

__all__ = ["JevJudge"]

DEFAULT_BASE_URL = "https://api.typesafe.ai"
DEFAULT_MODEL = "jev-latest"
SYSTEM_ONE_PATH = "/v1/systemone"
RETRY_STATUSES = frozenset({408, 429, 500, 502, 503, 504})
MAX_RETRIES = 2
MAX_RETRY_DELAY = 5.0

Transport = Callable[[str, bytes, dict[str, str], float], tuple[int, dict[str, str], bytes]]


def _urllib_transport(
    url: str, body: bytes, headers: dict[str, str], timeout: float
) -> tuple[int, dict[str, str], bytes]:
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - fixed https URL
            return response.status, dict(response.headers.items()), response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers.items()), exc.read()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise JudgeError(f"cannot reach TypeSafe API: {exc}") from exc


def _retry_delay(headers: Mapping[str, str], attempt: int) -> float:
    lowered = {k.lower(): v for k, v in headers.items()}
    try:
        if "retry-after-ms" in lowered:
            return min(float(lowered["retry-after-ms"]) / 1000.0, MAX_RETRY_DELAY)
        if "retry-after" in lowered:
            return min(float(lowered["retry-after"]), MAX_RETRY_DELAY)
    except ValueError:
        pass
    return float(min(0.5 * (2**attempt), MAX_RETRY_DELAY))


class JevJudge:
    """Ask TypeSafe's Jev the catalog's yes/no questions (one request per piece of content)."""

    def __init__(
        self,
        api_key: str | None = None,
        *,
        model: str | None = None,
        base_url: str | None = None,
        timeout: float | None = None,
        transport: Transport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        key = (api_key or os.environ.get("TYPESAFE_API_KEY") or "").strip()
        if not key:
            raise JudgeError(
                "Jev needs TYPESAFE_API_KEY (set it in the environment or .env)", permanent=True
            )
        self._key = key
        self.model = (model or os.environ.get("TYPESAFE_DEFAULT_MODEL") or DEFAULT_MODEL).strip()
        self._url = (base_url or os.environ.get("TYPESAFE_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")
        self._timeout = timeout or float(os.environ.get("MCPGUARD_JEV_TIMEOUT") or 10.0)
        self._transport = transport or _urllib_transport
        self._sleep = sleep
        self.name = f"jev:{self.model}"

    def request_body(self, surface: str, content: str | Mapping[str, str]) -> dict[str, Any]:
        """The JSON body for one judgement (public for tests and debugging)."""
        state: dict[str, Any] = (
            {"content_under_review": content, "content_origin": surface}
            if isinstance(content, str)
            else {**content, "content_origin": surface}
        )
        return {
            "model": self.model,
            "state": state,
            "questions": {
                name: {
                    "type": "noul",
                    "instructions": q.instructions,
                    "criteria": {"true": q.yes, "false": q.no},
                }
                for name, q in questions_for(surface).items()
            },
        }

    def judge(self, surface: str, content: str | Mapping[str, str]) -> Verdict:
        body = json.dumps(self.request_body(surface, content)).encode("utf-8")
        headers = {
            "Authorization": f"Bearer {self._key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "mcpguard",
        }
        for attempt in range(MAX_RETRIES + 1):
            status, resp_headers, raw = self._transport(
                self._url + SYSTEM_ONE_PATH, body, headers, self._timeout
            )
            if status in RETRY_STATUSES and attempt < MAX_RETRIES:
                self._sleep(_retry_delay(resp_headers, attempt))
                continue
            break
        if status >= 400:
            snippet = raw[:200].decode("utf-8", "replace")
            raise JudgeError(
                f"TypeSafe API returned HTTP {status}: {snippet}",
                permanent=status in (400, 401, 402, 403, 404),
            )
        return self._parse(raw, surface)

    def _parse(self, raw: bytes, surface: str) -> Verdict:
        try:
            data = json.loads(raw)
        except ValueError as exc:
            raise JudgeError("TypeSafe API returned non-JSON") from exc
        answers = data.get("answers") if isinstance(data, dict) else None
        if not isinstance(answers, dict):
            raise JudgeError("TypeSafe API response has no 'answers'")
        scores: dict[str, float] = {}
        for name in questions_for(surface):
            answer = answers.get(name)
            value = answer.get("noul") if isinstance(answer, dict) else None
            if not isinstance(value, (int, float)) or not 0.0 <= float(value) <= 1.0:
                raise JudgeError(f"TypeSafe API answer {name!r} is missing or out of range")
            scores[name] = float(value)
        model = data.get("model") if isinstance(data.get("model"), str) else self.model
        return Verdict(scores=scores, judge=f"jev:{model}")
