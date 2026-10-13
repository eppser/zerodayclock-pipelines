"""OpenRouter, used as a cheap reader of free text, under a hard budget.

WHAT THE MODEL IS FOR, AND WHAT IT IS NOT. A model turns an article into candidate facts,
each with a verbatim quote. It decides nothing: grounding.check accepts or rejects every value
against the document, and reconciliation (not the model) decides which fact an incident shows.

REPRODUCIBLE AS FAR AS A MODEL CAN BE. The model id and provider are pinned (OpenRouter's
price sort was measured routing to a provider at 6x the headline price), temperature is 0,
reasoning is off, and every call stores model, provider, prompt hash, token counts and cost.
An extraction is cached on (document sha256, prompt hash, model); changing either produces a
new extraction row, never an overwrite.

THE BUDGET IS ENFORCED BEFORE THE CALL, FROM THE DATABASE. The owner's cap is 50 EUR a month.
The guard sums what breach_core.llm_calls says was spent this calendar month and today and
refuses to call once either cap would be crossed. Measured 2026-10-14: the expected workload
costs about 1-2 EUR a month, so hitting the cap means something is looping, and stopping is
the right response.

PROMPT INJECTION. Articles quote attackers. The document travels as data in the user message,
the system prompt says to ignore instructions in it, and the output is JSON that is validated
field by field. A successful injection can at worst produce a value, and a value without a
matching quote in the document is rejected by the gate.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"
MODEL = os.environ.get("BREACH_LLM_MODEL", "deepseek/deepseek-v4-flash")
# Providers measured at the headline price on 2026-10-14; fallbacks disabled so a request is
# never silently served by a dearer provider.
PROVIDERS = [p for p in os.environ.get("BREACH_LLM_PROVIDERS", "deepinfra,streamlake").split(",") if p]
MONTHLY_CAP_USD = float(os.environ.get("BREACH_LLM_MONTHLY_CAP_USD", "50"))  # ~46 EUR
DAILY_CAP_USD = float(os.environ.get("BREACH_LLM_DAILY_CAP_USD", "1.6"))

_KEY = re.compile(r"sk-or-[A-Za-z0-9-]{8,}")


def redact(text: str | None) -> str | None:
    return None if text is None else _KEY.sub("sk-or-[REDACTED]", text)


def prompt_hash(system: str, template: str) -> str:
    return hashlib.sha256((MODEL + "\n" + system + "\n" + template).encode()).hexdigest()[:16]


class BudgetExceeded(RuntimeError):
    pass


@dataclass
class LlmResult:
    ok: bool
    data: dict | None
    model: str
    provider: str | None
    input_tokens: int
    output_tokens: int
    cost_usd: float
    latency_ms: int
    error: str | None


class _RefuseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # the key never follows a redirect
        return None


_OPENER = urllib.request.build_opener(_RefuseRedirect)


class OpenRouter:
    def __init__(self, key: str, spent_month_usd: float, spent_today_usd: float,
                 *, timeout: int = 90, opener=None, sleep=time.sleep):
        if not key or not key.startswith("sk-or-"):
            raise ValueError("OPENROUTER_API_KEY is missing or malformed")
        self._key = key
        self.spent_month = spent_month_usd
        self.spent_today = spent_today_usd
        self.timeout = timeout
        self._open = (opener or _OPENER).open
        self._sleep = sleep

    def _guard(self, reserve_usd: float = 0.01) -> None:
        if self.spent_month + reserve_usd > MONTHLY_CAP_USD:
            raise BudgetExceeded(f"monthly LLM cap {MONTHLY_CAP_USD} USD reached ({self.spent_month:.4f})")
        if self.spent_today + reserve_usd > DAILY_CAP_USD:
            raise BudgetExceeded(f"daily LLM cap {DAILY_CAP_USD} USD reached ({self.spent_today:.4f})")

    def json(self, system: str, user: str, *, max_tokens: int = 3000) -> LlmResult:
        self._guard()
        body = {
            "model": MODEL,
            "temperature": 0,
            "max_tokens": max_tokens,
            "response_format": {"type": "json_object"},
            "reasoning": {"enabled": False},
            "usage": {"include": True},
            "provider": {"order": PROVIDERS, "allow_fallbacks": False,
                         "data_collection": "deny"},
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}],
        }
        req = urllib.request.Request(ENDPOINT, data=json.dumps(body).encode(), method="POST", headers={
            "Authorization": f"Bearer {self._key}", "Content-Type": "application/json",
            "HTTP-Referer": "https://zerodayclock.com", "X-Title": "ZeroDayClock breach pipeline"})
        t0 = time.monotonic()
        last_err = None
        for attempt in range(3):
            try:
                with self._open(req, timeout=self.timeout) as r:
                    payload = json.loads(r.read().decode())
                break
            except urllib.error.HTTPError as e:
                last_err = f"HTTP {e.code}: {redact(e.read()[:300].decode('utf-8', 'replace'))}"
                if e.code in (429, 500, 502, 503, 504) and attempt < 2:
                    self._sleep(5 * (attempt + 1))
                    continue
                return self._fail(last_err, t0)
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
                last_err = redact(f"{type(e).__name__}: {e}")
                if attempt < 2:
                    self._sleep(5 * (attempt + 1))
                    continue
                return self._fail(last_err, t0)
        else:
            return self._fail(last_err or "no response", t0)
        usage = payload.get("usage") or {}
        cost = float(usage.get("cost") or 0.0)
        self.spent_month += cost
        self.spent_today += cost
        latency = int((time.monotonic() - t0) * 1000)
        try:
            content = payload["choices"][0]["message"]["content"]
            data = json.loads(content)
            if not isinstance(data, dict):
                raise ValueError("not an object")
            err = None
        except (KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError) as e:
            data, err = None, f"unparseable model output: {type(e).__name__}"
        return LlmResult(err is None, data, payload.get("model", MODEL), payload.get("provider"),
                         int(usage.get("prompt_tokens") or 0), int(usage.get("completion_tokens") or 0),
                         cost, latency, err)

    def _fail(self, err: str, t0: float) -> LlmResult:
        return LlmResult(False, None, MODEL, None, 0, 0, 0.0, int((time.monotonic() - t0) * 1000), err)
