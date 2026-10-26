"""TypeSafe Jev client shared by the breach Jev methods (breach-profile-v1, breach-docjev-v1).

Moved out of profile.py unchanged (2026-10-21, RUBRIC_J1 s8): retries with back-off, out-of-funds detection, an
input-token spend guard, and the pinned-model probe. Never logs the key or a request/response body; an error carries
the HTTP status only. tests/test_breach_profile.py still exercises it through profile's names.
"""

from __future__ import annotations

import collections
import json
import os
import threading
import time
import urllib.error
import urllib.request

MODEL = 'jev-1.13.0'
API = 'https://api.typesafe.ai'
PRICE_PER_MTOK = 0.042          # USD per million input tokens (docs.typesafe.ai/models.md, 2026-10-21)


# =====================================================================================================
# Jev client (mirrors the research client: retries, back-off, out-of-funds). Never logs the key or a body.
# =====================================================================================================
class OutOfFunds(Exception):
    pass


class BudgetExhausted(Exception):
    pass


class JevError(Exception):
    pass


def _urllib_transport(method, url, headers, body, timeout):
    r = urllib.request.Request(url, method=method, headers=headers, data=body)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        txt = e.read().decode(errors='replace')[:2000]
        return e.code, dict(e.headers), {'error': txt}


class Budget:
    """Spend guard on input tokens. `reserve()` refuses a call once the spend so far plus the average call would
    pass max_usd."""

    def __init__(self, max_usd, price_per_mtok=PRICE_PER_MTOK):
        self.max_usd, self.price = float(max_usd), price_per_mtok
        self.input_tokens = self.output_tokens = self.calls = 0
        self._lock = threading.Lock()

    @property
    def spent_usd(self):
        return self.input_tokens * self.price / 1e6

    def reserve(self):
        with self._lock:
            avg = (self.spent_usd / self.calls) if self.calls else 0.0
            if self.spent_usd + avg > self.max_usd or self.spent_usd >= self.max_usd:
                raise BudgetExhausted()

    def charge(self, usage):
        with self._lock:
            self.calls += 1
            self.input_tokens += int((usage or {}).get('input_tokens') or 0)
            self.output_tokens += int((usage or {}).get('output_tokens') or 0)


class Jev:
    def __init__(self, budget, key=None, transport=None, sleep=time.sleep, retries=4, timeout=120,
                 user_agent='zdc-breach-profile/1'):
        self._key = key if key is not None else os.environ.get('TYPESAFE_API_KEY')
        if not self._key:
            raise SystemExit('TYPESAFE_API_KEY is not set')
        self.budget, self.transport, self.sleep, self.retries, self.timeout = budget, transport or _urllib_transport, sleep, retries, timeout
        self.user_agent = user_agent
        self.status = collections.Counter()

    def pin_answers(self):
        """Does the pinned model still answer as itself? TypeSafe's /v1/models lists only aliases (jev-latest,
        jev-preview), so the check is one minimal real question (~300 input tokens, ~0.00002 USD): True when the
        response names MODEL, False when the API refuses the model or answers with another one, None when it cannot
        be reached (a network failure is not evidence the model is gone)."""
        try:
            js = self.ask({'probe': {'text': 'Example Org makes tools.'}},
                          {'probe': {'type': 'noul', 'instructions': 'Does `probe.text` mention tools?'}})
        except OutOfFunds:
            raise
        except JevError as e:
            return False if any(w in str(e).lower() for w in ('model', '404', '400', '422')) else None
        except (BudgetExhausted, urllib.error.URLError, TimeoutError, OSError):
            return None
        return (js or {}).get('model') == MODEL

    def ask(self, state, questions, model=MODEL):
        self.budget.reserve()
        body = json.dumps({'model': model, 'state': state, 'questions': questions}).encode()
        headers = {'Authorization': 'Bearer ' + self._key, 'Content-Type': 'application/json', 'User-Agent': self.user_agent}
        for a in range(self.retries):
            try:
                st, hd, js = self.transport('POST', API + '/v1/systemone', headers, body, self.timeout)
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                self.status['net_' + type(e).__name__] += 1
                self.sleep(2 ** a)
                continue
            self.status[str(st)] += 1
            if st == 200:
                self.budget.charge(js.get('usage'))
                return js
            low = str(js).lower()
            if st in (402, 403) or 'credit' in low or 'balance' in low or 'fund' in low:
                raise OutOfFunds(st)
            if st in (429, 500, 502, 503, 504):
                hd = hd or {}
                self.sleep(float(hd.get('retry-after') or hd.get('Retry-After') or 2 ** a))
                continue
            raise JevError(st)          # the status only: an error body may echo the request
        raise JevError('retries exhausted')
