"""Currency conversion for ransom amounts, at the date of the claim, never today.

Fiat: the European Central Bank's daily reference rates (free, no key), via EUR. USD is the
identity. Crypto amounts are NOT converted: a Bitcoin demand converted at a guessed date is a
number nobody can check, so it stays in its original currency and amount_usd stays null.
"""

from __future__ import annotations

import io
import zipfile
from datetime import date, timedelta
from decimal import Decimal

from . import http

ECB_HIST = "https://www.ecb.europa.eu/stats/eurofxref/eurofxref-hist.zip"


class Fx:
    def __init__(self, getter=http.get):
        self._get = getter
        self._rates: dict[date, dict[str, Decimal]] | None = None
        self.error: str | None = None

    def _load(self):
        if self._rates is not None:
            return
        self._rates = {}
        f = self._get(ECB_HIST, timeout=60)
        if not f.ok:
            self.error = f.error or f"HTTP {f.status}"
            return
        with zipfile.ZipFile(io.BytesIO(f.body)) as z:
            text = z.read(z.namelist()[0]).decode()
        lines = text.strip().splitlines()
        header = [h.strip() for h in lines[0].split(",")]
        for line in lines[1:]:
            parts = [p.strip() for p in line.split(",")]
            try:
                d = date.fromisoformat(parts[0])
            except ValueError:
                continue
            row = {}
            for cur, val in zip(header[1:], parts[1:]):
                if cur and val and val != "N/A":
                    row[cur] = Decimal(val)
            self._rates[d] = row

    def usd_rate(self, currency: str, on: date) -> tuple[Decimal, date, str] | None:
        """USD per one unit of `currency` on the last ECB business day at or before `on`."""
        if currency == "USD":
            return Decimal(1), on, "identity"
        if currency in ("BTC", "XMR", "ETH", "USDT"):
            return None
        self._load()
        for back in range(0, 10):
            d = on - timedelta(days=back)
            row = (self._rates or {}).get(d)
            if not row or "USD" not in row:
                continue
            usd_per_eur = row["USD"]
            if currency == "EUR":
                return usd_per_eur, d, "ECB reference rate"
            if currency in row and row[currency] != 0:
                return usd_per_eur / row[currency], d, "ECB reference rate"
            return None
        return None
