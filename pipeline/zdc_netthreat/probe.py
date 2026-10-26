"""Daily check that the atlas's credentials still answer, run by the watchdog workflow.

The weekly run is the only thing that uses these keys, so a key revoked or expired on a Tuesday
was found the following Monday, when the week failed (CrowdSec disabled the Live Exploit Tracker
key without notice on 2026-10-15; the Cloudflare Radar token had been missing for a week before
the 2026-10-19 run found it). Each probe is one cheap, quota-free request; nothing is printed but
the source, its HTTP status and, for Cloudflare, the token's expiry date. Exit 1 when any key is
refused or Cloudflare's expires within EXPIRY_WARN_DAYS.

    python -m zdc_netthreat.probe
"""

from __future__ import annotations

import datetime as dt
import os
import sys

from .client import Http

EXPIRY_WARN_DAYS = 30


def probe(http: Http, env: dict[str, str], today: dt.date) -> list[dict]:
    out = []

    def add(source, r, note="", ok=True):
        out.append({"source": source, "ok": r is not None and r.ok and ok, "status": None if r is None else r.status,
                    "note": note if r is not None else "key not set"})

    k = env.get("CLOUDFLARE_RADAR_TOKEN")
    r = http.get("https://api.cloudflare.com/client/v4/user/tokens/verify", headers={"Authorization": f"Bearer {k}"}) if k else None
    note, fresh = "", True
    if r is not None and r.ok:
        res = (r.json() or {}).get("result") or {}
        exp = res.get("expires_on")
        if res.get("status") != "active":
            note, fresh = f"token status {res.get('status')}", False
        elif exp:
            days = (dt.date.fromisoformat(exp[:10]) - today).days
            note, fresh = f"expires {exp[:10]} ({days} days)", days >= EXPIRY_WARN_DAYS
    add("cloudflare", r, note, fresh)

    k = env.get("CROWDSEC_CTI_API_KEY")
    add("crowdsec_cti", http.get("https://cti.api.crowdsec.net/v2/info", headers={"x-api-key": k}) if k else None)
    k = env.get("VULNCHECK_API_TOKEN")
    add("vulncheck", http.get("https://api.vulncheck.com/v3/index",
                              headers={"Authorization": f"Bearer {k}", "Accept": "application/json"}) if k else None)
    k = env.get("SHODAN_API_KEY")
    add("shodan", http.get("https://api.shodan.io/api-info", params={"key": k}) if k else None)
    return out


def main() -> int:
    rows = probe(Http(pause=0.5), dict(os.environ), dt.datetime.now(dt.timezone.utc).date())
    for x in rows:
        print(f"{'OK  ' if x['ok'] else 'FAIL'} {x['source']:<13} HTTP {x['status']} {x['note']}")
    return 0 if all(x["ok"] for x in rows) else 1


if __name__ == "__main__":
    sys.exit(main())
