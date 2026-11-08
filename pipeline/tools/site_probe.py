"""Probe the public site from outside, daily, and fail loudly when a security control regresses.

The security review of 2026-10-26 found controls that were true on the day and had no check that
would say so the day after: admin paths behind a password, CSRF refusals, the header set, HTTP
answering with a redirect to HTTPS, old Pages deployments reachable on their own hostnames. CI
asserts the code; this asserts the live site, from a network the site does not control.

Two modes, two jobs, two levels of trust:

  python -m tools.site_probe              HTTP only. Needs no secret. Optional: CLOUDFLARE_API_TOKEN and
                                          CLOUDFLARE_ACCOUNT_ID (Pages:Read) to walk every deployment of the
                                          two Pages projects; SITE_PROBE_HEADER to pass the WAF's scraper rule.
  python -m tools.site_probe --exposure   Database only. DATABASE_URL. Compares what the anon role can read,
                                          write and execute in `public` with tools/anon_allowlist.txt.
  --json                                  machine-readable report on stdout (after the human one on stderr).

Severities: FAIL fails the run; WARN and INFO are recorded in the report and the step summary.
Every check is a pure function over fetched facts, so the tests cover the judgement without the network.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path

FAIL, WARN, INFO = "FAIL", "WARN", "INFO"

PRODUCTION_HOSTS = ("zerodayclock.com", "www.zerodayclock.com")
#: Pages hostnames that must answer like production for the admin paths (no Access app covers the bare aliases).
PAGES_ALIASES = ("zerodayclock-v2.pages.dev", "zerodayclock-v2-staging.pages.dev")
PAGES_PROJECTS = ("zerodayclock-v2", "zerodayclock-v2-staging")
#: Not /roadmap: it refuses self-declared automated clients, and this probe declares itself (see eval_roadmap_bot).
PAGES = ("/", "/explorer", "/breaches", "/internet", "/about", "/signatories", "/collapse")
HEADER_PATHS = ("/", "/api/health", "/favicon.ico")
ADMIN_PATHS = ("/admin", "/admin.rsc", "/ADMIN", "/api/admin/logs", "/api/Admin/logs")
#: A POST the browser marks cross-site must be refused; both forms the guard reads.
CSRF_CASES = (("sec-fetch-site", "cross-site"), ("origin", "https://evil.example"))
HSTS_MIN_AGE = 31536000
TLS_WARN_DAYS, TLS_FAIL_DAYS = 21, 7
#: Above this many deployments the project is accumulating build-time secrets on reachable hostnames.
DEPLOYMENTS_WARN = 30
DEPLOYMENTS_PROBE_CAP = 120
TIMEOUT = 30
USER_AGENT = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/130.0 Safari/537.36 zdc-site-probe")

ALLOWLIST = Path(__file__).with_name("anon_allowlist.txt")


@dataclass
class Result:
    name: str
    severity: str
    passed: bool
    summary: str
    detail: dict = field(default_factory=dict)


@dataclass
class Response:
    status: int
    headers: dict          # lower-cased names
    body: bytes
    url: str
    seconds: float


# ---- fetching -------------------------------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):   # noqa: D401 - stdlib signature
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def fetch(url: str, method: str = "GET", headers: dict | None = None, body: bytes | None = None,
          timeout: int = TIMEOUT) -> Response:
    """One request, redirects NOT followed (a redirect is a fact to judge, not a step to take)."""
    h = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if os.environ.get("SITE_PROBE_HEADER"):
        h["X-ZDC-Probe"] = os.environ["SITE_PROBE_HEADER"]
    h.update(headers or {})
    req = urllib.request.Request(url, data=body, method=method, headers=h)
    t0 = time.monotonic()
    try:
        with _OPENER.open(req, timeout=timeout) as r:
            return Response(r.status, {k.lower(): v for k, v in r.headers.items()}, r.read(65536), url,
                            time.monotonic() - t0)
    except urllib.error.HTTPError as e:
        return Response(e.code, {k.lower(): v for k, v in e.headers.items()}, e.read(65536) if e.fp else b"",
                        url, time.monotonic() - t0)
    except (urllib.error.URLError, socket.timeout, OSError) as e:
        return Response(0, {}, str(e).encode(), url, time.monotonic() - t0)


def tls_not_after(host: str, port: int = 443, timeout: int = TIMEOUT) -> float | None:
    """Certificate expiry as epoch seconds, or None when the handshake fails."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
    except (OSError, ssl.SSLError):
        return None
    return ssl.cert_time_to_seconds(cert["notAfter"]) if cert and cert.get("notAfter") else None


# ---- judgements (pure) ----------------------------------------------------------------------------

def eval_https_redirect(host: str, status: int, location: str | None) -> Result:
    want = f"https://{host}/"
    ok = status in (301, 308) and (location or "").startswith(want)
    how = f"{status} -> {location or '(no Location)'}"
    if status in (302, 307) and (location or "").startswith(want):
        return Result(f"http_redirect:{host}", WARN, False, f"http://{host}/ redirects, but temporarily ({how})",
                      {"status": status, "location": location})
    return Result(f"http_redirect:{host}", FAIL, ok,
                  f"http://{host}/ -> {want} ({status})" if ok else f"http://{host}/ does not redirect to HTTPS ({how})",
                  {"status": status, "location": location})


def eval_security_headers(label: str, headers: dict, production: bool) -> Result:
    """The header set the middleware and `_headers` promise; `production` adds: no noindex leaked from staging."""
    h = {k.lower(): v for k, v in headers.items()}
    problems: list[str] = []
    hsts = h.get("strict-transport-security", "")
    age = 0
    for part in hsts.split(";"):
        part = part.strip().lower()
        if part.startswith("max-age="):
            try:
                age = int(part.split("=", 1)[1])
            except ValueError:
                age = 0
    if age < HSTS_MIN_AGE:
        problems.append(f"HSTS max-age {age} < {HSTS_MIN_AGE}" if hsts else "no Strict-Transport-Security")
    csp = h.get("content-security-policy", "")
    if not csp:
        problems.append("no Content-Security-Policy")
    else:
        for d in ("frame-ancestors 'none'", "object-src 'none'", "base-uri 'self'"):
            if d not in csp:
                problems.append(f"CSP lacks {d}")
    if h.get("x-frame-options", "").upper() != "DENY":
        problems.append("X-Frame-Options is not DENY")
    if h.get("x-content-type-options", "").lower() != "nosniff":
        problems.append("X-Content-Type-Options is not nosniff")
    for name in ("referrer-policy", "permissions-policy"):
        if not h.get(name):
            problems.append(f"no {name}")
    if h.get("cross-origin-opener-policy", "").lower() != "same-origin":
        problems.append("COOP is not same-origin")
    if "x-powered-by" in h:
        problems.append("X-Powered-By is exposed")
    if production and "noindex" in h.get("x-robots-tag", "").lower():
        problems.append("production answers with X-Robots-Tag noindex (a staging build?)")
    return Result(f"headers:{label}", FAIL, not problems,
                  "all security headers present" if not problems else "; ".join(problems),
                  {"problems": problems})


def eval_admin_path(label: str, status: int, headers: dict) -> Result:
    """401 with a Basic challenge, or a redirect into Cloudflare Access, is a closed door. Anything else is not."""
    h = {k.lower(): v for k, v in headers.items()}
    if status == 401 and h.get("www-authenticate", "").lower().startswith("basic"):
        return Result(f"admin:{label}", FAIL, True, "401 Basic challenge", {"status": status})
    loc = h.get("location", "")
    if status in (302, 303, 307) and ".cloudflareaccess.com/" in loc:
        return Result(f"admin:{label}", FAIL, True, "redirected to Cloudflare Access", {"status": status})
    if status == 0:
        return Result(f"admin:{label}", WARN, False, "unreachable", {"status": status})
    return Result(f"admin:{label}", FAIL, False, f"admin path answered {status} without a challenge",
                  {"status": status, "location": loc})


def eval_roadmap_bot(status: int) -> Result:
    """The roadmap refuses self-declared automated clients with 403; this probe's User-Agent is one."""
    return Result("roadmap_bot_refusal", FAIL, status == 403,
                  "roadmap refuses an automated client (403)" if status == 403
                  else f"roadmap answered {status} to an automated client, not 403", {"status": status})


def eval_csrf(label: str, status: int) -> Result:
    return Result(f"csrf:{label}", FAIL, status == 403,
                  "cross-site POST refused (403)" if status == 403 else f"cross-site POST answered {status}, not 403",
                  {"status": status})


def eval_tls(host: str, not_after: float | None, now: float) -> Result:
    if not_after is None:
        return Result(f"tls:{host}", FAIL, False, "TLS handshake failed or no certificate", {})
    days = (not_after - now) / 86400
    sev = FAIL if days < TLS_FAIL_DAYS else WARN if days < TLS_WARN_DAYS else INFO
    return Result(f"tls:{host}", sev, days >= TLS_WARN_DAYS, f"certificate valid for {days:.0f} more days",
                  {"days": round(days, 1)})


def eval_pages(host: str, results: list[tuple[str, int, float]]) -> Result:
    bad = [(p, s) for p, s, _ in results if s != 200]
    slowest = max(results, key=lambda r: r[2]) if results else ("", 0, 0.0)
    detail = {"status": {p: s for p, s, _ in results}, "seconds": {p: round(t, 2) for p, _, t in results}}
    if bad:
        return Result(f"pages:{host}", FAIL, False, "not 200: " + ", ".join(f"{p} ({s})" for p, s in bad), detail)
    return Result(f"pages:{host}", FAIL, True,
                  f"{len(results)} pages answer 200; slowest {slowest[0]} {slowest[2]:.1f}s", detail)


def eval_health(status: int, body: bytes) -> Result:
    """Reachable and well-formed is the bar; staleness is the watchdog's verdict, recorded here as information."""
    try:
        doc = json.loads(body.decode("utf-8", "replace"))
    except ValueError:
        doc = None
    if status not in (200, 503) or not isinstance(doc, dict):
        return Result("health", FAIL, False, f"/api/health answered {status} without a JSON body", {"status": status})
    stale = doc.get("stalePipelines") or []
    return Result("health", INFO, True,
                  f"/api/health {status}; stale: {', '.join(stale) if stale else 'none'}",
                  {"status": status, "stale": stale})


def eval_deployments(project: str, deployments: list[dict], admin: dict[str, Result]) -> list[Result]:
    """One result for the count, one for the doors. `admin` maps deployment url -> its admin judgement."""
    out = [Result(f"deployments:{project}", WARN, len(deployments) <= DEPLOYMENTS_WARN,
                  f"{len(deployments)} deployments kept (each keeps its build-time secrets on its own hostname)",
                  {"count": len(deployments),
                   "oldest": min((d.get("created_on", "") for d in deployments), default=None)})]
    open_doors = [u for u, r in admin.items() if not r.passed and r.severity == FAIL]
    out.append(Result(f"deployment_admin:{project}", FAIL, not open_doors,
                      f"{len(admin)} deployment hostnames probed, all closed" if not open_doors
                      else f"{len(open_doors)} deployment hostname(s) serve /admin without a challenge",
                      {"open": open_doors[:20], "probed": len(admin)}))
    return out


def eval_exposure(readable: set[str], writable: set[str], executable: set[str], allowlist: set[str]) -> list[Result]:
    """anon may SELECT exactly the allowlist, write nothing, and execute nothing (0197) unless `rpc:name` is listed."""
    allowed_rel = {a for a in allowlist if not a.startswith("rpc:")}
    allowed_fn = {a[4:] for a in allowlist if a.startswith("rpc:")}
    unexpected = sorted(readable - allowed_rel)
    gone = sorted(allowed_rel - readable)
    out = [Result("anon_readable", FAIL, not unexpected,
                  f"anon reads {len(readable)} relations, all allowlisted" if not unexpected
                  else f"anon can read {len(unexpected)} relation(s) not in the allowlist: {', '.join(unexpected[:12])}",
                  {"unexpected": unexpected, "count": len(readable)})]
    if gone:
        out.append(Result("anon_allowlist_stale", INFO, True,
                          f"{len(gone)} allowlisted relation(s) no longer readable (tidy the list): {', '.join(gone[:12])}",
                          {"gone": gone}))
    out.append(Result("anon_writable", FAIL, not writable,
                      "anon holds no INSERT/UPDATE/DELETE in public" if not writable
                      else f"anon can write {len(writable)} relation(s): {', '.join(sorted(writable)[:12])}",
                      {"writable": sorted(writable)}))
    bad_fn = sorted(executable - allowed_fn)
    out.append(Result("anon_executable", FAIL, not bad_fn,
                      "anon can execute no function in public" if not bad_fn
                      else f"anon can execute {len(bad_fn)} function(s) in public: {', '.join(bad_fn[:12])}",
                      {"executable": bad_fn}))
    return out


# ---- orchestration --------------------------------------------------------------------------------

def http_checks(get=fetch, tls=tls_not_after, now=None) -> list[Result]:
    now = time.time() if now is None else now
    out: list[Result] = []
    for host in PRODUCTION_HOSTS:
        r = get(f"http://{host}/")
        out.append(eval_https_redirect(host, r.status, r.headers.get("location")))
        out.append(eval_tls(host, tls(host), now))
    apex = f"https://{PRODUCTION_HOSTS[0]}"
    for path in HEADER_PATHS:
        r = get(apex + path)
        out.append(eval_security_headers(path, r.headers, production=True))
        if path == "/api/health":
            out.append(eval_health(r.status, r.body))
    out.append(eval_pages(PRODUCTION_HOSTS[0], [(p, (r := get(apex + p)).status, r.seconds) for p in PAGES]))
    out.append(eval_roadmap_bot(get(apex + "/roadmap").status))
    for base in (apex,) + tuple(f"https://{a}" for a in PAGES_ALIASES):
        for path in ADMIN_PATHS:
            r = get(base + path)
            out.append(eval_admin_path(f"{urllib.parse.urlsplit(base).hostname}{path}", r.status, r.headers))
    for name, value in CSRF_CASES:
        r = get(apex + "/api/chart-vote", method="POST", body=b"{}",
                headers={"Content-Type": "application/json", name: value})
        out.append(eval_csrf(f"{name}={value}", r.status))
    return out


def list_deployments(get, token: str, account: str, project: str) -> list[dict]:
    out: list[dict] = []
    page = 1
    while True:
        url = (f"https://api.cloudflare.com/client/v4/accounts/{account}/pages/projects/{project}/deployments"
               f"?per_page=25&page={page}")
        r = get(url, headers={"Authorization": f"Bearer {token}"})
        if r.status != 200:
            raise RuntimeError(f"Cloudflare API {r.status} listing {project} deployments")
        batch = json.loads(r.body.decode("utf-8", "replace")).get("result", [])
        out.extend(batch)
        if len(batch) < 25 or page >= 40:
            return out
        page += 1


def deployment_checks(get=fetch) -> list[Result]:
    token, account = os.environ.get("CLOUDFLARE_API_TOKEN"), os.environ.get("CLOUDFLARE_ACCOUNT_ID")
    if not token or not account:
        return [Result("deployments", WARN, False,
                       "CLOUDFLARE_API_TOKEN / CLOUDFLARE_ACCOUNT_ID not set: old deployments not probed", {})]
    out: list[Result] = []
    for project in PAGES_PROJECTS:
        try:
            deps = list_deployments(get, token, account, project)
        except (RuntimeError, ValueError) as e:
            out.append(Result(f"deployments:{project}", FAIL, False, str(e), {}))
            continue
        admin: dict[str, Result] = {}
        for d in sorted(deps, key=lambda d: d.get("created_on", ""))[:DEPLOYMENTS_PROBE_CAP]:
            url = d.get("url")
            if not url:
                continue
            r = get(url.rstrip("/") + "/admin")
            admin[url] = eval_admin_path(url, r.status, r.headers)
        out.extend(eval_deployments(project, deps, admin))
    return out


def read_allowlist(path: Path = ALLOWLIST) -> set[str]:
    return {line.split("#", 1)[0].strip() for line in path.read_text().splitlines()
            if line.split("#", 1)[0].strip()}


def exposure_checks(conn, allowlist: set[str]) -> list[Result]:
    with conn.cursor() as cur:
        cur.execute("""select c.relname,
                              has_table_privilege('anon', c.oid, 'insert')
                              or has_table_privilege('anon', c.oid, 'update')
                              or has_table_privilege('anon', c.oid, 'delete')
                         from pg_class c join pg_namespace n on n.oid = c.relnamespace
                        where n.nspname = 'public' and c.relkind in ('r', 'v', 'm', 'p', 'f')
                          and has_table_privilege('anon', c.oid, 'select')""")
        rows = cur.fetchall()
        cur.execute("""select p.proname
                         from pg_proc p join pg_namespace n on n.oid = p.pronamespace
                        where n.nspname = 'public' and has_function_privilege('anon', p.oid, 'execute')""")
        fns = {r[0] for r in cur.fetchall()}
    return eval_exposure({r[0] for r in rows}, {r[0] for r in rows if r[1]}, fns, allowlist)


# ---- reporting ------------------------------------------------------------------------------------

def render(results: list[Result]) -> str:
    lines = []
    for r in results:
        tag = "PASS" if r.passed else r.severity
        lines.append(f"[{tag:4}] {r.severity.lower():4} {r.name}: {r.summary}")
    failed = [r for r in results if not r.passed and r.severity == FAIL]
    lines.append(f"RESULT: {'FAILED - ' + str(len(failed)) + ' check(s)' if failed else 'OK'}")
    return "\n".join(lines)


def step_summary(results: list[Result], title: str) -> str:
    rows = ["| check | result | detail |", "|---|---|---|"]
    for r in results:
        tag = "pass" if r.passed else r.severity.lower()
        rows.append(f"| {r.name} | {tag} | {r.summary.replace('|', '/')} |")
    return f"### {title}\n\n" + "\n".join(rows) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--exposure", action="store_true", help="database-side anon exposure check (DATABASE_URL)")
    ap.add_argument("--skip-deployments", action="store_true")
    args = ap.parse_args(argv)

    if args.exposure:
        url = os.environ.get("DATABASE_URL")
        if not url:
            print("DATABASE_URL is not set", file=sys.stderr)
            return 2
        import psycopg   # only this mode needs it
        with psycopg.connect(url, options="-c statement_timeout=30s") as conn:
            results = exposure_checks(conn, read_allowlist())
        title = "Site probe: anon exposure"
    else:
        results = http_checks()
        if not args.skip_deployments:
            results += deployment_checks()
        title = "Site probe: live site"

    print(render(results), file=sys.stderr)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(step_summary(results, title))
    if args.json:
        print(json.dumps({"ok": not any(not r.passed and r.severity == FAIL for r in results),
                          "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                          "results": [asdict(r) for r in results]}, indent=1))
    return 0 if not any(not r.passed and r.severity == FAIL for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
