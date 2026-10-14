"""Reference data that turns an IP into a network and a network into a profile.

- RouteViews prefix-to-AS (CAIDA), daily: IP -> origin AS, and each AS's routed /24s.
  Most-specific prefix wins per /24; prefixes longer than /24 and shorter than /8 are
  ignored; MOAS entries (a_b, a,b) take the first AS.
- CAIDA AS-to-organisation, monthly: names, organisation, sister networks.
- RIR delegated-extended files (5 RIRs): registration date and registry.
- PeeringDB networks: self-declared type, traffic, scope, policy, website.
- SANS ISC research-scanner list: IPs that are removed from every attack feed.
"""

from __future__ import annotations

import array
import collections
import gzip
import io
import json
import re
from dataclasses import dataclass

PFX_LOG = "https://publicdata.caida.org/datasets/routing/routeviews-prefix2as/pfx2as-creation.log"
PFX_BASE = "https://publicdata.caida.org/datasets/routing/routeviews-prefix2as/"
ORG_INDEX = "https://publicdata.caida.org/datasets/as-organizations/"
RIR_URLS = {
    "ripencc": "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
    "arin": "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
    "apnic": "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest",
    "lacnic": "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
    "afrinic": "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest",
}
PDB_URL = ("https://www.peeringdb.com/api/net?fields=asn,name,website,info_type,"
           "info_traffic,info_scope,policy_general")
RESEARCH_URL = "https://isc.sans.edu/api/threatcategory/research?json"


def latest_pfx2as_path(log_text: str) -> str:
    """The newest file named in CAIDA's creation log (last non-comment line)."""
    lines = [l for l in log_text.splitlines() if l.strip() and not l.startswith("#")]
    if not lines:
        raise ValueError("pfx2as creation log is empty")
    return lines[-1].split()[-1]


def latest_org_file(index_html: str) -> str:
    files = sorted(set(re.findall(r"\d{8}\.as-org2info\.txt\.gz", index_html)))
    if not files:
        raise ValueError("no as-org2info file in the CAIDA index")
    return files[-1]


class Routing:
    """/24 -> origin AS lookup over the whole IPv4 space (2^24 slots, 64 MB)."""

    def __init__(self, gz_bytes: bytes):
        pf = []
        with gzip.open(io.BytesIO(gz_bytes), "rt") as fh:
            for line in fh:
                parts = line.split("\t")
                if len(parts) != 3:
                    continue
                ip, ln, origin = parts
                ln = int(ln)
                if ln > 24 or ln < 8:
                    continue
                first = re.split(r"[_,]", origin.strip())[0]
                if not first.isdigit():
                    continue
                o = list(map(int, ip.split(".")))
                pf.append(((o[0] << 16) | (o[1] << 8) | o[2], ln, int(first)))
        pf.sort(key=lambda x: x[1])                 # shorter first: longer overwrite
        self.s24 = array.array("I", [0]) * (1 << 24)
        for start, ln, a in pf:
            n = 1 << (24 - ln)
            self.s24[start:start + n] = array.array("I", [a]) * n
        self.prefixes = collections.Counter(a for _, _, a in pf)
        self.announced = collections.Counter()
        for _, ln, a in pf:
            self.announced[a] += 1 << (32 - ln)
        self.size24 = collections.Counter(self.s24)
        self.size24.pop(0, None)
        self.rows = len(pf)

    def asn(self, ip: str) -> int:
        """Origin AS for a dotted-quad IPv4 address; 0 if unrouted or not IPv4."""
        p = ip.split(".")
        if len(p) != 4:
            return 0
        try:
            a, b, c = int(p[0]), int(p[1]), int(p[2])
        except ValueError:
            return 0
        if not (0 <= a < 256 and 0 <= b < 256 and 0 <= c < 256):
            return 0
        return self.s24[(a << 16) | (b << 8) | c]


@dataclass
class Org:
    handle: str
    org_id: str
    org_name: str
    cc: str


def parse_org(gz_bytes: bytes) -> tuple[dict[int, Org], collections.Counter]:
    orgs, ases = {}, {}
    with gzip.open(io.BytesIO(gz_bytes), "rt", errors="replace") as fh:
        for line in fh:
            if line.startswith("#"):
                continue
            p = line.rstrip("\n").split("|")
            if len(p) == 5:
                orgs[p[0]] = (p[2], p[3])
            elif len(p) >= 6 and p[0].isdigit():
                ases[int(p[0])] = (p[2], p[3])
    out = {a: Org(h, oid, orgs.get(oid, ("", ""))[0], orgs.get(oid, ("", ""))[1]) for a, (h, oid) in ases.items()}
    siblings = collections.Counter(o.org_id for o in out.values())
    return out, siblings


def parse_rir(texts: dict[str, str]) -> dict[int, tuple[str, str, str]]:
    """asn -> (rir, cc, YYYY-MM-DD). Ranges are expanded (capped at 100,000 per line)."""
    out = {}
    for text in texts.values():
        for line in text.splitlines():
            p = line.strip().split("|")
            if len(p) >= 7 and p[2] == "asn" and p[3].isdigit():
                start, cnt, d = int(p[3]), int(p[4]), p[5]
                date = f"{d[:4]}-{d[4:6]}-{d[6:]}" if len(d) == 8 and d != "00000000" else ""
                for a in range(start, start + min(cnt, 100_000)):
                    out[a] = (p[0], p[1], date)
    return out


BGPTOOLS_URL = "https://bgp.tools/asns.csv"
#: bgp.tools asks every client to identify itself with a contact.
BGPTOOLS_UA = "zerodayclock.com research (sergej.epp@zerodayclock.com)"


def parse_bgptools(body: bytes) -> dict[int, str]:
    """bgp.tools' curated AS names (asn,name,class,cc). Unlike the registry text they are
    the names networks are known by: 'Tencent' rather than the street address APNIC holds,
    'Telecom Egypt' rather than 'IDDQD-AS'."""
    import csv
    out = {}
    for r in csv.DictReader(io.StringIO(body.decode("utf-8", "replace"))):
        a, n = (r.get("asn") or "").upper().removeprefix("AS"), (r.get("name") or "").strip()
        if a.isdigit() and n:
            out[int(a)] = n
    return out


_STOP = {"ltd", "inc", "llc", "gmbh", "the", "and", "sas", "com", "net", "limited", "corporation", "company",
         "corp", "pvt", "private", "group", "asn", "as", "ap", "co", "sa", "srl", "ltda", "pt", "tbk", "jsc", "ojsc",
         "network", "networks", "internet", "communications", "communication", "telecom", "telecommunications",
         "services", "service", "technology", "technologies", "information", "systems", "data", "online", "cloud"}


def _words(s: str | None) -> set[str]:
    return {w for w in re.findall(r"[a-z0-9]{3,}", (s or "").lower()) if w not in _STOP}


#: Registry text that is not a name: an address, or an APNIC/AFRINIC description line.
NOT_A_NAME = re.compile(r"\b(building|avenue|street|road|floor|district|room|no\.\s*\d+)\b|"
                        r"^(as number|autonomous system|asn? for)\b|\bis an isp\b|^iddqd", re.I)


def network_name(asn: int, cf: str | None, pdb: str | None, bgptools: str | None,
                 org_name: str | None, handle: str | None) -> str:
    """The name a reader knows the network by. Curated names first: PeeringDB, which operators
    maintain themselves, then bgp.tools. Cloudflare Radar's names are the registry's legal
    names ('Cablevisión, S.A. de C.V.' for izzi, 'TE-AS' for Telecom Egypt), so they come
    after both; the registrant's name only when none has one, and never registry text that
    is an address or a sentence."""
    for n in (pdb, bgptools, cf):
        n = re.sub(r"\s*\(AS\s?\d+\)\s*$", "", n or "", flags=re.I).strip()   # 'izzi telecom (AS28548)'
        if n and not NOT_A_NAME.search(n):
            return n
    if org_name and not NOT_A_NAME.search(org_name):
        return org_name
    return handle or org_name or f"AS{asn}"


def org_belongs(name: str, handle: str | None, org_name: str | None, rir: str | None) -> bool:
    """CAIDA infers APNIC organisations, which hold no org objects, from shared contacts, and
    some links are wrong (AS7470 TRUE INTERNET was linked to 'KGI Securities'). An APNIC
    organisation is kept when any word of it appears in the network's name or handle, or a
    word of those appears in it, compared without spaces or hyphens ('LG DACOM' in
    'LGDACOM'). Elsewhere the org object is the registry's own, so a parent with a
    different name (Level 3 under Lumen) is kept."""
    if not org_name or NOT_A_NAME.search(org_name):
        return False
    if (rir or "").lower() != "apnic":
        return True
    flat = lambda t: re.sub(r"[^a-z0-9]", "", (t or "").lower())    # noqa: E731
    org_flat, mine_flat = flat(org_name), flat(name) + "|" + flat(handle)
    words = lambda t: {w for w in re.findall(r"[a-z0-9]{2,}", (t or "").lower()) if w not in _STOP}   # noqa: E731
    name_flat = flat(name)
    if len(name_flat) >= 4 and (name_flat in org_flat or org_flat in name_flat):      # 'M.A.T Co., Ltd.'
        return True
    return any(w in mine_flat for w in words(org_name)) or any(len(w) >= 3 and w in org_flat for w in words(name) | words(handle))


def parse_pdb(body: bytes) -> dict[int, dict]:
    return {x["asn"]: x for x in json.loads(body)["data"]}


def parse_research(body: bytes) -> set[str]:
    return {x["ipv4"] for x in json.loads(body) if x.get("ipv4")}


# ---- network type ----------------------------------------------------------------
CLOUD = {150436, 136907, 55990, 16509, 14618, 8075, 8068, 8069, 396982, 15169, 19527, 31898,
         45102, 37963, 132203, 45090, 36351, 135377, 24429, 58466, 58519, 38365, 55967}
CDN = {13335, 209242, 20940, 54113, 16625, 62597, 14789, 395747, 13414, 32934, 63179, 16550}
TRANSIT = {174, 6939, 3356, 1299, 6461, 3257, 2914, 6762, 6453, 3491, 5511, 1273, 7473, 4637,
           9002, 6830, 58453}
BROAD = {12389, 8452, 17858, 16135, 29465, 4837, 4134, 9808, 56040, 56041, 56046, 56047, 24400,
         4812, 4813, 17621, 17622, 17623, 4808, 9929, 4766, 3462, 7922, 7018, 701, 20115, 9121,
         47331, 55836, 45609, 24560, 9829}
HOST = {137409, 35916, 63949}
HOSTRX = re.compile(r"host|server|data ?cent|cloud|vps|hetzner|ovh|digitalocean|contabo|constant|"
                    r"linode|m247|datacamp|netcup|leaseweb|choopa|vultr|ionos|scaleway|colocation|"
                    r"seo|proxy|dedipath|dedicated|aeza|hivelocity|psychz|gcore|kamatera|clouvider|"
                    r"quadranet|frantech|buyvm|zenlayer|ucloud|webnx|serverion|selectel|timeweb|"
                    r"worldstream|liquid web|godaddy|rackspace|servers\.com|equinix|akamai|vpn|colo", re.I)
ISPRX = re.compile(r"telecom|telekom|telecomunica|mobile|cable|broadband|vodafone|vodacom|orange|"
                   r"telefonica|airtel|jio|comcast|charter|verizon|at&t|china unicom|china mobile|"
                   r"ttnet|superonline|turksat|rostelecom|beeline|viettel|vnpt|telkom|claro|vivo|"
                   r"movistar|telstra|rogers|kddi|softbank|korea telecom|hinet|chunghwa|pldt|globe|"
                   r"etisalat|zain|optus|cox|frontier|altice|liberty|virgin|deutsche|bouygues|sfr|"
                   r"swisscom|telmex|true online|internet service|fibra|fibre|fiber|wireless", re.I)
TYPES = ("Hyperscale cloud", "Hosting & VPS", "Broadband & mobile", "Transit & backbone",
         "CDN & platforms", "Enterprise, edu & gov", "Other")


def network_type(asn: int, name: str, pdb_type: str | None, dc_share: float | None,
                 home_share: float | None) -> tuple[str, str]:
    """(type, basis). Fixed lists first, then CrowdSec's per-IP connection type where a
    network has enough malicious IPs to judge, then names, then PeeringDB."""
    if asn in HOST: return "Hosting & VPS", "list"
    if asn in CDN: return "CDN & platforms", "list"
    if asn in CLOUD: return "Hyperscale cloud", "list"
    if asn in TRANSIT: return "Transit & backbone", "list"
    if asn in BROAD: return "Broadband & mobile", "list"
    if dc_share is not None and dc_share >= 0.7: return "Hosting & VPS", "crowdsec_connection"
    if home_share is not None and home_share >= 0.7: return "Broadband & mobile", "crowdsec_connection"
    if HOSTRX.search(name): return "Hosting & VPS", "name"
    if pdb_type == "Cable/DSL/ISP" or ISPRX.search(name): return "Broadband & mobile", "name_or_peeringdb"
    if dc_share is not None and dc_share >= 0.6: return "Hosting & VPS", "crowdsec_connection"
    if home_share is not None and home_share >= 0.5: return "Broadband & mobile", "crowdsec_connection"
    if pdb_type in ("Content", "Network Services"): return "Hosting & VPS", "peeringdb"
    if pdb_type == "NSP": return "Transit & backbone", "peeringdb"
    if pdb_type in ("Enterprise", "Educational/Research", "Government", "Non-Profit"):
        return "Enterprise, edu & gov", "peeringdb"
    return "Other", "none"


SCANNER_RX = re.compile(r"censys|modat|shodan|onyphe|driftnet|binaryedge|stretchoid|"
                        r"internet-measurement|alpha ?strike|recyber|leakix|criminalip|expanse|"
                        r"palo alto|rapid7|shadowserver|bitsight|internet census", re.I)
