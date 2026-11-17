"""IP intelligence for the network signals (F286-F295, F340).

Always available (standard library):
  scope          private | loopback | link_local | reserved | multicast | public

Available when the free data files are in backend/data/geo/ (run tools/update_geo.py):
  country        DB-IP "IP to Country Lite"  dbip-country-lite.csv(.gz)   (CC BY 4.0, db-ip.com)
  asn, asn_org   DB-IP "IP to ASN Lite"      dbip-asn-lite.csv(.gz)
  tor_exit       Tor Project exit list        tor-exit-nodes.txt
  asn_type       derived from the ASN organisation name: hosting | mobile | isp

Without the files those fields are None and the signals that need them are reported as
"not computed" with the reason, never guessed.
"""
import bisect
import csv
import gzip
import ipaddress
import logging
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

HOSTING = ("amazon", "aws", "google cloud", "google llc", "microsoft", "azure", "digitalocean", "ovh", "hetzner",
           "linode", "akamai", "vultr", "choopa", "oracle", "alibaba", "tencent", "contabo", "leaseweb", "scaleway",
           "cloudflare", "fastly", "hostinger", "godaddy", "m247", "datacamp", "packethub", "hosting", "data center",
           "datacenter", "server", "cloud")
MOBILE = ("mobile", "cellular", "wireless", "jio", "airtel", "vodafone", "idea cellular", "bsnl", "t-mobile",
          "verizon wireless", "at&t mobility", "telefonica", "orange", "lte", "gsm")


@dataclass
class IpInfo:
    ip: str | None
    scope: str                 # private | loopback | link_local | reserved | multicast | public | invalid
    country: str | None = None
    asn: int | None = None
    asn_org: str | None = None
    asn_type: str | None = None  # hosting | mobile | isp (public IPs with ASN data); the scope otherwise
    tor_exit: bool | None = None


def scope_of(ip: str | None) -> str:
    try:
        a = ipaddress.ip_address(ip or "")
    except ValueError:
        return "invalid"
    if a.is_loopback:
        return "loopback"
    if a.is_link_local:
        return "link_local"
    if a.is_private:
        return "private"
    if a.is_multicast:
        return "multicast"
    if a.is_reserved or a.is_unspecified:
        return "reserved"
    return "public"


def asn_type_of(org: str | None) -> str | None:
    if not org:
        return None
    o = org.lower()
    if any(k in o for k in HOSTING):
        return "hosting"
    if any(k in o for k in MOBILE):
        return "mobile"
    return "isp"


class _Ranges:
    """Sorted, non-overlapping IP ranges -> value, looked up by binary search.
    IPv4 and IPv6 are kept apart: as integers their address spaces overlap."""

    def __init__(self):
        self._v = {4: ([], [], []), 6: ([], [], [])}   # version -> (starts, ends, values)

    def add(self, start: str, end: str, value) -> None:
        a, b = ipaddress.ip_address(start), ipaddress.ip_address(end)
        starts, ends, values = self._v[a.version]
        starts.append(int(a))
        ends.append(int(b))
        values.append(value)

    def finish(self) -> None:
        for version, (starts, ends, values) in list(self._v.items()):
            order = sorted(range(len(starts)), key=starts.__getitem__)
            self._v[version] = ([starts[i] for i in order], [ends[i] for i in order], [values[i] for i in order])

    def get(self, ip: str):
        a = ipaddress.ip_address(ip)
        starts, ends, values = self._v[a.version]
        n = int(a)
        i = bisect.bisect_right(starts, n) - 1
        return values[i] if i >= 0 and n <= ends[i] else None

    def __len__(self):
        return sum(len(s) for s, _, _ in self._v.values())


def _rows(path: Path):
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8", newline="") as f:
        yield from csv.reader(f)


def _find(directory: Path, stem: str) -> Path | None:
    for name in (f"{stem}.csv", f"{stem}.csv.gz"):
        if (directory / name).exists():
            return directory / name
    return None


class GeoIP:
    def __init__(self, directory: Path):
        self.directory = directory
        self.countries: _Ranges | None = None
        self.asns: _Ranges | None = None
        self.tor: set[str] | None = None
        self._load()

    def _load(self) -> None:
        if p := _find(self.directory, "dbip-country-lite"):
            r = _Ranges()
            for row in _rows(p):
                if len(row) >= 3:
                    r.add(row[0], row[1], row[2].upper())
            r.finish()
            self.countries = r
        if p := _find(self.directory, "dbip-asn-lite"):
            r = _Ranges()
            for row in _rows(p):
                if len(row) >= 4 and row[2].isdigit():
                    r.add(row[0], row[1], (int(row[2]), row[3]))
            r.finish()
            self.asns = r
        tor = self.directory / "tor-exit-nodes.txt"
        if tor.exists():
            self.tor = {line.strip() for line in tor.read_text().splitlines() if line.strip() and not line.startswith("#")}
        log.info("geo data: countries=%s asn=%s tor=%s",
                 len(self.countries) if self.countries else "missing",
                 len(self.asns) if self.asns else "missing",
                 len(self.tor) if self.tor is not None else "missing")

    @property
    def available(self) -> dict:
        return {"country": self.countries is not None, "asn": self.asns is not None, "tor": self.tor is not None}

    def lookup(self, ip: str | None) -> IpInfo:
        scope = scope_of(ip)
        info = IpInfo(ip=ip, scope=scope)
        if scope != "public":
            info.asn_type = scope
            return info
        if self.countries is not None:
            info.country = self.countries.get(ip)
        if self.asns is not None:
            hit = self.asns.get(ip)
            if hit:
                info.asn, info.asn_org = hit
                info.asn_type = asn_type_of(info.asn_org)
        if self.tor is not None:
            info.tor_exit = ip in self.tor
        return info
