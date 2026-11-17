"""Download the free IP data used by trustpoc/geo.py into backend/data/geo/.

    python tools/update_geo.py

  DB-IP IP to Country Lite + IP to ASN Lite (monthly, CC BY 4.0, https://db-ip.com/db/lite.php)
  Tor Project exit-node list (https://check.torproject.org/torbulkexitlist)

Run it monthly (Tor list: daily). The server loads the files at startup.
Attribution required by the DB-IP licence: "IP Geolocation by DB-IP (https://db-ip.com)".
"""
import datetime as dt
import sys
import urllib.error
import urllib.request
from pathlib import Path

DEST = Path(__file__).resolve().parent.parent / "data" / "geo"
UA = {"User-Agent": "rasp-ml-geo-updater/1.0"}


def fetch(url: str, target: Path) -> bool:
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=120) as r:
            data = r.read()
    except urllib.error.URLError as exc:
        print(f"  failed: {url} ({exc})")
        return False
    target.write_bytes(data)
    print(f"  saved {target.name} ({len(data) / 1e6:.1f} MB)")
    return True


def main() -> int:
    DEST.mkdir(parents=True, exist_ok=True)
    ok = True
    today = dt.date.today()
    for stem in ("dbip-country-lite", "dbip-asn-lite"):
        # The current month's file appears early in the month; fall back to last month's.
        months = [today, (today.replace(day=1) - dt.timedelta(days=1))]
        if not any(fetch(f"https://download.db-ip.com/free/{stem}-{m:%Y-%m}.csv.gz", DEST / f"{stem}.csv.gz") for m in months):
            ok = False
    ok &= fetch("https://check.torproject.org/torbulkexitlist", DEST / "tor-exit-nodes.txt")
    print("done" if ok else "some downloads failed")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
