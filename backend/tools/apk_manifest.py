"""Build-manifest entry for a release APK, matching the app's ApkInspector digests.

Run once per release (CI), then add the printed object to config.json "release_manifests":

    python tools/apk_manifest.py app-release.apk --version-code 12

The app reports these digests as catalogue signals F084 (DEX), F086 (native libs),
F090 (resources.arsc CRC), F091 (AndroidManifest.xml CRC) and F092 (assets). If release
manifests are configured and the installed APK matches none of them, the backend raises
AP_CODE_MISMATCH.
"""
import argparse
import hashlib
import json
import re
import sys
import zipfile

DEX = re.compile(r"^classes\d*\.dex$")


def digest(lines: list[str]) -> str:
    return hashlib.sha256("\n".join(sorted(lines)).encode()).hexdigest()[:32]


def manifest(path: str, version_code: int | None = None) -> dict:
    dex, so, assets = [], [], []
    arsc = man = None
    with zipfile.ZipFile(path) as z:
        for e in z.infolist():
            n = e.filename
            line = f"{n}:{e.CRC:08x}:{e.file_size}"
            if DEX.match(n):
                dex.append(line)
            elif n.startswith("lib/") and n.endswith(".so"):
                so.append(line)
            elif n.startswith("assets/"):
                assets.append(line)
            elif n == "resources.arsc":
                arsc = f"{e.CRC:08x}"
            elif n == "AndroidManifest.xml":
                man = f"{e.CRC:08x}"
    out = {"dex_digest": digest(dex), "so_digest": digest(so), "assets_digest": digest(assets),
           "arsc_crc": arsc or "missing", "manifest_crc": man or "missing"}
    if version_code is not None:
        out["version_code"] = version_code
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("apk")
    ap.add_argument("--version-code", type=int)
    a = ap.parse_args()
    json.dump(manifest(a.apk, a.version_code), sys.stdout, indent=2)
    print()
