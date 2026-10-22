#!/usr/bin/env python3
"""
PHP version triage for CVE-2026-109618 / CVE-2026-109619.

Defensive version-detection ONLY. This script does NOT attempt to exploit the
vulnerabilities. It performs an ordinary HTTP(S) request to each host, reads the
PHP version advertised in the `Server` and `X-Powered-By` response headers, and
compares it against the patched releases:

    8.2.35, 8.3.36, 8.4.27, 8.5.12

Use this only against hosts you own or are authorized to assess.

Exit status is 0 on a clean run (regardless of findings). Results are written as
a table to stdout and optionally as CSV.

Usage:
    python php_cve_2026_109618_scanner.py hosts.txt
    python php_cve_2026_109618_scanner.py hosts.txt --csv report.csv --workers 20

hosts.txt: one host per line. Accepts bare hostnames (example.com), host:port,
or full URLs (https://example.com/). Blank lines and lines starting with # are
ignored.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import csv
import re
import sys
import urllib.request
import urllib.error
import ssl
from dataclasses import dataclass

# --- Patched versions per supported branch -------------------------------------
# A host is VULNERABLE if its PHP version is below the patched release for its
# branch. Branches older than 8.2 are end-of-life and treated as vulnerable.
PATCHED = {
    (8, 2): (8, 2, 35),
    (8, 3): (8, 3, 36),
    (8, 4): (8, 4, 27),
    (8, 5): (8, 5, 12),
}

VERSION_RE = re.compile(r"PHP/(\d+)\.(\d+)\.(\d+)", re.IGNORECASE)


@dataclass
class Result:
    host: str
    url: str
    php_version: str | None
    status: str  # VULNERABLE | PATCHED | EOL_VULNERABLE | UNKNOWN | ERROR
    detail: str


def normalize_url(raw: str) -> str:
    raw = raw.strip()
    if raw.startswith(("http://", "https://")):
        return raw
    return "https://" + raw


def parse_version(headers) -> tuple[int, int, int] | None:
    for field in ("Server", "X-Powered-By"):
        value = headers.get(field, "")
        m = VERSION_RE.search(value)
        if m:
            return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    return None


def classify(ver: tuple[int, int, int]) -> tuple[str, str]:
    major, minor, patch = ver
    branch = (major, minor)
    vstr = f"{major}.{minor}.{patch}"
    if major < 8 or branch < (8, 2):
        return "EOL_VULNERABLE", f"{vstr} is end-of-life; upgrade to a supported, patched branch"
    patched = PATCHED.get(branch)
    if patched is None:
        # A branch newer than we know about (e.g. 8.6+): assume patched but flag.
        return "UNKNOWN", f"{vstr} is a branch not in the known list; verify manually"
    if ver < patched:
        fixed = ".".join(map(str, patched))
        return "VULNERABLE", f"{vstr} < {fixed}; upgrade to {fixed}"
    return "PATCHED", f"{vstr} meets or exceeds the patched release"


def check_host(raw: str, timeout: float) -> Result:
    url = normalize_url(raw)
    ctx = ssl.create_default_context()
    # Internal sites often use private CAs / self-signed certs; don't fail triage
    # on cert validation. We only read response headers, not content.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "php-cve-triage/1.0"})
    try:
        try:
            resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        except urllib.error.HTTPError as e:
            # HTTP error responses still carry Server/X-Powered-By headers.
            resp = e
        headers = resp.headers
    except Exception as e:  # noqa: BLE001 - triage should never crash the run
        return Result(raw, url, None, "ERROR", f"{type(e).__name__}: {e}")

    ver = parse_version(headers)
    if ver is None:
        return Result(
            raw, url, None, "UNKNOWN",
            "No PHP version in Server/X-Powered-By headers "
            "(expose_php may be off, or PHP is behind a proxy)",
        )
    status, detail = classify(ver)
    return Result(raw, url, ".".join(map(str, ver)), status, detail)


def load_hosts(path: str) -> list[str]:
    hosts = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                hosts.append(line)
    return hosts


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("hosts_file", help="File with one host/URL per line")
    ap.add_argument("--csv", help="Write results to this CSV file")
    ap.add_argument("--workers", type=int, default=10, help="Concurrent requests (default 10)")
    ap.add_argument("--timeout", type=float, default=10.0, help="Per-host timeout seconds (default 10)")
    args = ap.parse_args()

    hosts = load_hosts(args.hosts_file)
    if not hosts:
        print("No hosts to check.", file=sys.stderr)
        return 1

    results: list[Result] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = {ex.submit(check_host, h, args.timeout): h for h in hosts}
        for fut in concurrent.futures.as_completed(futures):
            results.append(fut.result())

    order = {"VULNERABLE": 0, "EOL_VULNERABLE": 1, "UNKNOWN": 2, "ERROR": 3, "PATCHED": 4}
    results.sort(key=lambda r: (order.get(r.status, 9), r.host))

    width = max((len(r.host) for r in results), default=4)
    print(f"{'HOST'.ljust(width)}  {'VERSION':9}  {'STATUS':15}  DETAIL")
    print("-" * (width + 40))
    for r in results:
        print(f"{r.host.ljust(width)}  {(r.php_version or '-'):9}  {r.status:15}  {r.detail}")

    counts: dict[str, int] = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
    summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
    print("\nSummary:", summary)

    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["host", "url", "php_version", "status", "detail"])
            for r in results:
                w.writerow([r.host, r.url, r.php_version or "", r.status, r.detail])
        print(f"CSV written to {args.csv}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
