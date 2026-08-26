#!/usr/bin/env python3
from __future__ import annotations

import concurrent.futures
import datetime as dt
import hashlib
import json
import os
import re
import socket
import ssl
import subprocess
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

OUT = Path("probe-output/discovery")
OUT.mkdir(parents=True, exist_ok=True)
NEW_HOST = "falcon-bug-bounty-flag-pgsql-dev-sandbox.e.aivencloud.com"
OLD_HOST = "falcon-bug-bounty-flag-pgsql-dev-sandbox.aivencloud.com"
PREFIX = "falcon-bug-bounty-flag-pgsql"
OLD_IP = "193.122.144.9"
UA = "Aiven-CTF-authorized-passive-discovery/1.0"


def utcnow() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fetch(url: str, *, timeout: int = 45) -> dict[str, Any]:
    row: dict[str, Any] = {"url": url, "observed_at": utcnow()}
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json,text/plain,text/html,*/*"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as response:
            body = response.read(50_000_000)
            row.update(
                {
                    "status": response.status,
                    "final_url": response.geturl(),
                    "headers": dict(response.headers.items()),
                    "body_b64": __import__("base64").b64encode(body).decode(),
                    "body_sha256": sha256(body),
                    "body_bytes": len(body),
                }
            )
    except Exception as exc:
        row["error"] = f"{type(exc).__name__}: {exc}"
    return row


def body_text(row: dict[str, Any]) -> str:
    encoded = row.get("body_b64")
    if not encoded:
        return ""
    try:
        return __import__("base64").b64decode(encoded).decode("utf-8", "replace")
    except Exception:
        return ""


def extract_names(text: str) -> set[str]:
    candidates = set()
    for raw in re.findall(r"(?i)(?:\*\.)?[a-z0-9][a-z0-9._-]{2,253}\.aivencloud\.com", text):
        name = raw.lower().strip(".\"' ,;()[]{}<>")
        if "falcon-bug-bounty" in name or PREFIX in name:
            candidates.add(name)
    return candidates


def resolve(name: str) -> dict[str, Any]:
    row: dict[str, Any] = {"name": name, "observed_at": utcnow()}
    try:
        infos = socket.getaddrinfo(name.lstrip("*."), None, type=socket.SOCK_STREAM)
        row["addresses"] = sorted({entry[4][0] for entry in infos})
    except Exception as exc:
        row["error"] = f"{type(exc).__name__}: {exc}"
    return row


def dig(name: str, qtype: str) -> dict[str, Any]:
    argv = ["dig", "+time=2", "+tries=1", "+short", qtype, name]
    try:
        cp = subprocess.run(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8, check=False)
        return {
            "name": name,
            "qtype": qtype,
            "returncode": cp.returncode,
            "stdout": cp.stdout,
            "stderr": cp.stderr,
            "observed_at": utcnow(),
        }
    except Exception as exc:
        return {"name": name, "qtype": qtype, "error": f"{type(exc).__name__}: {exc}", "observed_at": utcnow()}


queries = {
    "crt_prefix": "https://crt.sh/?q=" + urllib.parse.quote("%" + PREFIX + "%") + "&output=json",
    "crt_new_exact": "https://crt.sh/?q=" + urllib.parse.quote(NEW_HOST) + "&output=json",
    "crt_old_exact": "https://crt.sh/?q=" + urllib.parse.quote(OLD_HOST) + "&output=json",
    "certspotter_new": "https://api.certspotter.com/v1/issuances?domain=" + urllib.parse.quote(NEW_HOST) + "&include_subdomains=true&expand=dns_names&expand=issuer&expand=cert",
    "certspotter_old": "https://api.certspotter.com/v1/issuances?domain=" + urllib.parse.quote(OLD_HOST) + "&include_subdomains=true&expand=dns_names&expand=issuer&expand=cert",
    "otx_new": "https://otx.alienvault.com/api/v1/indicators/hostname/" + urllib.parse.quote(NEW_HOST, safe="") + "/passive_dns",
    "otx_old": "https://otx.alienvault.com/api/v1/indicators/hostname/" + urllib.parse.quote(OLD_HOST, safe="") + "/passive_dns",
    "urlscan_new": "https://urlscan.io/api/v1/search/?q=" + urllib.parse.quote("domain:" + NEW_HOST),
    "urlscan_old": "https://urlscan.io/api/v1/search/?q=" + urllib.parse.quote("domain:" + OLD_HOST),
    "wayback_new": "https://web.archive.org/cdx/search/cdx?url=" + urllib.parse.quote(NEW_HOST + "/*") + "&output=json&fl=timestamp,original,statuscode,digest&filter=statuscode:200&collapse=digest",
    "wayback_old": "https://web.archive.org/cdx/search/cdx?url=" + urllib.parse.quote(OLD_HOST + "/*") + "&output=json&fl=timestamp,original,statuscode,digest&collapse=digest",
    "commoncrawl_new": "https://index.commoncrawl.org/CC-MAIN-2026-30-index?url=" + urllib.parse.quote(NEW_HOST + "/*") + "&output=json",
    "commoncrawl_old": "https://index.commoncrawl.org/CC-MAIN-2026-30-index?url=" + urllib.parse.quote(OLD_HOST + "/*") + "&output=json",
    "hackertarget_e_zone": "https://api.hackertarget.com/hostsearch/?q=e.aivencloud.com",
    "shodan_old_ip": "https://internetdb.shodan.io/" + OLD_IP,
    "bufferover_new": "https://dns.bufferover.run/dns?q=" + urllib.parse.quote(NEW_HOST),
    "bufferover_old": "https://dns.bufferover.run/dns?q=" + urllib.parse.quote(OLD_HOST),
}

report: dict[str, Any] = {
    "schema": "aiven-ctf-passive-discovery-v1",
    "target": NEW_HOST,
    "run_started_utc": utcnow(),
    "runner": {
        "repository": os.environ.get("GITHUB_REPOSITORY"),
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "sha": os.environ.get("GITHUB_SHA"),
    },
    "safety": {
        "passive_sources_only": True,
        "active_queries": "DNS lookups limited to exact challenge-derived labels",
        "no_authentication": True,
        "no_passwords": True,
        "no_sql": True,
    },
}

source_rows: dict[str, Any] = {}
with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
    future_map = {pool.submit(fetch, url): label for label, url in queries.items()}
    for future in concurrent.futures.as_completed(future_map):
        label = future_map[future]
        source_rows[label] = future.result()
report["passive_sources"] = source_rows

names: set[str] = {NEW_HOST, OLD_HOST}
for row in source_rows.values():
    names.update(extract_names(body_text(row)))

# Bounded challenge-specific DNS candidate set. This is not zone-wide enumeration.
for n in range(1, 257):
    for label in (
        f"{PREFIX}-{n}.e.aivencloud.com",
        f"n-{PREFIX}-{n}.e.aivencloud.com",
        f"public-n-{PREFIX}-{n}.e.aivencloud.com",
        f"{PREFIX}-{n}.aivencloud.com",
        f"n-{PREFIX}-{n}.aivencloud.com",
        f"public-n-{PREFIX}-{n}.aivencloud.com",
    ):
        names.add(label)

for label in (
    "public-" + NEW_HOST,
    "public-" + OLD_HOST,
    "n-" + NEW_HOST,
    "n-" + OLD_HOST,
):
    names.add(label)

report["candidate_name_count"] = len(names)
resolutions: list[dict[str, Any]] = []
with concurrent.futures.ThreadPoolExecutor(max_workers=48) as pool:
    futures = [pool.submit(resolve, name) for name in sorted(names)]
    for future in concurrent.futures.as_completed(futures):
        resolutions.append(future.result())
report["resolutions"] = sorted(resolutions, key=lambda row: row["name"])

resolved_names = sorted({row["name"] for row in resolutions if row.get("addresses")})
report["resolved_names"] = resolved_names

# Record non-address DNS material for exact and any discovered live names.
dig_names = sorted(set([NEW_HOST, OLD_HOST, *resolved_names]))
dig_rows: list[dict[str, Any]] = []
with concurrent.futures.ThreadPoolExecutor(max_workers=24) as pool:
    futures = [pool.submit(dig, name, qtype) for name in dig_names for qtype in ("A", "AAAA", "CNAME", "HTTPS", "SVCB", "TXT", "SRV")]
    for future in concurrent.futures.as_completed(futures):
        dig_rows.append(future.result())
report["dns_records"] = sorted(dig_rows, key=lambda row: (row["name"], row["qtype"]))
report["run_finished_utc"] = utcnow()

report_bytes = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
(OUT / "passive-discovery.json").write_bytes(report_bytes)

summary = {
    "schema": report["schema"],
    "target": NEW_HOST,
    "run_started_utc": report["run_started_utc"],
    "run_finished_utc": report["run_finished_utc"],
    "candidate_name_count": report["candidate_name_count"],
    "resolved_names": resolved_names,
    "source_statuses": {
        key: {"status": row.get("status"), "error": row.get("error"), "bytes": row.get("body_bytes"), "sha256": row.get("body_sha256")}
        for key, row in sorted(source_rows.items())
    },
    "report_sha256": sha256(report_bytes),
}
summary_bytes = (json.dumps(summary, indent=2, sort_keys=True) + "\n").encode()
(OUT / "summary.json").write_bytes(summary_bytes)
manifest = {
    "schema": "aiven-ctf-passive-discovery-manifest-v1",
    "created_at_utc": utcnow(),
    "files": [
        {"path": "passive-discovery.json", "bytes": len(report_bytes), "sha256": sha256(report_bytes)},
        {"path": "summary.json", "bytes": len(summary_bytes), "sha256": sha256(summary_bytes)},
    ],
}
(OUT / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
print(json.dumps(summary, sort_keys=True))
