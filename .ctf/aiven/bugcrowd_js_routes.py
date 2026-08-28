#!/usr/bin/env python3
from __future__ import annotations

import concurrent.futures
import datetime as dt
import hashlib
import json
import os
import re
import urllib.parse
import urllib.request
from collections import deque
from pathlib import Path
from typing import Any

OUT = Path("probe-output/bugcrowd-js-routes")
BUNDLES = OUT / "bundles"
OUT.mkdir(parents=True, exist_ok=True)
BUNDLES.mkdir(parents=True, exist_ok=True)
ORIGIN = "https://assets.bugcrowdusercontent.com"
SEEDS = [
    ORIGIN + "/assets/researcher-engagement-brief/app-0edf9437.js",
    ORIGIN + "/assets/researcher-engagement-brief/chunk-HKDPJZPO.digested.js",
    ORIGIN + "/assets/researcher-engagement-brief/chunk-VHNBT6PB.digested.js",
]
MAX_FILES = 160
MAX_BYTES_PER_FILE = 12_000_000
UA = "Aiven-CTF-authorized-public-bundle-inspection/1.0"
KEYWORDS = [
    "credential", "resource", "participat", "claim", "join", "enroll",
    "activate", "provision", "target_group", "target-group", "targetgroup",
    "engagement", "researcher", "invitation", "access", "submission",
    "download", "api/", "graphql", "ctf", "scope", "brief", "announcement",
]


def utcnow() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fetch(url: str) -> dict[str, Any]:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/javascript,text/javascript,*/*"})
    row: dict[str, Any] = {"url": url, "observed_at": utcnow()}
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            body = response.read(MAX_BYTES_PER_FILE + 1)
            if len(body) > MAX_BYTES_PER_FILE:
                row["error"] = "body_over_limit"
                row["body_bytes_seen"] = len(body)
                return row
            row.update({
                "status": response.status,
                "final_url": response.geturl(),
                "content_type": response.headers.get("content-type"),
                "body": body,
                "body_bytes": len(body),
                "body_sha256": sha256(body),
            })
    except Exception as exc:
        row["error"] = f"{type(exc).__name__}: {exc}"
    return row


def referenced_js(base_url: str, text: str) -> set[str]:
    refs: set[str] = set()
    patterns = [
        r"(?:from\s*|import\s*\(|import\s*)[\"']([^\"']+\.js(?:\?[^\"']*)?)[\"']",
        r"[\"']([^\"']+(?:chunk|app)-[A-Za-z0-9_.-]+\.js(?:\?[^\"']*)?)[\"']",
        r"[\"']([^\"']+\.digested\.js(?:\?[^\"']*)?)[\"']",
        r"sourceMappingURL=([^\s*]+\.map)",
    ]
    for pattern in patterns:
        for raw in re.findall(pattern, text):
            url = urllib.parse.urljoin(base_url, raw)
            parsed = urllib.parse.urlparse(url)
            if parsed.scheme == "https" and parsed.netloc == urllib.parse.urlparse(ORIGIN).netloc:
                refs.add(url)
    return refs


def strings_and_contexts(url: str, text: str) -> tuple[list[dict[str, Any]], list[str]]:
    hits: list[dict[str, Any]] = []
    endpoints: set[str] = set()
    string_re = re.compile(r"(?P<q>[\"'`])(?P<s>(?:\\.|(?!\1).){1,1200})(?P=q)", re.S)
    for match in string_re.finditer(text):
        value = match.group("s")
        lower = value.lower()
        matched = sorted({kw for kw in KEYWORDS if kw in lower})
        if not matched:
            continue
        if value.startswith("/") or "bugcrowd.com/" in lower or "/api/" in lower or "graphql" in lower:
            endpoints.add(value[:1200])
        start = max(0, match.start() - 500)
        end = min(len(text), match.end() + 500)
        hits.append({
            "url": url,
            "offset": match.start(),
            "keywords": matched,
            "value": value[:1200],
            "context": text[start:end][:2500],
        })
    # Also capture direct route-like literals not cleanly delimited due to minification.
    route_re = re.compile(r"/(?:api|engagements?|researchers?|targets?|target_groups?|target-groups?|resources?|credentials?|participations?|claims?|invitations?|submissions?)[A-Za-z0-9_?&=./:{}-]{0,500}")
    endpoints.update(m.group(0) for m in route_re.finditer(text))
    return hits, sorted(endpoints)


def safe_name(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    stem = Path(parsed.path).name or "bundle.js"
    return f"{sha256(url.encode())[:16]}-{stem}"


report: dict[str, Any] = {
    "schema": "aiven-ctf-bugcrowd-public-js-route-inspection-v1",
    "started_at_utc": utcnow(),
    "seeds": SEEDS,
    "safety": {
        "public_unauthenticated_get_only": True,
        "credentials_used": False,
        "cookies_used": False,
        "mutations": False,
        "max_files": MAX_FILES,
        "max_bytes_per_file": MAX_BYTES_PER_FILE,
    },
    "runner": {
        "repository": os.environ.get("GITHUB_REPOSITORY"),
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "sha": os.environ.get("GITHUB_SHA"),
    },
}

queue = deque(SEEDS)
queued = set(SEEDS)
rows: list[dict[str, Any]] = []
all_hits: list[dict[str, Any]] = []
all_endpoints: set[str] = set()

while queue and len(rows) < MAX_FILES:
    batch: list[str] = []
    while queue and len(batch) < 12 and len(rows) + len(batch) < MAX_FILES:
        batch.append(queue.popleft())
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(12, len(batch))) as pool:
        fetched = list(pool.map(fetch, batch))
    for row in fetched:
        body = row.pop("body", None)
        if body is None:
            rows.append(row)
            continue
        path = BUNDLES / safe_name(row["url"])
        path.write_bytes(body)
        row["artifact_path"] = str(path)
        text = body.decode("utf-8", "replace")
        refs = sorted(referenced_js(row.get("final_url") or row["url"], text))
        row["references"] = refs
        hits, endpoints = strings_and_contexts(row["url"], text)
        row["interesting_hit_count"] = len(hits)
        row["endpoint_count"] = len(endpoints)
        all_hits.extend(hits)
        all_endpoints.update(endpoints)
        for ref in refs:
            if ref not in queued and len(queued) < MAX_FILES * 3:
                queued.add(ref)
                queue.append(ref)
        rows.append(row)

report["files"] = rows
report["hits"] = all_hits
report["endpoints"] = sorted(all_endpoints)
report["finished_at_utc"] = utcnow()
raw = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
(OUT / "route-inspection.json").write_bytes(raw)

keyword_counts: dict[str, int] = {}
for hit in all_hits:
    for keyword in hit["keywords"]:
        keyword_counts[keyword] = keyword_counts.get(keyword, 0) + 1
summary = {
    "schema": report["schema"],
    "started_at_utc": report["started_at_utc"],
    "finished_at_utc": report["finished_at_utc"],
    "file_count": len(rows),
    "successful_file_count": sum(1 for r in rows if r.get("status") == 200),
    "total_bytes": sum(r.get("body_bytes", 0) for r in rows),
    "hit_count": len(all_hits),
    "endpoint_count": len(all_endpoints),
    "keyword_counts": keyword_counts,
    "endpoints": sorted(all_endpoints),
    "errors": [{"url": r["url"], "error": r.get("error")} for r in rows if r.get("error")],
    "report_sha256": sha256(raw),
}
summary_raw = (json.dumps(summary, indent=2, sort_keys=True) + "\n").encode()
(OUT / "summary.json").write_bytes(summary_raw)
(OUT / "SHA256SUMS").write_text(
    f"{sha256(raw)}  route-inspection.json\n{sha256(summary_raw)}  summary.json\n"
)
print(json.dumps({
    "file_count": summary["file_count"],
    "successful_file_count": summary["successful_file_count"],
    "total_bytes": summary["total_bytes"],
    "hit_count": summary["hit_count"],
    "endpoint_count": summary["endpoint_count"],
    "endpoints_preview": summary["endpoints"][:100],
    "errors": summary["errors"],
    "report_sha256": summary["report_sha256"],
}, sort_keys=True))
