#!/usr/bin/env python3
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import html
import json
import os
import re
import ssl
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

BASE = "https://console.aiven.io/"
OUT = Path("probe-output/console-auth-code")
OUT.mkdir(parents=True, exist_ok=True)
UA = "Mozilla/5.0 authorized-aiven-ctf-console-source-research/1.0"
TERMS = [
    "/user/password_reset_request",
    "/user/password_reset/{verification_code}",
    "forgot-password",
    "passwordResetRequest",
    "resetEmail",
]


def utcnow() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fetch(url: str, limit: int = 80_000_000) -> dict[str, Any]:
    row: dict[str, Any] = {"url": url, "observed_at": utcnow()}
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "text/html,application/javascript,application/json,*/*"})
    try:
        with urllib.request.urlopen(req, timeout=60, context=ssl.create_default_context()) as response:
            body = response.read(limit + 1)
            row.update({
                "status": response.status,
                "final_url": response.geturl(),
                "headers": dict(response.headers.items()),
                "body_bytes": len(body),
                "body_sha256": sha256(body),
                "truncated": len(body) > limit,
                "body_b64": base64.b64encode(body[:limit]).decode(),
            })
    except Exception as exc:
        row["error"] = f"{type(exc).__name__}: {exc}"
    return row


def body(row: dict[str, Any]) -> bytes:
    try:
        return base64.b64decode(row.get("body_b64", ""))
    except Exception:
        return b""


def asset_urls(index_text: str, base: str) -> list[str]:
    urls = set()
    for pattern in (
        r'<script[^>]+src=["\']([^"\']+)["\']',
        r'<link[^>]+href=["\']([^"\']+)["\']',
    ):
        for raw in re.findall(pattern, index_text, re.I):
            url = urllib.parse.urljoin(base, html.unescape(raw))
            if urllib.parse.urlparse(url).netloc == urllib.parse.urlparse(BASE).netloc:
                urls.add(url)
    return sorted(urls)


def contexts(text: str, term: str, radius: int = 25_000) -> list[dict[str, Any]]:
    out = []
    lower = text.lower()
    needle = term.lower()
    pos = 0
    while len(out) < 20:
        idx = lower.find(needle, pos)
        if idx < 0:
            break
        left = max(0, idx - radius)
        right = min(len(text), idx + len(term) + radius)
        out.append({"offset": idx, "start": left, "end": right, "text": text[left:right]})
        pos = idx + max(1, len(term))
    return out


report: dict[str, Any] = {
    "schema": "aiven-console-auth-code-v1",
    "base": BASE,
    "run_started_utc": utcnow(),
    "runner": {
        "repository": os.environ.get("GITHUB_REPOSITORY"),
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "sha": os.environ.get("GITHUB_SHA"),
    },
    "safety": {"passive_get_only": True, "no_credentials": True, "no_state_change": True},
}
index = fetch(BASE)
report["index"] = {k: v for k, v in index.items() if k != "body_b64"}
index_text = body(index).decode("utf-8", "replace")
urls = asset_urls(index_text, index.get("final_url") or BASE)
report["asset_urls"] = urls
report["asset_hits"] = []
report["source_map_hits"] = []
for url in urls:
    if not re.search(r"\.(?:js|mjs)(?:\?|$)", url, re.I):
        continue
    row = fetch(url)
    raw = body(row)
    text = raw.decode("utf-8", "replace")
    hit_terms = [term for term in TERMS if term.lower() in text.lower()]
    if not hit_terms:
        continue
    hit = {
        "url": url,
        "status": row.get("status"),
        "bytes": len(raw),
        "sha256": sha256(raw),
        "terms": {},
    }
    for term in hit_terms:
        hit["terms"][term] = contexts(text, term)
    report["asset_hits"].append(hit)

    map_match = re.search(r"[#@]\s*sourceMappingURL=([^\s*]+)", text[-10_000:])
    if not map_match:
        continue
    map_url = urllib.parse.urljoin(url, map_match.group(1).strip())
    map_row = fetch(map_url)
    map_raw = body(map_row)
    map_summary: dict[str, Any] = {
        "url": map_url,
        "status": map_row.get("status"),
        "error": map_row.get("error"),
        "bytes": len(map_raw),
        "sha256": sha256(map_raw),
        "hits": [],
    }
    try:
        source_map = json.loads(map_raw)
        sources = source_map.get("sources") or []
        contents = source_map.get("sourcesContent") or []
        for idx, content in enumerate(contents):
            if not isinstance(content, str):
                continue
            source_name = sources[idx] if idx < len(sources) else str(idx)
            for term in TERMS:
                found = contexts(content, term, radius=10_000)
                if found:
                    map_summary["hits"].append({"source": source_name, "term": term, "contexts": found})
    except Exception as exc:
        map_summary["parse_error"] = f"{type(exc).__name__}: {exc}"
    report["source_map_hits"].append(map_summary)

report["run_finished_utc"] = utcnow()
report_bytes = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
(OUT / "auth-code.json").write_bytes(report_bytes)
summary = {
    "schema": report["schema"],
    "base": BASE,
    "run_started_utc": report["run_started_utc"],
    "run_finished_utc": report["run_finished_utc"],
    "asset_count": len(urls),
    "asset_hit_count": len(report["asset_hits"]),
    "source_map_count": len(report["source_map_hits"]),
    "source_map_hit_count": sum(len(row.get("hits", [])) for row in report["source_map_hits"]),
    "report_sha256": sha256(report_bytes),
}
summary_bytes = (json.dumps(summary, indent=2, sort_keys=True) + "\n").encode()
(OUT / "summary.json").write_bytes(summary_bytes)
(OUT / "manifest.json").write_text(json.dumps({
    "schema": "aiven-console-auth-code-manifest-v1",
    "created_at_utc": utcnow(),
    "files": [
        {"path": "auth-code.json", "bytes": len(report_bytes), "sha256": sha256(report_bytes)},
        {"path": "summary.json", "bytes": len(summary_bytes), "sha256": sha256(summary_bytes)},
    ],
}, indent=2, sort_keys=True) + "\n")
print(json.dumps(summary, sort_keys=True))
