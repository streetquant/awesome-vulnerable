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
OUT = Path("probe-output/console-auth-surface")
OUT.mkdir(parents=True, exist_ok=True)
UA = "Mozilla/5.0 authorized-aiven-ctf-auth-surface-research/1.0"
TERMS = [
    "forgot password",
    "forgot-password",
    "forgot_password",
    "reset password",
    "reset-password",
    "reset_password",
    "password reset",
    "password-reset",
    "password_reset",
    "recover password",
    "recovery",
    "authenticate_user",
    "two_factor",
    "totp",
    "email otp",
    "mfa",
    "/v1/user",
    "/v1/auth",
    "/v1/me",
    "api.aiven.io",
]
MAX_ASSETS = 80
MAX_ASSET_BYTES = 25_000_000


def utcnow() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fetch(url: str) -> dict[str, Any]:
    row: dict[str, Any] = {"url": url, "observed_at": utcnow()}
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "text/html,application/javascript,application/json,text/plain,*/*"})
    try:
        with urllib.request.urlopen(req, timeout=45, context=ssl.create_default_context()) as response:
            body = response.read(MAX_ASSET_BYTES + 1)
            row.update({
                "status": response.status,
                "final_url": response.geturl(),
                "headers": dict(response.headers.items()),
                "body_bytes": len(body),
                "body_sha256": sha256(body),
                "truncated": len(body) > MAX_ASSET_BYTES,
            })
            if len(body) <= MAX_ASSET_BYTES:
                row["body_b64"] = base64.b64encode(body).decode()
    except Exception as exc:
        row["error"] = f"{type(exc).__name__}: {exc}"
    return row


def body(row: dict[str, Any]) -> bytes:
    try:
        return base64.b64decode(row.get("body_b64", ""))
    except Exception:
        return b""


def extract_asset_urls(index_text: str, base_url: str) -> list[str]:
    candidates = set()
    patterns = [
        r'<script[^>]+src=["\']([^"\']+)["\']',
        r'<link[^>]+href=["\']([^"\']+)["\']',
        r'["\']([^"\']+\.(?:js|mjs|css)(?:\?[^"\']*)?)["\']',
    ]
    for pattern in patterns:
        for raw in re.findall(pattern, index_text, flags=re.I):
            raw = html.unescape(raw.strip())
            url = urllib.parse.urljoin(base_url, raw)
            parsed = urllib.parse.urlparse(url)
            if parsed.scheme in ("http", "https") and parsed.netloc == urllib.parse.urlparse(BASE).netloc:
                candidates.add(url)
    return sorted(candidates)[:MAX_ASSETS]


def contexts(text: str, term: str, radius: int = 700) -> list[str]:
    out = []
    lower = text.lower()
    needle = term.lower()
    start = 0
    while len(out) < 40:
        idx = lower.find(needle, start)
        if idx < 0:
            break
        left = max(0, idx - radius)
        right = min(len(text), idx + len(term) + radius)
        out.append(text[left:right])
        start = idx + max(1, len(term))
    return out


report: dict[str, Any] = {
    "schema": "aiven-console-auth-surface-v1",
    "base": BASE,
    "run_started_utc": utcnow(),
    "runner": {
        "repository": os.environ.get("GITHUB_REPOSITORY"),
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "sha": os.environ.get("GITHUB_SHA"),
    },
    "safety": {
        "passive_get_only": True,
        "no_credentials": True,
        "no_login_attempt": True,
        "no_password_reset_trigger": True,
    },
}

index = fetch(BASE)
report["index"] = index
index_text = body(index).decode("utf-8", "replace")
asset_urls = extract_asset_urls(index_text, index.get("final_url") or BASE)
report["asset_urls"] = asset_urls
assets = []
hits = []
for url in asset_urls:
    row = fetch(url)
    assets.append({k: v for k, v in row.items() if k != "body_b64"})
    text = body(row).decode("utf-8", "replace")
    if not text:
        continue
    for term in TERMS:
        found = contexts(text, term)
        if found:
            hits.append({
                "url": url,
                "asset_sha256": row.get("body_sha256"),
                "term": term,
                "contexts": found,
            })
report["assets"] = assets
report["hits"] = hits
report["run_finished_utc"] = utcnow()

report_bytes = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
(OUT / "auth-surface.json").write_bytes(report_bytes)
summary = {
    "schema": report["schema"],
    "base": BASE,
    "run_started_utc": report["run_started_utc"],
    "run_finished_utc": report["run_finished_utc"],
    "index_status": index.get("status"),
    "index_error": index.get("error"),
    "asset_count": len(asset_urls),
    "fetched_asset_count": sum(1 for row in assets if row.get("status") == 200),
    "hit_count": len(hits),
    "terms_with_hits": sorted({row["term"] for row in hits}),
    "report_sha256": sha256(report_bytes),
}
summary_bytes = (json.dumps(summary, indent=2, sort_keys=True) + "\n").encode()
(OUT / "summary.json").write_bytes(summary_bytes)
manifest = {
    "schema": "aiven-console-auth-surface-manifest-v1",
    "created_at_utc": utcnow(),
    "files": [
        {"path": "auth-surface.json", "bytes": len(report_bytes), "sha256": sha256(report_bytes)},
        {"path": "summary.json", "bytes": len(summary_bytes), "sha256": sha256(summary_bytes)},
    ],
}
(OUT / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
print(json.dumps(summary, sort_keys=True))
