#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from playwright.async_api import async_playwright, Response

URL = "https://bugcrowd.com/engagements/aiven-mbb-og"
OUT = Path("probe-output/bugcrowd-public")
OUT.mkdir(parents=True, exist_ok=True)
MAX_BODY = 2_000_000
INTEREST = re.compile(r"(?i)(engagement|brief|scope|target|reward|credential|resource|claim|challenge|aiven|api|graphql)")
SENSITIVE_HEADER = re.compile(r"(?i)^(set-cookie|cookie|authorization|proxy-authorization|x-csrf-token|x-xsrf-token)$")


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def clean_headers(headers: dict[str, str]) -> dict[str, str]:
    return {k: v for k, v in headers.items() if not SENSITIVE_HEADER.match(k)}


async def main() -> None:
    report: dict[str, Any] = {
        "schema": "aiven-ctf-bugcrowd-public-render-v1",
        "target_url": URL,
        "started_at_utc": utcnow(),
        "runner": {
            "repository": os.environ.get("GITHUB_REPOSITORY"),
            "run_id": os.environ.get("GITHUB_RUN_ID"),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
            "sha": os.environ.get("GITHUB_SHA"),
        },
        "safety": {
            "public_unauthenticated_only": True,
            "cookies_recorded": False,
            "credentials_used": False,
            "mutations": False,
        },
        "responses": [],
        "requests": [],
        "console": [],
    }

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True, args=["--disable-dev-shm-usage"])
        context = await browser.new_context(
            locale="en-US",
            user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/151 Safari/537.36",
            viewport={"width": 1440, "height": 1000},
        )
        page = await context.new_page()

        page.on("console", lambda msg: report["console"].append({"type": msg.type, "text": msg.text[:4000]}))
        page.on(
            "request",
            lambda req: report["requests"].append(
                {
                    "url": req.url,
                    "method": req.method,
                    "resource_type": req.resource_type,
                    "is_navigation": req.is_navigation_request(),
                }
            )
            if INTEREST.search(req.url)
            else None,
        )

        async def capture_response(response: Response) -> None:
            if not INTEREST.search(response.url):
                return
            row: dict[str, Any] = {
                "url": response.url,
                "status": response.status,
                "headers": clean_headers(await response.all_headers()),
            }
            content_type = row["headers"].get("content-type", "")
            if any(kind in content_type.lower() for kind in ("json", "text", "javascript", "html", "xml")):
                try:
                    body = await response.body()
                    if len(body) <= MAX_BODY:
                        row["body_b64"] = base64.b64encode(body).decode()
                        row["body_bytes"] = len(body)
                        row["body_sha256"] = sha256(body)
                    else:
                        row["body_bytes"] = len(body)
                        row["body_sha256"] = sha256(body)
                        row["body_omitted"] = "over_limit"
                except Exception as exc:
                    row["body_error"] = f"{type(exc).__name__}: {exc}"
            report["responses"].append(row)

        page.on("response", capture_response)

        navigation_error = None
        try:
            response = await page.goto(URL, wait_until="domcontentloaded", timeout=90_000)
            report["navigation"] = {
                "final_url": page.url,
                "status": response.status if response else None,
            }
            await page.wait_for_timeout(15_000)
            try:
                await page.wait_for_load_state("networkidle", timeout=20_000)
            except Exception:
                pass
        except Exception as exc:
            navigation_error = f"{type(exc).__name__}: {exc}"
            report["navigation_error"] = navigation_error

        html = await page.content()
        text = await page.locator("body").inner_text() if await page.locator("body").count() else ""
        links = await page.locator("a").evaluate_all(
            "els => els.map(a => ({text:(a.innerText||'').trim(), href:a.href})).filter(x => x.href)"
        )
        scripts = await page.locator("script").evaluate_all(
            "els => els.map(s => ({src:s.src, type:s.type, text:(s.textContent||'').slice(0,200000)}))"
        )
        report["dom"] = {
            "final_url": page.url,
            "title": await page.title(),
            "html_b64": base64.b64encode(html.encode()).decode(),
            "html_bytes": len(html.encode()),
            "html_sha256": sha256(html.encode()),
            "body_text": text[:1_000_000],
            "body_text_sha256": sha256(text.encode()),
            "links": links[:5000],
            "scripts": scripts[:1000],
        }
        await page.screenshot(path=str(OUT / "page.png"), full_page=True)

        storage = await page.evaluate(
            """() => ({
              localStorageKeys: Object.keys(localStorage),
              sessionStorageKeys: Object.keys(sessionStorage)
            })"""
        )
        report["storage_keys_only"] = storage
        await browser.close()

    report["finished_at_utc"] = utcnow()
    raw = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
    (OUT / "public-render.json").write_bytes(raw)

    # Produce a compact text extract for quick triage without response bodies.
    compact = {
        "schema": report["schema"],
        "target_url": URL,
        "started_at_utc": report["started_at_utc"],
        "finished_at_utc": report["finished_at_utc"],
        "navigation": report.get("navigation"),
        "navigation_error": report.get("navigation_error"),
        "title": report.get("dom", {}).get("title"),
        "final_url": report.get("dom", {}).get("final_url"),
        "body_text": report.get("dom", {}).get("body_text", "")[:100_000],
        "interesting_response_urls": sorted({r["url"] for r in report["responses"]}),
        "interesting_request_urls": sorted({r["url"] for r in report["requests"]}),
        "report_sha256": sha256(raw),
    }
    compact_raw = (json.dumps(compact, indent=2, sort_keys=True) + "\n").encode()
    (OUT / "summary.json").write_bytes(compact_raw)
    print(json.dumps({
        "title": compact["title"],
        "final_url": compact["final_url"],
        "body_preview": compact["body_text"][:2000],
        "interesting_response_count": len(compact["interesting_response_urls"]),
        "report_sha256": compact["report_sha256"],
    }, sort_keys=True))


if __name__ == "__main__":
    asyncio.run(main())
