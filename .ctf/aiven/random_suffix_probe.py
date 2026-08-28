#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import ipaddress
import itertools
import json
import os
import ssl
import socket
import string
from pathlib import Path
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.resolver

OUT = Path("probe-output/random-suffix")
OUT.mkdir(parents=True, exist_ok=True)
SERVICE = "falcon-bug-bounty-flag-pgsql"
PROJECT = "dev-sandbox"
ZONE = "e.aivencloud.com"
EXACT_SCOPE = f"{SERVICE}-{PROJECT}.{ZONE}"
CONCURRENCY = 96
QUERY_TIMEOUT = 2.5


def utcnow() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def candidate_names() -> list[str]:
    # Aiven's official hostname documentation states that a recently reused
    # service name may become <SERVICE_NAME><3RANDOMLETTERS>-<PROJECT_NAME>.*.
    return [
        f"{SERVICE}{''.join(chars)}-{PROJECT}.{ZONE}"
        for chars in itertools.product(string.ascii_lowercase, repeat=3)
    ]


def resolver(nameservers: list[str]) -> dns.asyncresolver.Resolver:
    r = dns.asyncresolver.Resolver(configure=False)
    r.nameservers = nameservers
    r.timeout = QUERY_TIMEOUT
    r.lifetime = QUERY_TIMEOUT
    return r


async def resolve_one(name: str, sem: asyncio.Semaphore) -> dict[str, Any] | None:
    # Use two independent recursive resolvers, but only ask the second when
    # the first produces a positive/non-NXDOMAIN signal. This keeps query load bounded.
    async with sem:
        first = resolver(["1.1.1.1"])
        try:
            ans = await first.resolve(name, "A", raise_on_no_answer=False)
            values = sorted({rr.to_text() for rr in ans}) if ans.rrset is not None else []
            canonical = str(ans.canonical_name)
        except dns.resolver.NXDOMAIN:
            return None
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout) as exc:
            # A timeout or SERVFAIL is not a positive identity signal; record only a bounded sample elsewhere.
            return {"name": name, "transient": type(exc).__name__}
        except Exception as exc:
            return {"name": name, "transient": f"{type(exc).__name__}: {exc}"}

        if not values and canonical.rstrip(".").lower() == name.lower():
            return None

        row: dict[str, Any] = {
            "name": name,
            "cloudflare": {"A": values, "canonical_name": canonical},
            "observed_at": utcnow(),
        }
        second = resolver(["8.8.8.8"])
        try:
            ans2 = await second.resolve(name, "A", raise_on_no_answer=False)
            row["google"] = {
                "A": sorted({rr.to_text() for rr in ans2}) if ans2.rrset is not None else [],
                "canonical_name": str(ans2.canonical_name),
            }
        except Exception as exc:
            row["google"] = {"error": f"{type(exc).__name__}: {exc}"}
        return row


async def enumerate_names() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    sem = asyncio.Semaphore(CONCURRENCY)
    positives: list[dict[str, Any]] = []
    transient_sample: list[dict[str, Any]] = []
    names = candidate_names()
    for start in range(0, len(names), 512):
        batch = names[start:start + 512]
        rows = await asyncio.gather(*(resolve_one(name, sem) for name in batch))
        for row in rows:
            if not row:
                continue
            if "transient" in row:
                if len(transient_sample) < 100:
                    transient_sample.append(row)
            else:
                positives.append(row)
    return positives, transient_sample


def tcp_connect(ip: str, port: int, timeout: float = 4.0) -> dict[str, Any]:
    row: dict[str, Any] = {"ip": ip, "port": port, "observed_at": utcnow()}
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            row["connected"] = True
            row["peer"] = list(sock.getpeername())
    except Exception as exc:
        row["connected"] = False
        row["error"] = f"{type(exc).__name__}: {exc}"
    return row


def tls_cert(ip: str, port: int, sni: str, timeout: float = 5.0) -> dict[str, Any]:
    row: dict[str, Any] = {"ip": ip, "port": port, "sni": sni, "observed_at": utcnow()}
    raw = None
    tls = None
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
        raw.settimeout(timeout)
        # PostgreSQL SSLRequest; if this is not a PostgreSQL listener, stop.
        raw.sendall((8).to_bytes(4, "big") + (80877103).to_bytes(4, "big"))
        response = raw.recv(1)
        row["sslrequest_response_hex"] = response.hex()
        if response != b"S":
            row["classification"] = "not_postgresql_ssl"
            return row
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["postgresql"])
        tls = ctx.wrap_socket(raw, server_hostname=sni)
        raw = None
        der = tls.getpeercert(binary_form=True) or b""
        row.update({
            "classification": "postgresql_tls",
            "tls_version": tls.version(),
            "cipher": list(tls.cipher() or ()),
            "selected_alpn": tls.selected_alpn_protocol(),
            "cert_der_b64": __import__("base64").b64encode(der).decode(),
            "cert_der_sha256": sha256(der),
        })
    except Exception as exc:
        row["classification"] = "probe_error"
        row["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        for candidate in (tls, raw):
            try:
                if candidate is not None:
                    candidate.close()
            except Exception:
                pass
    return row


async def main() -> None:
    started = utcnow()
    positives, transient = await enumerate_names()

    # Active follow-up is strictly limited to a DNS-positive name from the
    # documented exact challenge-derived naming rule. No password or SQL is sent.
    followups: list[dict[str, Any]] = []
    for row in positives:
        addresses: set[str] = set()
        for source in (row.get("cloudflare", {}), row.get("google", {})):
            for value in source.get("A", []):
                try:
                    addresses.add(str(ipaddress.ip_address(value)))
                except ValueError:
                    pass
        names_to_try = [row["name"], "public-" + row["name"]]
        for ip in sorted(addresses):
            for port in (12691, 12692, 5432, 443):
                tcp = tcp_connect(ip, port)
                tcp["derived_name"] = row["name"]
                followups.append(tcp)
                if tcp.get("connected") and port in (12691, 12692, 5432):
                    for sni in names_to_try:
                        followups.append(tls_cert(ip, port, sni))

    report: dict[str, Any] = {
        "schema": "aiven-ctf-documented-random-suffix-probe-v1",
        "exact_scope_target": EXACT_SCOPE,
        "started_at_utc": started,
        "finished_at_utc": utcnow(),
        "runner": {
            "repository": os.environ.get("GITHUB_REPOSITORY"),
            "run_id": os.environ.get("GITHUB_RUN_ID"),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
            "sha": os.environ.get("GITHUB_SHA"),
        },
        "safety": {
            "candidate_rule": "official Aiven <SERVICE_NAME><3RANDOMLETTERS>-<PROJECT_NAME> hostname rule",
            "candidate_count": 26 ** 3,
            "dns_only_until_positive": True,
            "password_messages_sent": 0,
            "sql_statements_sent": 0,
            "credential_guessing": False,
        },
        "positive_dns_rows": positives,
        "transient_error_sample": transient,
        "followups": followups,
    }
    raw = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
    (OUT / "random-suffix-probe.json").write_bytes(raw)
    summary = {
        "schema": report["schema"],
        "exact_scope_target": EXACT_SCOPE,
        "candidate_count": 26 ** 3,
        "positive_count": len(positives),
        "positive_names": [row["name"] for row in positives],
        "followup_open": [
            {"ip": row.get("ip"), "port": row.get("port"), "derived_name": row.get("derived_name")}
            for row in followups if row.get("connected")
        ],
        "certificate_sha256s": sorted({row.get("cert_der_sha256") for row in followups if row.get("cert_der_sha256")}),
        "started_at_utc": started,
        "finished_at_utc": report["finished_at_utc"],
        "report_sha256": sha256(raw),
    }
    summary_raw = (json.dumps(summary, indent=2, sort_keys=True) + "\n").encode()
    (OUT / "summary.json").write_bytes(summary_raw)
    (OUT / "SHA256SUMS").write_text(
        f"{sha256(raw)}  random-suffix-probe.json\n{sha256(summary_raw)}  summary.json\n"
    )
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    asyncio.run(main())
