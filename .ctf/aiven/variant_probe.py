#!/usr/bin/env python3
from __future__ import annotations

import concurrent.futures
import datetime as dt
import hashlib
import ipaddress
import json
import os
import socket
import ssl
import struct
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

import dns.exception
import dns.resolver

OUT = Path("probe-output/variants")
OUT.mkdir(parents=True, exist_ok=True)
TARGET = "falcon-bug-bounty-flag-pgsql-dev-sandbox.e.aivencloud.com"
PROJECT = "dev-sandbox"
SERVICE_STEMS = [
    "falcon-bug-bounty-flag-pgsql",
    "falcon-bug-bounty-flag-psql",
    "falcon-bug-bounty-flag-pg",
    "falcon-bug-bounty-flag-postgres",
    "falcon-bug-bounty-flag-postgresql",
]
ZONES = ["e.aivencloud.com", "aivencloud.com"]
KNOWN_PORTS = [22, 80, 443, 5432, 12691, 12692, 25060]
TIMEOUT = 4.0
UA = "Aiven-CTF-authorized-variant-probe/1.0"


def utcnow() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run(argv: list[str], timeout: int = 60) -> dict[str, Any]:
    started = time.monotonic()
    try:
        cp = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
        return {
            "argv": argv,
            "returncode": cp.returncode,
            "stdout": cp.stdout.decode("utf-8", "replace"),
            "stderr": cp.stderr.decode("utf-8", "replace"),
            "stdout_sha256": sha256(cp.stdout),
            "stderr_sha256": sha256(cp.stderr),
            "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
        }
    except Exception as exc:
        return {"argv": argv, "error": f"{type(exc).__name__}: {exc}", "elapsed_ms": round((time.monotonic() - started) * 1000, 3)}


def candidates() -> list[str]:
    names: set[str] = {TARGET}
    for stem in SERVICE_STEMS:
        service_project = f"{stem}-{PROJECT}"
        for zone in ZONES:
            for prefix in ("", "public-", "replica-", "public-replica-"):
                names.add(f"{prefix}{service_project}.{zone}")
            # The old certificate exposed an Aiven node-number naming family.
            for node_id in range(1, 129):
                for prefix in ("n-", "public-n-", "replica-n-", "public-replica-n-"):
                    names.add(f"{prefix}{stem}-{node_id}.{zone}")
        # Exact Aiven service/project layout plus plausible separator/canonicalization deltas.
        names.add(f"{stem}.{PROJECT}.e.aivencloud.com")
        names.add(f"{stem}_{PROJECT}.e.aivencloud.com")
        names.add(f"{stem}-43-{PROJECT}.e.aivencloud.com")
        names.add(f"{stem}43-{PROJECT}.e.aivencloud.com")
    return sorted(names)


def make_resolver(nameserver: str | None) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver(configure=nameserver is None)
    if nameserver:
        resolver.nameservers = [nameserver]
    resolver.timeout = 2.0
    resolver.lifetime = 3.5
    return resolver


def query_name(name: str) -> dict[str, Any]:
    row: dict[str, Any] = {"name": name, "observed_at": utcnow(), "answers": {}}
    for label, ns in (("system", None), ("cloudflare", "1.1.1.1"), ("google", "8.8.8.8"), ("quad9", "9.9.9.9")):
        resolver = make_resolver(ns)
        per: dict[str, Any] = {}
        for qtype in ("A", "AAAA", "CNAME", "HTTPS", "SVCB", "TXT", "SRV"):
            try:
                answer = resolver.resolve(name, qtype, raise_on_no_answer=False)
                values = sorted({r.to_text() for r in answer}) if answer.rrset is not None else []
                per[qtype] = {"values": values, "canonical_name": str(answer.canonical_name)}
            except dns.resolver.NXDOMAIN:
                per[qtype] = {"rcode": "NXDOMAIN"}
            except dns.resolver.NoAnswer:
                per[qtype] = {"rcode": "NOANSWER"}
            except dns.resolver.NoNameservers as exc:
                per[qtype] = {"error": f"NoNameservers: {exc}"}
            except dns.exception.Timeout:
                per[qtype] = {"error": "Timeout"}
            except Exception as exc:
                per[qtype] = {"error": f"{type(exc).__name__}: {exc}"}
        row["answers"][label] = per
    return row


def extract_addresses(row: dict[str, Any]) -> set[str]:
    result: set[str] = set()
    for per_resolver in row.get("answers", {}).values():
        for qtype in ("A", "AAAA"):
            for value in per_resolver.get(qtype, {}).get("values", []):
                try:
                    result.add(str(ipaddress.ip_address(value)))
                except ValueError:
                    pass
    return result


def tcp_probe(ip: str, port: int) -> dict[str, Any]:
    row: dict[str, Any] = {"ip": ip, "port": port, "observed_at": utcnow()}
    started = time.monotonic()
    try:
        with socket.create_connection((ip, port), timeout=TIMEOUT) as sock:
            row["connected"] = True
            row["peer"] = list(sock.getpeername())
            sock.settimeout(1.0)
            try:
                banner = sock.recv(512)
            except socket.timeout:
                banner = b""
            row["banner_b64"] = __import__("base64").b64encode(banner).decode()
            row["banner_text"] = banner.decode("utf-8", "replace")[:1000]
            row["banner_sha256"] = sha256(banner)
    except Exception as exc:
        row["connected"] = False
        row["error"] = f"{type(exc).__name__}: {exc}"
    row["elapsed_ms"] = round((time.monotonic() - started) * 1000, 3)
    return row


def recv_exact(sock: socket.socket, count: int) -> bytes:
    chunks: list[bytes] = []
    remaining = count
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise EOFError(f"wanted={count} received={count-remaining}")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def pg_probe(ip: str, port: int, sni: str) -> dict[str, Any]:
    row: dict[str, Any] = {
        "ip": ip,
        "port": port,
        "sni": sni,
        "observed_at": utcnow(),
        "sent_password_message": False,
        "sent_sql": False,
    }
    raw = None
    tls = None
    try:
        raw = socket.create_connection((ip, port), timeout=TIMEOUT)
        raw.settimeout(TIMEOUT)
        raw.sendall(struct.pack("!II", 8, 80877103))
        ssl_response = recv_exact(raw, 1)
        row["ssl_response_hex"] = ssl_response.hex()
        if ssl_response != b"S":
            row["classification"] = "not_postgresql_ssl"
            return row
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["postgresql"])
        tls = ctx.wrap_socket(raw, server_hostname=sni)
        raw = None
        tls.settimeout(TIMEOUT)
        cert = tls.getpeercert(binary_form=True) or b""
        row["tls"] = {
            "version": tls.version(),
            "cipher": list(tls.cipher() or ()),
            "alpn": tls.selected_alpn_protocol(),
            "cert_der_sha256": sha256(cert),
            "cert_der_b64": __import__("base64").b64encode(cert).decode(),
        }
        params = (
            b"user\x00avnadmin\x00"
            b"database\x00defaultdb\x00"
            b"application_name\x00aiven-ctf-variant-probe\x00"
            b"client_encoding\x00UTF8\x00\x00"
        )
        packet = struct.pack("!II", 8 + len(params), 196608) + params
        tls.sendall(packet)
        typ = recv_exact(tls, 1)
        length = struct.unpack("!I", recv_exact(tls, 4))[0]
        payload = recv_exact(tls, length - 4)
        first: dict[str, Any] = {
            "type": typ.decode("ascii", "replace"),
            "length": length,
            "payload_b64": __import__("base64").b64encode(payload).decode(),
            "payload_sha256": sha256(payload),
        }
        if typ == b"R" and len(payload) >= 4:
            code = struct.unpack("!I", payload[:4])[0]
            first["auth_code"] = code
            first["auth_name"] = {0: "AuthenticationOk", 3: "AuthenticationCleartextPassword", 5: "AuthenticationMD5Password", 10: "AuthenticationSASL"}.get(code, "Other")
            if code == 5 and len(payload) >= 8:
                first["md5_salt_hex"] = payload[4:8].hex()
        row["first_message"] = first
        row["classification"] = first.get("auth_name", "postgres_response")
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


def full_scan(ip: str) -> dict[str, Any]:
    with tempfile.NamedTemporaryFile(prefix="aiven-variant-", suffix=".xml", delete=False) as handle:
        path = Path(handle.name)
    try:
        result = run([
            "nmap", "-Pn", "-n", "-sT", "-p-", "--open", "--reason",
            "--min-rate", "800", "--max-retries", "1", "--host-timeout", "5m",
            "-oX", str(path), ip,
        ], timeout=360)
        xml = path.read_bytes() if path.exists() else b""
        result["xml_b64"] = __import__("base64").b64encode(xml).decode()
        result["xml_sha256"] = sha256(xml)
        return result
    finally:
        try:
            path.unlink()
        except Exception:
            pass


def passive_sources() -> dict[str, Any]:
    urls = {
        "crt_project_zone": "https://crt.sh/?q=" + urllib.parse.quote("%25." + PROJECT + ".e.aivencloud.com") + "&output=json",
        "crt_target_stem": "https://crt.sh/?q=" + urllib.parse.quote("%25falcon-bug-bounty-flag%25") + "&output=json",
        "certspotter_project_zone": "https://api.certspotter.com/v1/issuances?domain=" + urllib.parse.quote(PROJECT + ".e.aivencloud.com") + "&include_subdomains=true&expand=dns_names",
        "google_doh_exact": "https://dns.google/resolve?name=" + urllib.parse.quote(TARGET) + "&type=ANY",
    }
    rows: dict[str, Any] = {}
    for label, url in urls.items():
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json,*/*"})
        try:
            with urllib.request.urlopen(req, timeout=45) as response:
                body = response.read(25_000_000)
                rows[label] = {
                    "url": url,
                    "status": response.status,
                    "headers": dict(response.headers.items()),
                    "body_b64": __import__("base64").b64encode(body).decode(),
                    "body_bytes": len(body),
                    "body_sha256": sha256(body),
                }
        except Exception as exc:
            rows[label] = {"url": url, "error": f"{type(exc).__name__}: {exc}"}
    return rows


report: dict[str, Any] = {
    "schema": "aiven-ctf-challenge-derived-variant-probe-v1",
    "target": TARGET,
    "started_at_utc": utcnow(),
    "runner": {
        "repository": os.environ.get("GITHUB_REPOSITORY"),
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "sha": os.environ.get("GITHUB_SHA"),
    },
    "safety": {
        "dns_names_only_from_exact_challenge_identity": True,
        "credential_guessing": False,
        "password_messages_sent": 0,
        "sql_statements_sent": 0,
        "full_tcp_scan_only_if_challenge_derived_name_resolves": True,
    },
}

names = candidates()
report["candidate_count"] = len(names)
report["passive_sources"] = passive_sources()
rows: list[dict[str, Any]] = []
with concurrent.futures.ThreadPoolExecutor(max_workers=24) as pool:
    futures = {pool.submit(query_name, name): name for name in names}
    for future in concurrent.futures.as_completed(futures):
        rows.append(future.result())
rows.sort(key=lambda x: x["name"])
report["dns"] = rows

resolved = []
for row in rows:
    addresses = sorted(extract_addresses(row))
    if addresses:
        resolved.append({"name": row["name"], "addresses": addresses})
report["resolved"] = resolved

address_to_names: dict[str, list[str]] = {}
for item in resolved:
    for ip in item["addresses"]:
        address_to_names.setdefault(ip, []).append(item["name"])

report["tcp_known_ports"] = []
report["full_scans"] = []
report["postgresql"] = []
for ip, ip_names in sorted(address_to_names.items()):
    for port in KNOWN_PORTS:
        row = tcp_probe(ip, port)
        row["derived_names"] = sorted(ip_names)
        report["tcp_known_ports"].append(row)
    report["full_scans"].append({"ip": ip, "derived_names": sorted(ip_names), "scan": full_scan(ip)})
    for port in (5432, 12691, 12692, 25060):
        if any(r.get("ip") == ip and r.get("port") == port and r.get("connected") for r in report["tcp_known_ports"]):
            for sni in sorted(ip_names)[:20]:
                report["postgresql"].append(pg_probe(ip, port, sni))

report["finished_at_utc"] = utcnow()
raw = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
(OUT / "variant-probe.json").write_bytes(raw)
summary = {
    "schema": report["schema"],
    "target": TARGET,
    "started_at_utc": report["started_at_utc"],
    "finished_at_utc": report["finished_at_utc"],
    "candidate_count": len(names),
    "resolved": resolved,
    "open_known_ports": sorted({(r["ip"], r["port"]) for r in report["tcp_known_ports"] if r.get("connected")}),
    "pg_classifications": sorted({r.get("classification", "unknown") for r in report["postgresql"]}),
    "report_sha256": sha256(raw),
}
summary_raw = (json.dumps(summary, indent=2, sort_keys=True) + "\n").encode()
(OUT / "summary.json").write_bytes(summary_raw)
(OUT / "SHA256SUMS").write_text(
    f"{sha256(raw)}  variant-probe.json\n{sha256(summary_raw)}  summary.json\n"
)
print(json.dumps(summary, sort_keys=True))
