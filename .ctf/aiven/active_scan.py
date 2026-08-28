#!/usr/bin/env python3
from __future__ import annotations

import base64
import datetime as dt
import hashlib
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
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

TARGET_HOST = "falcon-bug-bounty-flag-pgsql-dev-sandbox.e.aivencloud.com"
OLD_HOST = "falcon-bug-bounty-flag-pgsql-dev-sandbox.aivencloud.com"
PASSIVE_IP = "150.136.73.18"
OLD_IP = "193.122.144.9"
OUT = Path("probe-output/active")
OUT.mkdir(parents=True, exist_ok=True)
RUN_STARTED = dt.datetime.now(dt.timezone.utc).isoformat()
TIMEOUT = 6.0
UA = "Aiven-CTF-authorized-target-probe/2.0"


def utcnow() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run(argv: list[str], timeout: int = 600) -> dict[str, Any]:
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
        return {
            "argv": argv,
            "error": f"{type(exc).__name__}: {exc}",
            "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
        }


def fetch(url: str, timeout: int = 30) -> dict[str, Any]:
    row: dict[str, Any] = {"url": url, "observed_at": utcnow()}
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json,text/plain,*/*"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as response:
            body = response.read(20_000_000)
            row.update({
                "status": response.status,
                "final_url": response.geturl(),
                "headers": dict(response.headers.items()),
                "body_b64": base64.b64encode(body).decode(),
                "body_bytes": len(body),
                "body_sha256": sha256(body),
            })
    except Exception as exc:
        row["error"] = f"{type(exc).__name__}: {exc}"
    return row


def body_text(row: dict[str, Any]) -> str:
    try:
        return base64.b64decode(row.get("body_b64", "")).decode("utf-8", "replace")
    except Exception:
        return ""


def exact_dns() -> dict[str, Any]:
    rows = []
    authorities = [
        "ns-1426.awsdns-50.org",
        "ns-1765.awsdns-28.co.uk",
        "ns-341.awsdns-42.com",
        "ns-553.awsdns-05.net",
    ]
    for name in (TARGET_HOST, OLD_HOST):
        for resolver in (None, "1.1.1.1", "8.8.8.8", "9.9.9.9", *authorities):
            for qtype in ("A", "AAAA", "CNAME", "TXT", "SRV", "HTTPS", "SVCB", "SOA"):
                argv = ["dig", "+time=3", "+tries=1", "+noall", "+comments", "+answer", "+authority"]
                if resolver:
                    argv.append("@" + resolver)
                argv.extend([qtype, name])
                row = run(argv, timeout=12)
                row.update({"name": name, "resolver": resolver or "system", "qtype": qtype, "observed_at": utcnow()})
                rows.append(row)
    return {"queries": rows}


def nmap_full(ip: str) -> dict[str, Any]:
    with tempfile.NamedTemporaryFile(prefix="aiven-nmap-", suffix=".xml", delete=False) as handle:
        xml_path = Path(handle.name)
    try:
        result = run([
            "nmap", "-Pn", "-n", "-sT", "-p-", "--open", "--reason",
            "--min-rate", "1200", "--max-retries", "1", "--host-timeout", "7m",
            "-oX", str(xml_path), ip,
        ], timeout=510)
        xml = xml_path.read_bytes() if xml_path.exists() else b""
        result["xml_b64"] = base64.b64encode(xml).decode()
        result["xml_sha256"] = sha256(xml)
        result["open_ports"] = []
        if xml:
            try:
                root = ET.fromstring(xml)
                for port in root.findall(".//port"):
                    state = port.find("state")
                    if state is not None and state.get("state") == "open":
                        service = port.find("service")
                        result["open_ports"].append({
                            "protocol": port.get("protocol"),
                            "port": int(port.get("portid", "0")),
                            "reason": state.get("reason"),
                            "service": service.attrib if service is not None else {},
                        })
            except Exception as exc:
                result["parse_error"] = f"{type(exc).__name__}: {exc}"
        return result
    finally:
        try:
            xml_path.unlink()
        except Exception:
            pass


def recv_exact(sock: socket.socket, count: int) -> bytes:
    chunks: list[bytes] = []
    remaining = count
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise EOFError(f"wanted {count}, got {count - remaining}")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def cert_info(der: bytes) -> dict[str, Any]:
    row: dict[str, Any] = {"der_b64": base64.b64encode(der).decode(), "der_sha256": sha256(der)}
    if not der:
        return row
    pem = ssl.DER_cert_to_PEM_cert(der).encode()
    with tempfile.NamedTemporaryFile(prefix="aiven-cert-", suffix=".pem", delete=False) as handle:
        handle.write(pem)
        path = handle.name
    try:
        row["openssl"] = run([
            "openssl", "x509", "-in", path, "-noout", "-subject", "-issuer", "-serial", "-dates",
            "-fingerprint", "-sha256", "-ext", "subjectAltName",
        ], timeout=20)
    finally:
        try:
            os.unlink(path)
        except Exception:
            pass
    return row


def tcp_banner(ip: str, port: int) -> dict[str, Any]:
    row: dict[str, Any] = {"ip": ip, "port": port, "observed_at": utcnow()}
    started = time.monotonic()
    try:
        with socket.create_connection((ip, port), timeout=TIMEOUT) as sock:
            sock.settimeout(1.5)
            row["connected"] = True
            try:
                data = sock.recv(1024)
            except socket.timeout:
                data = b""
            row["banner_b64"] = base64.b64encode(data).decode()
            row["banner_sha256"] = sha256(data)
            row["banner_text"] = data.decode("utf-8", "replace")[:1000]
    except Exception as exc:
        row["connected"] = False
        row["error"] = f"{type(exc).__name__}: {exc}"
    row["elapsed_ms"] = round((time.monotonic() - started) * 1000, 3)
    return row


def pg_probe(ip: str, port: int, sni: str | None, user: str = "avnadmin", database: str = "defaultdb") -> dict[str, Any]:
    row: dict[str, Any] = {
        "ip": ip,
        "port": port,
        "sni": sni,
        "user": user,
        "database": database,
        "observed_at": utcnow(),
        "sent_password_message": False,
        "sent_sql": False,
    }
    raw = None
    tls = None
    try:
        raw = socket.create_connection((ip, port), timeout=TIMEOUT)
        raw.settimeout(TIMEOUT)
        ssl_request = struct.pack("!II", 8, 80877103)
        raw.sendall(ssl_request)
        response = recv_exact(raw, 1)
        row["ssl_response_hex"] = response.hex()
        if response != b"S":
            row["classification"] = "postgres_ssl_refused_or_not_postgresql"
            return row
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_alpn_protocols(["postgresql"])
        tls = context.wrap_socket(raw, server_hostname=sni)
        raw = None
        tls.settimeout(TIMEOUT)
        row["tls_version"] = tls.version()
        row["tls_cipher"] = list(tls.cipher() or ())
        row["selected_alpn"] = tls.selected_alpn_protocol()
        row["certificate"] = cert_info(tls.getpeercert(binary_form=True) or b"")
        params = (
            b"user\x00" + user.encode() + b"\x00"
            + b"database\x00" + database.encode() + b"\x00"
            + b"application_name\x00aiven-ctf-active-probe\x00"
            + b"client_encoding\x00UTF8\x00\x00"
        )
        startup = struct.pack("!II", 8 + len(params), 196608) + params
        tls.sendall(startup)
        msg_type = recv_exact(tls, 1)
        length = struct.unpack("!I", recv_exact(tls, 4))[0]
        payload = recv_exact(tls, length - 4)
        msg = {
            "type": msg_type.decode("ascii", "replace"),
            "length": length,
            "payload_b64": base64.b64encode(payload).decode(),
            "payload_sha256": sha256(payload),
        }
        if msg_type == b"R" and len(payload) >= 4:
            code = struct.unpack("!I", payload[:4])[0]
            msg["auth_code"] = code
            msg["auth_name"] = {0:"AuthenticationOk",3:"AuthenticationCleartextPassword",5:"AuthenticationMD5Password",10:"AuthenticationSASL"}.get(code,"Other")
            if code == 5 and len(payload) >= 8:
                msg["md5_salt_hex"] = payload[4:8].hex()
        row["first_message"] = msg
        row["classification"] = msg.get("auth_name", "postgres_response")
    except Exception as exc:
        row["classification"] = "probe_error"
        row["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        for sock in (tls, raw):
            try:
                if sock is not None:
                    sock.close()
            except Exception:
                pass
    return row


def http_probe(ip: str, port: int, tls_mode: bool) -> dict[str, Any]:
    row: dict[str, Any] = {"ip": ip, "port": port, "tls": tls_mode, "observed_at": utcnow()}
    raw = None
    sock = None
    try:
        raw = socket.create_connection((ip, port), timeout=TIMEOUT)
        raw.settimeout(TIMEOUT)
        if tls_mode:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw, server_hostname=TARGET_HOST)
            raw = None
            row["certificate"] = cert_info(sock.getpeercert(binary_form=True) or b"")
        else:
            sock = raw
            raw = None
        request = f"HEAD / HTTP/1.1\r\nHost: {TARGET_HOST}\r\nUser-Agent: {UA}\r\nConnection: close\r\n\r\n".encode()
        sock.sendall(request)
        chunks = []
        total = 0
        while total < 65536:
            try:
                chunk = sock.recv(min(8192, 65536-total))
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        data = b"".join(chunks)
        row["response_b64"] = base64.b64encode(data).decode()
        row["response_sha256"] = sha256(data)
        row["response_text"] = data.decode("utf-8", "replace")[:10000]
    except Exception as exc:
        row["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        for candidate in (sock, raw):
            try:
                if candidate is not None:
                    candidate.close()
            except Exception:
                pass
    return row


report: dict[str, Any] = {
    "schema": "aiven-ctf-active-passive-ip-probe-v1",
    "target": TARGET_HOST,
    "passive_ip": PASSIVE_IP,
    "old_ip": OLD_IP,
    "run_started_utc": RUN_STARTED,
    "runner": {
        "repository": os.environ.get("GITHUB_REPOSITORY"),
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "sha": os.environ.get("GITHUB_SHA"),
    },
    "safety": {
        "scope": "single exact authorized CTF hostname and two target-derived IP observations",
        "password_messages_sent": 0,
        "sql_statements_sent": 0,
        "brute_force": False,
        "full_tcp_scan_targets": [PASSIVE_IP],
    },
}

report["dns"] = exact_dns()
report["passive_sources"] = {
    "internetdb_passive_ip": fetch("https://internetdb.shodan.io/" + PASSIVE_IP),
    "otx_passive_ip_general": fetch("https://otx.alienvault.com/api/v1/indicators/IPv4/" + PASSIVE_IP + "/general"),
    "otx_passive_ip_passive_dns": fetch("https://otx.alienvault.com/api/v1/indicators/IPv4/" + PASSIVE_IP + "/passive_dns"),
    "hackertarget_reverse_ip": fetch("https://api.hackertarget.com/reverseiplookup/?q=" + PASSIVE_IP),
    "hackertarget_geoip": fetch("https://api.hackertarget.com/geoip/?q=" + PASSIVE_IP),
    "arin_rdap": fetch("https://rdap.arin.net/registry/ip/" + PASSIVE_IP),
    "google_doh_target_a": fetch("https://dns.google/resolve?name=" + urllib.parse.quote(TARGET_HOST) + "&type=A"),
}
report["nmap_passive_ip"] = nmap_full(PASSIVE_IP)
open_ports = sorted({row["port"] for row in report["nmap_passive_ip"].get("open_ports", []) if row.get("protocol") == "tcp"})
report["open_ports"] = open_ports
report["banners"] = [tcp_banner(PASSIVE_IP, port) for port in open_ports]
report["protocol_probes"] = []
for port in open_ports:
    for sni in (TARGET_HOST, OLD_HOST, None):
        report["protocol_probes"].append({"kind": "postgresql", "result": pg_probe(PASSIVE_IP, port, sni)})
    report["protocol_probes"].append({"kind": "http", "result": http_probe(PASSIVE_IP, port, False)})
    report["protocol_probes"].append({"kind": "https", "result": http_probe(PASSIVE_IP, port, True)})

report["old_ip_known_ports"] = [tcp_banner(OLD_IP, port) for port in (12691, 12692)]
report["run_finished_utc"] = utcnow()

report_path = OUT / "active-probe.json"
report_bytes = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
report_path.write_bytes(report_bytes)
summary = {
    "schema": report["schema"],
    "target": TARGET_HOST,
    "passive_ip": PASSIVE_IP,
    "run_started_utc": RUN_STARTED,
    "run_finished_utc": report["run_finished_utc"],
    "open_ports": open_ports,
    "nmap_returncode": report["nmap_passive_ip"].get("returncode"),
    "passive_source_statuses": {
        k: {"status": v.get("status"), "error": v.get("error"), "bytes": v.get("body_bytes"), "sha256": v.get("body_sha256")}
        for k, v in sorted(report["passive_sources"].items())
    },
    "report_sha256": sha256(report_bytes),
}
summary_bytes = (json.dumps(summary, indent=2, sort_keys=True) + "\n").encode()
(OUT / "summary.json").write_bytes(summary_bytes)
manifest = {
    "schema": "aiven-ctf-active-probe-manifest-v1",
    "created_at_utc": utcnow(),
    "files": [
        {"path": "active-probe.json", "bytes": len(report_bytes), "sha256": sha256(report_bytes)},
        {"path": "summary.json", "bytes": len(summary_bytes), "sha256": sha256(summary_bytes)},
    ],
}
(OUT / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
print(json.dumps(summary, sort_keys=True))
