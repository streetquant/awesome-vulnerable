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
from pathlib import Path
from typing import Any

NEW_HOST = "falcon-bug-bounty-flag-pgsql-dev-sandbox.e.aivencloud.com"
OLD_HOST = "falcon-bug-bounty-flag-pgsql-dev-sandbox.aivencloud.com"
OLD_PUBLIC_HOST = "public-falcon-bug-bounty-flag-pgsql-dev-sandbox.aivencloud.com"
NEW_PUBLIC_HOST = "public-falcon-bug-bounty-flag-pgsql-dev-sandbox.e.aivencloud.com"
OLD_SERVICE_HOST = "public-n-falcon-bug-bounty-flag-pgsql-43.aivencloud.com"
NEW_SERVICE_HOST = "public-n-falcon-bug-bounty-flag-pgsql-43.e.aivencloud.com"
LAST_KNOWN_IP = "193.122.144.9"
KNOWN_PG_PORTS = [12691, 12692]
DNS_NAMES = [
    NEW_HOST,
    NEW_PUBLIC_HOST,
    NEW_SERVICE_HOST,
    OLD_HOST,
    OLD_PUBLIC_HOST,
    OLD_SERVICE_HOST,
    "e.aivencloud.com",
    "aivencloud.com",
]
DNS_RESOLVERS = [
    ("system", None),
    ("cloudflare", "1.1.1.1"),
    ("google", "8.8.8.8"),
    ("quad9", "9.9.9.9"),
]
SNI_VARIANTS = [NEW_HOST, NEW_PUBLIC_HOST, NEW_SERVICE_HOST, OLD_HOST, OLD_PUBLIC_HOST, OLD_SERVICE_HOST, None]
PG_IDENTITIES = [
    ("avnadmin", "defaultdb"),
    ("postgres", "postgres"),
    ("ctf_probe_nonexistent", "postgres"),
]
OUT = Path("probe-output")
OUT.mkdir(parents=True, exist_ok=True)
TIMEOUT = 7.0
RUN_STARTED = dt.datetime.now(dt.timezone.utc).isoformat()


def utcnow() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def which(name: str) -> str | None:
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(directory) / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def safe_run(argv: list[str], timeout: int = 30, input_bytes: bytes | None = None) -> dict[str, Any]:
    started = time.monotonic()
    try:
        cp = subprocess.run(
            argv,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        return {
            "argv": argv,
            "returncode": cp.returncode,
            "stdout": cp.stdout.decode("utf-8", "replace"),
            "stderr": cp.stderr.decode("utf-8", "replace"),
            "stdout_sha256": sha256_bytes(cp.stdout),
            "stderr_sha256": sha256_bytes(cp.stderr),
            "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
        }
    except Exception as exc:
        return {
            "argv": argv,
            "error": f"{type(exc).__name__}: {exc}",
            "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
        }


def dns_probe() -> dict[str, Any]:
    result: dict[str, Any] = {
        "observed_at": utcnow(),
        "queries": [],
        "getaddrinfo": {},
        "trace": None,
    }
    for name in DNS_NAMES:
        try:
            infos = socket.getaddrinfo(name, None, type=socket.SOCK_STREAM)
            result["getaddrinfo"][name] = sorted({row[4][0] for row in infos})
        except Exception as exc:
            result["getaddrinfo"][name] = {"error": f"{type(exc).__name__}: {exc}"}

    if not which("dig"):
        result["dig_unavailable"] = True
        return result

    for resolver_name, resolver_ip in DNS_RESOLVERS:
        for name in DNS_NAMES:
            for qtype in ("A", "AAAA", "CNAME", "SOA", "NS"):
                argv = ["dig", "+time=3", "+tries=1", "+noall", "+comments", "+answer", "+authority"]
                if resolver_ip:
                    argv.append(f"@{resolver_ip}")
                argv.extend([qtype, name])
                row = safe_run(argv, timeout=10)
                row.update({"resolver_name": resolver_name, "resolver_ip": resolver_ip, "name": name, "qtype": qtype})
                result["queries"].append(row)

    result["trace"] = safe_run(["dig", "+time=3", "+tries=1", "+trace", "A", NEW_HOST], timeout=30)
    return result


def recv_exact(sock: socket.socket, count: int) -> bytes:
    chunks: list[bytes] = []
    remaining = count
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise EOFError(f"wanted {count} bytes, received {count - remaining}")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def parse_pg_error(payload: bytes) -> dict[str, str]:
    fields: dict[str, str] = {}
    i = 0
    while i < len(payload) and payload[i] != 0:
        code = chr(payload[i])
        i += 1
        end = payload.find(b"\x00", i)
        if end < 0:
            break
        fields[code] = payload[i:end].decode("utf-8", "replace")
        i = end + 1
    return fields


def read_first_pg_message(sock: socket.socket) -> dict[str, Any]:
    msg_type = recv_exact(sock, 1)
    length_raw = recv_exact(sock, 4)
    length = struct.unpack("!I", length_raw)[0]
    if length < 4 or length > 1024 * 1024:
        return {"type": msg_type.decode("ascii", "replace"), "invalid_length": length}
    payload = recv_exact(sock, length - 4)
    row: dict[str, Any] = {
        "type": msg_type.decode("ascii", "replace"),
        "length": length,
        "payload_b64": base64.b64encode(payload).decode(),
        "payload_sha256": sha256_bytes(payload),
    }
    if msg_type == b"R" and len(payload) >= 4:
        auth_code = struct.unpack("!I", payload[:4])[0]
        auth_names = {
            0: "AuthenticationOk",
            2: "AuthenticationKerberosV5",
            3: "AuthenticationCleartextPassword",
            5: "AuthenticationMD5Password",
            6: "AuthenticationSCMCredential",
            7: "AuthenticationGSS",
            8: "AuthenticationGSSContinue",
            9: "AuthenticationSSPI",
            10: "AuthenticationSASL",
            11: "AuthenticationSASLContinue",
            12: "AuthenticationSASLFinal",
        }
        row["auth_code"] = auth_code
        row["auth_name"] = auth_names.get(auth_code, "Unknown")
        if auth_code == 5 and len(payload) >= 8:
            row["md5_salt_hex"] = payload[4:8].hex()
        if auth_code == 10 and len(payload) > 4:
            row["sasl_mechanisms"] = [
                part.decode("ascii", "replace")
                for part in payload[4:].split(b"\x00")
                if part
            ]
    elif msg_type == b"E":
        row["error_fields"] = parse_pg_error(payload)
    return row


def decode_certificate(der: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {
        "der_b64": base64.b64encode(der).decode(),
        "der_sha256": sha256_bytes(der),
    }
    if not der:
        return result
    pem = ssl.DER_cert_to_PEM_cert(der).encode()
    result["pem_sha256"] = sha256_bytes(pem)
    if which("openssl"):
        with tempfile.NamedTemporaryFile(prefix="aiven-cert-", suffix=".pem", delete=True) as handle:
            handle.write(pem)
            handle.flush()
            result["openssl"] = safe_run(
                [
                    "openssl", "x509", "-in", handle.name, "-noout",
                    "-subject", "-issuer", "-serial", "-dates",
                    "-fingerprint", "-sha256", "-ext", "subjectAltName",
                ],
                timeout=10,
            )
    return result


def tcp_connect(ip: str, port: int) -> dict[str, Any]:
    started = time.monotonic()
    row: dict[str, Any] = {"ip": ip, "port": port, "observed_at": utcnow()}
    try:
        with socket.create_connection((ip, port), timeout=TIMEOUT) as sock:
            row["connected"] = True
            row["peername"] = list(sock.getpeername())
            sock.settimeout(1.0)
            try:
                banner = sock.recv(256)
            except socket.timeout:
                banner = b""
            row["initial_banner_b64"] = base64.b64encode(banner).decode()
            row["initial_banner_sha256"] = sha256_bytes(banner)
    except Exception as exc:
        row["connected"] = False
        row["error"] = f"{type(exc).__name__}: {exc}"
    row["elapsed_ms"] = round((time.monotonic() - started) * 1000, 3)
    return row


def pg_tls_probe(ip: str, port: int, sni: str | None, alpn: bool, user: str, database: str) -> dict[str, Any]:
    row: dict[str, Any] = {
        "observed_at": utcnow(),
        "ip": ip,
        "port": port,
        "sni": sni,
        "requested_alpn": "postgresql" if alpn else None,
        "user": user,
        "database": database,
        "sent_password_message": False,
        "sent_sasl_message": False,
        "sent_sql": False,
    }
    raw: socket.socket | None = None
    tls: ssl.SSLSocket | None = None
    try:
        raw = socket.create_connection((ip, port), timeout=TIMEOUT)
        raw.settimeout(TIMEOUT)
        ssl_request = struct.pack("!II", 8, 80877103)
        raw.sendall(ssl_request)
        ssl_response = recv_exact(raw, 1)
        row["ssl_request_hex"] = ssl_request.hex()
        row["ssl_response_hex"] = ssl_response.hex()
        if ssl_response != b"S":
            row["classification"] = "postgres_ssl_refused_or_not_postgresql"
            return row

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        if alpn:
            context.set_alpn_protocols(["postgresql"])
        tls = context.wrap_socket(raw, server_hostname=sni)
        raw = None
        tls.settimeout(TIMEOUT)
        row["tls_version"] = tls.version()
        row["tls_cipher"] = list(tls.cipher() or ())
        row["selected_alpn"] = tls.selected_alpn_protocol()
        row["certificate"] = decode_certificate(tls.getpeercert(binary_form=True) or b"")

        params = (
            b"user\x00" + user.encode() + b"\x00"
            + b"database\x00" + database.encode() + b"\x00"
            + b"application_name\x00aiven-ctf-direct-ip-probe\x00"
            + b"client_encoding\x00UTF8\x00"
            + b"\x00"
        )
        startup = struct.pack("!II", 8 + len(params), 196608) + params
        tls.sendall(startup)
        row["startup_packet_b64"] = base64.b64encode(startup).decode()
        row["startup_packet_sha256"] = sha256_bytes(startup)
        row["first_message"] = read_first_pg_message(tls)
        auth_name = row["first_message"].get("auth_name")
        if auth_name == "AuthenticationOk":
            row["classification"] = "authentication_ok_observed_no_sql_sent"
        elif auth_name:
            row["classification"] = "authentication_challenge_observed_no_response_sent"
        elif row["first_message"].get("error_fields"):
            row["classification"] = "server_error_before_auth"
        else:
            row["classification"] = "postgres_response_unclassified"
    except Exception as exc:
        row["classification"] = "probe_error"
        row["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        try:
            if tls is not None:
                tls.close()
        except Exception:
            pass
        try:
            if raw is not None:
                raw.close()
        except Exception:
            pass
    return row


report: dict[str, Any] = {
    "schema": "aiven-ctf-direct-ip-dns-probe-v2",
    "target": NEW_HOST,
    "last_known_target_ip": LAST_KNOWN_IP,
    "run_started_utc": RUN_STARTED,
    "runner": {
        "github_repository": os.environ.get("GITHUB_REPOSITORY"),
        "github_run_id": os.environ.get("GITHUB_RUN_ID"),
        "github_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "github_sha": os.environ.get("GITHUB_SHA"),
        "runner_os": os.environ.get("RUNNER_OS"),
        "runner_arch": os.environ.get("RUNNER_ARCH"),
    },
    "safety": {
        "scope": "exact authorized Aiven CTF hostname plus its last independently observed target IP",
        "password_messages_sent": 0,
        "sasl_messages_sent": 0,
        "sql_statements_sent": 0,
        "brute_force": False,
        "known_ports_only": KNOWN_PG_PORTS,
    },
}

report["dns"] = dns_probe()
report["direct_ip_tcp"] = [tcp_connect(LAST_KNOWN_IP, port) for port in KNOWN_PG_PORTS]

pg_rows: list[dict[str, Any]] = []
for port in KNOWN_PG_PORTS:
    if not any(row.get("port") == port and row.get("connected") for row in report["direct_ip_tcp"]):
        continue
    for sni in SNI_VARIANTS:
        for alpn in (False, True):
            for user, database in PG_IDENTITIES:
                pg_rows.append(pg_tls_probe(LAST_KNOWN_IP, port, sni, alpn, user, database))
report["direct_ip_postgresql"] = pg_rows
report["run_finished_utc"] = utcnow()

report_path = OUT / "probe-v2.json"
report_bytes = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
report_path.write_bytes(report_bytes)

summary = {
    "schema": report["schema"],
    "target": NEW_HOST,
    "run_started_utc": RUN_STARTED,
    "run_finished_utc": report["run_finished_utc"],
    "system_new_host_addresses": report["dns"]["getaddrinfo"].get(NEW_HOST),
    "open_known_ports": sorted({row["port"] for row in report["direct_ip_tcp"] if row.get("connected")}),
    "pg_classifications": sorted({row.get("classification", "unknown") for row in pg_rows}),
    "certificate_sha256s": sorted({
        row.get("certificate", {}).get("der_sha256")
        for row in pg_rows
        if row.get("certificate", {}).get("der_sha256")
    }),
    "probe_sha256": sha256_bytes(report_bytes),
}
summary_path = OUT / "summary-v2.json"
summary_bytes = (json.dumps(summary, indent=2, sort_keys=True) + "\n").encode()
summary_path.write_bytes(summary_bytes)

manifest = {
    "schema": "aiven-ctf-direct-ip-dns-probe-manifest-v2",
    "target": NEW_HOST,
    "created_at_utc": utcnow(),
    "files": [
        {"path": str(report_path), "bytes": len(report_bytes), "sha256": sha256_bytes(report_bytes)},
        {"path": str(summary_path), "bytes": len(summary_bytes), "sha256": sha256_bytes(summary_bytes)},
    ],
}
manifest_path = OUT / "manifest-v2.json"
manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
manifest_path.write_bytes(manifest_bytes)
print(json.dumps(summary, sort_keys=True))
