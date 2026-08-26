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
import time
from pathlib import Path
from typing import Any

HOST = "falcon-bug-bounty-flag-pgsql-dev-sandbox.e.aivencloud.com"
PORTS = [22, 80, 443, 5432, 12691, 12692, 25060]
PG_USERS = ["avnadmin", "postgres", "ctf_probe_nonexistent"]
PG_DATABASES = ["defaultdb", "postgres"]
OUT = Path("probe-output")
OUT.mkdir(parents=True, exist_ok=True)

RUN_STARTED = dt.datetime.now(dt.timezone.utc).isoformat()
TIMEOUT = 8.0


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_run(argv: list[str], timeout: int = 30) -> dict[str, Any]:
    started = time.monotonic()
    try:
        cp = subprocess.run(
            argv,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        return {
            "argv": argv,
            "returncode": cp.returncode,
            "stdout": cp.stdout,
            "stderr": cp.stderr,
            "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
        }
    except Exception as exc:
        return {
            "argv": argv,
            "error": f"{type(exc).__name__}: {exc}",
            "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
        }


def resolve_host() -> dict[str, Any]:
    result: dict[str, Any] = {"host": HOST, "observed_at": dt.datetime.now(dt.timezone.utc).isoformat()}
    try:
        infos = socket.getaddrinfo(HOST, None, type=socket.SOCK_STREAM)
        rows = []
        for family, socktype, proto, canonname, sockaddr in infos:
            rows.append(
                {
                    "family": socket.AddressFamily(family).name,
                    "socktype": socket.SocketKind(socktype).name,
                    "proto": proto,
                    "canonname": canonname,
                    "sockaddr": list(sockaddr),
                }
            )
        unique = []
        seen = set()
        for row in rows:
            key = json.dumps(row, sort_keys=True)
            if key not in seen:
                seen.add(key)
                unique.append(row)
        result["getaddrinfo"] = unique
        result["ipv4"] = sorted({r["sockaddr"][0] for r in unique if r["family"] == "AF_INET"})
        result["ipv6"] = sorted({r["sockaddr"][0] for r in unique if r["family"] == "AF_INET6"})
    except Exception as exc:
        result["getaddrinfo_error"] = f"{type(exc).__name__}: {exc}"

    for qtype in ("A", "AAAA", "CNAME", "TXT", "SRV"):
        if shutil_which("dig"):
            result[f"dig_{qtype}"] = safe_run(["dig", "+time=3", "+tries=1", "+short", qtype, HOST], timeout=10)
    return result


def shutil_which(name: str) -> str | None:
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(directory) / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def tcp_probe(ip: str, port: int) -> dict[str, Any]:
    observed_at = dt.datetime.now(dt.timezone.utc).isoformat()
    started = time.monotonic()
    row: dict[str, Any] = {"ip": ip, "port": port, "observed_at": observed_at}
    try:
        with socket.create_connection((ip, port), timeout=TIMEOUT) as sock:
            row["connected"] = True
            row["peername"] = list(sock.getpeername())
            sock.settimeout(1.0)
            try:
                banner = sock.recv(512)
                row["initial_banner_b64"] = base64.b64encode(banner).decode()
                row["initial_banner_sha256"] = sha256_bytes(banner)
            except socket.timeout:
                row["initial_banner_b64"] = ""
                row["initial_banner_sha256"] = sha256_bytes(b"")
    except Exception as exc:
        row["connected"] = False
        row["error"] = f"{type(exc).__name__}: {exc}"
    row["elapsed_ms"] = round((time.monotonic() - started) * 1000, 3)
    return row


def recv_exact(sock: socket.socket, count: int) -> bytes:
    chunks = []
    remaining = count
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise EOFError(f"wanted {count} bytes, received {count - remaining}")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def recv_pg_messages(sock: socket.socket, max_messages: int = 64, max_total: int = 1024 * 1024) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    total = 0
    for _ in range(max_messages):
        try:
            msg_type = recv_exact(sock, 1)
            length_raw = recv_exact(sock, 4)
            length = struct.unpack("!I", length_raw)[0]
            if length < 4 or length > max_total:
                rows.append({"type": msg_type.decode("ascii", "replace"), "invalid_length": length})
                break
            payload = recv_exact(sock, length - 4)
        except socket.timeout:
            rows.append({"timeout": True})
            break
        except Exception as exc:
            rows.append({"receive_error": f"{type(exc).__name__}: {exc}"})
            break

        total += 1 + 4 + len(payload)
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
        elif msg_type == b"E":
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
            row["error_fields"] = fields
        elif msg_type == b"S":
            parts = payload.split(b"\x00")
            if len(parts) >= 2:
                row["parameter"] = parts[0].decode("utf-8", "replace")
                row["value"] = parts[1].decode("utf-8", "replace")
        elif msg_type == b"K" and len(payload) == 8:
            row["backend_pid"] = struct.unpack("!I", payload[:4])[0]
            row["backend_key_redacted"] = True
        rows.append(row)
        if total >= max_total:
            rows.append({"truncated": True, "total_bytes": total})
            break
        # Hard stop: never answer any authentication challenge.
        if msg_type == b"R":
            break
        if msg_type in (b"E", b"Z"):
            break
    return rows


def tls_certificate_from_socket(raw: socket.socket, server_hostname: str) -> tuple[ssl.SSLSocket, dict[str, Any]]:
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    tls = context.wrap_socket(raw, server_hostname=server_hostname)
    der = tls.getpeercert(binary_form=True) or b""
    info = {
        "version": tls.version(),
        "cipher": list(tls.cipher() or ()),
        "selected_alpn_protocol": tls.selected_alpn_protocol(),
        "peer_cert_der_b64": base64.b64encode(der).decode(),
        "peer_cert_sha256": sha256_bytes(der),
        "peer_cert": tls.getpeercert(),
    }
    return tls, info


def pg_startup_probe(ip: str, port: int, user: str, database: str) -> dict[str, Any]:
    observed_at = dt.datetime.now(dt.timezone.utc).isoformat()
    row: dict[str, Any] = {
        "host": HOST,
        "ip": ip,
        "port": port,
        "user": user,
        "database": database,
        "observed_at": observed_at,
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
            row["classification"] = "not_postgresql_tls_or_ssl_refused"
            return row

        tls, cert_info = tls_certificate_from_socket(raw, HOST)
        raw = None
        row["tls"] = cert_info

        params = (
            b"user\x00" + user.encode() + b"\x00"
            + b"database\x00" + database.encode() + b"\x00"
            + b"application_name\x00aiven-ctf-bounded-probe\x00"
            + b"client_encoding\x00UTF8\x00"
            + b"\x00"
        )
        startup = struct.pack("!II", 8 + len(params), 196608) + params
        tls.sendall(startup)
        row["startup_packet_b64"] = base64.b64encode(startup).decode()
        row["startup_packet_sha256"] = sha256_bytes(startup)
        row["messages"] = recv_pg_messages(tls)
        auth_names = [m.get("auth_name") for m in row["messages"] if isinstance(m, dict) and m.get("auth_name")]
        if "AuthenticationOk" in auth_names:
            row["classification"] = "authentication_ok_observed_no_sql_sent"
        elif auth_names:
            row["classification"] = "authentication_challenge_observed_no_response_sent"
        elif any(m.get("error_fields") for m in row["messages"] if isinstance(m, dict)):
            row["classification"] = "server_error_before_auth"
        else:
            row["classification"] = "postgresql_response_unclassified"
    except ssl.SSLCertVerificationError as exc:
        row["classification"] = "tls_certificate_verification_failed"
        row["error"] = f"{type(exc).__name__}: {exc}"
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


def https_probe() -> dict[str, Any]:
    if not shutil_which("curl"):
        return {"skipped": "curl_not_available"}
    return safe_run(
        [
            "curl", "--silent", "--show-error", "--include", "--head",
            "--max-time", "10", "--connect-timeout", "5",
            "--resolve", f"{HOST}:443:{RESOLVED_IPS[0]}" if RESOLVED_IPS else "",
            f"https://{HOST}/",
        ] if RESOLVED_IPS else [
            "curl", "--silent", "--show-error", "--include", "--head",
            "--max-time", "10", "--connect-timeout", "5",
            f"https://{HOST}/",
        ],
        timeout=15,
    )


report: dict[str, Any] = {
    "schema": "aiven-ctf-bounded-probe-v1",
    "target": HOST,
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
        "scope": "single authorized Aiven CTF hostname",
        "ports": PORTS,
        "password_messages_sent": 0,
        "sasl_messages_sent": 0,
        "sql_statements_sent": 0,
        "brute_force": False,
    },
}

report["dns"] = resolve_host()
RESOLVED_IPS = report["dns"].get("ipv4", [])
report["tcp"] = [tcp_probe(ip, port) for ip in RESOLVED_IPS for port in PORTS]
report["https"] = https_probe()

pg_rows: list[dict[str, Any]] = []
for ip in RESOLVED_IPS:
    for port in PORTS:
        if not any(r.get("ip") == ip and r.get("port") == port and r.get("connected") for r in report["tcp"]):
            continue
        for user in PG_USERS:
            for database in PG_DATABASES:
                pg_rows.append(pg_startup_probe(ip, port, user, database))
report["postgresql_startup_probes"] = pg_rows

report["run_finished_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
report_path = OUT / "probe.json"
report_bytes = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
report_path.write_bytes(report_bytes)

manifest = {
    "schema": "aiven-ctf-bounded-probe-manifest-v1",
    "target": HOST,
    "created_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
    "files": [
        {
            "path": str(report_path),
            "bytes": len(report_bytes),
            "sha256": sha256_bytes(report_bytes),
        }
    ],
}
manifest_path = OUT / "manifest.json"
manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
manifest_path.write_bytes(manifest_bytes)

summary = {
    "target": HOST,
    "ipv4_count": len(RESOLVED_IPS),
    "open_tcp_ports": sorted({
        r["port"] for r in report["tcp"] if r.get("connected")
    }),
    "pg_classifications": sorted({
        r.get("classification", "unknown") for r in pg_rows
    }),
    "probe_sha256": sha256_bytes(report_bytes),
    "manifest_sha256": sha256_bytes(manifest_bytes),
}
print(json.dumps(summary, sort_keys=True))
