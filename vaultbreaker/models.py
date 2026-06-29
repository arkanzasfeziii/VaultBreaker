"""Data models for VaultBreaker."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from vaultbreaker.logger import console


# ─────────────────────────────────────────────────────────────
# Core data classes
# ─────────────────────────────────────────────────────────────

TOOL_NAME = "VaultBreaker Framework"
VERSION = "1.0.0"


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
        if console is not None:
            prefix_map = {
                "ok": "[bold green][OK][/bold green]",
                "fail": "[bold yellow][WARN][/bold yellow]",
                "critical": "[bold red][CRIT][/bold red]",
            }
            prefix = prefix_map.get(result.status, "[bold blue][INFO][/bold blue]")
            console.print(f"  {prefix} [{result.severity.upper()}] {result.action}: {result.notes}")

    def add_credential(self, cred: Credential):
        self.credentials.append(cred)
        if console is not None:
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
        if console is not None:
            console.print(f"\n[bold blue][INFO][/bold blue] Results written to {self.output_file}")
