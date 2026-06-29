"""CLI for VaultBreaker."""
from __future__ import annotations
import argparse, json, os, sys, time
from pathlib import Path
from vaultbreaker.config import COMMAND, TOOL_NAME, VERSION
from vaultbreaker.logger import info, ok, warn, crit, section, console, HAS_RICH
from vaultbreaker.models import AttackResult, EngagementContext
from vaultbreaker.modules import SQLiModule, MongoModule, RedisModule, ElasticModule, CredExtractModule, ExfilModule

MODULE_MAP = {"sqli": SQLiModule, "mongo": MongoModule, "redis": RedisModule,
              "elastic": ElasticModule, "cred": CredExtractModule, "exfil": ExfilModule}

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=COMMAND, description=f"{TOOL_NAME} v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--targets", "-t", required=True, help="Comma-separated hosts/URLs")
    p.add_argument("--ports", "-p", default="")
    p.add_argument("--modules", "-m", default="all", help="sqli,mongo,redis,elastic,cred,exfil,all")
    p.add_argument("--output", "-o", default=None)
    p.add_argument("--yes", "-y", action="store_true")
    p.add_argument("--timeout", default=10, type=int)
    p.add_argument("--db-type", default="auto", choices=["auto","mysql","mssql","postgres","mongo","redis","elastic"])
    p.add_argument("--version", "-V", action="version", version=f"{TOOL_NAME} v{VERSION}")
    return p

def main() -> None:
    args = build_parser().parse_args()
    if HAS_RICH:
        try:
            import pyfiglet
            console.print(f"[bold red]{pyfiglet.figlet_format('VaultBreaker', font='slant')}[/bold red]", highlight=False)
        except ImportError:
            pass
        console.print(f"[dim]  {TOOL_NAME} v{VERSION} — Database Offensive Framework[/dim]\n")
    else:
        print(f"\n  {TOOL_NAME} v{VERSION}\n")

    if not args.yes:
        try:
            if input("  Authorization? [y/N] ").strip().lower() not in ("y", "yes"):
                print("  Aborted."); sys.exit(1)
        except (EOFError, KeyboardInterrupt):
            sys.exit(1)

    ctx = EngagementContext(target_host=args.targets, timeout=args.timeout,
                           db_type=args.db_type, output_file=args.output)
    os.makedirs(ctx.output_dir, exist_ok=True)

    selected = list(MODULE_MAP.keys()) if "all" in args.modules.lower().split(",") else [m.strip().lower() for m in args.modules.split(",")]

    info(f"Targets: {args.targets}")
    info(f"Modules: {', '.join(selected)}")

    for mod_name in selected:
        if mod_name not in MODULE_MAP:
            warn(f"Unknown module: {mod_name}"); continue
        try:
            MODULE_MAP[mod_name]().run(ctx)
        except KeyboardInterrupt:
            warn("Interrupted"); break
        except Exception as e:
            crit(f"Module {mod_name} failed: {e}")
            ctx.results.append(AttackResult(mod_name, "error", "fail", "info", str(e)))

    section("SUMMARY")
    ok_c = sum(1 for r in ctx.results if r.status == "ok")
    print(f"  Total: {len(ctx.results)} | OK: {ok_c} | Creds: {len(ctx.credentials)}")

    if ctx.output_file:
        Path(ctx.output_file).write_text(json.dumps({"tool": TOOL_NAME, "version": VERSION,
            "results": [{"module": r.module, "action": r.action, "status": r.status,
                         "severity": r.severity, "notes": r.notes} for r in ctx.results]}, indent=2), encoding="utf-8")
        ok(f"Results saved: {ctx.output_file}")
