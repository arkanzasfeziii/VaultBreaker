"""Rich-based terminal output."""
from __future__ import annotations
try:
    from rich.console import Console
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

console = Console() if HAS_RICH else None

def _p(m: str) -> None:
    console.print(m) if console else print(m)

def info(m: str) -> None: _p(f"  [bold cyan][INFO][/bold cyan]  {m}" if HAS_RICH else f"  [INFO]  {m}")
def ok(m: str) -> None: _p(f"  [bold green][ OK ][/bold green]  {m}" if HAS_RICH else f"  [ OK ]  {m}")
def warn(m: str) -> None: _p(f"  [bold yellow][WARN][/bold yellow]  {m}" if HAS_RICH else f"  [WARN]  {m}")
def crit(m: str) -> None: _p(f"  [bold red][CRIT][/bold red]  {m}" if HAS_RICH else f"  [CRIT]  {m}")
def section(t: str) -> None:
    if HAS_RICH:
        console.print(f"\n  [bold magenta]{'─'*60}[/bold magenta]")
        console.print(f"  [bold magenta]  {t}[/bold magenta]")
        console.print(f"  [bold magenta]{'─'*60}[/bold magenta]\n")
    else:
        print(f"\n  {'─'*60}\n    {t}\n  {'─'*60}\n")
