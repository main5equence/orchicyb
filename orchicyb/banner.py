from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __version__

console = Console(highlight=False)

BANNER = r"""
                 _     _            _     
  ___  _ __ ___ | |__ (_) ___ _   _| |__  
 / _ \| '__/ __|| '_ \| |/ __| | | | '_ \ 
| (_) | | | (__ | | | | | (__| |_| | |_) |
 \___/|_|  \___||_| |_|_|\___|\__, |_.__/ 
                               |___/       
"""

ABOUT = (
    "[white]orchicyb[/white] is a defensive digital risk toolkit for authorized "
    "domain assessment. It combines lightweight OSINT-style visibility with "
    "practical security checks: HTTP headers, TLS posture, DNS footprint, and "
    "email authentication in a single, readable terminal workflow.\n\n"
    "Use it to baseline exposure, validate hardening, and export shareable "
    "reports for teams and stakeholders."
)


def print_banner() -> None:
    console.print(BANNER, style="white", markup=False)
    console.print(
        Text.from_markup(
            f"[white]Digital Risk & OSINT Toolkit[/]  [dim]v{__version__}[/]"
        )
    )
    console.print()


def print_welcome() -> None:
    print_banner()
    console.print(Panel(ABOUT, title="About", border_style="dim", padding=(1, 2)))
    console.print()

    commands = Table(
        title="Commands",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold white",
        border_style="dim",
    )
    commands.add_column("Command", style="cyan", no_wrap=True)
    commands.add_column("Description", style="white")
    commands.add_row("scan", "Full assessment: headers, TLS, DNS, email, risk score")
    commands.add_row("headers", "Analyze HTTP security headers and HTTPS behavior")
    commands.add_row("tls", "Inspect TLS certificate validity and expiry")
    commands.add_row("dns", "Resolve A, AAAA, MX, NS, TXT, CAA, and SOA records")
    commands.add_row("email", "Validate SPF, DMARC, and DKIM configuration")
    commands.add_row("risk", "Compute weighted digital risk score")
    commands.add_row("report", "Export Markdown and/or PDF report for stakeholders")
    console.print(commands)
    console.print()

    console.print("[bold white]Quick start[/]")
    console.print("  [cyan]orchicyb scan example.com[/]")
    console.print("  [cyan]orchicyb report yourdomain.com -f pdf[/]")
    console.print("  [cyan]orchicyb report yourdomain.com -f both --output reports[/]")
    console.print("  [cyan]orchicyb headers https://yourdomain.com[/]")
    console.print()
    console.print(
        "[dim]Authorized use only - assess domains you own or have explicit permission to test.[/]"
    )
    console.print()
