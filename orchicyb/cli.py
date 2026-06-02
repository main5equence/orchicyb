import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from . import __version__
from .banner import print_welcome
from .dns_check import lookup_dns
from .email_security import check_email_security
from .headers import check_headers
from .report import generate_reports
from .risk import calculate_risk
from .tls_check import check_tls
from .utils import domain_from_url, risk_level, risk_level_style, score_style

console = Console(highlight=False)


def _print_recommendations(items: list[str]) -> None:
    if not items:
        return
    console.print("\n[bold white]Recommendations[/]")
    for item in items[:8]:
        console.print(f"  [dim]-[/] {item}")


def _print_score(label: str, score: int) -> None:
    console.print(
        f"\n{label}: [{score_style(score)}]{score}/100[/{score_style(score)}]"
    )


@click.group(invoke_without_command=True)
@click.pass_context
@click.version_option(__version__, prog_name="orchicyb")
def main(ctx):
    """orchicyb — Digital Risk & OSINT Toolkit."""
    if ctx.invoked_subcommand is None:
        print_welcome()


@main.command()
@click.argument("target")
def scan(target: str):
    """Run a full digital risk assessment."""
    domain = domain_from_url(target)
    console.print(f"\n[bold white]Scanning[/] [cyan]{domain}[/]\n")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("Checking HTTP security headers…", total=None)
        headers = check_headers(domain)
        progress.add_task("Inspecting TLS certificate…", total=None)
        tls = check_tls(domain)
        progress.add_task("Resolving DNS records…", total=None)
        dns = lookup_dns(domain)
        progress.add_task("Validating email authentication…", total=None)
        email = check_email_security(domain)

    scores = [headers["score"], tls["score"], dns["score"], email["score"]]
    overall = int(sum(scores) / len(scores))
    level = risk_level(overall)

    table = Table(title=f"Assessment: {domain}", border_style="dim")
    table.add_column("Category", style="white")
    table.add_column("Score", justify="right")
    table.add_row("Website security", f"[{score_style(headers['score'])}]{headers['score']}/100[/]")
    table.add_row("TLS certificate", f"[{score_style(tls['score'])}]{tls['score']}/100[/]")
    table.add_row("DNS visibility", f"[{score_style(dns['score'])}]{dns['score']}/100[/]")
    table.add_row("Email authentication", f"[{score_style(email['score'])}]{email['score']}/100[/]")
    table.add_row("Overall", f"[bold {score_style(overall)}]{overall}/100[/]")
    table.add_row("Risk level", f"[{risk_level_style(level)}]{level}[/]")
    console.print(table)

    recs = []
    for block in (headers, tls, dns, email):
        recs.extend(block.get("recommendations", []))
    _print_recommendations(recs)
    console.print(f"\n[dim]Export report:[/] [cyan]orchicyb report {domain}[/]\n")


@main.command()
@click.argument("target")
def headers(target: str):
    """Check website security headers."""
    result = check_headers(target)
    table = Table(title=f"Security Headers — {result['domain']}", border_style="dim")
    table.add_column("Header", style="white")
    table.add_column("Status")
    table.add_column("Value", overflow="fold")

    for header, value in result.get("present", {}).items():
        table.add_row(header, "[green]Present[/]", value)
    for header in result.get("missing", []):
        table.add_row(header, "[red]Missing[/]", "—")

    console.print(table)
    if result.get("error"):
        console.print(f"\n[red]Error:[/] {result['error']}")
    console.print(f"\n[dim]Status:[/] {result.get('status_code')}  [dim]Final URL:[/] {result.get('final_url')}")
    redirect = result.get("https_redirect")
    if redirect is True:
        console.print("[dim]HTTP → HTTPS:[/] [green]Yes[/]")
    elif redirect is False:
        console.print("[dim]HTTP → HTTPS:[/] [red]No[/]")
    _print_score("Score", result.get("score", 0))
    _print_recommendations(result.get("recommendations", []))


@main.command()
@click.argument("domain")
def tls(domain: str):
    """Inspect TLS certificate and protocol."""
    domain = domain_from_url(domain)
    result = check_tls(domain)
    table = Table(title=f"TLS — {domain}", border_style="dim")
    table.add_column("Field", style="white")
    table.add_column("Value", overflow="fold")

    rows = [
        ("Reachable", "Yes" if result["reachable"] else "No"),
        ("Protocol", result.get("protocol") or "—"),
        ("Issuer", result.get("issuer") or "—"),
        ("Subject", result.get("subject") or "—"),
        ("Expires", result.get("expires") or "—"),
        ("Days remaining", str(result.get("days_remaining")) if result.get("days_remaining") is not None else "—"),
    ]
    for field, value in rows:
        table.add_row(field, value)

    console.print(table)
    if result.get("error"):
        console.print(f"\n[red]Error:[/] {result['error']}")
    _print_score("Score", result.get("score", 0))
    _print_recommendations(result.get("recommendations", []))


@main.command()
@click.argument("domain")
def dns(domain: str):
    """Lookup DNS records."""
    result = lookup_dns(domain)
    table = Table(title=f"DNS — {result['domain']}", border_style="dim")
    table.add_column("Type", style="cyan", no_wrap=True)
    table.add_column("Values", overflow="fold")

    for record_type, values in result["records"].items():
        table.add_row(record_type, "\n".join(values) if values else "[dim]—[/]")

    console.print(table)
    _print_score("DNS visibility score", result.get("score", 0))
    _print_recommendations(result.get("recommendations", []))


@main.command()
@click.argument("domain")
@click.option(
    "--selector",
    default=None,
    help="DKIM selector (auto-detects common selectors if omitted).",
)
def email(domain: str, selector: str | None):
    """Check SPF, DMARC, and DKIM records."""
    result = check_email_security(domain, selector)
    table = Table(title=f"Email Security — {result['domain']}", border_style="dim")
    table.add_column("Control", style="white")
    table.add_column("Status")
    table.add_column("Detail", overflow="fold")

    table.add_row(
        "SPF",
        "[green]Found[/]" if result["spf"] else "[red]Missing[/]",
        result["spf"][0] if result["spf"] else "—",
    )
    table.add_row(
        "DMARC",
        "[green]Found[/]" if result["dmarc"] else "[red]Missing[/]",
        result["dmarc"][0] if result["dmarc"] else "—",
    )
    table.add_row(
        "DKIM",
        "[green]Found[/]" if result["dkim"] else "[yellow]Not found[/]",
        result["dkim"][0] if result["dkim"] else f"Checked: {', '.join(result['selectors_checked'][:5])}…",
    )

    console.print(table)
    if result["dkim"]:
        console.print(f"[dim]Matched selector:[/] [cyan]{result['dkim_selector']}[/]")
    _print_score("Email security score", result.get("score", 0))
    _print_recommendations(result.get("recommendations", []))


@main.command()
@click.argument("target")
def risk(target: str):
    """Generate a digital risk score."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("Calculating digital risk score…", total=None)
        data = calculate_risk(target)

    table = Table(title=f"Digital Risk — {data['target']}", border_style="dim")
    table.add_column("Category", style="white")
    table.add_column("Score", justify="right")

    ws, tls, dns, em = data["website_security"], data["tls"], data["dns_visibility"], data["email_security"]
    table.add_row("Website security", f"[{score_style(ws['score'])}]{ws['score']}/100[/]")
    table.add_row("TLS certificate", f"[{score_style(tls['score'])}]{tls['score']}/100[/]")
    table.add_row("DNS visibility", f"[{score_style(dns['score'])}]{dns['score']}/100[/]")
    table.add_row("Email authentication", f"[{score_style(em['score'])}]{em['score']}/100[/]")
    table.add_row(
        "Overall",
        f"[bold {score_style(data['overall_score'])}]{data['overall_score']}/100[/]",
    )
    table.add_row(
        "Risk level",
        f"[{risk_level_style(data['risk_level'])}]{data['risk_level']}[/]",
    )
    console.print(table)
    _print_recommendations(data.get("recommendations", []))


@main.command()
@click.argument("target")
@click.option("--output", default="reports", help="Output directory for the report.")
@click.option(
    "--format",
    "-f",
    "fmt",
    type=click.Choice(["md", "pdf", "both"], case_sensitive=False),
    default="md",
    show_default=True,
    help="Report format: Markdown, PDF, or both.",
)
def report(target: str, output: str, fmt: str):
    """Export a digital risk report (Markdown and/or PDF)."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("Generating report…", total=None)
        paths = generate_reports(target, output, fmt=fmt.lower())
    lines = "\n".join(f"[cyan]{path}[/]" for path in paths)
    console.print(
        Panel(
            f"[white]Report saved ({fmt.upper()})[/]\n{lines}",
            border_style="dim",
            padding=(1, 2),
        )
    )


if __name__ == "__main__":
    main()
