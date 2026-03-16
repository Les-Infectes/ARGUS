#!/usr/bin/env python3
"""
ARGUS - Network and AD Infrastructure Mapper
Interactive wizard for argus_pipeline.py

Usage:
    python3 argus.py          # interactive wizard
    python3 argus.py --help   # quick help
"""
import sys
import os
import shutil
import subprocess
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent.resolve()


# ── Colors ────────────────────────────────────────────────────────────────────

class C:
    RESET  = '\033[0m'
    BOLD   = '\033[1m'
    DIM    = '\033[2m'
    RED    = '\033[91m'
    GREEN  = '\033[92m'
    NAVY   = '\033[38;5;27m'   # titres, prompts, choix — bleu marine
    GRAY   = '\033[90m'


# ── Banner ────────────────────────────────────────────────────────────────────

LOGO = [
    "  █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗",
    " ██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝",
    " ███████║██████╔╝██║  ███╗██║   ██║███████╗",
    " ██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║",
    " ██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║",
    " ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝",
]

TAGLINE = "Network & AD Infrastructure Mapper"

HELP_TEXT = f"""
{C.NAVY}{C.BOLD}ARGUS{C.RESET} {C.DIM}— {TAGLINE}{C.RESET}

{C.NAVY}{C.BOLD}USAGE{C.RESET}
  python3 argus.py            Interactive wizard
  python3 argus.py --help     Show this help

{C.NAVY}{C.BOLD}ACCESS MODES{C.RESET}
  {C.NAVY}Direct{C.RESET}  — Direct access to target network
  {C.NAVY}Pivot{C.RESET}   — Access via SOCKS tunnel / proxychains

{C.NAVY}{C.BOLD}DIRECT SCANS{C.RESET}
  {C.DIM}Individual:{C.RESET}
    {C.NAVY}[1]{C.RESET} DC only         port scan + AD + ADCS on a single machine
    {C.NAVY}[2]{C.RESET} Network         network discovery (ARP, traceroute, ports)
    {C.NAVY}[3]{C.RESET} AD + ADCS       BloodHound + Certipy identity collection
  {C.DIM}All-in-one:{C.RESET}
    {C.NAVY}[4]{C.RESET} Full            network + AD + ADCS in a single pass
  {C.DIM}Combine:{C.RESET}
    {C.NAVY}[5]{C.RESET} Network + map   add network to an existing AD scan

{C.NAVY}{C.BOLD}PIVOT SCANS{C.RESET}
    {C.NAVY}[1]{C.RESET} AD + ADCS       BloodHound + Certipy via proxychains (no sudo)
    {C.NAVY}[2]{C.RESET} Network         network discovery via proxychains (sudo)

  {C.DIM}Combine: same --output-dir. Order does not matter.{C.RESET}
"""


# ── UI helpers ────────────────────────────────────────────────────────────────

def tw():
    return shutil.get_terminal_size((80, 24)).columns


def clear():
    os.system('clear' if os.name == 'posix' else 'cls')


def print_banner():
    w = tw()
    logo_w = max(len(l) for l in LOGO if l.strip())
    pad = " " * max(0, (w - logo_w) // 2)
    print()
    for line in LOGO:
        if line.strip():
            print(f"{C.NAVY}{C.BOLD}{pad}{line}{C.RESET}")
    print()
    tag_pad = " " * max(0, (w - len(TAGLINE)) // 2)
    print(f"{C.DIM}{tag_pad}{TAGLINE}{C.RESET}")
    print()


def hr():
    print(f"\n{C.DIM}{'─' * tw()}{C.RESET}\n")


def header(text):
    print(f"  {C.NAVY}{C.BOLD}{text.upper()}{C.RESET}")


def section_label(text):
    print(f"  {C.DIM}── {text} ──{C.RESET}")


def show_options(params):
    """Metasploit-style options table."""
    col = 26
    print()
    print(f"  {C.NAVY}{'Name':<{col}}{'Required':<10}Description{C.RESET}")
    print(f"  {C.DIM}{'─' * (col-2):<{col}}{'─' * 8:<10}{'─' * 30}{C.RESET}")
    for p in params:
        req = "yes" if p.get("req", True) else "no"
        name_color = C.NAVY if p.get("req", True) else C.DIM
        print(f"  {name_color}{p['name']:<{col}}{C.RESET}{req:<10}{p['desc']}")
    print()


def ask(label, required=True, default=None, hint=None, ctx=">"):
    mark = f"{C.RED}*{C.RESET}" if required else " "
    default_str = f" {C.DIM}[{default}]{C.RESET}" if default is not None else ""
    while True:
        try:
            if hint:
                print(f"  {C.DIM}{hint}{C.RESET}")
            val = input(f"  {C.NAVY}{C.BOLD}{ctx}{C.RESET} {mark} {label}{default_str}: ").strip()
        except (KeyboardInterrupt, EOFError):
            print()
            sys.exit(0)
        if not val and default is not None:
            return default
        if not val and required:
            print(f"  {C.RED}required.{C.RESET}")
            continue
        return val or None


def _resolve_output_dir(raw):
    """Pass through — user provides the full path."""
    return raw


def ask_bool(label, default=False, ctx=">"):
    choices = "Y/n" if default else "y/N"
    try:
        val = input(f"  {C.NAVY}{C.BOLD}{ctx}{C.RESET}   {label} {C.DIM}[{choices}]{C.RESET}: ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        print()
        sys.exit(0)
    return (val in ('y', 'o', 'yes', 'oui')) if val else default


def menu(options, heading, ctx=">", note=None):
    """Display menu. options = list of (key, label) or (None, "section header")."""
    hr()
    header(heading)
    print()
    selectable = []
    for key, label in options:
        if key is None:
            section_label(label)
        else:
            selectable.append((key, label))
            idx = len(selectable)
            print(f"    {C.NAVY}[{idx}]{C.RESET}  {label}")
    if note:
        print(f"\n  {C.DIM}{note}{C.RESET}")
    print(f"\n    {C.DIM}[q]  quit{C.RESET}\n")
    while True:
        try:
            choice = input(f"  {C.NAVY}{C.BOLD}{ctx}{C.RESET} ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print()
            sys.exit(0)
        if choice == 'q':
            sys.exit(0)
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(selectable):
                return selectable[idx][0]
        except ValueError:
            pass
        print(f"  {C.RED}invalid choice.{C.RESET}")


def show_command(cmd_parts):
    hr()
    header("Generated command")
    oneliner = ' '.join(cmd_parts)
    print(f"\n{C.GREEN}{oneliner}{C.RESET}\n")


def confirm_and_run(cmd_parts):
    show_command(cmd_parts)
    print(f"    {C.GREEN}[enter]{C.RESET} run    {C.RED}[q]{C.RESET} cancel\n")
    try:
        choice = input(f"  {C.NAVY}{C.BOLD}>{C.RESET} ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        print()
        return
    if choice == 'q':
        print(f"\n  {C.DIM}Cancelled.{C.RESET}")
        return
    hr()
    subprocess.run(cmd_parts)
    hr()


# ── Backend helpers ───────────────────────────────────────────────────────────

def _python():
    return str(SCRIPT_DIR / ".env" / "bin" / "python3")

def _script():
    return str(SCRIPT_DIR / "argus_pipeline.py")

def _ask_auth(ctx=">"):
    auth = menu(
        [("password", "Password"), ("hash", "NTLM hash  (-H)")],
        "Authentication",
        ctx=ctx
    )
    if auth == "password":
        return ["--password", ask("Password", ctx=ctx)]
    else:
        return ["-H", ask("NT hash", hint="e.g. 649f65073a6672a9898cb4eb61f9684a", ctx=ctx)]


# ── Builders ──────────────────────────────────────────────────────────────────

def build_direct_dc_only():
    ctx = "direct/dc>"
    hr()
    header("DC only — single machine scan")
    show_options([
        {"name": "--dc-ip",      "desc": "Domain Controller IP"},
        {"name": "--domain",     "desc": "AD domain name"},
        {"name": "--user",       "desc": "AD username"},
        {"name": "--password/-H","desc": "Password or NT hash"},
        {"name": "--start",      "desc": "Start node for path analysis"},
        {"name": "--port-scan",  "desc": "Scan top-100 TCP ports", "req": False},
        {"name": "--output-dir", "desc": "Output directory", "req": False},
    ])
    dc_ip      = ask("dc-ip",   hint="e.g. 10.10.11.42", ctx=ctx)
    domain     = ask("domain",   hint="e.g. corp.local", ctx=ctx)
    user       = ask("user",     hint="e.g. Administrator", ctx=ctx)
    auth_args  = _ask_auth(ctx=ctx)
    default_start = f"{user}@{domain}" if user and domain else None
    start      = ask("start", default=default_start, ctx=ctx)
    port_scan  = ask_bool("enable port scan (top-100 TCP)?", default=True, ctx=ctx)
    output_dir = _resolve_output_dir(ask("output-dir", required=False, hint="e.g. results/my_scan", ctx=ctx))

    cmd = [
        "sudo", _python(), _script(),
        "--single-host",
        "--ip-cidr", dc_ip,
        "--gateway", dc_ip, "--dns", dc_ip,
        "--domain", domain, "--dc-ip", dc_ip, "--user", user, "--start", start,
    ] + auth_args
    if port_scan:  cmd.append("--port-scan")
    if output_dir: cmd += ["--output-dir", output_dir]
    return cmd


def build_direct_network_only():
    ctx = "direct/net>"
    hr()
    header("Network — host discovery and port scan")
    show_options([
        {"name": "--ip-cidr",    "desc": "Target network range"},
        {"name": "--gateway",    "desc": "Network gateway"},
        {"name": "--dns",        "desc": "DNS server (usually DC IP)"},
        {"name": "--port-scan",  "desc": "Scan top-100 TCP ports", "req": False},
        {"name": "--output-dir", "desc": "Output directory", "req": False},
    ])
    ip_cidr    = ask("ip-cidr",    hint="e.g. 192.168.1.0/24", ctx=ctx)
    gateway    = ask("gateway",    hint="e.g. 192.168.1.1", ctx=ctx)
    dns        = ask("dns",        hint="usually the DC IP", ctx=ctx)
    port_scan  = ask_bool("enable port scan (top-100 TCP)?", ctx=ctx)
    output_dir = _resolve_output_dir(ask("output-dir", required=False, hint="e.g. results/my_scan", ctx=ctx))

    cmd = [
        "sudo", _python(), _script(),
        "--ip-cidr", ip_cidr, "--gateway", gateway, "--dns", dns,
        "--domain", "x", "--dc-ip", "x", "--user", "x", "--password", "x", "--start", "x@x",
        "--skip-bloodhound", "--skip-certipy", "--skip-enrichment",
    ]
    if port_scan:  cmd.append("--port-scan")
    if output_dir: cmd += ["--output-dir", output_dir]
    return cmd


def build_direct_network_mapping():
    ctx = "direct/net+map>"
    hr()
    header("Network + mapping — network scan with AD name resolution")

    scope = menu(
        [
            ("single", "Single machine    port scan on one IP"),
            ("network", "Full network      ARP discovery + traceroute + port scan"),
        ],
        "Scan scope",
        ctx=ctx,
    )

    show_options([
        {"name": "--ip-cidr",    "desc": "Target IP or network range"},
        {"name": "--gateway",    "desc": "Network gateway"},
        {"name": "--dns",        "desc": "DNS server (DC IP)"},
        {"name": "--bh-dir",     "desc": "Existing BloodHound data directory"},
        {"name": "--port-scan",  "desc": "Scan top-100 TCP ports", "req": False},
    ])

    if scope == "single":
        dc_ip      = ask("target-ip",     hint="e.g. 10.129.7.152", ctx=ctx)
        ip_cidr    = dc_ip
        gateway    = dc_ip
        dns        = dc_ip
    else:
        ip_cidr    = ask("ip-cidr",        hint="e.g. 192.168.1.0/24", ctx=ctx)
        gateway    = ask("gateway",        hint="e.g. 192.168.1.1", ctx=ctx)
        dns        = ask("dns",            hint="usually the DC IP", ctx=ctx)

    bh_dir     = ask("bh-dir",         hint="e.g. results/scan_ethan  (or results/scan_ethan/bloodhound_data)", ctx=ctx)
    port_scan  = ask_bool("enable port scan (top-100 TCP)?", ctx=ctx)

    import os
    normalized = os.path.normpath(bh_dir)
    if os.path.basename(normalized) == "bloodhound_data":
        output_dir = os.path.dirname(normalized)
    else:
        output_dir = normalized
        bh_dir = os.path.join(normalized, "bloodhound_data")
    print(f"\n  {C.DIM}bh-dir     -> {bh_dir}{C.RESET}")
    print(f"  {C.DIM}output-dir -> {output_dir}{C.RESET}")

    cmd = [
        "sudo", _python(), _script(),
        "--ip-cidr", ip_cidr, "--gateway", gateway, "--dns", dns,
        "--domain", "x", "--dc-ip", "x", "--user", "x", "--password", "x", "--start", "x@x",
        "--skip-bloodhound", "--bh-dir", bh_dir, "--skip-certipy",
        "--output-dir", output_dir,
    ]
    if scope == "single": cmd.append("--single-host")
    if port_scan:  cmd.append("--port-scan")
    return cmd


def build_direct_ad_only():
    ctx = "direct/ad>"
    hr()
    header("AD + ADCS — BloodHound + Certipy collection")
    show_options([
        {"name": "--domain",      "desc": "AD domain name"},
        {"name": "--dc-ip",       "desc": "Domain Controller IP"},
        {"name": "--user",        "desc": "AD username"},
        {"name": "--password/-H", "desc": "Password or NT hash"},
        {"name": "--start",       "desc": "Start node for path analysis"},
        {"name": "--output-dir",  "desc": "Output directory", "req": False},
    ])
    domain     = ask("domain",     hint="e.g. corp.local", ctx=ctx)
    dc_ip      = ask("dc-ip",      hint="e.g. 192.168.1.10", ctx=ctx)
    user       = ask("user",       hint="e.g. Administrator", ctx=ctx)
    auth_args  = _ask_auth(ctx=ctx)
    default_start = f"{user}@{domain}" if user and domain else None
    start      = ask("start", default=default_start, ctx=ctx)
    output_dir = _resolve_output_dir(ask("output-dir", required=False, hint="e.g. results/my_scan", ctx=ctx))

    cmd = [
        "sudo", _python(), _script(),
        "--skip-network",
        "--domain", domain, "--dc-ip", dc_ip, "--user", user, "--start", start,
    ] + auth_args
    if output_dir: cmd += ["--output-dir", output_dir]
    return cmd


def build_direct_full():
    ctx = "direct/full>"
    hr()
    header("Full scan — Network + BloodHound + Certipy + Graphs")

    net_mode = menu(
        [
            ("single", "Single machine  (1 DC, no network discovery)"),
            ("network", "Full network    (gateway, DNS, traceroute, ARP)"),
        ],
        "Network scope",
        ctx=ctx
    )

    if net_mode == "single":
        show_options([
            {"name": "--dc-ip",       "desc": "Domain Controller IP"},
            {"name": "--domain",      "desc": "AD domain name"},
            {"name": "--user",        "desc": "AD username"},
            {"name": "--password/-H", "desc": "Password or NT hash"},
            {"name": "--start",       "desc": "Start node for path analysis"},
            {"name": "--port-scan",   "desc": "Scan top-100 TCP ports", "req": False},
            {"name": "--output-dir",  "desc": "Output directory", "req": False},
        ])
        dc_ip      = ask("dc-ip",   hint="e.g. 10.10.11.42", ctx=ctx)
        domain     = ask("domain",   hint="e.g. corp.local", ctx=ctx)
        user       = ask("user",     hint="e.g. Administrator", ctx=ctx)
        auth_args  = _ask_auth(ctx=ctx)
        default_start = f"{user}@{domain}" if user and domain else None
        start      = ask("start", default=default_start, ctx=ctx)
        port_scan  = ask_bool("enable port scan (top-100 TCP)?", default=True, ctx=ctx)
        output_dir = _resolve_output_dir(ask("output-dir", required=False, hint="e.g. results/my_scan", ctx=ctx))

        cmd = [
            "sudo", _python(), _script(),
            "--single-host",
            "--ip-cidr", dc_ip,
            "--gateway", dc_ip, "--dns", dc_ip,
            "--domain", domain, "--dc-ip", dc_ip, "--user", user, "--start", start,
        ] + auth_args
        if port_scan:  cmd.append("--port-scan")
        if output_dir: cmd += ["--output-dir", output_dir]
        return cmd

    show_options([
        {"name": "--ip-cidr",     "desc": "Target network range"},
        {"name": "--gateway",     "desc": "Network gateway"},
        {"name": "--dns",         "desc": "DNS server (DC IP)"},
        {"name": "--domain",      "desc": "AD domain name"},
        {"name": "--dc-ip",       "desc": "Domain Controller IP"},
        {"name": "--user",        "desc": "AD username"},
        {"name": "--password/-H", "desc": "Password or NT hash"},
        {"name": "--start",       "desc": "Start node for path analysis"},
        {"name": "--port-scan",   "desc": "Scan top-100 TCP ports", "req": False},
        {"name": "--output-dir",  "desc": "Output directory", "req": False},
    ])
    ip_cidr    = ask("ip-cidr",    hint="e.g. 192.168.1.0/24", ctx=ctx)
    gateway    = ask("gateway",    hint="e.g. 192.168.1.1", ctx=ctx)
    dns        = ask("dns",        hint="usually the DC IP", ctx=ctx)
    domain     = ask("domain",     hint="e.g. corp.local", ctx=ctx)
    dc_ip      = ask("dc-ip",      hint="e.g. 192.168.1.10", ctx=ctx)
    user       = ask("user",       hint="e.g. Administrator", ctx=ctx)
    auth_args  = _ask_auth(ctx=ctx)
    default_start = f"{user}@{domain}" if user and domain else None
    start      = ask("start", default=default_start, ctx=ctx)
    port_scan  = ask_bool("enable port scan (top-100 TCP)?", ctx=ctx)
    output_dir = _resolve_output_dir(ask("output-dir", required=False, hint="e.g. results/my_scan", ctx=ctx))

    cmd = [
        "sudo", _python(), _script(),
        "--ip-cidr", ip_cidr, "--gateway", gateway, "--dns", dns,
        "--domain", domain, "--dc-ip", dc_ip, "--user", user, "--start", start,
    ] + auth_args
    if port_scan:  cmd.append("--port-scan")
    if output_dir: cmd += ["--output-dir", output_dir]
    return cmd


def build_pivot_ad():
    ctx = "pivot/ad>"
    hr()
    header("Pivot — AD + ADCS via proxychains")
    show_options([
        {"name": "--proxychains-conf", "desc": "proxychains4 config file"},
        {"name": "--domain",           "desc": "AD domain name"},
        {"name": "--dc-ip",            "desc": "Domain Controller IP"},
        {"name": "--dc-hostname",      "desc": "DC FQDN (recommended)", "req": False},
        {"name": "--user",             "desc": "AD username"},
        {"name": "--password/-H",      "desc": "Password or NT hash"},
        {"name": "--start",            "desc": "Start node for path analysis"},
        {"name": "--output-dir",       "desc": "Output directory"},
    ])
    proxychains = ask("proxychains-conf", hint="e.g. /etc/pivot.conf", ctx=ctx)
    domain      = ask("domain",          hint="e.g. dante.local", ctx=ctx)
    dc_ip       = ask("dc-ip",           hint="e.g. 172.16.1.20", ctx=ctx)
    dc_hostname = ask("dc-hostname",     hint="e.g. DC01.dante.local", required=False, ctx=ctx)
    user        = ask("user",            hint="e.g. xadmin", ctx=ctx)
    auth_args   = _ask_auth(ctx=ctx)
    default_start = f"{user}@{domain}" if user and domain else None
    start       = ask("start", default=default_start, ctx=ctx)
    output_dir  = _resolve_output_dir(ask("output-dir", hint="e.g. results/dante", ctx=ctx))

    cmd = [
        "proxychains4", "-f", proxychains,
        _python(), _script(),
        "--skip-network",
        "--domain", domain, "--dc-ip", dc_ip, "--user", user,
        "--start", start, "--dns-tcp",
    ] + auth_args
    if dc_hostname: cmd += ["--dc-hostname", dc_hostname]
    if output_dir:  cmd += ["--output-dir", output_dir]
    return cmd


def build_pivot_network():
    ctx = "pivot/net>"
    hr()
    header("Pivot — Network scan via proxychains")
    show_options([
        {"name": "--proxychains-conf", "desc": "proxychains4 config file"},
        {"name": "--targets",          "desc": "Target IPs (1 or more, comma-separated)"},
        {"name": "--bh-dir",           "desc": "BloodHound data directory"},
        {"name": "--output-dir",       "desc": "Output directory"},
    ])
    proxychains = ask("proxychains-conf", hint="e.g. /etc/pivot.conf", ctx=ctx)
    targets     = ask("targets",         hint="e.g. 172.16.1.20 or 172.16.1.5,172.16.1.20,172.16.1.100", ctx=ctx)
    bh_dir      = ask("bh-dir",          hint="e.g. results/dante/bloodhound_data", ctx=ctx)
    output_dir  = _resolve_output_dir(ask("output-dir", hint="same as AD scan  e.g. results/dante", ctx=ctx))

    # ip-cidr déduit du premier target (requis par argparse mais non utilisé avec --targets)
    first_ip = targets.split(",")[0].strip()
    cmd = [
        "sudo", _python(), _script(),
        "--ip-cidr", first_ip,
        "--domain", "x", "--dc-ip", "x", "--user", "x", "--password", "x", "--start", "x@x",
        "--proxychains-conf", proxychains,
        "--targets", targets,
        "--skip-bloodhound", "--bh-dir", bh_dir,
        "--skip-certipy", "--skip-enrichment",
        "--output-dir", output_dir,
    ]
    return cmd


# ── Menus ─────────────────────────────────────────────────────────────────────

BUILDERS = {
    "dc_only":       build_direct_dc_only,
    "net_only":      build_direct_network_only,
    "net_map":       build_direct_network_mapping,
    "ad_only":       build_direct_ad_only,
    "full":          build_direct_full,
    "pivot_ad":      build_pivot_ad,
    "pivot_network": build_pivot_network,
}


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    if "--help" in sys.argv or "-h" in sys.argv:
        print(HELP_TEXT)
        return

    clear()
    print_banner()

    mode = menu(
        [
            ("direct",  "Direct   — Direct access to target network"),
            ("pivot",   "Pivot    — Access via SOCKS tunnel / proxychains"),
        ],
        "Access mode",
        ctx="argus>"
    )

    if mode == "direct":
        submode = menu(
            [
                (None,       "Individual scan"),
                ("dc_only",  "DC only        port scan + AD + ADCS on a single machine"),
                ("net_only", "Network        network discovery (ARP, traceroute, ports)"),
                ("ad_only",  "AD + ADCS      BloodHound + Certipy identity collection"),
                (None,       "All-in-one"),
                ("full",     "Full           network + AD + ADCS in a single pass"),
                (None,       "Combine scans"),
                ("net_map",  "Network + map  add network layer to an existing AD scan"),
            ],
            "Scan type",
            ctx="direct>",
            note="Combine: use same --output-dir. Order does not matter."
        )
    else:
        submode = menu(
            [
                (None,             "Individual scan"),
                ("pivot_ad",       "AD + ADCS      BloodHound + Certipy via proxychains"),
                ("pivot_network",  "Network        network discovery via proxychains"),
            ],
            "Scan type",
            ctx="pivot>",
            note="Combine: use same --output-dir. Order does not matter."
        )

    cmd = BUILDERS[submode]()
    confirm_and_run(cmd)


if __name__ == "__main__":
    main()
