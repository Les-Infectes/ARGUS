#!/usr/bin/env python3
"""
ARGUS Import — Build cartography from existing nmap XML and BloodHound data.

Converts external scan files into ARGUS format and generates the unified cartography.

Usage:
    # Network only (nmap XML → network_scan.json)
    python3 argus_import.py --nmap-xml scan.xml --output-dir results/import

    # Full import (nmap XML + BloodHound → unified cartography)
    python3 argus_import.py --nmap-xml scan.xml --bh-dir bloodhound_data/ --start user@domain --output-dir results/import

    # Full import with mapping (DC accessible)
    python3 argus_import.py --nmap-xml scan.xml --bh-dir bloodhound_data/ --start user@domain --dc-ip 10.0.1.10 --output-dir results/import
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent.resolve()


def parse_nmap_xml_file(xml_path: str) -> list:
    """Parse an nmap XML file and return list of host dicts in ARGUS format.

    Reuses the existing parser from argus_network.py.
    """
    from argus_network import _parse_nmap_xml

    path = Path(xml_path)
    if not path.exists():
        print(f"✗ Nmap XML file not found: {xml_path}")
        return []

    xml_content = path.read_text(encoding="utf-8", errors="replace")
    hosts = _parse_nmap_xml(xml_content)
    print(f"✓ Parsed {len(hosts)} hosts from: {path.name}")

    hosts_with_hostname = sum(1 for h in hosts if h.get("hostname"))
    if hosts_with_hostname:
        print(f"  → {hosts_with_hostname} hosts with SMB hostname (usable for mapping)")
    total_services = sum(len(h.get("services", [])) for h in hosts)
    print(f"  → {total_services} open ports total")

    return hosts


def build_network_report(hosts: list, source_file: str) -> dict:
    """Build an ARGUS network_scan.json report from parsed nmap hosts."""
    active_hosts = []
    for h in hosts:
        entry = {"ip": h["ip"], "status": "up"}
        if h.get("hostname"):
            entry["hostname"] = h["hostname"]
        active_hosts.append(entry)

    return {
        "configuration": {
            "ip_cidr": "imported",
            "gateway": None,
            "dns": None,
            "mode": "import",
            "source_file": source_file,
        },
        "vlan_scan": {
            "target_cidr": "imported",
            "hosts_found": len(hosts),
            "active_hosts": active_hosts,
        },
        "phase_traceroutes": [],
        "router_discovery": {"skipped": True, "reason": "import mode"},
        "subnet_scans": [],
        "service_scan": {
            "enabled": True,
            "mode": "import",
            "ports": "from-nmap-xml",
            "results": hosts,
        },
    }


def run_step(description: str, cmd: list) -> bool:
    """Run a subprocess step with status display."""
    print(f"\n{'='*70}")
    print(f"  {description}")
    print(f"{'='*70}")
    result = subprocess.run(cmd)
    if result.returncode != 0:
        print(f"✗ Failed: {description}")
        return False
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Import existing nmap XML and BloodHound data into ARGUS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Network only
  python3 argus_import.py --nmap-xml scan.xml --output-dir results/import

  # Full import (offline, no mapping)
  python3 argus_import.py --nmap-xml scan.xml --bh-dir bh_data/ --start user@domain

  # Full import with DNS mapping (DC accessible)
  python3 argus_import.py --nmap-xml scan.xml --bh-dir bh_data/ --start user@domain --dc-ip 10.0.1.10
        """,
    )
    parser.add_argument("--nmap-xml", required=True, help="Path to nmap XML file (-oX output)")
    parser.add_argument("--output-dir", default="results/import", help="Output directory (default: results/import)")
    parser.add_argument("--bh-dir", default=None, help="BloodHound data directory (enables AD graph generation)")
    parser.add_argument("--start", default=None, help="Start node for path analysis (required with --bh-dir)")
    parser.add_argument("--certipy-json", default=None, help="Certipy JSON file for ADCS analysis")
    parser.add_argument("--dc-ip", default=None, help="DC IP for hostname mapping (requires network access)")
    parser.add_argument("--dns-tcp", action="store_true", help="Use TCP for DNS (pivot mode)")
    parser.add_argument("--proxychains-conf", default=None, help="proxychains4 config (pivot DNS mapping)")

    args = parser.parse_args()

    print("=" * 70)
    print("ARGUS — Import Mode")
    print("=" * 70)
    print(f"Nmap XML:   {args.nmap_xml}")
    if args.bh_dir:
        print(f"BH dir:     {args.bh_dir}")
        print(f"Start node: {args.start}")
    if args.certipy_json:
        print(f"Certipy:    {args.certipy_json}")
    if args.dc_ip:
        proto = "TCP (pivot)" if args.dns_tcp else "UDP (direct)"
        print(f"DC IP:      {args.dc_ip} ({proto})")
    print(f"Output dir: {args.output_dir}")

    # Validate args
    if args.bh_dir and not args.start:
        print("\n✗ --start is required when --bh-dir is provided")
        return 1

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # ── Step 1: Parse nmap XML → network_scan.json ────────────────────────
    print(f"\n{'='*70}")
    print("  Step 1 — Parsing nmap XML")
    print(f"{'='*70}")

    hosts = parse_nmap_xml_file(args.nmap_xml)
    if not hosts:
        print("✗ No hosts found in nmap XML")
        return 1

    report = build_network_report(hosts, args.nmap_xml)
    network_json = output_dir / "network_scan.json"
    with open(network_json, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"✓ Saved: {network_json}")

    # If no BH data, we're done (network only mode)
    if not args.bh_dir:
        print(f"\n✓ Network import complete: {network_json}")
        print("  Load this file in cartographie.html to view the network layer.")
        return 0

    # ── Step 2: Hostname mapping (if DC accessible) ───────────────────────
    if args.dc_ip:
        enrich_cmd = [
            sys.executable, str(SCRIPT_DIR / "argus_enrich.py"),
            "--bh-dir", args.bh_dir,
            "--dc-ip", args.dc_ip,
            "--domain", "imported",
            "--output", str(output_dir / "hostname_mapping.json"),
            "--network-scan", str(network_json),
        ]
        if args.dns_tcp:
            enrich_cmd.append("--dns-tcp")

        # Wrap with proxychains if pivot mode
        if args.proxychains_conf:
            enrich_cmd = ["proxychains4", "-f", args.proxychains_conf] + enrich_cmd

        if not run_step("Step 2 — Hostname mapping (DNS resolution)", enrich_cmd):
            print("  ⚠ Mapping failed, continuing without hostname→IP mapping")
    else:
        print(f"\n  ⚠ No --dc-ip provided, skipping hostname mapping")
        print(f"    Network and AD layers will not be linked in cartographie")

    # ── Step 3: Generate tier graphs ──────────────────────────────────────
    graph_cmd = [
        sys.executable, str(SCRIPT_DIR / "argus_graph.py"),
        "--data-dir", args.bh_dir,
        "--start", args.start,
        "--output-dir", str(output_dir),
    ]
    if args.certipy_json:
        graph_cmd += ["--certipy-json", args.certipy_json]

    if not run_step("Step 3 — Generating tier graphs", graph_cmd):
        return 1

    # ── Summary ───────────────────────────────────────────────────────────
    print(f"\n{'='*70}")
    print("IMPORT COMPLETE")
    print(f"{'='*70}")
    print(f"Output directory: {output_dir}/")
    print(f"  - network_scan.json        (network layer)")
    print(f"  - graph_tier0/1/2.json     (AD tier graphs)")
    if args.dc_ip and (output_dir / "hostname_mapping.json").exists():
        print(f"  - hostname_mapping.json    (network ↔ AD mapping)")
    print(f"\nOpen cartographie.html and load these files to view the unified cartography.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
