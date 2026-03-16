#!/usr/bin/env python3
"""
Enrich network mapping by resolving Computer hostnames to IPs using domain credentials.

This script uses authenticated DNS queries to the Domain Controller to map
BloodHound Computer objects (hostnames) to network IPs discovered during scanning.

Features:
- Direct DNS queries to DC (using dnspython)
- LDAP queries for additional attributes (optional, requires ldap3)
Usage:
    python3 argus_enrich.py \\
        --bh-dir bh/jsonBoxDomain \\
        --dc-ip 192.168.1.1 \\
        --domain domain.local \\
        --output results/hostname_mapping.json
"""
import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional

import dns.resolver
import dns.query
import dns.message


def load_bloodhound_computers(bh_dir: str) -> List[Dict]:
    """
    Load Computer objects from BloodHound JSON.

    Supports both standard filename (computers.json) and
    timestamped filenames (e.g., 20260118185834_computers.json).
    """
    bh_path = Path(bh_dir)

    # Try to find computers file with glob pattern (timestamped files)
    computers_files = list(bh_path.glob("*_computers.json"))

    if computers_files:
        # Use the most recent one if multiple exist
        computers_file = sorted(computers_files)[-1]
    else:
        # Fallback to standard filename
        computers_file = bh_path / "computers.json"

    if not computers_file.exists():
        print(f"✗ BloodHound computers.json not found in: {bh_dir}")
        print(f"  Searched for: *_computers.json and computers.json")
        return []

    with open(computers_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    computers = data.get("data", [])
    print(f"✓ Loaded {len(computers)} computers from: {computers_file.name}")
    return computers


def resolve_with_dnspython(hostname: str, dc_ip: str, timeout: int = 2, use_tcp: bool = False) -> List[str]:
    """
    Resolve hostname using dnspython with direct query to DC.

    This bypasses system resolver and queries the DC directly.
    use_tcp: force TCP transport (required when going through proxychains/SOCKS).
    """
    ips = []

    try:
        # Create a custom resolver pointing to the DC
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dc_ip]
        resolver.timeout = timeout
        resolver.lifetime = timeout
        if use_tcp:
            resolver.use_tcp = True

        # Query A records (IPv4)
        try:
            answers = resolver.resolve(hostname, 'A')
            ips = [str(rdata.address) for rdata in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            pass

    except Exception as e:
        # DNS query failed
        pass

    return ips


def resolve_hostname_to_ip(hostname: str, dc_ip: Optional[str] = None, timeout: int = 2, use_tcp: bool = False) -> List[str]:
    """Resolve hostname to IP address(es) via DNS query to DC."""
    if dc_ip:
        return resolve_with_dnspython(hostname, dc_ip, timeout, use_tcp=use_tcp)
    return []


def build_nmap_hostname_index(network_scan_path: str) -> Dict[str, str]:
    """Build a hostname -> IP index from a network_scan.json (nmap SMB discovery).

    Returns: Dict mapping normalized_hostname -> ip
    """
    index = {}
    if not network_scan_path:
        return index
    try:
        with open(network_scan_path, "r", encoding="utf-8") as f:
            scan = json.load(f)
    except (IOError, json.JSONDecodeError):
        print(f"  ⚠ Cannot read network scan: {network_scan_path}")
        return index

    # Collect hosts from all scan sections
    hosts = []
    for h in scan.get("vlan_scan", {}).get("active_hosts", []):
        hosts.append(h)
    for result in scan.get("service_scan", {}).get("results", []):
        hosts.append(result)

    for h in hosts:
        ip = h.get("ip")
        hostname = h.get("hostname")
        if ip and hostname:
            # Index by short name and FQDN
            key_fqdn = hostname.lower().rstrip(".")
            key_short = key_fqdn.split(".")[0]
            index[key_fqdn] = ip
            index[key_short] = ip

    if index:
        print(f"  → Network scan hostnames indexed: {len(index)} entries from {network_scan_path}")
    return index


def enrich_mapping(computers: List[Dict], dc_ip: Optional[str] = None, timeout: int = 2,
                   use_tcp: bool = False, nmap_index: Optional[Dict[str, str]] = None) -> Dict[str, Dict]:
    """
    Enrich Computer objects with IP addresses by resolving hostnames.

    Priority: nmap SMB hostname index > DNS (TCP or UDP) > system resolver

    Returns: Dict mapping hostname -> {ips: [], objectid: str, properties: {}}
    """
    mapping = {}
    resolved_count = 0
    failed_count = 0

    print("\n[ENRICHMENT] Resolving Computer hostnames to IPs...")

    if nmap_index:
        print(f"  → Using nmap SMB hostnames (pivot mode, no DNS needed)")
    elif dc_ip:
        proto = "TCP" if use_tcp else "UDP"
        print(f"  → Using direct DNS queries to DC: {dc_ip} ({proto})")
    else:
        print(f"  ⚠ No DC IP provided, DNS resolution disabled")

    for i, comp in enumerate(computers):
        object_id = comp.get("ObjectIdentifier", "")
        properties = comp.get("Properties", {}) or {}

        # Get hostname variants
        dns_hostname = properties.get("dnshostname", "")
        name = properties.get("name", "")

        if not dns_hostname and not name:
            continue

        # Try to resolve (prefer dNSHostName which is FQDN)
        hostname = dns_hostname or name

        # Priority 1: nmap SMB index (most reliable in pivot mode)
        ips = []
        if nmap_index:
            key_fqdn = hostname.lower().rstrip(".")
            key_short = key_fqdn.split(".")[0]
            ip = nmap_index.get(key_fqdn) or nmap_index.get(key_short)
            if ip:
                ips = [ip]

        # Priority 2: DNS resolution
        if not ips:
            ips = resolve_hostname_to_ip(hostname, dc_ip, timeout, use_tcp=use_tcp)

        # Store mapping
        hostname_key = hostname.lower()
        mapping[hostname_key] = {
            "hostname": hostname,
            "ips": ips,
            "objectid": object_id,
            "properties": {
                "dnshostname": dns_hostname,
                "name": name,
                "enabled": properties.get("enabled", True),
                "operatingsystem": properties.get("operatingsystem", ""),
            }
        }

        if ips:
            resolved_count += 1
            print(f"  ✓ [{i+1}/{len(computers)}] {hostname} → {', '.join(ips)}")
        else:
            failed_count += 1
            # Only print failures for first 10, then summarize
            if failed_count <= 10:
                print(f"  ✗ [{i+1}/{len(computers)}] {hostname} (no resolution)")

    if failed_count > 10:
        print(f"  ... and {failed_count - 10} more failed")

    print(f"\n  ✓ Successfully resolved: {resolved_count}/{len(computers)} computers ({resolved_count*100//len(computers) if computers else 0}%)")
    print(f"  ✗ Failed to resolve: {failed_count}/{len(computers)} computers")

    return mapping


def main():
    parser = argparse.ArgumentParser(
        description="Enrich network mapping by resolving AD Computer hostnames to IPs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage (system resolver)
  python3 argus_enrich.py --bh-dir bh/jsonBoxDomain

  # With DC IP (direct DNS queries)
  python3 argus_enrich.py \\
    --bh-dir bh/jsonBoxDomain \\
    --dc-ip 192.168.1.1 \\
    --domain domain.local

  # Custom output and timeout
  python3 argus_enrich.py \\
    --bh-dir bh/jsonBoxDomain \\
    --dc-ip 192.168.1.1 \\
    --output results/mapping.json \\
    --timeout 5
        """
    )
    parser.add_argument(
        "--bh-dir",
        required=True,
        help="Path to BloodHound JSON folder (e.g., bh/jsonBoxDomain)"
    )
    parser.add_argument(
        "--dc-ip",
        help="Domain Controller IP for direct DNS queries (recommended)"
    )
    parser.add_argument(
        "--domain",
        help="Domain name (e.g., domain.local) - for metadata only"
    )
    parser.add_argument(
        "--output",
        default="results/hostname_mapping.json",
        help="Output JSON path for hostname->IP mapping (default: results/hostname_mapping.json)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=2,
        help="DNS resolution timeout in seconds (default: 2)"
    )
    parser.add_argument(
        "--dns-tcp",
        action="store_true",
        help="Use TCP for DNS queries (required when going through proxychains/SOCKS)"
    )
    parser.add_argument(
        "--network-scan",
        default=None,
        help="Path to network_scan.json to use nmap SMB hostnames instead of DNS (pivot mode)"
    )

    args = parser.parse_args()

    print("="*70)
    print("CartoAD - Network ↔ AD Mapping Enrichment")
    print("="*70)
    print(f"BloodHound dir: {args.bh_dir}")
    if args.dc_ip:
        print(f"DC IP: {args.dc_ip}")
    if args.domain:
        print(f"Domain: {args.domain}")
    print(f"Output: {args.output}")
    print(f"Timeout: {args.timeout}s")
    if args.dns_tcp:
        print(f"DNS transport: TCP (proxychains mode)")

    # Load BloodHound computers
    computers = load_bloodhound_computers(args.bh_dir)
    if not computers:
        print("\n✗ No computers found in BloodHound data")
        return 1

    # Build nmap SMB hostname index (pivot mode)
    nmap_index = build_nmap_hostname_index(args.network_scan) if args.network_scan else None

    # Enrich with IP resolution
    mapping = enrich_mapping(computers, args.dc_ip, args.timeout, use_tcp=args.dns_tcp, nmap_index=nmap_index)

    # Save mapping
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    output_data = {
        "metadata": {
            "domain": args.domain or "unknown",
            "dc_ip": args.dc_ip or "system-resolver",
            "total_computers": len(computers),
            "resolved_count": len([m for m in mapping.values() if m["ips"]]),
            "failed_count": len([m for m in mapping.values() if not m["ips"]]),
            "resolution_rate": f"{len([m for m in mapping.values() if m['ips']])*100//len(computers) if computers else 0}%",
        },
        "mapping": mapping
    }

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2)

    print(f"\n✓ Saved hostname mapping to: {output_path}")
    print("\n" + "="*70)
    print("USAGE")
    print("="*70)
    print("This mapping file improves network ↔ AD fusion in cartographie.html")
    print("by providing explicit hostname->IP mappings.")
    print("\nNext steps:")
    print("  1. Load your network scan JSON in the UI")
    print("  2. Load your AD graph JSON (graph_tierX.json)")
    print("  3. The mapping will automatically improve Computer ↔ Machine bridges")

    return 0


if __name__ == "__main__":
    sys.exit(main())
