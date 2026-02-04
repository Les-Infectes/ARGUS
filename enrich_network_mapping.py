#!/usr/bin/env python3
"""
Enrich network mapping by resolving Computer hostnames to IPs using domain credentials.

This script uses authenticated DNS queries to the Domain Controller to map
BloodHound Computer objects (hostnames) to network IPs discovered during scanning.

Features:
- Direct DNS queries to DC (using dnspython)
- LDAP queries for additional attributes (optional, requires ldap3)
- Fallback to system resolver if DC not reachable

Usage:
    python3 enrich_network_mapping.py \\
        --bh-dir bh/jsonBoxDomain \\
        --dc-ip 192.168.1.1 \\
        --domain domain.local \\
        --output results/hostname_mapping.json
"""
import argparse
import json
import socket
import sys
from pathlib import Path
from typing import Dict, List, Optional

try:
    import dns.resolver
    import dns.query
    import dns.message
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    print("[WARNING] dnspython not installed. Install with: pip install dnspython")


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


def resolve_with_dnspython(hostname: str, dc_ip: str, timeout: int = 2) -> List[str]:
    """
    Resolve hostname using dnspython with direct query to DC.

    This bypasses system resolver and queries the DC directly.
    """
    if not DNS_AVAILABLE:
        return []

    ips = []

    try:
        # Create a custom resolver pointing to the DC
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dc_ip]
        resolver.timeout = timeout
        resolver.lifetime = timeout

        # Query A records (IPv4)
        try:
            answers = resolver.resolve(hostname, 'A')
            ips = [str(rdata.address) for rdata in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            pass

        # Optionally query AAAA records (IPv6) - uncomment if needed
        # try:
        #     answers = resolver.resolve(hostname, 'AAAA')
        #     ips.extend([str(rdata.address) for rdata in answers])
        # except:
        #     pass

    except Exception as e:
        # DNS query failed
        pass

    return ips


def resolve_with_system(hostname: str, timeout: int = 2) -> List[str]:
    """
    Fallback: Resolve hostname using system resolver.

    This uses /etc/resolv.conf and requires DNS to point to DC.
    """
    ips = []

    try:
        # Set socket timeout
        original_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)

        # Standard DNS resolution
        result = socket.getaddrinfo(hostname, None, socket.AF_INET)
        ips = list(set([r[4][0] for r in result]))

        # Restore original timeout
        socket.setdefaulttimeout(original_timeout)

    except (socket.gaierror, socket.timeout):
        pass

    return ips


def resolve_hostname_to_ip(hostname: str, dc_ip: Optional[str] = None, timeout: int = 2) -> List[str]:
    """
    Resolve hostname to IP address(es).

    Strategy:
    1. Try direct DNS query to DC (if dc_ip provided and dnspython available)
    2. Fallback to system resolver
    """
    ips = []

    # Try dnspython first (direct DC query)
    if dc_ip and DNS_AVAILABLE:
        ips = resolve_with_dnspython(hostname, dc_ip, timeout)
        if ips:
            return ips

    # Fallback to system resolver
    ips = resolve_with_system(hostname, timeout)

    return ips


def enrich_mapping(computers: List[Dict], dc_ip: Optional[str] = None, timeout: int = 2) -> Dict[str, Dict]:
    """
    Enrich Computer objects with IP addresses by resolving hostnames.

    Returns: Dict mapping hostname -> {ips: [], objectid: str, properties: {}}
    """
    mapping = {}
    resolved_count = 0
    failed_count = 0

    print("\n[ENRICHMENT] Resolving Computer hostnames to IPs...")

    if dc_ip:
        if DNS_AVAILABLE:
            print(f"  → Using direct DNS queries to DC: {dc_ip}")
        else:
            print(f"  ⚠ dnspython not available, using system resolver")
    else:
        print(f"  → Using system resolver (check /etc/resolv.conf points to DC)")

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
        ips = resolve_hostname_to_ip(hostname, dc_ip, timeout)

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
  python3 enrich_network_mapping.py --bh-dir bh/jsonBoxDomain

  # With DC IP (direct DNS queries)
  python3 enrich_network_mapping.py \\
    --bh-dir bh/jsonBoxDomain \\
    --dc-ip 192.168.1.1 \\
    --domain domain.local

  # Custom output and timeout
  python3 enrich_network_mapping.py \\
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

    # Check dnspython availability
    if not DNS_AVAILABLE:
        print("\n⚠ WARNING: dnspython not installed!")
        print("   Install with: pip install dnspython")
        print("   Falling back to system resolver (less reliable)")
        if not args.dc_ip:
            print("\n   Make sure /etc/resolv.conf points to the DC:")
            print("   echo 'nameserver <DC_IP>' | sudo tee /etc/resolv.conf")

    # Load BloodHound computers
    computers = load_bloodhound_computers(args.bh_dir)
    if not computers:
        print("\n✗ No computers found in BloodHound data")
        return 1

    # Enrich with IP resolution
    mapping = enrich_mapping(computers, args.dc_ip, args.timeout)

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
