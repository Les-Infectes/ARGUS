#!/usr/bin/env python3
"""
ARGUS - Full Scan Pipeline
Execute the complete workflow: Network scan → BloodHound → Enrichment → Graph generation

Usage:
    # IMPORTANT: Use the virtualenv Python with sudo to ensure dependencies are found
    sudo .env/bin/python3 argus_pipeline.py \\
        --ip-cidr 192.168.30.0/24 \\
        --gateway 192.168.30.1 \\
        --dns 192.168.30.254 \\
        --domain domain.local \\
        --dc-ip 192.168.30.254 \\
        --user admin \\
        --password 'P@ssw0rd' \\
        --start "admin@domain.local" \\
        --output-dir results/my_scan
"""
import argparse
import subprocess
import sys
import os
import shutil
import tempfile
import zipfile
import glob as glob_module
from pathlib import Path
from datetime import datetime

# Get the directory where this script is located
SCRIPT_DIR = Path(__file__).parent.resolve()

# Get the bin directory of the current Python (for virtualenv support)
PYTHON_BIN_DIR = Path(sys.executable).parent


class Colors:
    """ANSI color codes for terminal output."""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


def print_header(msg):
    print(f"\n{Colors.BOLD}{Colors.HEADER}{'='*70}")
    print(f" {msg}")
    print(f"{'='*70}{Colors.ENDC}\n")


def print_step(step_num, total, msg):
    print(f"{Colors.CYAN}[{step_num}/{total}]{Colors.ENDC} {Colors.BOLD}{msg}{Colors.ENDC}")


def print_success(msg):
    print(f"{Colors.GREEN}✓ {msg}{Colors.ENDC}")


def print_error(msg):
    print(f"{Colors.RED}✗ {msg}{Colors.ENDC}")


def print_warning(msg):
    print(f"{Colors.YELLOW}⚠ {msg}{Colors.ENDC}")


def print_info(msg):
    print(f"{Colors.BLUE}ℹ {msg}{Colors.ENDC}")


def check_root():
    """Check if running as root (required for nmap)."""
    if os.geteuid() != 0:
        print_error("This script requires root privileges for network scanning.")
        print_info("Please run with: sudo .env/bin/python3 argus_pipeline.py ...")
        return False
    return True


def check_dependencies():
    """Check that required tools are available."""
    missing = []

    # Check nmap
    if shutil.which("nmap") is None:
        missing.append("nmap")

    # Check traceroute
    if shutil.which("traceroute") is None:
        missing.append("traceroute")

    # Check bloodhound-python
    try:
        subprocess.run([sys.executable, "-c", "import bloodhound"],
                      capture_output=True, check=True)
    except subprocess.CalledProcessError:
        missing.append("bloodhound (pip install bloodhound)")

    # Check dnspython
    try:
        subprocess.run([sys.executable, "-c", "import dns.resolver"],
                      capture_output=True, check=True)
    except subprocess.CalledProcessError:
        missing.append("dnspython (pip install dnspython)")

    if missing:
        print_error("Missing dependencies:")
        for dep in missing:
            print(f"  - {dep}")
        return False

    return True



def run_network_scan(args, output_dir):
    """Run the network scan script."""
    script = SCRIPT_DIR / "argus_network.py"
    output_file = output_dir / "network_scan.json"

    cmd = [
        sys.executable,
        str(script),
        "--ip_cidr", args.ip_cidr,
        "--output", str(output_file),
    ]

    if args.gateway:
        cmd.extend(["--gateway", args.gateway])
    if args.dns:
        cmd.extend(["--dns", args.dns])

    if args.proxychains_conf:
        cmd += ["--proxychains", "--proxychains-conf", args.proxychains_conf]

    if args.targets:
        cmd += ["--targets", args.targets]

    if args.port_scan or args.proxychains_conf:
        cmd.append("--port-scan")

    if args.port_list:
        cmd.extend(["--port-list", args.port_list])

    if args.single_host:
        cmd.append("--single-host")

    try:
        result = subprocess.run(cmd, check=True)
        if output_file.exists():
            print_success(f"Network scan completed: {output_file}")
            return True
        else:
            print_error("Network scan completed but output file not found")
            return False
    except subprocess.CalledProcessError as e:
        print_error(f"Network scan failed with code {e.returncode}")
        return False


def run_bloodhound_collection(args, output_dir):
    """Run BloodHound collection."""
    bh_dir = output_dir / "bloodhound_data"
    bh_dir.mkdir(parents=True, exist_ok=True)

    # Format username
    if '@' not in args.user:
        username = f"{args.user}@{args.domain}"
    else:
        username = args.user

    # Find bloodhound-python in the same directory as the current Python
    # This ensures we use the virtualenv's bloodhound-python when running with sudo
    bh_executable = PYTHON_BIN_DIR / "bloodhound-python"
    if not bh_executable.exists():
        # Fallback to system PATH
        bh_executable = shutil.which("bloodhound-python")
        if bh_executable is None:
            print_error("bloodhound-python not found. Install with: pip install bloodhound")
            return None

    cmd = [
        str(bh_executable),
        "-u", username,
        "-d", args.domain,
        "-ns", args.dc_ip,
        "-c", "All",
        "--zip",
    ]
    if args.hashes:
        # bloodhound-python expects LM:NT format
        cmd.extend(["--hashes", f"aad3b435b51404eeaad3b435b51404ee:{args.hashes}"])
        auth_display = "-H ***"
    else:
        cmd.extend(["-p", args.password])
        auth_display = "-p ***"
    if args.dns_tcp:
        cmd.append("--dns-tcp")
    cmd += ["--dns-timeout", str(args.dns_timeout)]
    if args.dc_hostname:
        cmd += ["-dc", args.dc_hostname]

    # Run from output_dir to get the zip there
    try:
        result = subprocess.run(cmd, check=True, cwd=str(output_dir))

        # Find and extract the zip file
        zip_files = list(output_dir.glob("*_bloodhound.zip"))
        if not zip_files:
            # Try other patterns
            zip_files = list(output_dir.glob("*.zip"))

        if zip_files:
            zip_file = zip_files[0]
            print_info(f"Extracting {zip_file.name}...")

            with zipfile.ZipFile(zip_file, 'r') as zf:
                zf.extractall(bh_dir)

            # Remove zip after extraction
            zip_file.unlink()

            # Validate extracted data
            json_files = list(bh_dir.glob("*.json"))
            if not json_files:
                print_error("BloodHound zip extracted but no JSON files found inside")
                return None

            print_success(f"BloodHound data extracted to: {bh_dir} ({len(json_files)} JSON files)")
            return str(bh_dir)
        else:
            # Fallback: check if bloodhound-python created JSON files directly (no zip)
            json_files = list(output_dir.glob("*_computers.json")) + list(output_dir.glob("*_users.json"))
            if json_files:
                print_info("No zip found, but JSON files detected. Moving to bloodhound_data/...")
                for jf in output_dir.glob("*.json"):
                    if jf.name.startswith("20"):  # bloodhound timestamp format
                        jf.rename(bh_dir / jf.name)
                json_files = list(bh_dir.glob("*.json"))
                if json_files:
                    print_success(f"BloodHound data moved to: {bh_dir} ({len(json_files)} JSON files)")
                    return str(bh_dir)
            print_error("BloodHound completed but no zip file or JSON data found")
            return None

    except subprocess.CalledProcessError as e:
        print_error(f"BloodHound collection failed with code {e.returncode}")
        return None
    except FileNotFoundError:
        print_error("bloodhound-python not found. Install with: pip install bloodhound")
        return None


def run_enrichment(args, output_dir, bh_dir):
    """Run hostname enrichment."""
    script = SCRIPT_DIR / "argus_enrich.py"
    output_file = output_dir / "hostname_mapping.json"

    cmd = [
        sys.executable,
        str(script),
        "--bh-dir", bh_dir,
        "--dc-ip", args.dc_ip,
        "--domain", args.domain,
        "--output", str(output_file),
    ]
    if args.dns_tcp:
        cmd.append("--dns-tcp")
    # Pass network_scan.json if it exists: nmap/SMB hostnames take priority over DNS
    network_scan_file = output_dir / "network_scan.json"
    if network_scan_file.exists():
        cmd.extend(["--network-scan", str(network_scan_file)])

    try:
        result = subprocess.run(cmd, check=True)
        if output_file.exists():
            print_success(f"Hostname mapping completed: {output_file}")
            return True
        else:
            print_warning("Enrichment completed but output file not found")
            return False
    except subprocess.CalledProcessError as e:
        print_warning(f"Enrichment failed with code {e.returncode} (non-blocking)")
        return False


def run_certipy_enumeration(args, output_dir, bh_dir):
    """Run Certipy ADCS enumeration and parse results."""
    script = SCRIPT_DIR / "argus_certipy.py"
    certipy_data_file = output_dir / "certipy_data.json"

    cmd = [
        sys.executable,
        str(script),
        "--data-dir", bh_dir,
        "--out", str(certipy_data_file),
    ]

    if args.certipy_json:
        cmd.extend(["--certipy-json", args.certipy_json])
    else:
        certipy_prefix = str(output_dir / "certipy_scan")
        cmd.extend([
            "--domain", args.domain,
            "--username", args.user,
            "--dc-ip", args.dc_ip,
            "--output-prefix", certipy_prefix,
        ])
        if args.hashes:
            cmd.extend(["--hashes", args.hashes])
        else:
            cmd.extend(["--password", args.password])
        if args.dns_tcp:
            cmd.append("--dns-tcp")

    try:
        result = subprocess.run(cmd, check=True)
        if certipy_data_file.exists():
            print_success(f"Certipy ADCS enumeration completed: {certipy_data_file}")
            return str(certipy_data_file)
        else:
            print_warning("Certipy completed but output file not found")
            return None
    except subprocess.CalledProcessError as e:
        print_warning(f"Certipy enumeration failed with code {e.returncode} (non-blocking)")
        # Fallback: check if certipy_data.json exists from a previous run
        if certipy_data_file.exists():
            print_info(f"Using existing certipy data: {certipy_data_file}")
            return str(certipy_data_file)
        return None


def run_graph_generation(args, output_dir, bh_dir, certipy_data=None):
    """Run graph generation for all tiers."""
    script = SCRIPT_DIR / "argus_graph.py"

    cmd = [
        sys.executable,
        str(script),
        "--data-dir", bh_dir,
        "--start", args.start,
        "--output-dir", str(output_dir),
    ]
    if certipy_data:
        cmd.extend(["--certipy-json", certipy_data])

    try:
        result = subprocess.run(cmd, check=True)

        # Check output files
        expected_files = ["graph_tier0.json", "graph_tier1.json", "graph_tier2.json"]
        found = [f for f in expected_files if (output_dir / f).exists()]

        if found:
            print_success(f"Graph generation completed: {len(found)}/{len(expected_files)} files")
            return True
        else:
            print_error("Graph generation completed but no output files found")
            return False

    except subprocess.CalledProcessError as e:
        print_error(f"Graph generation failed with code {e.returncode}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="ARGUS - Full Scan Pipeline: Network + BloodHound + Enrichment + Graphs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full scan with port detection
  sudo python3 argus_pipeline.py \\
      --ip-cidr 192.168.30.0/24 \\
      --gateway 192.168.30.1 \\
      --dns 192.168.30.254 \\
      --domain domain.local \\
      --dc-ip 192.168.30.254 \\
      --user admin \\
      --password 'P@ssw0rd' \\
      --start "admin@domain.local" \\
      --port-scan

  # Minimal scan (no port scan)
  sudo python3 argus_pipeline.py \\
      --ip-cidr 10.0.0.0/24 \\
      --gateway 10.0.0.1 \\
      --dns 10.0.0.10 \\
      --domain corp.local \\
      --dc-ip 10.0.0.10 \\
      --user scanner \\
      --password 'secret' \\
      --start "scanner@corp.local"

  # Skip network scan (BloodHound only)
  python3 argus_pipeline.py \\
      --skip-network \\
      --domain domain.local \\
      --dc-ip 192.168.30.254 \\
      --user admin \\
      --password 'P@ssw0rd' \\
      --start "admin@domain.local"
        """
    )

    # Network arguments
    net_group = parser.add_argument_group('Network scan options')
    net_group.add_argument("--ip-cidr", help="IP range to scan (e.g., 192.168.30.0/24)")
    net_group.add_argument("--gateway", help="Gateway IP address (not required in --proxychains-conf mode)")
    net_group.add_argument("--dns", help="DNS server IP (not required in --proxychains-conf mode)")
    net_group.add_argument("--port-scan", action="store_true", help="Enable port/service scanning")
    net_group.add_argument("--port-list", help="Custom port list (e.g., '22,80,443,445')")
    net_group.add_argument("--skip-network", action="store_true", help="Skip network scan (AD only)")
    net_group.add_argument("--proxychains-conf", default=None, help="Pivot mode: proxychains4 config file for network scan (e.g., pivot.conf). Skips ARP/ICMP/traceroute, uses TCP connect only.")
    net_group.add_argument("--targets", default=None, help="Pivot mode: comma-separated list of known IPs to port-scan (e.g., '172.16.1.20,172.16.1.45'). Much faster than full CIDR scan.")
    net_group.add_argument("--single-host", action="store_true", help="Single host mode: skip traceroute/ARP, only port scan the target IP")

    # AD arguments
    ad_group = parser.add_argument_group('Active Directory options')
    ad_group.add_argument("--domain", required=True, help="AD domain name (e.g., domain.local)")
    ad_group.add_argument("--dc-ip", required=True, help="Domain Controller IP address")
    ad_group.add_argument("--user", required=True, help="AD username for BloodHound collection")
    auth_group = ad_group.add_mutually_exclusive_group()
    auth_group.add_argument("--password", help="AD password")
    auth_group.add_argument("-H", "--hashes", help="NTLM hash for authentication (NT hash only, e.g., 31d6cfe0d16ae931b73c59d7e0c089c0)")
    ad_group.add_argument("--start", required=True, help="Start node for path analysis (e.g., user@domain.local)")
    ad_group.add_argument("--dns-tcp", action="store_true", help="Use TCP instead of UDP for DNS queries (required for proxychains/SOCKS)")
    ad_group.add_argument("--dns-timeout", type=int, default=10, help="DNS query timeout in seconds for bloodhound-python (default: 10)")
    ad_group.add_argument("--dc-hostname", default=None, help="DC FQDN for bloodhound-python -dc flag (e.g., dc01.DANTE.local)")
    ad_group.add_argument("--skip-bloodhound", action="store_true", help="Skip BloodHound collection (use existing data)")
    ad_group.add_argument("--bh-dir", help="Existing BloodHound data directory (with --skip-bloodhound)")

    # ADCS arguments
    adcs_group = parser.add_argument_group('ADCS options')
    adcs_group.add_argument("--skip-certipy", action="store_true", help="Skip Certipy ADCS enumeration")
    adcs_group.add_argument("--certipy-json", default=None, help="Use existing Certipy JSON file instead of running certipy")

    # Output arguments
    out_group = parser.add_argument_group('Output options')
    out_group.add_argument("--output-dir", default=None, help="Output directory (default: results/<timestamp>)")
    out_group.add_argument("--skip-enrichment", action="store_true", help="Skip hostname enrichment step")

    args = parser.parse_args()

    # Validate arguments
    if not args.skip_network:
        if not args.ip_cidr:
            parser.error("--ip-cidr is required unless --skip-network is used")
        if not args.proxychains_conf and not args.single_host and (not args.gateway or not args.dns):
            parser.error("--gateway and --dns are required unless --skip-network, --proxychains-conf, or --single-host is used")

    if not args.password and not args.hashes:
        parser.error("one of --password or -H/--hashes is required")

    dummy_start = not args.start or args.start.lower() == "x@x"
    if args.skip_bloodhound and not args.bh_dir and not dummy_start:
        parser.error("--bh-dir is required when using --skip-bloodhound with a real --start node")

    # Check root for network scan
    if not args.skip_network and not check_root():
        return 1

    print(f"\n{Colors.BOLD}ARGUS Pipeline{Colors.ENDC}")

    # Check dependencies
    if not check_dependencies():
        return 1

    # Setup output directory
    if args.output_dir:
        output_dir = Path(args.output_dir)
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = SCRIPT_DIR / "results" / f"scan_{timestamp}"

    output_dir.mkdir(parents=True, exist_ok=True)

    # Track results
    results = {
        "network_scan": None,
        "bloodhound": None,
        "enrichment": None,
        "certipy": None,
        "graphs": None,
    }

    total_steps = 5
    current_step = 0

    # Step 1: Network scan
    current_step += 1
    if args.skip_network:
        print_step(current_step, total_steps, "Network scan (SKIPPED)")
        results["network_scan"] = "skipped"
    else:
        print_step(current_step, total_steps, "Network scan...")
        if run_network_scan(args, output_dir):
            results["network_scan"] = "success"
        else:
            results["network_scan"] = "failed"
            print_error("Network scan failed. Continuing with AD collection...")

    # Step 2: BloodHound collection
    current_step += 1
    bh_dir = None
    if args.skip_bloodhound:
        print_step(current_step, total_steps, "BloodHound collection (SKIPPED - using existing data)")
        bh_dir = args.bh_dir
        results["bloodhound"] = "skipped"
    else:
        print_step(current_step, total_steps, "BloodHound collection...")
        bh_dir = run_bloodhound_collection(args, output_dir)
        if bh_dir:
            results["bloodhound"] = "success"
        else:
            results["bloodhound"] = "failed"
            print_error("BloodHound collection failed. Cannot continue without AD data.")
            return 1

    # Step 3: Enrichment
    # In pivot mode (--proxychains-conf), force enrichment even if --skip-enrichment was passed,
    # using nmap SMB hostnames from network_scan.json (no DNS needed).
    current_step += 1
    force_enrichment = bool(args.proxychains_conf and args.bh_dir)
    if (args.skip_enrichment and not force_enrichment) or not bh_dir:
        print_step(current_step, total_steps, "Hostname enrichment (SKIPPED)")
        results["enrichment"] = "skipped"
    else:
        label = "Hostname enrichment (pivot: SMB hostnames)..." if force_enrichment else "Hostname enrichment..."
        print_step(current_step, total_steps, label)
        if run_enrichment(args, output_dir, bh_dir):
            results["enrichment"] = "success"
        else:
            results["enrichment"] = "warning"
            print_warning("Enrichment failed but continuing (non-blocking)")

    # Step 4: Certipy ADCS enumeration
    current_step += 1
    certipy_data = None
    if args.skip_certipy:
        print_step(current_step, total_steps, "Certipy ADCS enumeration (SKIPPED)")
        results["certipy"] = "skipped"
    else:
        print_step(current_step, total_steps, "Certipy ADCS enumeration...")
        certipy_data = run_certipy_enumeration(args, output_dir, bh_dir)
        if certipy_data:
            results["certipy"] = "success"
        else:
            results["certipy"] = "warning"
            print_warning("Certipy failed but continuing (non-blocking)")

    # Step 5: Graph generation
    current_step += 1
    # Skip graphs if no usable BH data: skip-bloodhound with a dummy start (x@x = network-only intent)
    dummy_start = not args.start or args.start.lower() == "x@x"
    network_only_pass = args.skip_bloodhound and dummy_start
    if network_only_pass:
        print_step(current_step, total_steps, "Graph generation (SKIPPED - network-only pass)")
        results["graphs"] = "skipped"
    elif run_graph_generation(args, output_dir, bh_dir, certipy_data):
        results["graphs"] = "success"
    else:
        results["graphs"] = "failed"

    # Summary
    icons = {"success": "✓", "failed": "✗", "warning": "⚠", "skipped": "○"}
    print(f"\n{Colors.BOLD}── Summary ──{Colors.ENDC}")
    for key, label in [("network_scan", "Network"), ("bloodhound", "BloodHound"),
                       ("enrichment", "Mapping"), ("certipy", "Certipy"), ("graphs", "Graphs")]:
        print(f"  {icons[results[key]]} {label}: {results[key]}")
    print(f"  Output: {output_dir}")

    if results["graphs"] in ("success", "skipped"):
        return 0
    else:
        print_error("Pipeline completed with errors")
        return 1


if __name__ == "__main__":
    sys.exit(main())
