#!/usr/bin/env python3
"""
CartoAD - Full Scan Pipeline
Execute the complete workflow: Network scan → BloodHound → Enrichment → Graph generation

Usage:
    # IMPORTANT: Use the virtualenv Python with sudo to ensure dependencies are found
    sudo .env/bin/python3 run_full_scan.py \\
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
        print_info("Please run with: sudo .env/bin/python3 run_full_scan.py ...")
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


def detect_network_class(ip_cidr):
    """Detect if network is class C or larger."""
    ip_part = ip_cidr.split('/')[0]
    first_octet = int(ip_part.split('.')[0])

    # Get CIDR mask
    if '/' in ip_cidr:
        mask = int(ip_cidr.split('/')[1])
    else:
        mask = 24

    # Class C: 192.168.x.x/24 or similar small networks
    if first_octet == 192 and mask >= 24:
        return "C"
    else:
        return "AB"


def run_network_scan(args, output_dir):
    """Run the network scan script."""
    # Detect which script to use
    network_class = detect_network_class(args.ip_cidr)

    if network_class == "C":
        script = SCRIPT_DIR / "global_network_scan_classeC.py"
        print_info(f"Detected Class C network, using: {script.name}")
    else:
        script = SCRIPT_DIR / "global_network_scan_classeAB.py"
        print_info(f"Detected Class A/B network, using: {script.name}")

    output_file = output_dir / "network_scan.json"

    cmd = [
        sys.executable,
        str(script),
        "--ip_cidr", args.ip_cidr,
        "--gateway", args.gateway,
        "--dns", args.dns,
        "--output", str(output_file),
    ]

    if args.port_scan:
        cmd.append("--port-scan")

    if args.port_list:
        cmd.extend(["--port-list", args.port_list])

    print_info(f"Command: {' '.join(cmd)}")

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
        "-p", args.password,
        "-d", args.domain,
        "-ns", args.dc_ip,
        "-c", "All",
        "--zip",
    ]

    # Run from output_dir to get the zip there
    print_info(f"Command: bloodhound-python -u {username} -p *** -d {args.domain} -ns {args.dc_ip} -c All --zip")

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

            print_success(f"BloodHound data extracted to: {bh_dir}")
            return str(bh_dir)
        else:
            print_error("BloodHound completed but no zip file found")
            return None

    except subprocess.CalledProcessError as e:
        print_error(f"BloodHound collection failed with code {e.returncode}")
        return None
    except FileNotFoundError:
        print_error("bloodhound-python not found. Install with: pip install bloodhound")
        return None


def run_enrichment(args, output_dir, bh_dir):
    """Run hostname enrichment."""
    script = SCRIPT_DIR / "enrich_network_mapping.py"
    output_file = output_dir / "hostname_mapping.json"

    cmd = [
        sys.executable,
        str(script),
        "--bh-dir", bh_dir,
        "--dc-ip", args.dc_ip,
        "--domain", args.domain,
        "--output", str(output_file),
    ]

    print_info(f"Command: {' '.join(cmd)}")

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


def run_graph_generation(args, output_dir, bh_dir):
    """Run graph generation for all tiers."""
    script = SCRIPT_DIR / "run_all_modes.py"

    cmd = [
        sys.executable,
        str(script),
        "--data-dir", bh_dir,
        "--start", args.start,
        "--output-dir", str(output_dir),
    ]

    print_info(f"Command: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, check=True)

        # Check output files
        expected_files = ["graph_tier0.json", "graph_tier1.json", "graph_tier2.json", "graph_tier3.json"]
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
        description="CartoAD - Full Scan Pipeline: Network + BloodHound + Enrichment + Graphs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full scan with port detection
  sudo python3 run_full_scan.py \\
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
  sudo python3 run_full_scan.py \\
      --ip-cidr 10.0.0.0/24 \\
      --gateway 10.0.0.1 \\
      --dns 10.0.0.10 \\
      --domain corp.local \\
      --dc-ip 10.0.0.10 \\
      --user scanner \\
      --password 'secret' \\
      --start "scanner@corp.local"

  # Skip network scan (BloodHound only)
  python3 run_full_scan.py \\
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
    net_group.add_argument("--gateway", help="Gateway IP address")
    net_group.add_argument("--dns", help="DNS server IP (usually DC)")
    net_group.add_argument("--port-scan", action="store_true", help="Enable port/service scanning")
    net_group.add_argument("--port-list", help="Custom port list (e.g., '22,80,443,445')")
    net_group.add_argument("--skip-network", action="store_true", help="Skip network scan (AD only)")

    # AD arguments
    ad_group = parser.add_argument_group('Active Directory options')
    ad_group.add_argument("--domain", required=True, help="AD domain name (e.g., domain.local)")
    ad_group.add_argument("--dc-ip", required=True, help="Domain Controller IP address")
    ad_group.add_argument("--user", required=True, help="AD username for BloodHound collection")
    ad_group.add_argument("--password", required=True, help="AD password")
    ad_group.add_argument("--start", required=True, help="Start node for path analysis (e.g., user@domain.local)")
    ad_group.add_argument("--skip-bloodhound", action="store_true", help="Skip BloodHound collection (use existing data)")
    ad_group.add_argument("--bh-dir", help="Existing BloodHound data directory (with --skip-bloodhound)")

    # Output arguments
    out_group = parser.add_argument_group('Output options')
    out_group.add_argument("--output-dir", default=None, help="Output directory (default: results/<timestamp>)")
    out_group.add_argument("--skip-enrichment", action="store_true", help="Skip hostname enrichment step")

    args = parser.parse_args()

    # Validate arguments
    if not args.skip_network:
        if not args.ip_cidr or not args.gateway or not args.dns:
            parser.error("--ip-cidr, --gateway, and --dns are required unless --skip-network is used")

    if args.skip_bloodhound and not args.bh_dir:
        parser.error("--bh-dir is required when using --skip-bloodhound")

    # Check root for network scan
    if not args.skip_network and not check_root():
        return 1

    print_header("CartoAD - Full Scan Pipeline")

    # Check dependencies
    print_step(0, 4, "Checking dependencies...")
    if not check_dependencies():
        return 1
    print_success("All dependencies found")

    # Setup output directory
    if args.output_dir:
        output_dir = Path(args.output_dir)
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = SCRIPT_DIR / "results" / f"scan_{timestamp}"

    output_dir.mkdir(parents=True, exist_ok=True)
    print_info(f"Output directory: {output_dir}")

    # Track results
    results = {
        "network_scan": None,
        "bloodhound": None,
        "enrichment": None,
        "graphs": None,
    }

    total_steps = 4
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
    current_step += 1
    if args.skip_enrichment:
        print_step(current_step, total_steps, "Hostname enrichment (SKIPPED)")
        results["enrichment"] = "skipped"
    else:
        print_step(current_step, total_steps, "Hostname enrichment...")
        if run_enrichment(args, output_dir, bh_dir):
            results["enrichment"] = "success"
        else:
            results["enrichment"] = "warning"
            print_warning("Enrichment failed but continuing (non-blocking)")

    # Step 4: Graph generation
    current_step += 1
    print_step(current_step, total_steps, "Graph generation...")
    if run_graph_generation(args, output_dir, bh_dir):
        results["graphs"] = "success"
    else:
        results["graphs"] = "failed"

    # Summary
    print_header("SUMMARY")

    status_icons = {
        "success": f"{Colors.GREEN}✓{Colors.ENDC}",
        "failed": f"{Colors.RED}✗{Colors.ENDC}",
        "warning": f"{Colors.YELLOW}⚠{Colors.ENDC}",
        "skipped": f"{Colors.BLUE}○{Colors.ENDC}",
    }

    print(f"  {status_icons[results['network_scan']]} Network scan: {results['network_scan']}")
    print(f"  {status_icons[results['bloodhound']]} BloodHound collection: {results['bloodhound']}")
    print(f"  {status_icons[results['enrichment']]} Hostname enrichment: {results['enrichment']}")
    print(f"  {status_icons[results['graphs']]} Graph generation: {results['graphs']}")

    print(f"\n{Colors.BOLD}Output directory:{Colors.ENDC} {output_dir}")

    # List generated files
    print(f"\n{Colors.BOLD}Generated files:{Colors.ENDC}")
    for f in sorted(output_dir.glob("*.json")):
        print(f"  - {f.name}")

    # Instructions
    print(f"\n{Colors.BOLD}Next steps:{Colors.ENDC}")
    print(f"  1. Open cartographie.html in a browser")
    print(f"  2. Load network_scan.json (network layer)")
    print(f"  3. Load graph_tier0.json (AD attack paths)")

    # Return code
    if results["graphs"] == "success":
        print_success("\nPipeline completed successfully!")
        return 0
    else:
        print_error("\nPipeline completed with errors")
        return 1


if __name__ == "__main__":
    sys.exit(main())
