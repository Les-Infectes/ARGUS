#!/usr/bin/env python3
"""
argus_certipy.py - Parse Certipy JSON output into argus_builder.py compatible format.

Takes certipy find -json output and generates certipy_data.json with:
- CertTemplate nodes for vulnerable templates (ESC1-ESC16)
- ACE edges (Enroll, GenericAll, WriteDacl, WriteOwner...) linked to BloodHound SIDs

Usage:
    # From existing certipy JSON:
    python3 argus_certipy.py \
        --certipy-json results/escape_ryan/20260211215427_Certipy.json \
        --data-dir results/escape_ryan_cooper/bloodhound_data \
        --out certipy_data.json

    # Run certipy and parse:
    python3 argus_certipy.py \
        --domain sequel.htb --username ryan.cooper --password 'pass' \
        --dc-ip 10.10.11.202 \
        --data-dir results/escape_ryan_cooper/bloodhound_data \
        --out certipy_data.json
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

# Get the bin directory of the current Python (for virtualenv support)
PYTHON_BIN_DIR = Path(sys.executable).parent


# Mapping certipy permission categories → RightName for argus_builder ACE edges
PERMISSION_MAPPING = {
    # Enrollment Permissions
    "Enrollment Rights": "Enroll",
    "All Extended Rights": "AllExtendedRights",
    # Object Control Permissions
    "Full Control Principals": "GenericAll",
    "Write Owner Principals": "WriteOwner",
    "Write Dacl Principals": "WriteDacl",
}

# Write Property permissions from certipy (prefixed with "Write Property ")
WRITE_PROPERTY_MAPPING = {
    "Write Property Enroll": "Enroll",
    "Write Property AutoEnroll": "AutoEnroll",
}


def build_name_to_sid(data_dir):
    """Build a mapping from DOMAIN\\name and NAME@DOMAIN to SID using BloodHound data."""
    name_to_sid = {}

    if not data_dir or not os.path.isdir(data_dir):
        print(f"[!] BloodHound data directory not found: {data_dir}", file=sys.stderr)
        return name_to_sid

    for fname in os.listdir(data_dir):
        if not fname.endswith(".json"):
            continue
        fpath = os.path.join(data_dir, fname)
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                content = json.load(f)
        except (json.JSONDecodeError, IOError):
            continue

        for obj in content.get("data", []):
            oid = obj.get("ObjectIdentifier")
            if not oid:
                continue
            props = obj.get("Properties", {}) or {}
            name = props.get("name", "")
            sam = props.get("samaccountname", "")
            domain = props.get("domain", "")

            # Index: NAME@DOMAIN -> SID (lowercase)
            if name:
                name_to_sid[name.lower()] = oid
            # Index: DOMAIN\sam -> SID (lowercase)
            if domain and sam:
                key = f"{domain}\\{sam}".lower()
                name_to_sid[key] = oid
                # Also index sam@DOMAIN
                key2 = f"{sam}@{domain}".lower()
                name_to_sid[key2] = oid

    return name_to_sid


def certipy_name_to_bh_key(certipy_name):
    """Convert certipy format DOMAIN\\name to BloodHound format NAME@DOMAIN (uppercase)."""
    if "\\" in certipy_name:
        domain, name = certipy_name.split("\\", 1)
        return f"{name.upper()}@{domain.upper()}"
    return certipy_name.upper()


def resolve_principal(certipy_name, name_to_sid):
    """Resolve a certipy principal name to a BloodHound SID."""
    # Try direct DOMAIN\name lookup
    key = certipy_name.lower()
    if key in name_to_sid:
        return name_to_sid[key]

    # Try NAME@DOMAIN format
    bh_key = certipy_name_to_bh_key(certipy_name).lower()
    if bh_key in name_to_sid:
        return name_to_sid[bh_key]

    # Try just the name part (without domain)
    if "\\" in certipy_name:
        _, name_part = certipy_name.split("\\", 1)
        name_lower = name_part.lower()
        for k, v in name_to_sid.items():
            if k.endswith(name_lower) or k.startswith(name_lower):
                return v

    return None


def parse_template_permissions(template, name_to_sid):
    """Extract ACE edges from certipy template permissions."""
    aces = []
    permissions = template.get("Permissions", {})

    # Enrollment Permissions
    enrollment_perms = permissions.get("Enrollment Permissions", {})
    for perm_key, right_name in PERMISSION_MAPPING.items():
        principals = enrollment_perms.get(perm_key, [])
        for principal_name in principals:
            sid = resolve_principal(principal_name, name_to_sid)
            if sid:
                aces.append({
                    "PrincipalSID": sid,
                    "RightName": right_name,
                    "IsInherited": False,
                })

    # Object Control Permissions
    obj_control = permissions.get("Object Control Permissions", {})

    # Owner -> Owns
    owner = obj_control.get("Owner")
    if owner:
        sid = resolve_principal(owner, name_to_sid)
        if sid:
            aces.append({
                "PrincipalSID": sid,
                "RightName": "Owns",
                "IsInherited": False,
            })

    # Other control permissions
    for perm_key, right_name in PERMISSION_MAPPING.items():
        principals = obj_control.get(perm_key, [])
        for principal_name in principals:
            sid = resolve_principal(principal_name, name_to_sid)
            if sid:
                aces.append({
                    "PrincipalSID": sid,
                    "RightName": right_name,
                    "IsInherited": False,
                })

    # Write Property permissions (dynamic keys like "Write Property Enroll")
    for perm_key, right_name in WRITE_PROPERTY_MAPPING.items():
        principals = obj_control.get(perm_key, [])
        for principal_name in principals:
            sid = resolve_principal(principal_name, name_to_sid)
            if sid:
                aces.append({
                    "PrincipalSID": sid,
                    "RightName": right_name,
                    "IsInherited": False,
                })

    # Handle any other "Write Property *" keys not in our mapping
    for key, principals in obj_control.items():
        if key.startswith("Write Property ") and key not in WRITE_PROPERTY_MAPPING:
            if isinstance(principals, list):
                for principal_name in principals:
                    sid = resolve_principal(principal_name, name_to_sid)
                    if sid:
                        aces.append({
                            "PrincipalSID": sid,
                            "RightName": "GenericWrite",
                            "IsInherited": False,
                        })

    return aces


def parse_certipy_json(certipy_data, name_to_sid):
    """Parse certipy JSON and generate argus_builder compatible data."""
    output_data = []

    templates = certipy_data.get("Certificate Templates", {})
    if isinstance(templates, str):
        print(f"[!] No certificate templates found: {templates}", file=sys.stderr)
        return output_data

    for idx, template in templates.items():
        template_name = template.get("Template Name", f"Unknown_{idx}")
        display_name = template.get("Display Name", template_name)
        vulnerabilities = template.get("[!] Vulnerabilities", {})
        enabled = template.get("Enabled", False)

        # Only include templates with vulnerabilities
        if not vulnerabilities:
            continue

        esc_list = sorted(vulnerabilities.keys())
        esc_label = ",".join(esc_list)

        # Generate a stable ObjectIdentifier for this template
        oid = f"certtemplate-{template_name}"

        # Build ACE edges from permissions
        aces = parse_template_permissions(template, name_to_sid)

        # Build node
        node = {
            "ObjectIdentifier": oid,
            "Properties": {
                "name": f"{template_name} [{esc_label}]",
                "display_name": display_name,
                "template_name": template_name,
                "esc_vulnerabilities": esc_list,
                "esc_details": vulnerabilities,
                "enabled": enabled,
                "client_authentication": template.get("Client Authentication", False),
                "enrollee_supplies_subject": template.get("Enrollee Supplies Subject", False),
                "ca_names": template.get("Certificate Authorities", []),
                "schema_version": template.get("Schema Version"),
                "extended_key_usage": template.get("Extended Key Usage", []),
            },
            "Aces": aces,
        }
        output_data.append(node)

    return output_data


def find_certipy_executable():
    """Find certipy binary in virtualenv or system PATH."""
    # First try the same directory as the current Python (virtualenv support)
    certipy_bin = PYTHON_BIN_DIR / "certipy"
    if certipy_bin.exists():
        return str(certipy_bin)

    # Fallback to system PATH
    found = shutil.which("certipy")
    if found:
        return found

    return None


def run_certipy(domain, username, password, dc_ip, output_prefix, dns_tcp=False, hashes=None):
    """Run certipy find and return the JSON output path.

    Note: certipy replaces '/' with '_' in -output prefix, so we must
    use cwd to control where the file is written and pass a simple prefix name.
    """
    certipy_executable = find_certipy_executable()
    if not certipy_executable:
        print("[!] certipy not found. Install with: pip install certipy-ad", file=sys.stderr)
        return None

    # Split prefix into directory + basename (certipy doesn't support absolute paths)
    output_dir = os.path.dirname(output_prefix) or "."
    prefix_name = os.path.basename(output_prefix)

    # Remove existing output to avoid certipy "Overwrite?" blocking prompt
    existing_json = os.path.join(output_dir, f"{prefix_name}_Certipy.json")
    if os.path.exists(existing_json):
        os.remove(existing_json)

    cmd = [
        certipy_executable, "find",
        "-json", "-vulnerable",
        "-u", f"{username}@{domain}",
        "-dc-ip", dc_ip,
        "-timeout", "10",
        "-output", prefix_name,
    ]
    if hashes:
        # certipy expects -hashes [lmhash:]nthash
        cmd.extend(["-hashes", f":{hashes}"])
    else:
        cmd.extend(["-p", password])
    if dns_tcp:
        cmd.append("-dns-tcp")
    print(f"[*] Running: {' '.join(cmd)}")
    print(f"[*] Working directory: {output_dir}")
    try:
        result = subprocess.run(cmd, timeout=600, cwd=output_dir)
        if result.returncode != 0:
            print(f"[!] Certipy exited with code {result.returncode}", file=sys.stderr)
            return None
    except FileNotFoundError:
        print("[!] certipy not found. Install with: pip install certipy-ad", file=sys.stderr)
        return None
    except subprocess.TimeoutExpired:
        print("[!] Certipy timed out after 600s", file=sys.stderr)
        return None

    # Find the generated JSON file
    json_path = os.path.join(output_dir, f"{prefix_name}_Certipy.json")
    if os.path.exists(json_path):
        return json_path

    # Fallback: search for any certipy JSON in output_dir
    for f in os.listdir(output_dir):
        if f.endswith("_Certipy.json") and prefix_name in f:
            return os.path.join(output_dir, f)

    print(f"[!] Certipy JSON not found at {json_path}", file=sys.stderr)
    return None


def main():
    parser = argparse.ArgumentParser(
        description="Parse Certipy JSON output into argus_builder.py compatible format"
    )
    parser.add_argument("--certipy-json", help="Path to existing Certipy JSON file")
    parser.add_argument("--data-dir", required=True,
                        help="BloodHound data directory (for name→SID resolution)")
    parser.add_argument("--out", default="certipy_data.json",
                        help="Output file path (default: certipy_data.json)")

    # Certipy run options (if no --certipy-json provided)
    parser.add_argument("--domain", help="Domain for certipy")
    parser.add_argument("--username", help="Username for certipy")
    parser.add_argument("--password", help="Password for certipy")
    parser.add_argument("--hashes", help="NTLM hash for authentication (NT hash only)")
    parser.add_argument("--dc-ip", help="DC IP for certipy")
    parser.add_argument("--output-prefix", default="certipy_scan",
                        help="Output prefix for certipy (default: certipy_scan)")
    parser.add_argument("--dns-tcp", action="store_true",
                        help="Use TCP instead of UDP for DNS queries (required for proxychains/SOCKS)")

    args = parser.parse_args()

    # Step 1: Get certipy JSON
    certipy_json_path = args.certipy_json
    if not certipy_json_path:
        if not all([args.domain, args.username, args.dc_ip]):
            parser.error("Either --certipy-json or --domain/--username/--dc-ip required")
        if not args.password and not args.hashes:
            parser.error("Either --password or --hashes is required when running certipy")
        certipy_json_path = run_certipy(
            args.domain, args.username, args.password, args.dc_ip, args.output_prefix,
            dns_tcp=args.dns_tcp, hashes=args.hashes
        )
        if not certipy_json_path:
            sys.exit(1)

    # Step 2: Load certipy JSON
    print(f"[*] Loading certipy JSON: {certipy_json_path}")
    with open(certipy_json_path, "r", encoding="utf-8") as f:
        certipy_data = json.load(f)

    # Step 3: Build name→SID mapping from BloodHound data
    print(f"[*] Building name→SID mapping from: {args.data_dir}")
    name_to_sid = build_name_to_sid(args.data_dir)
    print(f"    {len(name_to_sid)} entries indexed")

    # Step 4: Parse templates
    print(f"[*] Parsing certificate templates...")
    template_nodes = parse_certipy_json(certipy_data, name_to_sid)

    if not template_nodes:
        print("[!] No vulnerable templates found")
        # Still write empty file for consistency
        output = {"meta": {"type": "certtemplates"}, "data": []}
    else:
        output = {"meta": {"type": "certtemplates"}, "data": template_nodes}
        for node in template_nodes:
            props = node["Properties"]
            esc = props.get("esc_vulnerabilities", [])
            n_aces = len(node.get("Aces", []))
            print(f"    [+] {props['template_name']} [{','.join(esc)}] - {n_aces} ACE edges")

    # Step 5: Write output
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"[*] Output written to: {args.out}")
    print(f"    {len(template_nodes)} vulnerable template(s)")


if __name__ == "__main__":
    main()
