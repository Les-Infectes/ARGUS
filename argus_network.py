#!/usr/bin/env python3
import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

import nmap

DEFAULT_OUTPUT_FILE = "global_network_scan_results.json"
TRACEROUTE_TARGETS = ["8.8.8.8"]
DEFAULT_PORT_SCAN_COUNT = 100

TRACEROUTE_METHODS = [
    ("UDP",   "traceroute -n {target}"),
    ("ICMP",  "traceroute -n -I {target}"),
    ("TCP80", "traceroute -n -T -p 80 {target}"),
]


def is_private_ip(ip_value):
    """Filtre les adresses publiques."""
    try:
        ip_obj = ipaddress.ip_address(ip_value)
    except ValueError:
        return False
    return ip_obj.is_private


def is_private_network(network_value):
    """Vérifie si un réseau (/24 etc.) reste dans l'espace privé RFC1918."""
    try:
        network = ipaddress.ip_network(network_value, strict=False)
    except ValueError:
        return False
    return network.network_address.is_private


def run_traceroute(target_ip):
    """Traceroute multi-méthode (UDP + ICMP + TCP-80).

    Chaque méthode comble les *** des autres. Les hops sont fusionnés
    par numéro : on conserve la ligne qui révèle le plus d'IPs.
    Même en cas d'échec (code retour != 0), on extrait les hops partiels.
    """
    ip_re = re.compile(r'\d+\.\d+\.\d+\.\d+')
    hop_num_re = re.compile(r'^\s*(\d+)\s+')
    all_hop_lines = []
    any_success = False

    print(f"\n[TRACE] {target_ip}  (UDP / ICMP / TCP-80)")
    for name, cmd_tpl in TRACEROUTE_METHODS:
        command = cmd_tpl.format(target=target_ip)
        try:
            output = subprocess.check_output(
                command, shell=True, stderr=subprocess.STDOUT, timeout=30
            ).decode()
            hops = [line.strip() for line in output.splitlines()
                    if re.match(r'^\s*\d+', line)]
            all_hop_lines.extend(hops)
            any_success = True
            print(f"  [{name}] {len(hops)} hops")
        except subprocess.CalledProcessError as exc:
            # Traceroute peut sortir avec code != 0 même si des hops ont été trouvés
            # (ex : destination injoignable, maxhops atteint). On récupère quand même.
            partial = exc.output.decode(errors="ignore") if exc.output else ""
            hops = [line.strip() for line in partial.splitlines()
                    if re.match(r'^\s*\d+', line)]
            if hops:
                all_hop_lines.extend(hops)
                any_success = True
                print(f"  [{name}] {len(hops)} hops (sortie partielle, code {exc.returncode})")
            else:
                print(f"  [{name}] échec (code {exc.returncode}) : {partial.strip()[:80]}")
        except Exception as exc:
            print(f"  [{name}] exception : {exc}")

    # Par numéro de hop : garder la ligne avec le plus d'IPs découvertes
    hop_best: dict = {}
    for line in all_hop_lines:
        m = hop_num_re.match(line)
        if not m:
            continue
        hop_n = int(m.group(1))
        ips = ip_re.findall(line)
        existing_ips = ip_re.findall(hop_best.get(hop_n, ""))
        if len(ips) > len(existing_ips):
            hop_best[hop_n] = line

    merged = [hop_best[k] for k in sorted(hop_best)]
    return {
        "target": target_ip,
        "status": "success" if any_success else "error",
        "hop_lines": merged,
    }


def run_nmap_arp_scan(target_cidr):
    """Lance un ping scan ARP (-PR) pour le sous-réseau local (L2)."""
    print(f"\n[SCAN VLAN] Analyse ARP du segment {target_cidr}")
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=target_cidr, arguments='-sn -PR -T4')
        hosts = []
        for host in nm.all_hosts():
            status = nm[host].get("status", {}).get("state", "unknown")
            if status != "up":
                continue
            hosts.append({
                "ip": host,
                "status": status,
                "mac": nm[host].get("addresses", {}).get("mac", "N/A")
            })
        return {
            "target_cidr": target_cidr,
            "hosts_found": len(hosts),
            "active_hosts": hosts
        }
    except nmap.PortScannerError as exc:
        print(f"❌ Erreur Nmap ARP scan sur {target_cidr} : {exc}")
        return {
            "target_cidr": target_cidr,
            "hosts_found": 0,
            "active_hosts": [],
            "error": str(exc)
        }


def run_nmap_icmp_scan(target_cidr):
    """Lance un ping scan ICMP (-PE) pour les sous-réseaux distants (cross-router)."""
    print(f"\n[SCAN SUBNET] Analyse ICMP du segment {target_cidr}")
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=target_cidr, arguments='-sn -PE -T4')
        hosts = []
        for host in nm.all_hosts():
            status = nm[host].get("status", {}).get("state", "unknown")
            if status != "up":
                continue
            hosts.append({
                "ip": host,
                "status": status,
            })
        return {
            "target_cidr": target_cidr,
            "hosts_found": len(hosts),
            "active_hosts": hosts
        }
    except nmap.PortScannerError as exc:
        print(f"❌ Erreur Nmap ICMP scan sur {target_cidr} : {exc}")
        return {
            "target_cidr": target_cidr,
            "hosts_found": 0,
            "active_hosts": [],
            "error": str(exc)
        }



def collect_router_ips_from_traces(trace_results):
    """Extrait les IP de hop des traceroutes."""
    router_set = set()
    hop_regex = re.compile(r'^\s*\d+\s+(\d+\.\d+\.\d+\.\d+)')
    for trace in trace_results:
        for line in trace.get("hop_lines", []):
            match = hop_regex.match(line)
            if match:
                candidate_ip = match.group(1)
                if is_private_ip(candidate_ip):
                    router_set.add(candidate_ip)
                # Les IPs publiques sont silencieusement ignorées (attendu pour 8.8.8.8)
    return router_set



def network_from_ip(ip_value):
    """Retourne le /24 associé à l'adresse IP fournie."""
    try:
        ip_obj = ipaddress.ip_address(ip_value)
    except ValueError:
        return None
    if ip_obj.version == 4:
        base = ip_obj.exploded.rsplit('.', 1)[0]
        return f"{base}.0/24"
    return None



def normalize_port_list(port_list_str):
    """Nettoie la chaîne CSV de ports fournie par l'utilisateur."""
    if not port_list_str:
        return None
    ports = [part.strip() for part in port_list_str.split(",") if part.strip()]
    return ",".join(ports) if ports else None


def gather_detected_hosts(report):
    """Rassemble les IP trouvées lors des scans pour les réutiliser."""
    host_set = set()

    # Always include explicitly configured infra even if ARP/ping discovery misses it
    # (e.g. gateway not in the local /24, or DNS not responding to ARP scan).
    config = report.get("configuration", {}) or {}
    for key in ("gateway", "dns"):
        ip_val = config.get(key)
        if ip_val and is_private_ip(ip_val):
            host_set.add(ip_val)

    def collect(host_entries):
        for entry in host_entries or []:
            host_ip = entry.get("ip")
            if host_ip and is_private_ip(host_ip):
                host_set.add(host_ip)

    collect(report.get("vlan_scan", {}).get("active_hosts"))
    for subnet in report.get("subnet_scans", []):
        collect(subnet.get("active_hosts"))

    for router in report.get("router_discovery", {}).get("router_details", []):
        router_ip = router.get("ip")
        if router_ip and is_private_ip(router_ip):
            host_set.add(router_ip)

    return sorted(host_set)


def run_nmap_port_scan(hosts, port_list=None):
    """Scan TCP top-100 sans résolution DNS ni ping (hôtes déjà découverts)."""
    if not hosts:
        print("\n[SCAN PORTS] Aucun hôte détecté pour effectuer le scan.")
        return []

    port_arg = f"-p {port_list}" if port_list else f"--top-ports {DEFAULT_PORT_SCAN_COUNT}"
    argument_string = f"-Pn -n {port_arg} -T4"
    hosts_str = " ".join(hosts)
    print(f"\n[SCAN PORTS] nmap {argument_string} sur {len(hosts)} hôtes.")
    nm = nmap.PortScanner()

    try:
        nm.scan(hosts=hosts_str, arguments=argument_string)
        results = []
        for host in nm.all_hosts():
            host_info = nm[host]
            tcp_info = host_info.get("tcp", {})
            services = []
            for port_number, port_details in tcp_info.items():
                try:
                    port_value = int(port_number)
                except ValueError:
                    port_value = port_number
                services.append({
                    "port": port_value,
                    "protocol": "tcp",
                    "state": port_details.get("state"),
                    "service": port_details.get("name"),
                    "product": port_details.get("product"),
                    "version": port_details.get("version"),
                })
            services.sort(key=lambda entry: entry.get("port", 0))
            results.append({
                "ip": host,
                "status": host_info.get("status", {}).get("state"),
                "services": services
            })
        return results
    except nmap.PortScannerError as exc:
        print(f"❌ Erreur Nmap lors du scan des ports : {exc}")
        return []


def _parse_smb_hostname(host_elem):
    """Extract FQDN/hostname from smb-os-discovery script output in nmap XML."""
    for script in host_elem.findall(".//hostscript/script[@id='smb-os-discovery']"):
        # Try FQDN first (most complete)
        fqdn_elem = script.find("elem[@key='fqdn']")
        if fqdn_elem is not None and fqdn_elem.text:
            return fqdn_elem.text.strip()
        # Fallback: Computer name + Domain
        name_elem = script.find("elem[@key='Computer name']")
        domain_elem = script.find("elem[@key='Domain']")
        if name_elem is not None and name_elem.text:
            name = name_elem.text.strip().rstrip("\x00")
            if domain_elem is not None and domain_elem.text:
                return f"{name}.{domain_elem.text.strip()}"
            return name
    return None


def _parse_nmap_xml(xml_output):
    """Parse nmap XML output and return list of host dicts."""
    hosts = []
    try:
        root = ET.fromstring(xml_output)
        for host_elem in root.findall("host"):
            addr_elem = host_elem.find("address[@addrtype='ipv4']")
            if addr_elem is None:
                continue
            ip = addr_elem.get("addr")

            services = []
            ports_elem = host_elem.find("ports")
            if ports_elem is not None:
                for port_elem in ports_elem.findall("port"):
                    state_elem = port_elem.find("state")
                    if state_elem is None or state_elem.get("state") != "open":
                        continue
                    svc = port_elem.find("service")
                    services.append({
                        "port": int(port_elem.get("portid")),
                        "protocol": port_elem.get("protocol"),
                        "state": "open",
                        "service": svc.get("name") if svc is not None else None,
                        "product": svc.get("product") if svc is not None else None,
                        "version": svc.get("version") if svc is not None else None,
                    })

            host_entry = {
                "ip": ip,
                "status": "up",
                "services": services,
            }
            hostname = _parse_smb_hostname(host_elem)
            if hostname:
                host_entry["hostname"] = hostname

            hosts.append(host_entry)
    except ET.ParseError as e:
        print(f"❌ Erreur parsing XML nmap : {e}")
    return hosts


def run_nmap_proxychains_scan(target_cidr, proxychains_conf=None, port_list=None, targets=None):
    """Scan TCP via proxychains4 — mode pivot.

    Bypasse la découverte réseau (ARP/ICMP/traceroute) qui ne fonctionne pas
    à travers un proxy SOCKS. Utilise nmap -sT (TCP connect) qui passe via
    LD_PRELOAD proxychains.

    targets : liste d'IPs connues (optionnel). Si fourni, scanne IP par IP avec
              progression [X/N]. Sinon, scanne le CIDR complet en une passe.
    """
    base_cmd = ["proxychains4"]
    if proxychains_conf:
        base_cmd += ["-f", proxychains_conf]

    port_arg = f"-p {port_list}" if port_list else f"--top-ports {DEFAULT_PORT_SCAN_COUNT}"

    # ── Scan IP par IP avec barre de progression ────────────────────────────
    if targets:
        total = len(targets)
        print(f"\n[PIVOT SCAN] {total} cibles — port scan: {port_arg}")
        all_hosts = []
        for idx, ip in enumerate(targets, start=1):
            print(f"  [{idx}/{total}] Scanning {ip}...", end=" ", flush=True)
            cmd = base_cmd + ["nmap", "-sT", "-Pn", "-n", "--open", "--script=smb-os-discovery", "-oX", "-"] + port_arg.split() + [ip]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            except FileNotFoundError:
                print("❌ proxychains4 ou nmap introuvable")
                return []
            except subprocess.TimeoutExpired:
                print(f"timeout")
                continue

            if result.stdout.strip():
                hosts = _parse_nmap_xml(result.stdout)
                open_ports = sum(len(h["services"]) for h in hosts)
                if hosts:
                    print(f"{open_ports} port(s) ouvert(s)")
                    all_hosts.extend(hosts)
                else:
                    print("aucun port ouvert")
            else:
                print("pas de réponse")

        print(f"\n  {len(all_hosts)} hôtes avec ports ouverts sur {total} scannés")
        return all_hosts

    # ── Scan CIDR complet en une seule passe (lent) ─────────────────────────
    cmd = base_cmd + ["nmap", "-sT", "-Pn", "-n", "--open", "--script=smb-os-discovery", "-oX", "-"] + port_arg.split() + [target_cidr]
    print(f"\n[PIVOT SCAN] Scan CIDR complet (lent) : {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except FileNotFoundError:
        print("❌ proxychains4 ou nmap introuvable")
        return []
    except subprocess.TimeoutExpired:
        print("❌ Timeout proxychains nmap (600s)")
        return []

    if not result.stdout.strip():
        print(f"❌ Pas de sortie nmap (code {result.returncode})")
        return []

    hosts = _parse_nmap_xml(result.stdout)
    print(f"  {len(hosts)} hôtes détectés avec ports ouverts")
    return hosts


def main():
    parser = argparse.ArgumentParser(
        description="Scan réseau : VLAN ARP local + traceroute + sous-réseaux ICMP + scan de ports."
    )
    parser.add_argument('-i', '--ip_cidr', required=True, help="IP/CIDR locale.")
    parser.add_argument('-g', '--gateway', default=None, help="Passerelle locale (non requis en mode --proxychains).")
    parser.add_argument('-d', '--dns', default=None, help="DNS interne à tracer (non requis en mode --proxychains).")
    parser.add_argument('-o', '--output', default=DEFAULT_OUTPUT_FILE, help="Fichier de sortie JSON.")
    parser.add_argument('--port-scan', action='store_true', help="Activer un scan TCP (top-100, sans DNS) sur les hôtes détectés.")
    parser.add_argument('--port-list', help="Liste CSV de ports à scanner (active automatiquement le scan).", default=None)
    parser.add_argument('--proxychains', action='store_true', help="Mode pivot : scan TCP via proxychains4 (remplace ARP/ICMP/traceroute).")
    parser.add_argument('--proxychains-conf', default=None, help="Fichier de configuration proxychains4 (ex: pivot.conf).")
    parser.add_argument('--targets', default=None, help="IPs connues a scanner en mode pivot, separees par virgules (ex: '172.16.1.20,172.16.1.45'). Evite le scan CIDR complet.")
    parser.add_argument('--single-host', action='store_true', help="Mode machine unique : skip ARP/traceroute, scan direct de l'IP cible.")

    args = parser.parse_args()

    # Validate: gateway/dns required sauf en mode proxychains ou single-host
    if not args.proxychains and not args.single_host and (not args.gateway or not args.dns):
        parser.error("--gateway et --dns sont requis sauf en mode --proxychains ou --single-host")

    try:
        local_interface = ipaddress.ip_interface(args.ip_cidr)
    except ValueError as err:
        print(f"\n❌ CIDR invalide : {err}")
        sys.exit(1)

    report = {
        "configuration": {
            "ip_cidr": args.ip_cidr,
            "gateway": args.gateway,
            "dns": args.dns,
            "mode": "proxychains" if args.proxychains else "standard",
        },
        "vlan_scan": {},
        "phase_traceroutes": [],
        "router_discovery": {"trace_discovered": [], "router_details": []},
        "subnet_scans": [],
    }

    port_list_arg = normalize_port_list(args.port_list)

    # Si --proxychains + --single-host, on redirige vers le mode pivot
    # avec l'IP du CIDR comme seule target (pas besoin de --targets)
    if args.single_host and args.proxychains:
        target_ip = str(local_interface.ip)
        args.targets = target_ip  # sera splité par la virgule plus bas

    if args.single_host and not args.proxychains:
        # ── MODE SINGLE HOST (direct) ──────────────────────────────────────
        print("\n" + "=" * 70)
        print("## Scan machine unique (ARP/traceroute désactivés)")
        print("=" * 70)
        target_ip = str(local_interface.ip)
        print(f"Cible : {target_ip}")

        report["summary"] = "Scan machine unique : port scan direct sans découverte réseau."
        report["vlan_scan"] = {
            "target_cidr": args.ip_cidr,
            "hosts_found": 1,
            "active_hosts": [{"ip": target_ip, "status": "up"}],
        }
        report["router_discovery"] = {"skipped": True, "reason": "single-host mode"}

        port_scan_enabled = args.port_scan or bool(port_list_arg)
        report["service_scan"] = {
            "enabled": port_scan_enabled,
            "mode": "single-host",
            "ports": port_list_arg or f"top-{DEFAULT_PORT_SCAN_COUNT}",
            "results": [],
        }
        if port_scan_enabled:
            report["service_scan"]["results"] = run_nmap_port_scan([target_ip], port_list=port_list_arg)

    elif args.proxychains:
        # ── MODE PIVOT ─────────────────────────────────────────────────────────
        print("\n" + "=" * 70)
        print("## Scan pivot : TCP via proxychains4 (ARP/ICMP/traceroute désactivés)")
        print("=" * 70)
        print(f"Cible : {local_interface.network}")

        report["summary"] = "Scan pivot : TCP connect via proxychains4."
        report["vlan_scan"] = {"skipped": True, "reason": "proxychains mode"}
        report["router_discovery"] = {"skipped": True, "reason": "proxychains mode"}

        targets = [t.strip() for t in args.targets.split(",")] if args.targets else None
        if targets:
            print(f"  Cibles spécifiques ({len(targets)}) : {', '.join(targets)}")
        else:
            print(f"  Scan CIDR complet (lent) : {local_interface.network}")

        pivot_results = run_nmap_proxychains_scan(
            args.ip_cidr,
            proxychains_conf=args.proxychains_conf,
            port_list=port_list_arg,
            targets=targets,
        )
        # Populate vlan_scan.active_hosts so cartographie.html can display nodes
        report["vlan_scan"] = {
            "target_cidr": args.ip_cidr,
            "hosts_found": len(pivot_results),
            "active_hosts": [{"ip": h["ip"], "status": h["status"]} for h in pivot_results],
        }
        report["service_scan"] = {
            "enabled": True,
            "mode": "proxychains",
            "ports": port_list_arg or f"top-{DEFAULT_PORT_SCAN_COUNT}",
            "results": pivot_results,
        }

    else:
        # ── MODE STANDARD ──────────────────────────────────────────────────────
        report["summary"] = "Scan réseau : VLAN ARP + traceroute multi-méthode + sous-réseaux ICMP."

        print("\n" + "=" * 70)
        print("## Scan global : VLAN + Traceroute multi-méthode")
        print("=" * 70)
        print(f"IP locale : {local_interface.ip} / Réseau : {local_interface.network}")

        report["vlan_scan"] = run_nmap_arp_scan(args.ip_cidr)

        trace_targets = TRACEROUTE_TARGETS + [args.dns]
        trace_results = []
        for target in trace_targets:
            trace_results.append(run_traceroute(target))
        report["phase_traceroutes"] = trace_results

        discovered_routers = collect_router_ips_from_traces(trace_results)
        discovered_routers.update(
            router for router in (args.gateway, args.dns)
            if router and is_private_ip(router)
        )

        report["router_discovery"]["trace_discovered"] = sorted(discovered_routers)

        filtered_routers = sorted(r for r in discovered_routers if is_private_ip(r))
        report["router_discovery"]["router_details"] = [{"ip": r} for r in filtered_routers]

        subnet_networks = sorted({
            network
            for router in filtered_routers
            if (network := network_from_ip(router))
        })
        private_subnets = [n for n in subnet_networks if is_private_network(n)]
        if len(private_subnets) < len(subnet_networks):
            print("[SÉCURITÉ] Certains sous-réseaux publics ont été ignorés.")

        for network in private_subnets:
            scan_result = run_nmap_icmp_scan(network)
            scan_result["related_router_network"] = network
            report["subnet_scans"].append(scan_result)

        port_scan_enabled = args.port_scan or bool(port_list_arg)
        hosts_for_scan = gather_detected_hosts(report)
        report["service_scan"] = {
            "enabled": port_scan_enabled,
            "ports": port_list_arg or f"top-{DEFAULT_PORT_SCAN_COUNT}",
            "results": [],
        }
        if port_scan_enabled:
            report["service_scan"]["results"] = run_nmap_port_scan(hosts_for_scan, port_list=port_list_arg)

    output_dir = os.path.dirname(args.output) or "."
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    try:
        with open(args.output, 'w') as output_file:
            json.dump(report, output_file, indent=4)
        print(f"\n✅ Rapport enregistré dans {args.output}")
    except IOError as err:
        print(f"\n❌ Impossible d'écrire dans {args.output} : {err}")
        sys.exit(1)


if __name__ == "__main__":
    if 'root' not in subprocess.getoutput('whoami'):
        print("\n[ATTENTION] Les scans Nmap fonctionnent mieux avec sudo.")
    main()
