#!/usr/bin/env python3
import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys

import nmap

DEFAULT_OUTPUT_FILE = "global_network_scan_classeA_results.json"
TRACEROUTE_TARGETS = ["8.8.8.8"]
DEFAULT_PORT_SCAN_COUNT = 1000


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
    """Effectue un traceroute ICMP et retourne un résumé structuré."""
    command = f"traceroute -n {target_ip}"
    try:
        print(f"\n[LANCEMENT TRACE] {command}")
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, timeout=30).decode()
        lines = output.splitlines()
        hop_lines = [line.strip() for line in lines if re.match(r'^\s*\d+', line)]

        return {
            "target": target_ip,
            "status": "success",
            "hop_lines": hop_lines,
            "raw_output": output
        }
    except subprocess.CalledProcessError as exc:
        error_output = exc.output.decode(errors="ignore") if exc.output else ""
        print(f"\n[ATTENTION] Traceroute vers {target_ip} a échoué.")
        if error_output:
            print(error_output)
        return {
            "target": target_ip,
            "status": "error",
            "error": error_output or str(exc),
            "raw_output": error_output
        }
    except Exception as exc:
        print(f"\n[ERREUR INCONNUE] Traceroute vers {target_ip} : {exc}")
        return {
            "target": target_ip,
            "status": "exception",
            "error": str(exc),
            "raw_output": ""
        }


def run_nmap_arp_scan(target_cidr):
    """Lance un ping scan en utilisant des requêtes ARP (-PR)."""
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


def confirm_with_icmp(hosts):
    """Vérifie une réponse ICMP avant d'appeler traceroute."""
    verified = []
    for host in hosts:
        try:
            subprocess.run(
                ['ping', '-c', '1', '-W', '1', host],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True
            )
            verified.append(host)
        except subprocess.CalledProcessError:
            print(f"[PING] Pas de réponse rapide pour {host}, on saute le traceroute.")
    return verified


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
                else:
                    print(f"[SÉCURITÉ] Ignoré non-privé {candidate_ip} détecté dans {trace.get('target')}.")
    return router_set


def traceroute_stays_in_private_space(trace_result):
    """Vérifie qu'aucun saut du traceroute n'est sorti de RFC1918."""
    hop_ips = []
    hop_ip_pattern = re.compile(r'\d+\.\d+\.\d+\.\d+')
    for line in trace_result.get("hop_lines", []):
        ips_in_line = hop_ip_pattern.findall(line)
        if not ips_in_line:
            continue
        hop_ips.extend(ips_in_line)
        for hop_ip in ips_in_line:
            if not is_private_ip(hop_ip):
                return False, hop_ips, hop_ip
    return bool(hop_ips), hop_ips, None


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


def has_direct_route(target_ip):
    """Détermine si la route vers l'IP reste dans l'espace privé (pas de saut public)."""
    try:
        output = subprocess.check_output(
            ['ip', 'route', 'get', target_ip],
            stderr=subprocess.DEVNULL
        ).decode(errors='ignore')
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False, None

    gateway_match = re.search(r'via\s+(\d+\.\d+\.\d+\.\d+)', output)
    if gateway_match:
        gateway_ip = gateway_match.group(1)
        return is_private_ip(gateway_ip), gateway_ip
    return True, None


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
    """Exécute un scan top-port ou personnalisé et retourne les services par hôte."""
    if not hosts:
        print("\n[SCAN PORTS] Aucun hôte détecté pour effectuer le scan.")
        return []

    # Note: Sans spécification de ports, nmap scanne les 1000 ports les plus communs par défaut
    arguments = [
        "-Pn",
        "-A",
        "-T4",
        "--script",
        "smb-os-discovery",
    ]
    if port_list:
        arguments.append(f"-p {port_list}")

    argument_string = " ".join(arguments)
    hosts_str = " ".join(hosts)
    print(f"\n[SCAN PORTS] nmap {argument_string} sur {len(hosts)} hôtes.")
    nm = nmap.PortScanner()

    try:
        nm.scan(hosts=hosts_str, arguments=argument_string)
        results = []
        for host in nm.all_hosts():
            host_info = nm[host]
            tcp_info = host_info.get("tcp", {})
            os_matches = host_info.get("osmatch") or []
            os_label = None
            if os_matches:
                best = os_matches[0]
                name = best.get("name")
                accuracy = best.get("accuracy")
                os_label = f"{name} ({accuracy}%)" if name and accuracy else name
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
                    "extrainfo": port_details.get("extrainfo"),
                    "reason": port_details.get("reason")
                })
            services.sort(key=lambda entry: entry.get("port", 0))
            results.append({
                "ip": host,
                "status": host_info.get("status", {}).get("state"),
                "os": os_label,
                "services": services
            })
        return results
    except nmap.PortScannerError as exc:
        print(f"❌ Erreur Nmap lors du scan des ports : {exc}")
        return []


def main():
    parser = argparse.ArgumentParser(
        description="Scan global adapté aux grands blocs (ex : 10.0.0.0/8) sans brute-force Classe C."
    )
    parser.add_argument('-i', '--ip_cidr', required=True, help="IP/CIDR locale.")
    parser.add_argument('-g', '--gateway', required=True, help="Passerelle locale.")
    parser.add_argument('-d', '--dns', required=True, help="DNS interne à tracer.")
    parser.add_argument('-o', '--output', default=DEFAULT_OUTPUT_FILE, help="Fichier de sortie JSON.")
    parser.add_argument('--port-scan', action='store_true', help="Activer un scan TCP (top-1000) sur les hôtes détectés.")
    parser.add_argument('--port-list', help="Liste CSV de ports à scanner (active automatiquement le scan).", default=None)

    args = parser.parse_args()

    try:
        local_interface = ipaddress.ip_interface(args.ip_cidr)
    except ValueError as err:
        print(f"\n❌ CIDR invalide : {err}")
        sys.exit(1)

    report = {
        "summary": "Scan Classe A/B : VLAN ARP + traceroutes + routage découvert sans brute-force Classe C.",
        "configuration": {
            "ip_cidr": args.ip_cidr,
            "gateway": args.gateway,
            "dns": args.dns
        },
        "vlan_scan": {},
        "phase_traceroutes": [],
        "router_discovery": {
            "trace_discovered": [],
            "active": [],
            "icmp_verified": [],
            "traceroutes": [],
            "router_details": []
        },
        "subnet_scans": []
    }

    print("\n" + "=" * 70)
    print("## Scan global : VLAN + Trace (Classe A/B)")
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

    # Phase 3 simplifiée: Vérification ICMP directe (nmap -sn redondant supprimé)
    icmp_verified = confirm_with_icmp(sorted(discovered_routers))
    verified_routers = [router for router in icmp_verified if is_private_ip(router)]
    if len(verified_routers) < len(icmp_verified):
        print("[SÉCURITÉ] Des routeurs publics ont été écartés des validations ICMP.")
    report["router_discovery"]["icmp_verified"] = verified_routers

    filtered_routers = []
    trace_results_for_routers = []
    for router in verified_routers:
        trace_result = run_traceroute(router)
        trace_results_for_routers.append(trace_result)
        trace_ok, hop_ips, offending_ip = traceroute_stays_in_private_space(trace_result)
        if not trace_ok:
            reason = f" (passage via {offending_ip})" if offending_ip else ""
            print(f"[INFO] Traceroute vers {router} sort vers Internet{reason}, le router est ignoré.")
            continue
        filtered_routers.append(router)

    report["router_discovery"]["router_details"] = [
        {"ip": router}
        for router in filtered_routers
    ]
    report["router_discovery"]["traceroutes"] = trace_results_for_routers

    subnet_networks = sorted({
        network
        for router in filtered_routers
        if (network := network_from_ip(router))
    })
    private_subnets = [network for network in subnet_networks if is_private_network(network)]
    if len(private_subnets) < len(subnet_networks):
        print("[SÉCURITÉ] Certains sous-réseaux publics ont été ignorés.")

    router_network_map = {}
    for router in filtered_routers:
        network = network_from_ip(router)
        if network and network not in router_network_map:
            router_network_map[network] = router

    for network in private_subnets:
        router_ip = router_network_map.get(network)
        route_allowed = False
        route_gateway = None
        if router_ip:
            route_allowed, route_gateway = has_direct_route(router_ip)
        can_scan = router_ip and route_allowed
        if can_scan:
            scan_result = run_nmap_arp_scan(network)
        else:
            route_info = router_ip or "route inconnue"
            if route_gateway:
                route_info = f"{route_info} via {route_gateway}"
            warning_msg = (
                f"Pas de route directe vers {network} ({route_info}); scan ARP ignoré."
            )
            print(f"[INFO] {warning_msg}")
            scan_result = {
                "target_cidr": network,
                "hosts_found": 0,
                "active_hosts": [],
                "warning": warning_msg
            }
        scan_result["related_router_network"] = network
        report["subnet_scans"].append(scan_result)

    port_list_arg = normalize_port_list(args.port_list)
    port_scan_enabled = args.port_scan or bool(port_list_arg)
    hosts_for_scan = gather_detected_hosts(report)
    report["service_scan"] = {
        "enabled": port_scan_enabled,
        "ports": port_list_arg or f"top-{DEFAULT_PORT_SCAN_COUNT}",
        "results": []
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
