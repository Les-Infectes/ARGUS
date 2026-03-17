#!/usr/bin/env python3
"""
CartoAD - Local Reconnaissance
Gathers local system information, users, and potential credentials.
Optimized for both Linux and Windows.
"""
import os
import sys
import platform
import subprocess
import json
import socket
from pathlib import Path

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def print_info(msg):
    print(f"{Colors.BLUE}[*]{Colors.ENDC} {msg}")

def print_success(msg):
    print(f"{Colors.GREEN}[+]{Colors.ENDC} {msg}")

def print_warning(msg):
    print(f"{Colors.YELLOW}[!]{Colors.ENDC} {msg}")

def run_command(cmd):
    try:
        # Use shell=True for built-in commands like 'net' or 'ipconfig'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
        return result.stdout.strip()
    except Exception:
        return ""

def get_system_info():
    return {
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
    }

def get_user_info():
    info = {
        "current_user": os.getlogin() if hasattr(os, 'getlogin') else os.environ.get('USER', os.environ.get('USERNAME')),
        "home": str(Path.home()),
        "env_vars": {k: v for k, v in os.environ.items() if any(x in k.lower() for x in ['user', 'pass', 'key', 'token', 'secret', 'proxy', 'domain', 'logon'])},
    }
    
    if platform.system() == "Linux":
        info["uid"] = os.getuid()
        info["gid"] = os.getgid()
        info["groups"] = run_command("groups")
        info["all_users"] = run_command("cut -d: -f1 /etc/passwd").split('\n')
    elif platform.system() == "Windows":
        info["whoami_priv"] = run_command("whoami /priv")
        info["whoami_groups"] = run_command("whoami /groups")
        info["net_user_current"] = run_command(f"net user {info['current_user']}")
        
    return info

def get_network_info():
    info = {}
    if platform.system() == "Linux":
        info["interfaces"] = run_command("ip -4 addr show").split('\n')
        info["dns"] = run_command("grep nameserver /etc/resolv.conf").split('\n')
        info["routes"] = run_command("ip route").split('\n')
    elif platform.system() == "Windows":
        info["ipconfig"] = run_command("ipconfig /all")
        info["routes"] = run_command("route print -4")
        info["active_connections"] = run_command("netstat -ano")
    return info

def get_kerberos_info():
    info = {"tickets": []}
    klist = run_command("klist")
    if klist:
        info["tickets"] = klist.split('\n')
    
    if platform.system() == "Linux" and os.path.exists("/etc/krb5.keytab"):
        info["keytab_present"] = True
    return info

def get_ad_info():
    info = {"is_domain_joined": False, "details": {}}
    
    if platform.system() == "Linux":
        sssd = run_command("pgrep sssd")
        winbind = run_command("pgrep winbindd")
        if sssd or winbind:
            info["is_domain_joined"] = True
            info["method"] = "sssd" if sssd else "winbind"
            info["domain_accounts"] = run_command("getent passwd").split('\n')
            
    elif platform.system() == "Windows":
        domain_env = os.environ.get('USERDOMAIN')
        computer_env = os.environ.get('COMPUTERNAME')
        if domain_env and domain_env != computer_env:
            info["is_domain_joined"] = True
            info["domain_env"] = domain_env
        
        workstation = run_command("net config workstation")
        if "Workstation domain" in workstation:
            info["is_domain_joined"] = True
            info["net_config"] = workstation
            
        if info["is_domain_joined"]:
            info["domain_admins"] = run_command("net group \"Domain Admins\" /domain")
            
    return info

def find_interesting_files():
    found = []
    home = Path.home()
    
    if platform.system() == "Linux":
        patterns = [".ssh/id_*", ".bash_history", ".aws/credentials", "/etc/krb5.keytab", "*.kdbx"]
    else: # Windows
        patterns = [
            ".ssh/id_*", 
            "AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt",
            "C:/Windows/Panther/Unattend.xml",
            "C:/inetpub/wwwroot/web.config",
            "Documents/*.kdbx"
        ]
        
    for pat in patterns:
        p = Path(pat)
        if p.is_absolute():
            # Pour les chemins absolus, on vérifie directement l'existence
            if "*" in pat:
                # Si le chemin absolu contient une wildcard, on utilise glob sur la racine
                # Note: sur Windows, il faudrait gérer le drive, ici on simplifie
                try:
                    root = Path("/") if platform.system() == "Linux" else Path(p.anchor)
                    relative_pat = str(p.relative_to(root))
                    for match in root.glob(relative_pat):
                        found.append(str(match))
                except Exception: pass
            elif p.exists():
                found.append(str(p))
        else:
            # Pour les chemins relatifs, on cherche dans le HOME
            try:
                for match in home.glob(pat):
                    found.append(str(match))
            except Exception: pass
    return found

def search_history_for_creds():
    creds = []
    home = Path.home()
    hist_files = []
    
    if platform.system() == "Linux":
        hist_files = [home / ".bash_history", home / ".zsh_history"]
    else:
        hist_files = [
            home / "AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt",
            home / ".bash_history"
        ]
        
    for hf in hist_files:
        if hf.exists():
            try:
                with open(hf, 'r', errors='ignore') as f:
                    for line in f:
                        l = line.lower()
                        if any(x in l for x in ['pass', 'pwd', 'secret', 'token', 'login', '/domain']):
                            if len(line.strip()) > 8:
                                creds.append({"file": str(hf), "content": line.strip()})
            except Exception: pass
    return creds

def main():
    sys_info = get_system_info()
    print(f"{Colors.BOLD}{Colors.HEADER}--- Local Recon: {sys_info['hostname']} ({sys_info['os']}) ---{Colors.ENDC}")
    
    results = {
        "system": sys_info,
        "users": get_user_info(),
        "network": get_network_info(),
        "kerberos": get_kerberos_info(),
        "ad": get_ad_info(),
        "files": find_interesting_files(),
        "creds_in_history": search_history_for_creds()
    }


    print_success(f"Hostname: {results['system']['hostname']}")
    print_success(f"OS: {results['system']['os']} {results['system']['os_release']}")
    print_success(f"Current User: {results['users']['current_user']}")
    
    if results['kerberos']['tickets']:
        print_success("Kerberos tickets found!")

    if results["ad"]["is_domain_joined"]:
        print_success(f"Domain joined: {results['ad'].get('domain_env', 'Yes')}")
    
    if results['files']:
        print_info(f"Found {len(results['files'])} files/configs")

    if results["creds_in_history"]:
        print_warning(f"Found {len(results['creds_in_history'])} potential secrets in history files")
        
    if results["kerberos"]["tickets"]:
        print_success("Active Kerberos tickets detected")

    output = Path("local_recon.json")
    with open(output, "w") as f:
        json.dump(results, f, indent=4)
    print_success(f"Full results saved to {output}")

if __name__ == "__main__":
    main()
