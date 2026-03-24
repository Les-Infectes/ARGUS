#!/usr/bin/env python3
import argparse
import json
import os
import sys
import time
import re
from collections import defaultdict, deque
from typing import Dict, List, Tuple, Optional, Set

# ============================================================================
# TIER CLASSIFICATION - Scientific approach (v5)
# ============================================================================
#
# TIER 0 — Contrôle DÉTERMINISTE du domaine :
#   1. SEED (statique)     : Domain, DCs, KRBTGT, groupes critiques, DCSync, Cert Publishers
#   2. CLOSURE (hérité)    : Droits de contrôle direct sur Tier 0 (whitelist stricte)
#   3. INDIRECT (accès machines/objets T0) : TOUS les accès aux machines Tier 0 (AdminTo, LAPS, GPO, CanRDP, CanPSRemote, DCOM) + ReadGMSAPassword sur objets T0
#   4. MEMBRES             : Membres directs des groupes Tier 0
#   5. DISTANCE BFS        : Calcul distance depuis Tier 0 FINAL
#
# TIER 1/2 — Distance BFS depuis Tier 0 :
#   - Tier 1 : 1-7 hops depuis Tier 0 (proximite)
#   - Tier 2 : 8+ hops depuis Tier 0 (inclut les noeuds unreachable/terminaux)
#
# Principes :
#   - Tier 0 = contrôle IMMÉDIAT et DÉTERMINISTE du domaine
#   - Tier 1/2/3 = classification par distance uniquement (pas de promotions directes)
#   - Computers = noeuds normaux, traversables (héritage des droits du compte machine)
#   - Tous les edges (AdminTo, CanRDP, CanPSRemote, sessions) sont utilisés pour le BFS
#   - Phase INDIRECT complète tous les accès aux machines Tier 0 AVANT le calcul BFS (distances correctes)
# ============================================================================

# Well-known RID suffixes for Tier 0 SEED (domain-relative)
TIER0_RID_SUFFIXES = [
    "-500",   # Administrator account (builtin)
    "-502",   # KRBTGT (Kerberos TGT account)
    "-512",   # Domain Admins
    "-516",   # Domain Controllers (group)
    "-517",   # Cert Publishers (PKI - ESC attacks)
    "-518",   # Schema Admins
    "-519",   # Enterprise Admins
    "-520",   # Group Policy Creator Owners (Owns GPOs they create → pivot T0)
    "-526",   # Key Admins (Shadow Credentials on any account, WHfB)
    "-527",   # Enterprise Key Admins (forest-wide Key Admins)
    "-544",   # Administrators (BUILTIN)
    "-548",   # Account Operators
    "-549",   # Server Operators
    "-550",   # Print Operators
    "-551",   # Backup Operators
]

# DCSync rights = instant domain compromise
TIER0_DCSYNC_RIGHTS = {
    "DCSync",
    "GetChanges",
    "GetChangesAll",
    "GetChangesInFilteredSet",
}

# ACE Rights Hierarchy (from strongest to weakest)
# Used to consolidate multiple permissions on same object and display the strongest one
ACE_RIGHTS_HIERARCHY = [
    # Tier 1: Full control
    "GenericAll",

    # Tier 2: Can escalate to full control
    "WriteDacl",
    "WriteOwner",
    "Owns",

    # Tier 3: Immediate takeover
    "ForceChangePassword",
    "ResetPassword",

    # Tier 4: Group modification
    "AddMember",
    "WriteMember",

    # Tier 5: Credential access
    "ReadLAPSPassword",
    "ReadGMSAPassword",

    # Tier 6: Shadow credentials
    "AddKeyCredentialLink",
    "WriteKeyCredentialLink",

    # Tier 7: GPO control
    "WriteGPO",
    "EditGPO",

    # Tier 8: Limited modification
    "GenericWrite",
    "AllExtendedRights",

    # Tier 9: Account restrictions (UAC manipulation)
    "WriteAccountRestrictions",

    # Tier 10: ADCS enrollment
    "Enroll",
    "AutoEnroll",
]

# TIER 0 CLOSURE - Whitelist STRICTE
# Ces droits sur un objet Tier 0 = devenir Tier 0
TIER0_CLOSURE_RIGHTS = {
    # Contrôle total
    "GenericAll",
    "WriteDacl",       # Peut se donner GenericAll
    "WriteOwner",      # Peut devenir owner → WriteDacl
    "Owns",            # Ownership = contrôle
    # Modification de groupe
    "AddMember",       # Sur groupe Tier 0 = devenir membre
    "WriteMember",     # Alias AddMember
    # Takeover de compte
    "ForceChangePassword",  # Reset password sans connaître l'ancien
    "ResetPassword",        # Alias
    # Shadow Credentials
    "AddKeyCredentialLink",
    "WriteKeyCredentialLink",
}

# EXCLUS de la closure automatique (nécessitent analyse d'attribut)
# - GenericWrite : dépend de l'attribut modifié
# - AllExtendedRights : inclut plusieurs droits, trop de faux positifs
# - WriteProperty : attribute-aware requis
# - ChangePassword : nécessite l'ancien mot de passe

# Lecture de mot de passe d'un objet Tier 0 = contrôle garanti
# ReadLAPSPassword sur machine T0 ou ReadGMSAPassword sur gMSA T0
TIER0_READPASS_RIGHTS = {
    "ReadLAPSPassword",
    "ReadGMSAPassword",
}

# Accès admin : héritage d'identité valide (contrôle total de la machine)
# AdminTo = admin local → peut dumper credentials → hérite de l'identité machine
ADMIN_ACCESS_RIGHTS = {
    "AdminTo",
}

# Accès distant : accès machine SANS héritage d'identité
# CanRDP/CanPSRemote/DCOM ne donnent PAS les groupes/ACE de la machine
# Exclu du BFS de classification, inclus comme edges terminaux dans les chemins
REMOTE_ACCESS_RIGHTS = {
    "CanRDP",
    "CanPSRemote",
    "ExecuteDCOM",
    "DCOM",
}

# Droits de session : non-déterministes mais visibles dans les chemins
SESSION_RIGHTS = {
    "HasSession",
    "LoggedOn",
}

# Tous les droits significatifs pour la construction du graphe
ALL_PRIVILEGE_RIGHTS = {
    # DCSync
    "DCSync", "GetChanges", "GetChangesAll", "GetChangesInFilteredSet",
    # Contrôle direct
    "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns",
    "AllExtendedRights", "ForceChangePassword", "ResetPassword",
    "AddMember", "WriteMember",
    # Credentials
    "ReadLAPSPassword", "ReadGMSAPassword",
    # Shadow Credentials
    "AddKeyCredentialLink", "WriteKeyCredentialLink",
    # GPO
    "WriteGPO", "EditGPO",
    # ADCS Certificate Templates
    "Enroll", "AutoEnroll",
    # Account restrictions (UAC flags: AS-REPRoasting, disable account)
    "WriteAccountRestrictions",
    # SPN manipulation (Targeted Kerberoasting — resolved by some collectors)
    "WriteSPN",
}

WELL_KNOWN_PREFIXES = (
    "S-1-5-32-",  # BUILTIN
    "S-1-1-",     # World
    "S-1-5-7",    # ANONYMOUS LOGON
    "S-1-5-11",   # Authenticated Users
    "S-1-5-18",   # LOCAL SYSTEM
    "S-1-5-19",   # LOCAL SERVICE
    "S-1-5-20",   # NETWORK SERVICE
)

TYPE_BY_META = {
    "users": "User",
    "groups": "Group",
    "computers": "Computer",
    "ous": "OU",
    "gpos": "GPO",
    "containers": "Container",
    "domains": "Domain",
    "certtemplates": "CertTemplate",
}


# ============================================================================
# TIER CLASSIFICATION FUNCTIONS (v2)
# ============================================================================

def get_dc_computers(by_type: Dict[str, dict]) -> Set[str]:
    """
    Identify Domain Controllers via multiple detection methods:
    1. userAccountControl flag SERVER_TRUST_ACCOUNT (0x2000 = 8192)
    2. PrimaryGroupSID ending in -516 (Domain Controllers group)
    Some BloodHound exports have UAC=0 so PrimaryGroupSID is a reliable fallback.
    """
    dc_ids = set()
    computers = by_type.get("computers", {}).get("data", [])
    for comp in computers:
        props = comp.get("Properties", {}) or {}
        uac = props.get("useraccountcontrol", 0)
        cid = comp.get("ObjectIdentifier")
        if not cid:
            continue
        # Method 1: UAC flag
        if uac & 0x2000:
            dc_ids.add(cid)
            continue
        # Method 2: PrimaryGroupSID = Domain Controllers (-516)
        pgsid = comp.get("PrimaryGroupSID", "")
        if pgsid and pgsid.endswith("-516"):
            dc_ids.add(cid)
    return dc_ids


def get_tier0_computers(tier0: Set[str], by_type: Dict[str, dict]) -> Set[str]:
    """
    Return the subset of Tier 0 SIDs that are Computer objects.
    """
    computer_ids = set()
    computers = by_type.get("computers", {}).get("data", [])
    for comp in computers:
        cid = comp.get("ObjectIdentifier")
        if cid and cid in tier0:
            computer_ids.add(cid)
    return computer_ids


def get_ous_containing_machines(by_type: Dict[str, dict], machine_ids: Set[str]) -> Set[str]:
    """
    Find OUs that contain the given machines (for LAPS/GPO propagation).
    """
    ou_ids = set()
    ous = by_type.get("ous", {}).get("data", [])

    computers = by_type.get("computers", {}).get("data", [])
    for comp in computers:
        cid = comp.get("ObjectIdentifier")
        if cid not in machine_ids:
            continue
        props = comp.get("Properties", {}) or {}
        dn = props.get("distinguishedname", "")
        for ou in ous:
            ou_props = ou.get("Properties", {}) or {}
            ou_dn = ou_props.get("distinguishedname", "")
            if ou_dn and dn.endswith(ou_dn):
                ou_ids.add(ou.get("ObjectIdentifier"))

    return ou_ids


def get_gpos_linked_to_ous(by_type: Dict[str, dict], ou_ids: Set[str]) -> Set[str]:
    """
    Find GPOs linked to the given OUs + domain-level GPOs.
    """
    gpo_ids = set()

    ous = by_type.get("ous", {}).get("data", [])
    for ou in ous:
        oid = ou.get("ObjectIdentifier")
        if oid not in ou_ids:
            continue
        links = ou.get("Links", []) or []
        for link in links:
            gpo_id = link.get("GUID") or link.get("ObjectIdentifier")
            if gpo_id:
                gpo_ids.add(gpo_id)

    # Domain-level GPOs apply to all machines
    domains = by_type.get("domains", {}).get("data", [])
    for domain in domains:
        links = domain.get("Links", []) or []
        for link in links:
            gpo_id = link.get("GUID") or link.get("ObjectIdentifier")
            if gpo_id:
                gpo_ids.add(gpo_id)

    return gpo_ids


def identify_tier0_seed(nodes_by_id: Dict[str, dict], by_type: Dict[str, dict]) -> Set[str]:
    """
    PHASE 1: TIER 0 SEED (Statique)

    Identify base Tier 0 objects using technical criteria:
    - Domain objects
    - DC computers (UAC 0x2000)
    - KRBTGT
    - Critical groups (DA/EA/Schema Admins/Builtin Admins) by SID
    - Principals with DCSync rights on Domain

    Returns: Set of node IDs classified as Tier 0 seed
    """
    tier0 = set()

    # 1. Domain objects
    for nid, node in nodes_by_id.items():
        if node.get("type") == "Domain":
            tier0.add(nid)

    # 2. Well-known Tier 0 groups/accounts by SID suffix (RID)
    # Check both objectsid property AND ObjectIdentifier (BUILTIN groups
    # like S-1-5-32-551 have no objectsid in BloodHound, only an
    # ObjectIdentifier like "DOMAIN.HTB-S-1-5-32-551")
    for nid, node in nodes_by_id.items():
        props = node.get("_properties", {}) or {}
        sid = props.get("objectsid", "")
        # Fallback: extract SID from ObjectIdentifier (format: DOMAIN-S-1-5-...)
        if not sid and "-S-1-" in nid:
            sid = nid[nid.index("S-1-"):]
        if sid and any(sid.endswith(suffix) for suffix in TIER0_RID_SUFFIXES):
            tier0.add(nid)

    # 3. Domain Controllers by UAC flag
    dc_ids = get_dc_computers(by_type)
    tier0.update(dc_ids)

    # 4. AdminSDHolder (special AD object)
    for nid, node in nodes_by_id.items():
        props = node.get("_properties", {}) or {}
        dn = props.get("distinguishedname", "")
        if dn and "CN=ADMINSDHOLDER" in dn.upper():
            tier0.add(nid)

    # 5. DCSync rights holders
    domain_ids = {nid for nid, node in nodes_by_id.items() if node.get("type") == "Domain"}
    for meta_type, content in by_type.items():
        for obj in content.get("data", []):
            target_id = obj.get("ObjectIdentifier")
            if target_id not in domain_ids:
                continue
            for ace in obj.get("Aces", []) or []:
                principal = ace.get("PrincipalSID")
                right = ace.get("RightName")
                if right in TIER0_DCSYNC_RIGHTS and principal:
                    tier0.add(principal)

    # 6. ADCS Certificate Templates with ESC vulnerabilities = Tier 0
    for nid, node in nodes_by_id.items():
        if node.get("type") == "CertTemplate":
            esc = node.get("_properties", {}).get("esc_vulnerabilities", [])
            if esc:
                tier0.add(nid)

    # 7. Default Domain Policy & Default Domain Controllers Policy = Tier 0
    # These GPOs control security settings for the entire domain and all DCs.
    # Promoting them in SEED lets CLOSURE automatically handle anyone with
    # GenericAll/WriteDacl/WriteOwner on them.
    for nid, node in nodes_by_id.items():
        if node.get("type") == "GPO":
            gpo_name = (node.get("name") or "").upper()
            if "DEFAULT DOMAIN POLICY" in gpo_name or "DEFAULT DOMAIN CONTROLLERS POLICY" in gpo_name:
                tier0.add(nid)

    # 8. Enterprise CA host machines = Tier 0
    # If certipy data identifies CA server names, find the matching computers.
    # Compromising the CA machine = forge certificates, extract CA private key.
    ca_hostnames = set()
    for nid, node in nodes_by_id.items():
        if node.get("type") == "CertTemplate":
            ca_names = node.get("_properties", {}).get("ca_names", []) or []
            for ca in ca_names:
                ca_hostnames.add(ca.upper())
    if ca_hostnames:
        for nid, node in nodes_by_id.items():
            if node.get("type") == "Computer":
                comp_name = (node.get("name") or "").upper()
                # Match CA name against computer name (e.g. "AUTHORITY-CA" in "AUTHORITY.AUTHORITY.HTB")
                for ca in ca_hostnames:
                    # CA name often matches the hostname prefix (AUTHORITY-CA → AUTHORITY)
                    ca_host_prefix = ca.split("-")[0] if "-" in ca else ca
                    if comp_name.startswith(ca_host_prefix + ".") or ca in comp_name:
                        tier0.add(nid)

    return tier0


def expand_tier0_closure(
    tier0_seed: Set[str],
    nodes_by_id: Dict[str, dict],
    by_type: Dict[str, dict],
    max_iterations: int = 10
) -> Set[str]:
    """
    PHASE 2: TIER 0 CLOSURE (Hérité) - Whitelist stricte

    Expand Tier 0 with objects having critical control rights over Tier 0 objects.
    Uses TIER0_CLOSURE_RIGHTS (strict whitelist).

    GenericWrite/AllExtendedRights are EXCLUDED (need attribute-aware analysis).
    """
    tier0 = set(tier0_seed)
    iteration = 0
    total_added = 0

    while iteration < max_iterations:
        iteration += 1
        added_this_round = 0

        for meta_type, content in by_type.items():
            for obj in content.get("data", []):
                target_id = obj.get("ObjectIdentifier")

                # Skip if target is not Tier 0
                if target_id not in tier0:
                    continue

                # Check ACEs on this Tier 0 object
                for ace in obj.get("Aces", []) or []:
                    principal = ace.get("PrincipalSID")
                    right = ace.get("RightName")

                    # Only CLOSURE_RIGHTS promote to Tier 0
                    if principal and right in TIER0_CLOSURE_RIGHTS:
                        if principal not in tier0:
                            tier0.add(principal)
                            added_this_round += 1

        total_added += added_this_round

        # Fixpoint: stop if no new objects
        if added_this_round == 0:
            break

    if total_added > 0:
        print(f"  ✓ Closure: +{total_added} objects with control rights over Tier 0 ({iteration} iterations)")

    return tier0


def expand_tier0_indirect(
    tier0_closure: Set[str],
    nodes_by_id: Dict[str, dict],
    by_type: Dict[str, dict]
) -> Set[str]:
    """
    PHASE 3: TIER 0 INDIRECT (accès machines/objets Tier 0) - Déterministe

    Expand Tier 0 with ALL access methods to Tier 0 machines (DCs + others):
    - AdminTo on Tier 0 machine → Tier 0
    - ReadLAPSPassword on Tier 0 machine (or OU containing it) → Tier 0
    - ReadGMSAPassword on Tier 0 object → Tier 0
    - WriteGPO/GenericAll on GPO linked to Tier 0 machine OU → Tier 0
    - CanRDP/CanPSRemote/DCOM on Tier 0 machine → Tier 0
    """
    tier0 = set(tier0_closure)
    dc_ids = get_dc_computers(by_type)
    t0_machine_ids = get_tier0_computers(tier0, by_type)
    t0_ou_ids = get_ous_containing_machines(by_type, t0_machine_ids)
    gpos_on_t0 = get_gpos_linked_to_ous(by_type, t0_ou_ids)

    non_dc_count = len(t0_machine_ids - dc_ids)
    if non_dc_count > 0:
        print(f"  ℹ Indirect: {len(t0_machine_ids)} Tier 0 machines ({len(dc_ids)} DCs + {non_dc_count} others)")

    added_adminto = 0
    added_laps = 0
    added_gpo = 0
    added_remote = 0

    # Scan all computers for AdminTo and ReadLAPSPassword on Tier 0 machines
    computers = by_type.get("computers", {}).get("data", [])
    for comp in computers:
        cid = comp.get("ObjectIdentifier")
        is_t0 = cid in t0_machine_ids

        # AdminTo on Tier 0 machine → Tier 0
        if is_t0:
            la = comp.get("LocalAdmins", {}) or {}
            for r in la.get("Results", []) or []:
                pid = r.get("ObjectIdentifier")
                if pid and pid not in tier0:
                    tier0.add(pid)
                    added_adminto += 1

        # ReadLAPSPassword on Tier 0 machine → Tier 0
        for ace in comp.get("Aces", []) or []:
            principal = ace.get("PrincipalSID")
            right = ace.get("RightName")
            if right == "ReadLAPSPassword" and is_t0:
                if principal and principal not in tier0:
                    tier0.add(principal)
                    added_laps += 1

    # ReadLAPSPassword on OU containing Tier 0 machine → Tier 0
    ous = by_type.get("ous", {}).get("data", [])
    for ou in ous:
        ou_id = ou.get("ObjectIdentifier")
        if ou_id not in t0_ou_ids:
            continue
        for ace in ou.get("Aces", []) or []:
            principal = ace.get("PrincipalSID")
            right = ace.get("RightName")
            if right == "ReadLAPSPassword" and principal:
                if principal not in tier0:
                    tier0.add(principal)
                    added_laps += 1

    # WriteGPO on GPO linked to Tier 0 machine OU → Tier 0
    gpos = by_type.get("gpos", {}).get("data", [])
    for gpo in gpos:
        gpo_id = gpo.get("ObjectIdentifier")
        if gpo_id not in gpos_on_t0:
            continue
        for ace in gpo.get("Aces", []) or []:
            principal = ace.get("PrincipalSID")
            right = ace.get("RightName")
            if right in {"WriteGPO", "EditGPO", "GenericAll", "WriteDacl", "WriteOwner"}:
                if principal and principal not in tier0:
                    tier0.add(principal)
                    added_gpo += 1

    # Remote Access on Tier 0 machine: CanRDP/CanPSRemote/DCOM → Tier 0
    for comp in computers:
        cid = comp.get("ObjectIdentifier")
        if not cid or cid not in t0_machine_ids:
            continue
        for collector_key in ("RemoteDesktopUsers", "PSRemoteUsers", "DcomUsers"):
            collector = comp.get(collector_key, {}) or {}
            for r in collector.get("Results", []) or []:
                pid = r.get("ObjectIdentifier")
                if pid and pid not in tier0:
                    tier0.add(pid)
                    added_remote += 1

    # ReadGMSAPassword on Tier 0 object → Tier 0
    # Doit être APRÈS Remote Access car les gMSA peuvent être promus T0 par CanPSRemote
    added_gmsa = 0
    for meta_type, content in by_type.items():
        for obj in content.get("data", []):
            target_id = obj.get("ObjectIdentifier")
            if not target_id or target_id not in tier0:
                continue
            for ace in obj.get("Aces", []) or []:
                principal = ace.get("PrincipalSID")
                right = ace.get("RightName")
                if right == "ReadGMSAPassword" and principal and principal not in tier0:
                    tier0.add(principal)
                    added_gmsa += 1

    if added_adminto > 0:
        print(f"  ✓ Indirect: +{added_adminto} objects with AdminTo on Tier 0 machine")
    if added_laps > 0:
        print(f"  ✓ Indirect: +{added_laps} objects with ReadLAPSPassword on Tier 0 machine/OU")
    if added_gpo > 0:
        print(f"  ✓ Indirect: +{added_gpo} objects with WriteGPO on Tier 0-linked GPO")
    if added_remote > 0:
        print(f"  ✓ Indirect: +{added_remote} objects with CanRDP/CanPSRemote/DCOM on Tier 0 machine")
    if added_gmsa > 0:
        print(f"  ✓ Indirect: +{added_gmsa} objects with ReadGMSAPassword on Tier 0 object")

    return tier0


def expand_tier0_members(
    tier0_indirect: Set[str],
    nodes_by_id: Dict[str, dict],
    by_type: Dict[str, dict]
) -> Set[str]:
    """
    PHASE 4: TIER 0 MEMBERS

    Add direct members of Tier 0 groups to Tier 0.
    If you are member of Domain Admins, you ARE Domain Admin.
    """
    tier0 = set(tier0_indirect)
    added = 0

    groups = by_type.get("groups", {}).get("data", [])
    for group in groups:
        gid = group.get("ObjectIdentifier")
        if gid not in tier0:
            continue

        # Add all members of this Tier 0 group
        for member in group.get("Members", []) or []:
            mid = member.get("ObjectIdentifier")
            if mid and mid not in tier0:
                tier0.add(mid)
                added += 1

    if added > 0:
        print(f"  ✓ Members: +{added} members of Tier 0 groups")

    return tier0


def classify_objects_by_tier(
    nodes_by_id: Dict[str, dict],
    edges: List[dict],
    tier0_nodes: Set[str],
    max_distance: int = 10
) -> Dict[str, int]:
    """
    PHASE 5: DISTANCE CALCULATION

    Classify all AD objects into Tier 0/1/2/3 based on shortest path distance to Tier 0.

    Classification rules:
    - Tier 0: Objects in tier0_nodes (already computed)
    - Tier 1: Distance 1-2 hops from Tier 0 (high privilege, close to domain control)
    - Tier 2: Distance 3-5 hops from Tier 0 (standard servers, workstations)
    - Tier 3: Distance 6+ hops or unreachable (isolated/standard users)

    Note: tier = min(tier, new_tier) to avoid promotion loops.

    Returns: Dict mapping node_id -> tier_number (0, 1, 2, or 3)
    """
    classification = {}

    # Build adjacency list for graph traversal
    adjacency = defaultdict(list)
    for e in edges:
        adjacency[e["src"]].append(e["dst"])

    def shortest_distance_to_tier0(node_id: str) -> int:
        """BFS to find shortest path distance to any Tier 0 node."""
        if node_id in tier0_nodes:
            return 0

        visited = {node_id}
        queue = deque([(node_id, 0)])

        while queue:
            current, dist = queue.popleft()

            if dist >= max_distance:
                continue

            for neighbor in adjacency.get(current, []):
                if neighbor in tier0_nodes:
                    return dist + 1

                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, dist + 1))

        return 999  # Unreachable

    # Classify all nodes
    for nid in nodes_by_id.keys():
        if nid in tier0_nodes:
            classification[nid] = 0
        else:
            distance = shortest_distance_to_tier0(nid)

            if distance <= 7:
                classification[nid] = 1  # Tier 1: 1-7 hops (proximity)
            else:
                classification[nid] = 2  # Tier 2: 8+ hops or unreachable

    return classification


def compute_full_tier_classification(
    nodes_by_id: Dict[str, dict],
    edges: List[dict],
    by_type: Dict[str, dict],
) -> Tuple[Set[str], Dict[str, int]]:
    """
    Full Tier classification pipeline (v5):

    TIER 0 — Déterministe :
    1. SEED: Domain, DCs, KRBTGT, critical groups, DCSync, Cert Publishers
    2. CLOSURE: Control rights over Tier 0 (whitelist stricte)
    3. INDIRECT: ALL Tier 0 machine access (AdminTo, LAPS, GPO, CanRDP, CanPSRemote, DCOM)
    4. MEMBERS: Direct members of Tier 0 groups
    5. DISTANCE BFS: calcul distance depuis Tier 0 FINAL

    TIER 1/2 — Distance BFS uniquement :
    - Tier 1: 1-7 hops depuis Tier 0 (proximite)
    - Tier 2: 8+ hops depuis Tier 0 (inclut unreachable)

    Note: Mode 2 uses ego-graph exploration from start_node.

    Returns: (tier0_nodes, classification_dict)
    """
    print("\n[TIER CLASSIFICATION v5] Starting scientific classification...")

    # ====================================================================
    # TIER 0 — Contrôle déterministe du domaine
    # ====================================================================

    # Phase 1: Attribution directe
    tier0 = identify_tier0_seed(nodes_by_id, by_type)
    print(f"  \u2713 Phase 1 attribution directe: {len(tier0)} Tier 0 objects")

    # Phase 2: Héritage direct (point fixe)
    tier0 = expand_tier0_closure(tier0, nodes_by_id, by_type, max_iterations=10)

    # Phase 3: Héritage indirect (accès machines/objets Tier 0)
    tier0 = expand_tier0_indirect(tier0, nodes_by_id, by_type)

    # Phase 2 bis: Héritage direct après Phase 3
    # (les nouveaux T0 de Phase 3 peuvent être cibles de GenericAll, WriteDacl, etc.)
    tier0 = expand_tier0_closure(tier0, nodes_by_id, by_type, max_iterations=10)

    # Phase 4: Membres des groupes Tier 0
    tier0 = expand_tier0_members(tier0, nodes_by_id, by_type)

    print(f"  ✓ Final Tier 0: {len(tier0)} objects")

    # Phase 5: DISTANCE BFS for Tier 1/2/3 (depuis Tier 0 FINAL)
    print("\n[DISTANCE BFS] Computing distances from FINAL Tier 0 (all edges)...")
    classification = classify_objects_by_tier(nodes_by_id, edges, tier0, max_distance=10)

    # ====================================================================
    # SUMMARY
    # ====================================================================
    tier_counts = defaultdict(int)
    for tier in classification.values():
        tier_counts[tier] += 1

    print(f"\n  Tier 0: {tier_counts[0]} objects (deterministic domain control)")
    print(f"  Tier 1: {tier_counts[1]} objects (1-7 hops)")
    print(f"  Tier 2: {tier_counts[2]} objects (8+ hops or unreachable)")

    return tier0, classification


def get_tier_targets(
    tier: int,
    classification: Dict[str, int],
    nodes_by_id: Dict[str, dict],
    start_node_id: Optional[str] = None,
    all_edges: Optional[List[dict]] = None
) -> List[Tuple[str, str, str]]:
    """
    Get all targets for a specific tier.

    For Tier 2 (mode 2): If start_node_id and all_edges are provided,
    returns ALL objects reachable from start_node that are NOT in Tier 0/1.
    This creates an "ego-graph exploration" view of the start node.

    For Tier 0/1: Returns objects classified in that tier.

    Returns: List of (goal_type, node_id, node_name) tuples
    """
    targets = []

    # Special handling for Tier 2: ego-graph exploration
    if tier == 2 and start_node_id and all_edges:
        # Build adjacency list
        from collections import deque, defaultdict
        adjacency = defaultdict(list)
        for edge in all_edges:
            src = edge.get("src")
            dst = edge.get("dst")
            if src and dst:
                adjacency[src].append(dst)

        # BFS from start_node to find all reachable objects
        visited = set()
        queue = deque([start_node_id])
        visited.add(start_node_id)

        while queue:
            current = queue.popleft()
            for neighbor in adjacency.get(current, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(neighbor)

        # Filter: only objects NOT in Tier 0/1
        for nid in visited:
            tier_level = classification.get(nid, 2)
            if tier_level == 2:  # Not in Tier 0/1
                node = nodes_by_id.get(nid, {})
                node_type = node.get("type", "Unknown").lower()
                node_name = node.get("name", nid)
                targets.append((node_type, nid, node_name))

        return targets

    # Standard behavior for Tier 0/1
    for nid, tier_level in classification.items():
        if tier_level == tier:
            node = nodes_by_id.get(nid, {})
            node_type = node.get("type", "Unknown").lower()
            node_name = node.get("name", nid)
            targets.append((node_type, nid, node_name))

    return targets


def is_well_known_sid(sid: str) -> bool:
    return sid.startswith(WELL_KNOWN_PREFIXES)


def load_json_files(data_dir: str, certipy_json: str = None) -> Dict[str, dict]:
    if not os.path.isdir(data_dir):
        print(f"[!] Data directory not found: {data_dir}", file=sys.stderr)
        sys.exit(1)
    files = [f for f in os.listdir(data_dir) if f.endswith(".json")]
    if not files:
        print(f"[!] No JSON files found in: {data_dir}", file=sys.stderr)
        sys.exit(1)
    by_type = {}
    for fname in files:
        path = os.path.join(data_dir, fname)
        with open(path, "r", encoding="utf-8") as f:
            content = json.load(f)
        meta_type = content.get("meta", {}).get("type")
        if meta_type:
            by_type[meta_type] = content
        else:
            # Fallback to filename heuristic
            for key in TYPE_BY_META.keys():
                if fname.endswith(f"_{key}.json"):
                    by_type[key] = content
                    break

    # Load certipy data if provided
    if certipy_json and os.path.exists(certipy_json):
        with open(certipy_json, "r", encoding="utf-8") as f:
            content = json.load(f)
        by_type["certtemplates"] = content

    return by_type


def validate_bloodhound_data(by_type: Dict[str, dict]) -> None:
    """
    Non-blocking validation of BloodHound data completeness.
    Prints red/yellow warnings for empty or broken collectors.
    Does NOT raise exceptions -- execution always continues.
    """
    RED = "\033[91m"
    YELLOW = "\033[93m"
    RESET = "\033[0m"
    warnings_found = False

    # 1. Check critical object types exist and are non-empty
    critical_types = {
        "users": "Users",
        "groups": "Groups",
        "computers": "Computers",
        "domains": "Domains",
    }
    for meta_key, display_name in critical_types.items():
        content = by_type.get(meta_key, {})
        data = content.get("data", [])
        if not data:
            print(f"{RED}[WARNING] BloodHound: 0 {display_name} found - collection may have failed{RESET}")
            warnings_found = True

    # 2. Check Computer collector flags (Collected / FailureReason)
    collectors_to_check = [
        ("LocalAdmins", "Local Admins"),
        ("Sessions", "Sessions"),
        ("RemoteDesktopUsers", "Remote Desktop Users"),
        ("PSRemoteUsers", "PS Remote Users"),
    ]
    computers = by_type.get("computers", {}).get("data", [])
    for collector_key, display_name in collectors_to_check:
        not_collected = 0
        failed = 0
        total = 0
        for comp in computers:
            collector = comp.get(collector_key, {}) or {}
            if "Collected" in collector:
                total += 1
                if not collector.get("Collected"):
                    not_collected += 1
                if collector.get("FailureReason"):
                    failed += 1
        if total > 0 and not_collected == total:
            print(f"{RED}[WARNING] BloodHound collector '{display_name}' was NOT collected on any computer ({total} computers){RESET}")
            warnings_found = True
        elif failed > 0:
            print(f"{YELLOW}[WARNING] BloodHound collector '{display_name}' failed on {failed}/{total} computers{RESET}")
            warnings_found = True

    # 3. Check if any ACE data exists
    has_aces = False
    for content in by_type.values():
        for obj in content.get("data", []):
            if obj.get("Aces"):
                has_aces = True
                break
        if has_aces:
            break
    if not has_aces:
        print(f"{RED}[WARNING] No ACE data found in any BloodHound object - attack paths will be incomplete{RESET}")
        warnings_found = True

    if not warnings_found:
        print("  \u2713 BloodHound data validation: all checks passed")


def build_node_index(by_type: Dict[str, dict]) -> Tuple[Dict[str, dict], Dict[str, List[str]]]:
    nodes_by_id = {}
    key_to_ids: Dict[str, Set[str]] = defaultdict(set)
    for meta_type, content in by_type.items():
        node_type = TYPE_BY_META.get(meta_type, meta_type)
        for obj in content.get("data", []):
            oid = obj.get("ObjectIdentifier")
            if not oid:
                continue
            props = obj.get("Properties", {}) or {}
            name = props.get("name") or props.get("samaccountname") or oid
            node = {
                "id": oid,
                "type": node_type,
                "name": name,
                "_properties": props,
            }
            nodes_by_id[oid] = node

            # Index keys for lookup
            candidates: Set[str] = set()
            candidates.add(str(oid))
            if name:
                candidates.add(str(name))
            sam = props.get("samaccountname")
            if sam:
                candidates.add(str(sam))
            domain = props.get("domain")
            if domain and sam:
                d = str(domain)
                s = str(sam)
                candidates.add(f"{d}\\{s}")
                candidates.add(f"{s}@{d}")
            for c in candidates:
                key_to_ids[c.lower()].add(str(oid))
    # Convert to list for JSON-friendly error messages
    key_to_ids_out: Dict[str, List[str]] = {k: sorted(v) for k, v in key_to_ids.items()}
    return nodes_by_id, key_to_ids_out


def resolve_start_node(identifier: str, key_to_ids: Dict[str, List[str]]) -> str:
    key = identifier.lower()
    if key in key_to_ids:
        ids = key_to_ids[key]
        if len(ids) == 1:
            return ids[0]
        raise ValueError(f"Identifier ambiguous: {identifier} -> {ids[:5]}")

    # Try DOMAIN\\user -> user@DOMAIN
    if "\\" in identifier:
        domain, user = identifier.split("\\", 1)
        alt = f"{user}@{domain}".lower()
        if alt in key_to_ids:
            ids = key_to_ids[alt]
            if len(ids) == 1:
                return ids[0]
            raise ValueError(f"Identifier ambiguous: {identifier} -> {ids[:5]}")

    raise ValueError(f"Identifier not found: {identifier}")


def compute_effective_principals(
    start_id: str,
    member_to_groups: Dict[str, List[str]],
    include_well_known: bool,
) -> List[str]:
    effective = []
    seen = set()
    queue = deque([start_id])
    while queue:
        cur = queue.popleft()
        if cur in seen:
            continue
        seen.add(cur)
        if (cur != start_id) and (not include_well_known) and is_well_known_sid(cur):
            continue
        effective.append(cur)
        for grp in member_to_groups.get(cur, []):
            if grp not in seen:
                queue.append(grp)
    return effective


def add_edge(edges, src, dst, kind, right, inherited=False, confidence="observed"):
    edges.append(
        {
            "src": src,
            "dst": dst,
            "kind": kind,
            "right": right,
            "inherited": inherited,
            "source": "bloodhound",
            "confidence": confidence,
        }
    )


def build_observed_edges(
    principals,
    member_to_groups,
    by_type,
    include_sessions,
    start_id: str,
    right_whitelist: Optional[Set[str]],
):
    edges = []

    # MemberOf edges among principals
    for principal in principals:
        for grp in member_to_groups.get(principal, []):
            if grp in principals:
                add_edge(edges, principal, grp, "memberOf", "MemberOf", inherited=False)

    # ACL edges from ACEs (with DCSync hierarchy)
    dcsync_rights_map = defaultdict(lambda: defaultdict(set))
    non_dcsync_aces = []

    for meta_type, content in by_type.items():
        for obj in content.get("data", []):
            target_id = obj.get("ObjectIdentifier")
            # We don't care about "who has rights over the start object" for the ego-graph:
            # the goal is escalation paths *from* start, not a full inbound ACL view.
            if target_id == start_id:
                continue
            for ace in obj.get("Aces", []) or []:
                principal = ace.get("PrincipalSID")
                right = ace.get("RightName")
                if principal in principals and right and (right_whitelist is None or right in right_whitelist):
                    inherited = bool(ace.get("IsInherited"))

                    # Group DCSync rights for hierarchy processing
                    if right in TIER0_DCSYNC_RIGHTS:
                        dcsync_rights_map[principal][target_id].add(right)
                    else:
                        non_dcsync_aces.append((principal, target_id, right, inherited))

    # Add non-DCSync edges
    for principal, target_id, right, inherited in non_dcsync_aces:
        add_edge(edges, principal, target_id, "ace", right, inherited=inherited)

    # Add consolidated DCSync edges with hierarchy
    for principal, targets in dcsync_rights_map.items():
        for target_id, rights_set in targets.items():
            has_getchanges = "GetChanges" in rights_set
            has_getchangesall = "GetChangesAll" in rights_set
            has_dcsync = "DCSync" in rights_set

            if has_dcsync or (has_getchanges and has_getchangesall):
                display_right = "DCSync"
            elif has_getchanges:
                display_right = "GetChanges"
            elif has_getchangesall:
                display_right = "GetChangesAll"
            else:
                display_right = "GetChangesInFilteredSet"

            add_edge(edges, principal, target_id, "ace", display_right, inherited=False)

    # Machine access + sessions
    computers = by_type.get("computers", {}).get("data", [])
    for comp in computers:
        cid = comp.get("ObjectIdentifier")
        la = comp.get("LocalAdmins", {}) or {}
        for r in la.get("Results", []) or []:
            pid = r.get("ObjectIdentifier")
            if pid in principals:
                add_edge(edges, pid, cid, "local_admin", "AdminTo")

        rdp = comp.get("RemoteDesktopUsers", {}) or {}
        for r in rdp.get("Results", []) or []:
            pid = r.get("ObjectIdentifier")
            if pid in principals:
                add_edge(edges, pid, cid, "rdp", "CanRDP")

        psr = comp.get("PSRemoteUsers", {}) or {}
        for r in psr.get("Results", []) or []:
            pid = r.get("ObjectIdentifier")
            if pid in principals:
                add_edge(edges, pid, cid, "psremote", "CanPSRemote")

        dcom = comp.get("DcomUsers", {}) or {}
        for r in dcom.get("Results", []) or []:
            pid = r.get("ObjectIdentifier")
            if pid in principals:
                add_edge(edges, pid, cid, "dcom", "DCOM")

        if include_sessions:
            sessions = comp.get("Sessions", {}) or {}
            for r in sessions.get("Results", []) or []:
                pid = r.get("ObjectIdentifier")
                if pid in principals:
                    add_edge(edges, pid, cid, "session", "HasSession")

            priv = comp.get("PrivilegedSessions", {}) or {}
            for r in priv.get("Results", []) or []:
                pid = r.get("ObjectIdentifier")
                if pid in principals:
                    add_edge(edges, pid, cid, "session", "HasSession", confidence="high")

            reg = comp.get("RegistrySessions", {}) or {}
            for r in reg.get("Results", []) or []:
                pid = r.get("ObjectIdentifier")
                if pid in principals:
                    add_edge(edges, pid, cid, "session", "LoggedOn")

    return edges


def is_high_value(node: dict) -> bool:
    name = (node.get("name") or "").upper()
    ntype = node.get("type")
    keywords = (
        "DOMAIN ADMINS",
        "ENTERPRISE ADMINS",
        "ADMINISTRATORS",
        "DOMAIN CONTROLLERS",
        "KRBTGT",
        "CERT PUBLISHERS",
        "DNSADMINS",
    )
    if any(k in name for k in keywords):
        return True
    if ntype in ("Domain", "OU", "GPO") and name:
        return True
    return False


def classify_edge_severity(edge: dict, nodes_by_id: Dict[str, dict]) -> str:
    right_raw = (edge.get("right") or "")
    right = right_raw.upper()
    right_norm = re.sub(r"[^A-Z0-9]", "", right)
    dst = nodes_by_id.get(edge.get("dst"), {})
    dst_type = (dst.get("type") or "").upper()
    dst_name = (dst.get("name") or "").upper()
    src = nodes_by_id.get(edge.get("src"), {})
    src_name = (src.get("name") or "").upper()

    # CRITICAL
    if right_norm in {"DCSYNC", "GETCHANGES", "GETCHANGESALL", "GETCHANGESINFILTEREDSET"}:
        return "critical"
    if edge.get("kind") == "memberOf" and ("DOMAIN ADMINS" in dst_name or "ENTERPRISE ADMINS" in dst_name):
        return "critical"
    if "KRBTGT" in dst_name and right_norm in {"GENERICALL", "WRITEDACL", "WRITEOWNER", "ALLEXTENDEDRIGHTS", "FORCECHANGEPASSWORD"}:
        return "critical"
    if "NTDS" in dst_name and right:
        return "critical"

    # HIGH
    if dst_type == "DOMAIN" and right_norm in {"WRITEDACL", "WRITEOWNER", "GENERICALL"}:
        return "high"
    if "ADMINSDHOLDER" in dst_name and right_norm in {"WRITEDACL", "WRITEOWNER", "GENERICALL"}:
        return "high"
    if dst_type == "GPO" and "DOMAIN CONTROLLERS" in dst_name and right_norm in {"WRITEDACL", "WRITEOWNER", "GENERICALL"}:
        return "high"
    if "ADCS" in dst_name or "ESC" in right:
        return "high"

    # MEDIUM
    if right_norm in {"ADMINTO", "CANRDP", "CANPSREMOTE"} and "DC" in dst_name:
        return "medium"
    if right_norm in {"HASSESSION", "LOGGEDON"} and "DOMAIN ADMINS" in src_name:
        return "medium"
    if "LAPS" in right or "GMSA" in right:
        return "medium"
    if "RBCD" in right:
        return "medium"

    # LOW
    if "SHADOW" in right:
        return "low"
    if "WRITEMEMBER" in right_norm:
        return "low"
    if dst_type == "OU" and right_norm in {"GENERICALL", "WRITEDACL", "WRITEOWNER"}:
        return "low"
    if "SIDHISTORY" in right:
        return "low"

    return ""


def k_shortest_loopless_paths(
    start_id: str,
    target_id: str,
    edges: List[dict],
    k: int = 5,
    max_depth: int = 12,
) -> Tuple[List[List[str]], List[List[dict]]]:
    """Yen's algorithm (bounded) for k shortest loopless paths in an unweighted directed graph."""
    adjacency = defaultdict(list)
    edge_map = defaultdict(list)
    for e in edges:
        adjacency[e["src"]].append(e["dst"])
        edge_map[(e["src"], e["dst"])].append(e)

    def shortest_node_path_from(source_id: str, blocked_nodes=set(), blocked_edges=set()):
        q = deque([source_id])
        parent = {source_id: None}
        depth = {source_id: 0}
        while q:
            cur = q.popleft()
            if cur == target_id:
                break
            if depth[cur] >= max_depth:
                continue
            for nxt in adjacency.get(cur, []):
                if nxt in blocked_nodes:
                    continue
                if (cur, nxt) in blocked_edges:
                    continue
                if nxt not in parent:
                    parent[nxt] = cur
                    depth[nxt] = depth[cur] + 1
                    q.append(nxt)
        if target_id not in parent:
            return None
        # reconstruct
        path = []
        cur = target_id
        while cur is not None:
            path.append(cur)
            cur = parent[cur]
        return list(reversed(path))

    def node_path_to_edge_path(node_path):
        edge_path = []
        for a, b in zip(node_path, node_path[1:]):
            candidates = edge_map.get((a, b))
            if candidates:
                edge_path.append(candidates[0])
        return edge_path

    first = shortest_node_path_from(start_id)
    if not first:
        return [], []
    A = [first]  # accepted node paths
    B = []       # heap of candidate node paths: (len, path_tuple)
    seen_candidates = set()

    import heapq

    def push_candidate(path):
        if len(path) < 2:
            return
        if (len(path) - 1) > max_depth:
            return
        t = tuple(path)
        if t in seen_candidates:
            return
        seen_candidates.add(t)
        heapq.heappush(B, (len(path), t))

    for _ in range(1, k):
        prev = A[-1]
        for i in range(len(prev) - 1):
            spur_node = prev[i]
            root_path = prev[: i + 1]

            blocked_nodes = set(root_path[:-1])
            blocked_edges = set()

            # remove edges that would duplicate the same root_path in previous accepted paths
            for p in A:
                if len(p) > i and p[: i + 1] == root_path:
                    blocked_edges.add((p[i], p[i + 1]))

            spur_path = shortest_node_path_from(spur_node, blocked_nodes=blocked_nodes, blocked_edges=blocked_edges)
            if not spur_path:
                continue

            candidate = root_path[:-1] + spur_path
            if candidate not in A:
                push_candidate(candidate)

        if not B:
            break
        _, cand = heapq.heappop(B)
        A.append(list(cand))

    node_paths = [p for p in A if len(p) >= 2]
    edge_paths = [node_path_to_edge_path(p) for p in node_paths]
    return node_paths, edge_paths


def find_tier0_objects(data_dir: str, certipy_json: str = None) -> list:
    """
    Identify Tier 0 objects using the full classification pipeline.
    Returns a list of {name, type} for Tier 0 objects.
    Raises ValueError if data is invalid (does NOT sys.exit).
    """
    if not os.path.isdir(data_dir):
        raise ValueError(f"Data directory not found: {data_dir}")
    files = [f for f in os.listdir(data_dir) if f.endswith(".json")]
    if not files:
        raise ValueError(f"No JSON files in: {data_dir}")
    by_type = {}
    for fname in files:
        path = os.path.join(data_dir, fname)
        with open(path, "r", encoding="utf-8") as f:
            content = json.load(f)
        meta_type = content.get("meta", {}).get("type")
        if meta_type:
            by_type[meta_type] = content
    if certipy_json and os.path.exists(certipy_json):
        with open(certipy_json, "r", encoding="utf-8") as f:
            by_type["certtemplates"] = json.load(f)
    nodes_by_id, key_to_ids = build_node_index(by_type)

    # Full Tier 0 classification
    tier0 = identify_tier0_seed(nodes_by_id, by_type)
    tier0 = expand_tier0_closure(tier0, nodes_by_id, by_type)
    tier0 = expand_tier0_indirect(tier0, nodes_by_id, by_type)
    tier0 = expand_tier0_closure(tier0, nodes_by_id, by_type)  # 2nd pass après indirect
    tier0 = expand_tier0_members(tier0, nodes_by_id, by_type)

    results = []
    for sid in tier0:
        node = nodes_by_id.get(sid)
        if not node:
            continue
        results.append({
            "name": node.get("name", sid),
            "type": node.get("type", "Unknown").lower(),
        })

    results.sort(key=lambda x: (0 if x["type"] == "user" else 1, x["name"]))
    return results


def find_objects_with_tier0_paths(data_dir: str, certipy_json: str = None) -> list:
    """
    Identify all objects that have at least one attack path to a Tier 0
    object (including Tier 0 objects themselves if they have edges to other T0).

    Builds a global adjacency graph (all Aces + memberships + AdminTo +
    remote access) then does a single reverse BFS from Tier 0.
    """
    if not os.path.isdir(data_dir):
        raise ValueError(f"Data directory not found: {data_dir}")
    files = [f for f in os.listdir(data_dir) if f.endswith(".json")]
    if not files:
        raise ValueError(f"No JSON files in: {data_dir}")
    by_type = {}
    for fname in files:
        path = os.path.join(data_dir, fname)
        with open(path, "r", encoding="utf-8") as f:
            content = json.load(f)
        meta_type = content.get("meta", {}).get("type")
        if meta_type:
            by_type[meta_type] = content
    if certipy_json and os.path.exists(certipy_json):
        with open(certipy_json, "r", encoding="utf-8") as f:
            by_type["certtemplates"] = json.load(f)

    nodes_by_id, _ = build_node_index(by_type)

    # Full Tier 0 classification
    tier0 = identify_tier0_seed(nodes_by_id, by_type)
    tier0 = expand_tier0_closure(tier0, nodes_by_id, by_type)
    tier0 = expand_tier0_indirect(tier0, nodes_by_id, by_type)
    tier0 = expand_tier0_closure(tier0, nodes_by_id, by_type)  # 2nd pass après indirect
    tier0 = expand_tier0_members(tier0, nodes_by_id, by_type)

    # Build global forward adjacency: src -> {dst}
    # "src can attack/reach dst"
    forward = defaultdict(set)

    # 1. ACE rights filtered by ALL_PRIVILEGE_RIGHTS (same as graph builder)
    for meta_type, content in by_type.items():
        for obj in content.get("data", []):
            target_id = obj.get("ObjectIdentifier")
            if not target_id:
                continue
            for ace in obj.get("Aces", []) or []:
                principal = ace.get("PrincipalSID")
                right = ace.get("RightName")
                if principal and right and right in ALL_PRIVILEGE_RIGHTS and principal != target_id:
                    forward[principal].add(target_id)

    # 2. Group membership: member → group (member inherits group permissions)
    for g in by_type.get("groups", {}).get("data", []):
        gid = g.get("ObjectIdentifier")
        if not gid:
            continue
        for m in g.get("Members", []) or []:
            mid = m.get("ObjectIdentifier")
            if mid and mid != gid:
                forward[mid].add(gid)

    # 3. AdminTo / LocalAdmins: admin → computer
    for comp in by_type.get("computers", {}).get("data", []):
        cid = comp.get("ObjectIdentifier")
        if not cid:
            continue
        for collector_key in ("LocalAdmins", "RemoteDesktopUsers", "PSRemoteUsers", "DcomUsers"):
            collector = comp.get(collector_key, {}) or {}
            for r in collector.get("Results", []) or []:
                pid = r.get("ObjectIdentifier")
                if pid and pid != cid:
                    forward[pid].add(cid)

    # 4. Sessions: computer → user (user has session on computer)
    for comp in by_type.get("computers", {}).get("data", []):
        cid = comp.get("ObjectIdentifier")
        if not cid:
            continue
        sessions = comp.get("Sessions", {}) or {}
        for s in sessions.get("Results", []) or []:
            uid = s.get("UserSID") or s.get("ObjectIdentifier")
            if uid and uid != cid:
                forward[cid].add(uid)

    # Build reverse adjacency for BFS
    reverse_adj = defaultdict(set)
    for src, dsts in forward.items():
        for dst in dsts:
            reverse_adj[dst].add(src)

    # Reverse BFS from all Tier 0 nodes
    can_reach_t0 = set()
    queue = deque(tier0)
    visited = set(tier0)

    while queue:
        node = queue.popleft()
        for predecessor in reverse_adj.get(node, set()):
            if predecessor not in visited:
                visited.add(predecessor)
                can_reach_t0.add(predecessor)
                queue.append(predecessor)

    # Also include T0 objects that have at least one edge to another T0
    # (they produce non-empty Tier 0 graphs as start nodes)
    for sid in tier0:
        for dst in forward.get(sid, set()):
            if dst in tier0 and dst != sid:
                can_reach_t0.add(sid)
                break

    # Return all objects with known names
    results = []
    for sid in can_reach_t0:
        node = nodes_by_id.get(sid)
        if not node:
            continue
        results.append({
            "name": node.get("name", sid),
            "type": node.get("type", "Unknown").lower(),
        })

    results.sort(key=lambda x: (0 if x["type"] == "user" else 1, x["name"]))
    return results


def main():
    parser = argparse.ArgumentParser(description="Build BloodHound attack paths using Tier-based classification.")
    parser.add_argument("--data-dir", required=True, help="Path to BloodHound JSON folder")
    parser.add_argument("--start", required=True, help="Start node identifier")
    parser.add_argument("--out", default="graph.json", help="Output JSON path")
    parser.add_argument("--certipy-json", default=None, help="Path to certipy_data.json (ADCS templates)")
    parser.add_argument(
        "--mode",
        choices=["0", "1", "2", "3"],
        default="0",
        help=(
            "Tier-based analysis mode:\n"
            "  0 = ALL paths to Tier 0 (Domain, DCs, Domain Admins, KRBTGT, Cert Publishers) - no limit\n"
            "  1 = 30 shortest paths to Tier 1 (1-2 hops from Tier 0)\n"
            "  2 = 30 shortest paths to Tier 2 (3-7 hops from Tier 0)\n"
            "  3 = 40 paths exploring ALL relations from start_node (excluding Tier 0/1/2)\n"
            "\nClassification v5: Tier 0 (SEED→CLOSURE→INDIRECT→MEMBERS→BFS) + Tier 1/2 (BFS distance) + Tier 3 (ego-graph exploration)."
        ),
    )
    args = parser.parse_args()

    # Fixed defaults for global cartography
    include_sessions = False
    include_well_known = False
    max_nodes = 5000
    max_edges = 20000
    max_depth = 10
    max_controlled = 500
    max_time = 3.0

    by_type = load_json_files(args.data_dir, getattr(args, 'certipy_json', None))
    validate_bloodhound_data(by_type)
    nodes_by_id, key_to_ids = build_node_index(by_type)

    # All modes use ALL BloodHound rights (no filtering)
    acl_rights = None

    start_id = resolve_start_node(args.start, key_to_ids)

    # Build member -> groups index
    member_to_groups = defaultdict(list)
    group_to_members = defaultdict(list)
    groups = by_type.get("groups", {}).get("data", [])
    for g in groups:
        gid = g.get("ObjectIdentifier")
        for m in g.get("Members", []) or []:
            mid = m.get("ObjectIdentifier")
            if mid and gid:
                member_to_groups[mid].append(gid)
                group_to_members[gid].append(mid)

    effective_principals = compute_effective_principals(
        start_id, member_to_groups, include_well_known
    )
    edges = build_observed_edges(
        set(effective_principals),
        member_to_groups,
        by_type,
        include_sessions,
        start_id,
        acl_rights,
    )

    # Derived expansion: "can become admin when you want" (bounded).
    # We reuse ALL_PRIVILEGE_RIGHTS here to avoid introducing another rights list.
    derived_edges = []

    promotable_out = defaultdict(list)
    for meta_type, content in by_type.items():
        for obj in content.get("data", []):
            target_id = obj.get("ObjectIdentifier")
            for ace in obj.get("Aces", []) or []:
                principal = ace.get("PrincipalSID")
                right = ace.get("RightName")
                if right in ALL_PRIVILEGE_RIGHTS and principal and target_id:
                    inherited = bool(ace.get("IsInherited"))
                    promotable_out[principal].append((target_id, right, inherited))

    def node_type(nid: str) -> str:
        n = nodes_by_id.get(nid, {})
        return n.get("type", "Unknown")

    def add_controlled(nid: str, parent=None, via=None, depth=0):
        if nid in visited:
            return
        visited.add(nid)
        controlled.add(nid)
        queue.append((nid, depth))
        if parent and via:
            derived_edges.append(
                {
                    "src": parent,
                    "dst": nid,
                    "kind": "derived",
                    "right": via,
                    "inherited": False,
                    "source": "bloodhound",
                    "confidence": "derived",
                }
            )

    start_time = time.time()
    controlled = set(effective_principals)
    visited = set(effective_principals)
    queue = deque((nid, 0) for nid in effective_principals)

    while queue:
        if time.time() - start_time > max_time:
            break

        cur, depth = queue.popleft()
        if depth >= max_depth:
            continue

        # If we control a group, we control its members
        if node_type(cur) == "Group":
            for mid in group_to_members.get(cur, []):
                if len(controlled) >= max_controlled:
                    break
                add_controlled(mid, parent=cur, via="GroupMember", depth=depth + 1)

        # If we control an identity, we get its group memberships
        for gid in member_to_groups.get(cur, []):
            if len(controlled) >= max_controlled:
                break
            add_controlled(gid, parent=cur, via="MemberOf", depth=depth + 1)

        # Promote via rights (primitives)
        for target_id, right, inherited in promotable_out.get(cur, []):
            if len(controlled) >= max_controlled:
                break
            ttype = node_type(target_id)
            if ttype in ("User", "Group"):
                add_controlled(target_id, parent=cur, via=right, depth=depth + 1)
            elif ttype in ("Computer", "Domain", "GPO", "OU"):
                derived_edges.append(
                    {
                        "src": cur,
                        "dst": target_id,
                        "kind": "derived",
                        "right": right,
                        "inherited": inherited,
                        "source": "bloodhound",
                        "confidence": "derived",
                    }
                )

    # Rebuild observed edges based on controlled identities and append derived edges
    edges_observed = build_observed_edges(
        controlled,
        member_to_groups,
        by_type,
        include_sessions,
        start_id,
        acl_rights,
    )
    edges = edges_observed + derived_edges

    # Collect nodes for edges + principals
    node_ids = set(effective_principals)
    for e in edges:
        node_ids.add(e["src"])
        node_ids.add(e["dst"])

    # Severity tagging for visualization
    for e in edges:
        severity = classify_edge_severity(e, nodes_by_id)
        if severity:
            e["severity"] = severity

    # ========================================================================
    # TIER-BASED CLASSIFICATION AND PATH FINDING (v5)
    # ========================================================================
    #
    # Un seul jeu d'edges pour BFS et chemins d'attaque visuels :
    # - Tous les edges (MemberOf, ACE, AdminTo, CanRDP, CanPSRemote, DCOM, Sessions)
    # - Computers = noeuds normaux, traversables (héritage des droits du compte machine)
    # - Tous les edges utilisés pour le BFS de classification et les chemins visuels
    #
    # ========================================================================

    # Pre-compute Computer and DC node sets
    all_computer_ids = set()
    computers_data = by_type.get("computers", {}).get("data", [])
    for comp in computers_data:
        cid = comp.get("ObjectIdentifier")
        if cid:
            all_computer_ids.add(cid)
    dc_ids = get_dc_computers(by_type)

    # Pre-compute domain object IDs (AllExtendedRights on a domain = DCSync capability)
    domain_ids = set()
    for obj in by_type.get("domains", {}).get("data", []):
        oid = obj.get("ObjectIdentifier")
        if oid:
            domain_ids.add(oid)

    # Build unified edge set (all edges for both BFS classification and visual paths)
    all_edges = []

    # First pass: collect all ACEs and group ALL rights by (principal, target)
    # This allows us to consolidate multiple permissions and display the strongest one
    ace_rights_map = defaultdict(lambda: defaultdict(lambda: {"rights": set(), "inherited": False}))

    for meta_type, content in by_type.items():
        for obj in content.get("data", []):
            target_id = obj.get("ObjectIdentifier")
            if not target_id:
                continue

            # Collect ACEs
            for ace in obj.get("Aces", []) or []:
                principal = ace.get("PrincipalSID")
                right = ace.get("RightName")
                if principal and right and right in ALL_PRIVILEGE_RIGHTS:
                    inherited = bool(ace.get("IsInherited"))

                    # Group all rights by (principal, target)
                    ace_rights_map[principal][target_id]["rights"].add(right)
                    # Mark as inherited if ANY ACE is inherited
                    if inherited:
                        ace_rights_map[principal][target_id]["inherited"] = True

    # Helper function to select strongest right according to hierarchy
    def select_strongest_right(rights_set):
        """Select the strongest right from a set according to ACE_RIGHTS_HIERARCHY."""
        # Separate DCSync and non-DCSync rights
        dcsync_rights = rights_set & TIER0_DCSYNC_RIGHTS
        other_rights = rights_set - TIER0_DCSYNC_RIGHTS

        # Handle DCSync rights first (existing logic)
        if dcsync_rights:
            has_getchanges = "GetChanges" in dcsync_rights
            has_getchangesall = "GetChangesAll" in dcsync_rights
            has_dcsync = "DCSync" in dcsync_rights

            if has_dcsync or (has_getchanges and has_getchangesall):
                strongest_dcsync = "DCSync"
            elif has_getchanges:
                strongest_dcsync = "GetChanges"
            elif has_getchangesall:
                strongest_dcsync = "GetChangesAll"
            else:
                strongest_dcsync = "GetChangesInFilteredSet"

            # If we have non-DCSync rights, compare with DCSync
            if other_rights:
                # DCSync is always considered stronger than other rights for display
                return strongest_dcsync
            else:
                return strongest_dcsync

        # Handle non-DCSync rights according to hierarchy
        for right in ACE_RIGHTS_HIERARCHY:
            if right in other_rights:
                return right

        # Fallback: return first right if not in hierarchy
        return list(other_rights)[0] if other_rights else list(rights_set)[0]

    # Process all ACE edges with consolidation
    for principal, targets in ace_rights_map.items():
        for target_id, ace_data in targets.items():
            rights_set = ace_data["rights"]
            inherited = ace_data["inherited"]

            # AllExtendedRights on a domain object = GetChanges + GetChangesAll = DCSync
            # BloodHound often doesn't enumerate separate GetChanges/GetChangesAll for Domain Admins
            # even though AllExtendedRights on a domain grants replication (DCSync) capability
            if target_id in domain_ids and "AllExtendedRights" in rights_set:
                effective_rights = rights_set | {"GetChanges", "GetChangesAll"}
            else:
                effective_rights = rights_set

            # Select strongest right for display
            strongest_right = select_strongest_right(effective_rights)

            # Create single consolidated edge
            edge = {
                "src": principal,
                "dst": target_id,
                "kind": "ace",
                "right": strongest_right,  # Strongest right for display
                "all_rights": sorted(list(rights_set)),  # All rights for reference
                "inherited": inherited,
                "source": "bloodhound",
                "confidence": "observed",
            }
            all_edges.append(edge)

    # MemberOf edges from groups
    for meta_type, content in by_type.items():
        for obj in content.get("data", []):
            target_id = obj.get("ObjectIdentifier")
            if not target_id:
                continue

            # MemberOf edges: member -> group
            for member in obj.get("Members", []) or []:
                mid = member.get("ObjectIdentifier")
                if mid:
                    edge = {
                        "src": mid, "dst": target_id, "kind": "memberOf",
                        "right": "MemberOf", "inherited": False,
                        "source": "bloodhound", "confidence": "observed",
                    }
                    all_edges.append(edge)

    # PrimaryGroupSID edges: Add implicit group membership via PrimaryGroupSID
    # In AD, every object has a primary group (default: Domain Users for users, Domain Computers for computers)
    # This membership is NOT listed in the group's Members[], so we must add it explicitly
    for meta_type, content in by_type.items():
        for obj in content.get("data", []):
            obj_id = obj.get("ObjectIdentifier")
            primary_group_sid = obj.get("PrimaryGroupSID")

            if obj_id and primary_group_sid:
                # Add MemberOf edge: object -> primary group
                edge = {
                    "src": obj_id, "dst": primary_group_sid, "kind": "memberOf",
                    "right": "MemberOf", "inherited": False,
                    "source": "bloodhound", "confidence": "inferred_primary",
                }
                all_edges.append(edge)

    # Computer-specific access edges
    for comp in computers_data:
        cid = comp.get("ObjectIdentifier")
        if not cid:
            continue

        # LocalAdmins → AdminTo
        la = comp.get("LocalAdmins", {}) or {}
        for r in la.get("Results", []) or []:
            pid = r.get("ObjectIdentifier")
            if pid:
                all_edges.append({
                    "src": pid, "dst": cid, "kind": "local_admin", "right": "AdminTo",
                    "inherited": False, "source": "bloodhound", "confidence": "observed",
                })

        # CanRDP
        rdp = comp.get("RemoteDesktopUsers", {}) or {}
        for r in rdp.get("Results", []) or []:
            pid = r.get("ObjectIdentifier")
            if pid:
                all_edges.append({
                    "src": pid, "dst": cid, "kind": "rdp", "right": "CanRDP",
                    "inherited": False, "source": "bloodhound", "confidence": "observed",
                })

        # CanPSRemote
        psr = comp.get("PSRemoteUsers", {}) or {}
        for r in psr.get("Results", []) or []:
            pid = r.get("ObjectIdentifier")
            if pid:
                all_edges.append({
                    "src": pid, "dst": cid, "kind": "psremote", "right": "CanPSRemote",
                    "inherited": False, "source": "bloodhound", "confidence": "observed",
                })

        # DCOM
        dcom = comp.get("DcomUsers", {}) or {}
        for r in dcom.get("Results", []) or []:
            pid = r.get("ObjectIdentifier")
            if pid:
                all_edges.append({
                    "src": pid, "dst": cid, "kind": "dcom", "right": "DCOM",
                    "inherited": False, "source": "bloodhound", "confidence": "observed",
                })

        # Sessions
        for session_key, right_name in (("Sessions", "HasSession"), ("PrivilegedSessions", "HasSession"), ("RegistrySessions", "LoggedOn")):
            collector = comp.get(session_key, {}) or {}
            for r in collector.get("Results", []) or []:
                pid = r.get("ObjectIdentifier")
                if pid:
                    all_edges.append({
                        "src": pid, "dst": cid, "kind": "session", "right": right_name,
                        "inherited": False, "source": "bloodhound", "confidence": "observed",
                    })

    # Full Tier classification pipeline (v5):
    # Tier 0: SEED → CLOSURE → INDIRECT (includes DC remote) → MEMBERS → BFS
    # Tier 1/2/3: BFS distance depuis Tier 0 FINAL
    tier0_nodes, tier_classification = compute_full_tier_classification(
        nodes_by_id, all_edges, by_type
    )

    # Count objects per tier
    tier_counts = defaultdict(int)
    for tier in tier_classification.values():
        tier_counts[tier] += 1

    # Step 4: Get targets for the requested mode
    # Display modes (distinct from classification):
    #   Mode 0 = Deterministic paths to T0 (whitelist rights only)
    #   Mode 1 = Ambiguous paths to T0 (non-deterministic rights)
    #   Mode 2 = Distant paths (T2 objects, extended to T0 if possible)
    target_tier = int(args.mode)
    mode_names = ["Déterministe → T0", "Ambigu → T0", "Éloigné → T0"]
    tier_name = mode_names[target_tier]

    # Progressive path limits
    max_paths_by_tier = {
        0: 9999,  # Deterministic: ALL paths (no artificial limit)
        1: 30,    # Ambiguous: 30 paths
        2: 40,    # Distant: 40 paths (ego-graph exploration from start_node)
    }
    max_paths = max_paths_by_tier[target_tier]

    # Mode 1 (ambiguous) targets T0 objects directly, not T1-classified objects
    if target_tier == 2:
        tier_targets = get_tier_targets(target_tier, tier_classification, nodes_by_id, start_id, all_edges)
    elif target_tier == 1:
        tier_targets = []  # T1 mode finds its own targets (T0 objects via ambiguous rights)
    else:
        tier_targets = get_tier_targets(target_tier, tier_classification, nodes_by_id)

    print(f"\n[MODE {args.mode}] {tier_name}...")
    if tier_targets:
        print(f"  ✓ Found {len(tier_targets)} targets")

    if tier_targets:
        # Show sample of targets
        sample_size = min(10, len(tier_targets))
        for goal_type, _, name in tier_targets[:sample_size]:
            print(f"    - {goal_type}: {name}")
        if len(tier_targets) > sample_size:
            print(f"    ... and {len(tier_targets) - sample_size} more")

    # Step 5: Compute shortest paths to tier targets
    # Build edge index for fast lookup
    edge_index = defaultdict(list)
    for e in all_edges:
        edge_index[(e["src"], e["dst"])].append(e)

    tier0_valid_rights = (
        TIER0_CLOSURE_RIGHTS
        | TIER0_DCSYNC_RIGHTS
        | ADMIN_ACCESS_RIGHTS
        | REMOTE_ACCESS_RIGHTS
        | TIER0_READPASS_RIGHTS
    )

    if target_tier == 0:
        # T0 display: deterministic paths only (whitelist rights)
        path_edges = [
            e for e in all_edges
            if e.get("kind") == "memberOf"
            or e.get("right") in tier0_valid_rights
        ]
    else:
        path_edges = all_edges

    all_paths = []

    if target_tier == 1:
        # MODE 1 — Ambiguous paths to T0
        # Find all paths from start to T0 using ALL edges,
        # keep only those using at least one non-deterministic right.
        t0_targets = [
            (nodes_by_id.get(nid, {}).get("type", "Unknown").lower(), nid,
             nodes_by_id.get(nid, {}).get("name", nid))
            for nid, t in tier_classification.items()
            if t == 0 and nid != start_id
        ]
        for goal_type, target_id, target_name in t0_targets:
            node_paths, _ = k_shortest_loopless_paths(start_id, target_id, all_edges, k=3, max_depth=7)
            for path in node_paths:
                # Check if this path uses at least one non-whitelist right
                is_ambiguous = False
                for i in range(len(path) - 1):
                    for e in edge_index.get((path[i], path[i + 1]), []):
                        right = e.get("right", "")
                        if right and e.get("kind") != "memberOf" and right not in tier0_valid_rights:
                            is_ambiguous = True
                        break
                if is_ambiguous:
                    all_paths.append({
                        "goal": goal_type,
                        "target_id": target_id,
                        "target_name": target_name,
                        "nodes": path,
                        "length": max(0, len(path) - 1),
                        "tier": 1,
                    })
        print(f"  ✓ Found {len(all_paths)} ambiguous paths to Tier 0 (non-deterministic rights)")
    else:
        # MODE 0 (deterministic) and MODE 2 (distant)
        for goal_type, target_id, target_name in tier_targets:
            if target_id == start_id:
                continue
            node_paths, _ = k_shortest_loopless_paths(start_id, target_id, path_edges, k=3, max_depth=12)
            for path in node_paths:
                all_paths.append({
                    "goal": goal_type,
                    "target_id": target_id,
                    "target_name": target_name,
                    "nodes": path,
                    "length": max(0, len(path) - 1),
                    "tier": target_tier,
                })

    # For T2: extend paths from tier targets to Tier 0 objects
    # T2: start → T2 → ... → T0 (if reachable)
    if target_tier == 2:
        t0_targets = [
            (ntype, nid, nname)
            for nid, t in tier_classification.items()
            if t == 0
            for ntype, nname in [(nodes_by_id.get(nid, {}).get("type", "Unknown").lower(),
                                   nodes_by_id.get(nid, {}).get("name", nid))]
        ]
        extension_paths = []
        seen_extensions = set()
        for p in all_paths:
            tier_target_id = p["target_id"]
            already_visited = set(p["nodes"])
            for _, t0_id, t0_name in t0_targets:
                if t0_id in already_visited:
                    continue
                ext_key = (tier_target_id, t0_id)
                if ext_key in seen_extensions:
                    continue
                ext_node_paths, _ = k_shortest_loopless_paths(
                    tier_target_id, t0_id, path_edges, k=1, max_depth=8
                )
                if ext_node_paths:
                    seen_extensions.add(ext_key)
                    merged = p["nodes"] + ext_node_paths[0][1:]
                    extension_paths.append({
                        "goal": "domain",
                        "target_id": t0_id,
                        "target_name": t0_name,
                        "nodes": merged,
                        "length": max(0, len(merged) - 1),
                        "tier": target_tier,
                    })
        all_paths.extend(extension_paths)
        if extension_paths:
            print(f"  ✓ Extended {len(extension_paths)} paths from {tier_name} targets to Tier 0")

    # Step 6: Select paths - simple approach:
    # - Sort by path length (shortest first)
    # - One path per unique target (primary), then alternatives
    # - No special prioritization (Domain is Tier 0 like others)
    all_paths.sort(key=lambda p: p["length"])

    seen_targets = set()
    primary_paths = []
    alternative_paths = []

    for p in all_paths:
        if p["target_id"] not in seen_targets:
            primary_paths.append(p)
            seen_targets.add(p["target_id"])
        else:
            alternative_paths.append(p)

    # For Tier 0: include ALL primary paths (all unique targets)
    # For other tiers: limit to max_paths
    if target_tier == 0:
        selected_paths = primary_paths  # ALL Tier 0 targets
        # Add alternative paths if we want multiple paths per target
        selected_paths.extend(alternative_paths[:max(0, max_paths - len(primary_paths))])
    else:
        selected_paths = primary_paths[:max_paths]
        remaining_slots = max_paths - len(selected_paths)
        if remaining_slots > 0:
            selected_paths.extend(alternative_paths[:remaining_slots])

    print(f"  ✓ Selected {len(selected_paths)} paths to {tier_name} ({len(primary_paths)} unique targets)")

    # Step 7: Build edge map for path visualization
    edge_map = defaultdict(list)
    for e in all_edges:
        edge_map[(e["src"], e["dst"])].append(e)

    def edges_for_node_path(node_path):
        out = []
        for a, b in zip(node_path, node_path[1:]):
            if edge_map.get((a, b)):
                out.append(edge_map[(a, b)][0])
        return out

    # Step 8: Extract nodes and edges for selected paths
    nodes_in_paths = {start_id}
    edges_in_paths = []
    domain_edge_paths = []

    for p in selected_paths:
        node_path = p["nodes"]
        for nid in node_path:
            nodes_in_paths.add(nid)
        ep = edges_for_node_path(node_path)
        edges_in_paths.extend(ep)

        # Track domain paths for shortest path marking
        if p["goal"] == "domain":
            domain_edge_paths.append(ep)

    # Step 9: Mark shortest path (prefer domain if available)
    shortest_ep = None
    if domain_edge_paths:
        shortest_ep = min(domain_edge_paths, key=len)
    elif selected_paths:
        shortest_ep = edges_for_node_path(selected_paths[0]["nodes"])

    if shortest_ep:
        for e in shortest_ep:
            e["is_shortest"] = True

    node_ids = set(nodes_in_paths)
    paths_info = selected_paths

    # Identify target nodes (final nodes in paths) to highlight them
    target_node_ids = set()
    for path in selected_paths:
        target_node_ids.add(path["target_id"])

    # Include CertTemplate Tier 0 nodes only if they connect to nodes already in the graph
    # This avoids showing disconnected ACE holders that aren't part of any path from the start node
    for nid, node in nodes_by_id.items():
        if node.get("type") == "CertTemplate" and tier_classification.get(nid) == 0:
            cert_edges = []
            for e in all_edges:
                if e["dst"] == nid and e["src"] in node_ids:
                    cert_edges.append(e)
                elif e["src"] == nid and e["dst"] in node_ids:
                    cert_edges.append(e)
            # Only include the CertTemplate if it has at least one connected edge
            if cert_edges:
                node_ids.add(nid)
                target_node_ids.add(nid)
                edges_in_paths.extend(cert_edges)

    # Step 10: Deduplicate edges (AFTER CertTemplate inclusion)
    def edge_key(e):
        return (e.get("src"), e.get("dst"), e.get("kind"), e.get("right"), e.get("confidence"))

    dedup = {}
    for e in edges_in_paths:
        dedup[edge_key(e)] = e
    edges = list(dedup.values())

    # ========================================================================
    # OUTPUT GENERATION
    # ========================================================================

    # Limit edges if needed
    if len(edges) > max_edges:
        edges = edges[: max_edges]

    nodes = []
    for nid in node_ids:
        n = nodes_by_id.get(nid)
        if not n:
            n = {"id": nid, "type": "Unknown", "name": nid, "_properties": {}}
        props = n.get("_properties", {}) or {}
        display_name = n["name"]
        if n["type"] == "Computer":
            # Prefer FQDN-style name for display
            display_name = n["name"]
        # Add tier classification for color coding
        node_tier = tier_classification.get(n["id"], 3)  # Default to Tier 3 if not found
        is_target = n["id"] in target_node_ids  # Mark target nodes to highlight them

        nodes.append(
            {
                "id": n["id"],
                "type": n["type"],
                "name": n["name"],
                "display_name": display_name,
                "tier": node_tier,
                "is_target": is_target,
            }
        )

    if len(nodes) > max_nodes:
        nodes = nodes[: max_nodes]

    # Coverage estimation
    def collected_status(items, key):
        flags = []
        for it in items:
            if key in it:
                val = it.get(key, {}) or {}
                if "Collected" in val:
                    flags.append(bool(val.get("Collected")))
        if not flags:
            return False
        if all(flags):
            return True
        if not any(flags):
            return False
        return "partial"

    computers = by_type.get("computers", {}).get("data", [])
    coverage = {
        "acl": True if any("Aces" in obj for content in by_type.values() for obj in content.get("data", [])) else False,
        "local_admin": collected_status(computers, "LocalAdmins"),
        "sessions": collected_status(computers, "Sessions"),
    }

    summary = {
        "groups": sum(1 for n in nodes if n["type"] == "Group"),
        "machines_admin": sum(1 for e in edges if e["right"] == "AdminTo"),
        "objects_controlled": sum(1 for e in edges if e["kind"] == "ace"),
    }

    # paths_info is filled by mode 2 (optional)

    # Modes focus: 1 and 2

    edges_observed = [e for e in edges if e.get("confidence") == "observed"]
    edges_derived = [e for e in edges if e.get("confidence") == "derived"]

    observed_node_ids = set(effective_principals)
    for e in edges_observed:
        observed_node_ids.add(e["src"])
        observed_node_ids.add(e["dst"])

    nodes_observed = [n for n in nodes if n["id"] in observed_node_ids]
    nodes_derived = [n for n in nodes if n["id"] not in observed_node_ids]

    # Determine view name based on mode (tier)
    tier_names = {
        "0": "tier0",
        "1": "tier1",
        "2": "tier2",
    }
    view = tier_names.get(args.mode, "tier0")

    output = {
        "start_node": start_id,
        "mode": args.mode,
        "view": view,
        "tier": target_tier,
        "tier_name": tier_name,
        "tier_classification": {
            "tier0_count": tier_counts[0],
            "tier1_count": tier_counts[1],
            "tier2_count": tier_counts[2],
        },
        "coverage": coverage,
        "nodes": nodes,
        "nodes_observed": nodes_observed,
        "nodes_derived": nodes_derived,
        "edges": edges,
        "edges_observed": edges_observed,
        "edges_derived": edges_derived,
        "summary": summary,
        "paths": paths_info,
        "disclaimer": "Classification Tier v6. Tier 0 = deterministe (SEED + Cert Publishers -> CLOSURE -> INDIRECT [ALL Tier 0 machine access] -> MEMBERS -> BFS). Tier 1 = BFS distance depuis Tier 0 (1-7 hops). Tier 2 = ego-graph exploration depuis start_node (8+ hops ou unreachable). Computers = noeuds normaux traversables. ACE consolidation: permissions multiples -> single edge (right = strongest, all_rights = complete list).",
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print(f"Wrote {args.out} with {len(nodes)} nodes and {len(edges)} edges")


if __name__ == "__main__":
    main()
