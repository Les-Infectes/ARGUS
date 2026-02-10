# CartoAD — Documentation technique

Ce document explique le fonctionnement interne de chaque composant du projet.

---

## 1. Scan reseau

**Scripts** : `global_network_scan_classeC.py`, `global_network_scan_classeAB.py`

### Objectif

Produire un JSON contenant :
- Configuration reseau (IP/CIDR, gateway, DNS)
- Hotes detectes (IP, MAC, hostname)
- Routeurs decouverts (via traceroute)
- Services (si --port-scan active)

### Flux algorithmique

```
┌──────────────────────────────────────────────────────────────────┐
│                 PHASE 1 : DECOUVERTE LOCALE                      │
│                      (ARP scan VLAN)                             │
└──────────────────────────────────────────────────────────────────┘
                              │
                   nmap -sn -PR -T4 <IP_CIDR>
                              │
                              ▼
                ┌─────────────────────────────┐
                │     Hotes UP detectes       │
                │        (IP + MAC)           │
                └─────────────┬───────────────┘
                              │
┌──────────────────────────────────────────────────────────────────┐
│                 PHASE 2 : DECOUVERTE ROUTEURS                    │
│                       (traceroute)                               │
└──────────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
   traceroute            traceroute          [Classe C only]
    8.8.8.8                 DNS            Brute-force 192.168.x.1/254
        │                     │                     │
        └─────────────────────┼─────────────────────┘
                              │
                   Extraction hops prives
                   (routeurs candidats)
                              │
┌──────────────────────────────────────────────────────────────────┐
│                 PHASE 3 : VALIDATION ROUTEURS                    │
└──────────────────────────────────────────────────────────────────┘
                              │
                    ping -c 1 (verification ICMP)
                              │
                    traceroute vers chaque routeur
                              │
                 Filtrage (reste dans RFC1918 ?)
                              │
          ┌───────────────────┴───────────────────┐
          │                                       │
    Routeurs valides                      Routeurs rejetes
   (tous hops prives)                  (au moins 1 hop public)
          │
┌──────────────────────────────────────────────────────────────────┐
│                 PHASE 4 : SCAN SOUS-RESEAUX                      │
└──────────────────────────────────────────────────────────────────┘
          │
    Pour chaque routeur valide :
          │
    Extraction reseau /24 (network_from_ip)
          │
    Verification route (ip route get)
          │
    ┌─────┴─────┐
    │           │
 Route OK   Pas de route
    │           │
 nmap -sn   Warning (ignore)
    │
  Hotes UP
    │
┌──────────────────────────────────────────────────────────────────┐
│           PHASE 5 : ENRICHISSEMENT (si --port-scan)              │
└──────────────────────────────────────────────────────────────────┘
    │
    ├─> Collecte de TOUTES les IP
    │   (VLAN + sous-reseaux + routeurs + gateway + DNS)
    │
    └─> Scan ports/services
        nmap -Pn -A -T4 --script smb-os-discovery
        │
        ├─> Detection OS
        └─> Enumeration services (ports, versions)
```

### Detail des phases

#### Phase 1 : Decouverte locale (ARP scan)

**Commande** : `nmap -sn -PR -T4 <IP_CIDR>`

| Option | Description |
|--------|-------------|
| `-sn` | Host discovery uniquement (pas de scan ports) |
| `-PR` | ARP ping (niveau 2, optimal pour reseau local) |
| `-T4` | Timing aggressive |

**Fonction** : `run_nmap_arp_scan()`

#### Phase 2 : Decouverte routeurs (traceroute)

**Commande** : `traceroute -n <TARGET>`

| Cible | But |
|-------|-----|
| 8.8.8.8 | Decouvrir passerelles vers Internet |
| DNS configure | Decouvrir chemin vers DC |

**Filtrage securite** : Conservation uniquement des IP privees (RFC1918)

**Fonction** : `run_traceroute()`, `collect_router_ips_from_traces()`

#### Phase 2b : Brute-force (Classe C uniquement)

Generation de toutes les IP .1 et .254 pour 192.168.0.0/16 :
- 192.168.0.1, 192.168.0.254
- 192.168.1.1, 192.168.1.254
- ... jusqu'a 192.168.255.254

**Fonction** : `generate_class_c_router_targets()`

#### Phase 3 : Validation routeurs

1. **Verification ICMP** : `ping -c 1 -W 1 <ROUTER>`
2. **Traceroute vers routeur** : Verification que tous les hops restent prives
3. **Filtrage final** : Rejet si un hop public detecte

**Fonctions** : `confirm_with_icmp()`, `traceroute_stays_in_private_space()`

#### Phase 4 : Scan sous-reseaux

Pour chaque routeur valide :
1. Extraction du reseau /24 via `network_from_ip()`
2. Verification route directe : `ip route get <ROUTER_IP>`
3. Scan ARP du /24 : `nmap -sn -PR -T4 <SUBNET>`

**Limitation** : Force toujours un /24 (compromis vitesse/couverture)

#### Phase 5 : Enrichissement (ports/services)

**Commande** : `nmap -Pn -A -T4 --script smb-os-discovery <HOSTS>`

| Option | Description |
|--------|-------------|
| `-Pn` | Assume hosts UP |
| `-A` | Detection OS + versions + scripts |
| `--script smb-os-discovery` | Extraction hostname/OS via SMB |

**Extraction** :
- Hostname (nmap, DNS, SMB)
- OS (premier osmatch)
- Services (port, protocol, service, version)

### Format de sortie JSON

```json
{
  "configuration": {
    "ip_cidr": "192.168.30.0/24",
    "gateway": "192.168.30.1",
    "dns": "192.168.30.254"
  },
  "vlan_scan": {
    "active_hosts": [
      {"ip": "192.168.30.10", "mac": "00:0c:29:xx:xx:xx", "status": "up"}
    ]
  },
  "subnet_scans": [
    {"target_cidr": "192.168.31.0/24", "active_hosts": [...]}
  ],
  "service_scan": {
    "results": [
      {
        "ip": "192.168.30.10",
        "hostname": "DC01",
        "os": "Windows Server 2019",
        "services": [
          {"port": 445, "service": "microsoft-ds", "product": "Windows"}
        ]
      }
    ]
  }
}
```

---

## 2. Collecte BloodHound

**Outil** : `bloodhound-python`

### Objectif

Collecter les donnees Active Directory :
- Objets : Users, Groups, Computers, OUs, Domains, GPOs
- Relations : memberOf, AdminTo, CanRDP, CanPSRemote
- ACL : Tous les ACE (GenericAll, WriteDACL, ForceChangePassword, ...)
- Sessions : HasSession, LoggedOn

### Flux de collecte

```
┌──────────────────────────────────────────────────────────────────┐
│                    AUTHENTIFICATION LDAP                         │
│              (credentials utilisateur AD)                        │
└──────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│                    ENUMERATION OBJETS                            │
│         (requetes LDAP sur le Domain Controller)                 │
└──────────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
        ▼                     ▼                     ▼
   ┌─────────┐          ┌─────────┐          ┌─────────┐
   │  Users  │          │ Groups  │          │Computers│
   └─────────┘          └─────────┘          └─────────┘
        │                     │                     │
        └─────────────────────┼─────────────────────┘
                              │
┌──────────────────────────────────────────────────────────────────┐
│                    ENUMERATION ACL                               │
│            (lecture des DACL sur chaque objet)                   │
└──────────────────────────────────────────────────────────────────┘
                              │
                              ▼
                    ACE avec RightName :
                    - GenericAll
                    - WriteDacl
                    - WriteOwner
                    - ForceChangePassword
                    - AddMember
                    - ...
                              │
┌──────────────────────────────────────────────────────────────────┐
│              ENUMERATION SESSIONS (optionnel)                    │
│          (connexion SMB/RPC sur les machines)                    │
└──────────────────────────────────────────────────────────────────┘
                              │
                              ▼
                    HasSession, LoggedOn
                              │
┌──────────────────────────────────────────────────────────────────┐
│                      EXPORT JSON                                 │
└──────────────────────────────────────────────────────────────────┘
                              │
                              ▼
              users.json, groups.json, computers.json, ...
```

### Commande

```bash
bloodhound-python -u user@domain.local -p password \
    -d domain.local -ns 192.168.30.254 -c All --zip
```

| Option | Description |
|--------|-------------|
| `-c All` | Collecte complete (ACL + Sessions + LocalAdmin) |
| `-c DCOnly` | Uniquement ACL (rapide) |
| `--zip` | Compression des resultats |

### Donnees collectees

| Fichier | Contenu |
|---------|---------|
| `users.json` | Utilisateurs (SID, memberOf, properties) |
| `groups.json` | Groupes (members, SID) |
| `computers.json` | Machines (dNSHostName, OS, SID) |
| `domains.json` | Domaines (trusts, properties) |
| `ous.json` | Unites organisationnelles |
| `gpos.json` | Group Policy Objects |

### Notion : IsInherited

- `IsInherited: false` : ACE definie directement sur l'objet
- `IsInherited: true` : ACE heritee d'un parent (OU/Container)

**Important** : Les ACE heritees restent exploitables (ex: ReadLAPSPassword)

---

## 3. Mapping hostname -> IP

**Script** : `enrich_network_mapping.py`

### Objectif

Creer un mapping fiable **Computer AD -> IP reseau** en interrogeant le DC.

### Pourquoi un script separe ?

| Probleme | Solution |
|----------|----------|
| Reverse DNS peu fiable | Forward DNS via DC |
| NetBIOS non authentifie | Credentials du domaine |
| Machines non scannees | Tous les Computer AD |

### Flux algorithmique

```
┌──────────────────────────────────────────────────────────────────┐
│              CHARGEMENT BLOODHOUND                               │
│            (computers.json)                                      │
└──────────────────────────────────────────────────────────────────┘
                              │
                              ▼
              Pour chaque Computer AD :
              - Extraction dNSHostName
              - Extraction name (fallback)
                              │
┌──────────────────────────────────────────────────────────────────┐
│              RESOLUTION DNS VIA DC                               │
│            (dnspython -> DC)                                     │
└──────────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
        ▼                     ▼                     ▼
   Resolution OK       Timeout/NXDOMAIN      Fallback systeme
        │                     │                     │
        └─────────────────────┼─────────────────────┘
                              │
┌──────────────────────────────────────────────────────────────────┐
│              GENERATION MAPPING                                  │
│            (hostname_mapping.json)                               │
└──────────────────────────────────────────────────────────────────┘
```

### Resolution DNS

**Strategie 1 : dnspython (recommande)**

```python
resolver = dns.resolver.Resolver()
resolver.nameservers = [dc_ip]
answers = resolver.resolve(hostname, 'A')
ips = [str(rdata.address) for rdata in answers]
```

**Strategie 2 : Fallback systeme**

```python
result = socket.getaddrinfo(hostname, None, socket.AF_INET)
ips = [r[4][0] for r in result]
```

### Format de sortie

```json
{
  "metadata": {
    "domain": "domain.local",
    "dc_ip": "192.168.30.254",
    "total_computers": 150,
    "resolved_count": 142,
    "resolution_rate": "94%"
  },
  "mapping": {
    "dc01.domain.local": {
      "hostname": "DC01.domain.local",
      "ips": ["192.168.30.10"],
      "objectid": "S-1-5-21-...-1001",
      "properties": {
        "dnshostname": "DC01.domain.local",
        "operatingsystem": "Windows Server 2019"
      }
    }
  }
}
```

---

## 4. Classification Tier et generation des graphes

**Script** : `graph_builder.py`

### Objectif

Construire un graphe JSON avec classification Tier (0/1/2/3), chemins d'attaque
vers les cibles, et noeuds/edges exploitables par l'UI.

---

### Pipeline de classification (v5)

```
  Chargement BloodHound JSON + validation
                    │
                    ▼
  ┌─────────────────────────────────────┐
  │     TIER 0 : DETERMINISTE           │
  │  1. Seed    (RID, DC, KRBTGT,       │
  │              Cert Publishers,       │
  │              DCSync)                 │
  │  2. Closure (GenericAll, WriteDacl,  │
  │              AddMember...)           │
  │  3. Indirect(TOUS les accès DC :    │
  │              AdminTo, LAPS, GPO,    │
  │              CanRDP, CanPSRemote,   │
  │              DCOM)                   │
  │  4. Members (membres des groupes    │
  │              Tier 0)                 │
  └─────────────────┬───────────────────┘
                    │
            Tier 0 FINAL complet
                    │
                    ▼
  ┌─────────────────────────────────────┐
  │  5. DISTANCE BFS (depuis Tier 0)    │
  │     Tous les edges (MemberOf, ACE,  │
  │     AdminTo, CanRDP, CanPSRemote,   │
  │     DCOM, Sessions)                  │
  │     1-2 hops → Tier 1               │
  │     3-5 hops → Tier 2               │
  │     6+ hops/unreachable → Tier 3    │
  └─────────────────┬───────────────────┘
                    │
                    ▼
  Selection chemins (mode 0/1/2/3)
  Computers = noeuds normaux traversables
                    │
                    ▼
  { nodes, edges, paths, tier_classification }
```

**Note importante** : Phase 3 (INDIRECT) inclut maintenant TOUS les accès DC (AdminTo, LAPS, GPO, CanRDP, CanPSRemote, DCOM) pour compléter le Tier 0 AVANT le calcul BFS (Phase 5), garantissant que les distances sont calculées depuis le Tier 0 complet et définitif.

---

### Jeu d'edges unifié

Le graphe utilise un seul jeu d'edges pour le BFS de classification et les chemins visuels :

| Edges inclus | Description |
|--------------|-------------|
| `MemberOf` | Appartenance aux groupes |
| `ACE` | Droits ACL (`ALL_PRIVILEGE_RIGHTS`) |
| `AdminTo` | Admin local sur machine |
| `CanRDP`, `CanPSRemote`, `DCOM` | Accès distant aux machines |
| `HasSession`, `LoggedOn` | Sessions actives |

**Principe** : Les Computers sont des noeuds normaux, traversables. L'héritage des droits du compte machine (groupes, ACE) est pris en compte dans les chemins d'attaque.

---

### Phase 1 : SEED (Tier 0 statique)

Identification par criteres techniques. **Fonction** : `identify_tier0_seed()`

**SIDs Well-Known (RID suffixes)** :

| RID | Objet |
|-----|-------|
| `-500` | Administrator (builtin) |
| `-502` | KRBTGT (Golden Ticket) |
| `-512` | Domain Admins |
| `-516` | Domain Controllers (groupe) |
| `-517` | Cert Publishers (PKI - attaques ESC) |
| `-518` | Schema Admins |
| `-519` | Enterprise Admins |
| `-544` | Administrators (BUILTIN) |
| `-548` | Account Operators |
| `-549` | Server Operators |
| `-550` | Print Operators |
| `-551` | Backup Operators |

Note : Les groupes BUILTIN (`S-1-5-32-*`) n'ont pas de `objectsid` dans BloodHound.
Le SID est extrait depuis l'`ObjectIdentifier` (format `DOMAIN.HTB-S-1-5-32-551`).

**Autres criteres** :

| Critere | Detection |
|---------|-----------|
| Domain objects | `type == "Domain"` |
| Domain Controllers | `userAccountControl & 0x2000` OU `PrimaryGroupSID` finissant par `-516` |
| AdminSDHolder | DN contient `CN=AdminSDHolder` |
| DCSync | Droit DCSync/GetChanges/GetChangesAll/GetChangesInFilteredSet sur Domain |

---

### Phase 2 : CLOSURE (Tier 0 herite)

Si un principal a un droit de controle direct sur un objet Tier 0, il devient Tier 0.
Algorithme fixpoint (max 10 iterations). **Fonction** : `expand_tier0_closure()`

**Droits pris en compte** (`TIER0_CLOSURE_RIGHTS`) :

| Droit | Justification |
|-------|---------------|
| `GenericAll` | Controle total |
| `WriteDacl` | Peut se donner GenericAll |
| `WriteOwner` | Owner → WriteDacl → GenericAll |
| `Owns` | Ownership = controle total |
| `AddMember` / `WriteMember` | Sur groupe Tier 0 = devenir membre |
| `ForceChangePassword` / `ResetPassword` | Takeover immediat du compte |
| `AddKeyCredentialLink` / `WriteKeyCredentialLink` | Shadow Credentials |

---

### Phase 3 : INDIRECT - TOUS les accès DC

TOUS les droits et accès sur les Domain Controllers donnant un contrôle indirect du domaine.
**Fonction** : `expand_tier0_indirect()`

| Droit | Cible | Justification |
|-------|-------|---------------|
| `AdminTo` | DC | Peut dumper NTDS.dit |
| `ReadLAPSPassword` | DC ou OU contenant DC | Obtient le password admin local |
| `WriteGPO` / `EditGPO` / `GenericAll` / `WriteDacl` / `WriteOwner` | GPO liée à OU des DCs | Déploie scripts sur les DCs |
| `CanRDP` | DC | Accès bureau à distance au DC |
| `CanPSRemote` | DC | Accès PowerShell Remoting au DC |
| `DCOM` | DC | Accès DCOM au DC |

**Important** : Cette phase unifie TOUS les accès DC (directs et distants) pour compléter le Tier 0 AVANT le calcul BFS (Phase 5), garantissant que les distances sont calculées depuis le Tier 0 complet et définitif.

---

### Phase 4 : MEMBERS

Membres directs des groupes Tier 0 → Tier 0.
**Fonction** : `expand_tier0_members()`

---

---

### Phase 5 : BFS DISTANCE

Distance BFS depuis chaque noeud vers le Tier 0 le plus proche **FINAL** (après Phase 3 INDIRECT).
**Fonction** : `classify_objects_by_tier()`

**Tous les edges sont utilisés** :

| Kind | Description |
|------|-------------|
| `ace` | Droits ACL (`ALL_PRIVILEGE_RIGHTS`) |
| `memberOf` | Appartenance aux groupes (+ PrimaryGroupSID) |
| `local_admin` | AdminTo |
| `rdp` | CanRDP |
| `psremote` | CanPSRemote |
| `dcom` | DCOM |
| `session` | HasSession, LoggedOn |

| Distance | Tier |
|----------|------|
| 1-2 hops | Tier 1 | Standard: chemins vers Tier 1 |
| 3-7 hops | Tier 2 | Standard: chemins vers Tier 2 |
| 8+ hops ou unreachable | Tier 3 | **Ego-graph**: toutes relations depuis start_node |


**Note Mode 3 (Tier 3)** : Au lieu de chercher des chemins vers les objets classifiés Tier 3, Mode 3 effectue une **exploration ego-graph** depuis `start_node` pour découvrir TOUTES ses relations (groupes, objets contrôlés, sessions, etc.) qui ne sont pas déjà dans Tier 0/1/2. Cela permet de visualiser l'environnement complet du user même s'il n'a pas de chemin vers le Tier 0.

---

### Droits pour la construction du graphe

```python
ALL_PRIVILEGE_RIGHTS = {
    "DCSync", "GetChanges", "GetChangesAll", "GetChangesInFilteredSet",
    "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns",
    "AllExtendedRights", "ForceChangePassword", "ResetPassword",
    "AddMember", "WriteMember",
    "ReadLAPSPassword", "ReadGMSAPassword",
    "AddKeyCredentialLink", "WriteKeyCredentialLink",
    "WriteGPO", "EditGPO",
}
```

---

### Modes de sortie

| Mode | Cible | Limite | Description |
|------|-------|--------|-------------|
| 0 | Tier 0 | Aucune | Tous les chemins vers Domain/DCs/DA/Cert Publishers |
| 1 | Tier 1 | 30 | 1-2 hops depuis Tier 0 |
| 2 | Tier 2 | 30 | 3-5 hops depuis Tier 0 |
| 3 | Tier 3 | 40 | 6+ hops depuis Tier 0 (inclut unreachable) |

---

### Tableau recapitulatif des droits (v5)

| Droit | Tier 0 (closure) | Tier 0 (indirect DC) | BFS distance | Chemins visuels |
|-------|-------------------|---------------------|-------------|-----------------|
| GenericAll | oui | oui (GPO DC) | oui | oui |
| WriteDacl | oui | oui (GPO DC) | oui | oui |
| WriteOwner | oui | oui (GPO DC) | oui | oui |
| Owns | oui | - | oui | oui |
| AddMember / WriteMember | oui | - | oui | oui |
| ForceChangePassword / ResetPassword | oui | - | oui | oui |
| AddKeyCredentialLink | oui | - | oui | oui |
| DCSync / GetChanges* | oui (Domain) | - | oui | oui |
| AdminTo | - | oui (DC) | oui | oui |
| ReadLAPSPassword | - | oui (DC/OU) | oui | oui |
| ReadGMSAPassword | - | - | oui | oui |
| WriteGPO / EditGPO | - | oui (GPO DC) | oui | oui |
| GenericWrite | - | - | oui | oui |
| AllExtendedRights | - | - | oui | oui |
| CanRDP / CanPSRemote / DCOM | - | Tier 0 (Phase 6) | **oui** | oui |
| HasSession / LoggedOn | - | - | **oui** | oui |
| ChangePassword | - | - | non | non |

**Note v5** : Tous les edges (y compris CanRDP, CanPSRemote, DCOM, HasSession, LoggedOn) sont maintenant utilisés dans le BFS de distance. Les Computers sont des noeuds normaux, traversables.

---

### Format de sortie JSON

```json
{
  "mode": "0",
  "view": "tier0",
  "tier": 0,
  "tier_name": "Tier 0",
  "tier_classification": {
    "tier0_count": 15,
    "tier1_count": 3,
    "tier2_count": 0,
    "tier3_count": 71
  },
  "nodes": [
    {
      "id": "S-1-5-21-...",
      "type": "User",
      "name": "user@domain.local",
      "tier": 0,
      "is_target": false
    }
  ],
  "edges": [
    {
      "src": "S-1-5-21-...",
      "dst": "S-1-5-21-...",
      "kind": "psremote",
      "right": "CanPSRemote",
      "confidence": "observed"
    }
  ],
  "paths": [
    {
      "goal": "computer",
      "target_name": "DC01.DOMAIN.LOCAL",
      "target_id": "S-1-5-21-...",
      "length": 1,
      "tier": 0,
      "nodes": ["S-1-5-21-...-user", "S-1-5-21-...-1000"]
    }
  ]
}
```

---

## 5. Visualisation (fusion reseau/identite)

**Fichier** : `cartographie.html`

### Objectif

Fusionner les deux dimensions dans une interface unique :
- **Reseau** : IP, MAC, ports, services (haut)
- **Identite** : Users, Groups, ACE (bas)

### Architecture de la fusion

```
┌─────────────────────────────────────────────────────────────────┐
│                    PARTIE RESEAU (haut)                          │
│            Routeurs, Serveurs, Postes (IP/MAC)                  │
│                                                                  │
│   [Routeur] ──── [DC01: 10.0.0.5] ──── [Server]                 │
│                        │                                         │
│                        │ ← Pont (si chemin identite              │
│                        │    utilise cette machine)               │
└────────────────────────┼─────────────────────────────────────────┘
                         │
            ╔════════════╧═══════════════╗
            ║    BRIDGE (si applicable)  ║
            ║   HasSession / AdminTo     ║
            ╚════════════╤═══════════════╝
                         │
┌────────────────────────┼─────────────────────────────────────────┐
│                        │                                          │
│   [User: alice] ──[AdminTo]──→ [DC01]                            │
│        │                                                          │
│   [MemberOf]                                                     │
│        │                                                          │
│   [Group: Admins] ───────→ [Domain]                              │
│                                                                   │
│                 PARTIE IDENTITE (bas)                             │
│          Users, Groups, ACE, Permissions                         │
└───────────────────────────────────────────────────────────────────┘
```

### Algorithme de mapping (anti-doublon)

**Probleme** : Eviter les doublons visuels
- Reseau decouvre : `10.0.0.5` (hostname: `DC01.htb.local`)
- BloodHound collecte : Computer `DC01.HTB.LOCAL`

**Solution** :

```javascript
for (computer of identity_data.nodes) {
    if (computer.type == "Computer") {
        hostname = extract_hostname(computer)
        fqdn = computer.dNSHostName

        for (host of network_data.hosts) {
            if (matches(host.hostname, hostname, fqdn)) {
                // FUSION : Reutiliser le node physique
                computer.id = host.id
                computer.merged = true
                break
            }
        }
    }
}
```

**Regles de matching** :
- Exact match : `DC01.htb.local` == `DC01.htb.local`
- Hostname match : `DC01` in `DC01.htb.local`
- Case-insensitive : `dc01` == `DC01`

### Types de ponts (bridges)

| Type | Description |
|------|-------------|
| `HasSession` | Utilisateur connecte sur machine |
| `LoggedOn` | Utilisateur actuellement connecte |
| `AdminTo` | Admin local sur machine |
| `CanRDP` | Acces RDP sur machine |
| `CanPSRemote` | Acces PowerShell Remoting |

### Conventions visuelles

**Couleurs noeuds (Tier)** :
| Tier | Couleur | Signification |
|------|---------|---------------|
| 0 | Rouge | Critique (controle domaine) |
| 1 | Orange | Eleve (hauts privileges) |
| 2 | Jaune | Moyen (infrastructure) |
| 3 | Gris | Faible (isole) |

**Styles edges** :
| Type | Style |
|------|-------|
| Reseau | Trait plein gris |
| Identite | Trait plein colore |
| Bridge | Trait pointille noir |

---

## 6. Pipeline complet

**Script** : `run_full_scan.py`

### Flux d'execution

```
┌──────────────────────────────────────────────────────────────────┐
│                    run_full_scan.py                               │
└──────────────────────────────────────────────────────────────────┘
                              │
                    Verification dependances
                    (nmap, bloodhound, dnspython)
                              │
┌──────────────────────────────────────────────────────────────────┐
│              ETAPE 1 : SCAN RESEAU                               │
│            (global_network_scan_*.py)                            │
└──────────────────────────────────────────────────────────────────┘
                              │
                    Detection auto Classe C vs A/B
                              │
                    Execution scan (sudo requis)
                              │
                    → network_scan.json
                              │
┌──────────────────────────────────────────────────────────────────┐
│              ETAPE 2 : COLLECTE BLOODHOUND                       │
│            (bloodhound-python)                                   │
└──────────────────────────────────────────────────────────────────┘
                              │
                    Authentification AD
                              │
                    Collecte + extraction ZIP
                              │
                    → bloodhound_data/
                              │
┌──────────────────────────────────────────────────────────────────┐
│              ETAPE 3 : ENRICHISSEMENT                            │
│            (enrich_network_mapping.py)                           │
└──────────────────────────────────────────────────────────────────┘
                              │
                    Resolution DNS via DC
                              │
                    → hostname_mapping.json
                              │
┌──────────────────────────────────────────────────────────────────┐
│              ETAPE 4 : GENERATION GRAPHES                        │
│            (run_all_modes.py)                                    │
└──────────────────────────────────────────────────────────────────┘
                              │
                    Classification Tier
                              │
                    Calcul chemins
                              │
                    → graph_tier0.json
                    → graph_tier1.json
                    → graph_tier2.json
                    → graph_tier3.json
```

### Gestion des erreurs

| Etape | Echec | Action |
|-------|-------|--------|
| Scan reseau | Warning | Continue |
| BloodHound | **Arret** | Donnees AD requises |
| Enrichissement | Warning | Continue |
| Graphes | Erreur | Fin pipeline |

---

## 7. Limitations connues

| Limitation | Impact | Solution |
|------------|--------|----------|
| Scan limite au /24 | Decouverte partielle grands reseaux | Relancer avec CIDR specifique |
| Pas de detection VLAN | VLANs isoles non decouverts | Scan depuis chaque VLAN |
| DC-only pour machines T0 | Exchange/ADFS/PKI non detectes | Whitelist configurable (futur) |
| GenericWrite/AllExtendedRights hors Tier 0 | Faux negatifs possibles | Analyse attribut-aware (futur) |




