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

Construire un graphe JSON avec :
- Classification Tier scientifique (0/1/2/3)
- Chemins d'attaque vers les cibles
- Noeuds et edges exploitables par l'UI

### Principes fondamentaux

```
Tier 0 = Controle IMMEDIAT et DETERMINISTE du domaine
       - Pas de conditions (ex: session active requise)
       - Pas d'exploitation complexe
       - Resultat garanti si le droit est exerce

Sessions/CanRDP = OPPORTUNITE, pas Tier strict
       - Necessite qu'un utilisateur soit connecte
       - Non deterministe
```

### Flux algorithmique global

```
┌──────────────────────────────────────────────────────────────────┐
│              PHASE 1 : CHARGEMENT DONNEES                        │
│            (parsing BloodHound JSON)                             │
└──────────────────────────────────────────────────────────────────┘
                              │
                              ▼
              Index par objectID :
              - nodes_by_id[objectID] = node
              - edges par type (memberOf, ACE, AdminTo)
                              │
┌──────────────────────────────────────────────────────────────────┐
│              PHASE 2 : CLASSIFICATION TIER 0                     │
│    (5 sous-etapes : Seed → Closure → Indirect → Members)        │
└──────────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              │               │               │
              ▼               ▼               ▼
         2.1 Seed       2.2 Closure     2.3 Indirect
         (statique)     (ACL direct)    (via DC)
              │               │               │
              └───────┬───────┴───────┬───────┘
                      │               │
                      ▼               ▼
                 2.4 Members    2.5 Final Tier 0
              │
┌──────────────────────────────────────────────────────────────────┐
│              PHASE 3 : CLASSIFICATION TIER 1/2/3                 │
│            (calcul distance BFS)                                 │
└──────────────────────────────────────────────────────────────────┘
                              │
                              ▼
              BFS depuis Tier 0 :
              - Tier 1 : 1-2 hops
              - Tier 2 : 3-5 hops
              - Tier 3 : 6+ hops ou unreachable
                              │
┌──────────────────────────────────────────────────────────────────┐
│              PHASE 4 : SELECTION CHEMINS                         │
│            (selon mode 0/1/2/3)                                  │
└──────────────────────────────────────────────────────────────────┘
                              │
                              ▼
              { nodes, edges, paths, tier_classification }
```

---

### PHASE 2 : Classification Tier 0 (detail)

#### Etape 2.1 : SEED statique

Identification par criteres techniques (SIDs well-known, flags, patterns) :

**SIDs Well-Known (RID suffixes)** :

| RID | Objet | Justification |
|-----|-------|---------------|
| `-500` | Administrator | Compte admin builtin, toujours Tier 0 |
| `-502` | KRBTGT | Cle de chiffrement Kerberos, compromis = Golden Ticket |
| `-512` | Domain Admins | Groupe admin du domaine |
| `-516` | Domain Controllers | Groupe des DCs |
| `-518` | Schema Admins | Peut modifier le schema AD |
| `-519` | Enterprise Admins | Admin de la foret entiere |
| `-544` | Administrators (BUILTIN) | Admins locaux sur les DCs |
| `-548` | Account Operators | Peut creer/modifier des comptes |
| `-549` | Server Operators | Acces aux serveurs membres |
| `-550` | Print Operators | Historiquement exploitable |
| `-551` | Backup Operators | Peut lire tous les fichiers |

**Autres criteres** :

| Critere | Detection | Justification |
|---------|-----------|---------------|
| Domain objects | `type == "Domain"` | Objet racine du domaine |
| Domain Controllers | `userAccountControl & 0x2000` | Flag SERVER_TRUST_ACCOUNT |
| AdminSDHolder | DN contient `CN=AdminSDHolder` | Protege les objets critiques |
| DCSync rights | Droit DCSync sur Domain | Peut repliquer tous les secrets |

##### DROITS DCSYNC (Tier 0 si sur Domain)

| Droit | Effet | Tier 0 ? | Justification |
|-------|-------|----------|---------------|
| `DCSync` | Repliquer les secrets AD | **OUI** | Permet d'extraire tous les hashes NTLM |
| `GetChanges` | DS-Replication-Get-Changes | **OUI** | Necessaire pour DCSync |
| `GetChangesAll` | DS-Replication-Get-Changes-All | **OUI** | Permet replication complete |
| `GetChangesInFilteredSet` | Replication filtree | **OUI** | Variante de DCSync |

**Fonction** : `identify_tier0_seed()`

---

#### Etape 2.2 : CLOSURE ACL (extension iterative)

**Principe** : Si un principal a un droit de CONTROLE DIRECT sur un objet Tier 0, ce principal devient Tier 0.

**Algorithme** : Fixpoint (repete jusqu'a stabilisation, max 10 iterations)

##### DROITS PRIS EN COMPTE (TIER0_CLOSURE_RIGHTS)

| Droit | Effet | Tier 0 ? | Justification |
|-------|-------|----------|---------------|
| `GenericAll` | Controle total sur l'objet | **OUI** | Peut tout faire : reset password, modifier membres, etc. |
| `WriteDacl` | Modifier les ACL de l'objet | **OUI** | Peut se donner GenericAll |
| `WriteOwner` | Changer le proprietaire | **OUI** | Owner peut modifier DACL → WriteDacl → GenericAll |
| `Owns` | Est proprietaire de l'objet | **OUI** | Ownership = controle total |
| `AddMember` | Ajouter membre a un groupe | **OUI** | Sur groupe Tier 0 = devenir membre = Tier 0 |
| `WriteMember` | Alias de AddMember | **OUI** | Identique a AddMember |
| `ForceChangePassword` | Reset password sans connaitre l'ancien | **OUI** | Takeover immediat du compte |
| `ResetPassword` | Alias de ForceChangePassword | **OUI** | Identique |
| `AddKeyCredentialLink` | Ajouter Shadow Credentials | **OUI** | Permet authentification sans password |
| `WriteKeyCredentialLink` | Alias | **OUI** | Identique |

**Fonction** : `expand_tier0_closure()`

---

#### Etape 2.3 : INDIRECT via DC

**Principe** : Certains droits sur les Domain Controllers permettent un controle indirect du domaine.

##### DROITS PRIS EN COMPTE (sur DC uniquement)

| Droit | Cible | Tier 0 ? | Justification |
|-------|-------|----------|---------------|
| `AdminTo` | DC | **OUI** | Admin local sur DC = peut dumper NTDS.dit |
| `ReadLAPSPassword` | DC | **OUI** | Obtient le password admin local du DC |
| `ReadLAPSPassword` | OU contenant DC | **OUI** | LAPS herite sur les objets enfants |

##### DROITS SUR GPO LIEE AUX DC

| Droit | Cible | Tier 0 ? | Justification |
|-------|-------|----------|---------------|
| `WriteGPO` | GPO liee a OU des DCs | **OUI** | Peut deployer scripts/settings sur les DCs |
| `EditGPO` | GPO liee a OU des DCs | **OUI** | Identique |
| `GenericAll` | GPO liee a OU des DCs | **OUI** | Controle total de la GPO |
| `WriteDacl` | GPO liee a OU des DCs | **OUI** | Peut se donner WriteGPO |
| `WriteOwner` | GPO liee a OU des DCs | **OUI** | Peut devenir owner |

**Fonction** : `expand_tier0_indirect()`

---

#### Etape 2.4 : MEMBRES des groupes Tier 0

**Principe** : Si un groupe est Tier 0, tous ses membres directs sont Tier 0.

**Justification** : Etre membre de Domain Admins = ETRE Domain Admin

**Fonction** : `expand_tier0_members()`

---

### DROITS EXCLUS (non pris en compte pour Tier 0)

#### Exclus de la CLOSURE (necessitent analyse d'attribut)

| Droit | Raison d'exclusion | Impact |
|-------|-------------------|--------|
| `GenericWrite` | Depend de l'attribut modifie | Faux positifs si l'attribut n'est pas exploitable |
| `AllExtendedRights` | Inclut trop de droits heterogenes | ReadLAPSPassword mais aussi des droits non critiques |
| `WriteProperty` | Attribute-aware requis | Doit savoir QUEL attribut est modifiable |
| `WriteSPN` | Kerberoasting possible mais pas controle direct | Opportunite, pas Tier 0 |
| `WriteAllowedToAct` | RBCD possible mais necessite config | Exploitation complexe |

#### Exclus car NON DETERMINISTES

| Droit | Raison d'exclusion | Impact |
|-------|-------------------|--------|
| `ChangePassword` | Necessite l'ancien mot de passe | Non exploitable sans credentials |

---

### DROITS D'OPPORTUNITE (affectent distance, pas Tier strict)

Ces droits sont utilises pour calculer la DISTANCE dans le graphe mais ne propagent PAS automatiquement au Tier 0.

#### Acces machine

| Droit | Effet | Tier 0 direct ? | Utilisation |
|-------|-------|-----------------|-------------|
| `AdminTo` | Admin local sur machine | **NON** (sauf DC) | Affecte distance, Tier 0 seulement si cible = DC |
| `CanRDP` | Acces RDP | **NON** | Opportunite de lateral movement |
| `CanPSRemote` | PowerShell Remoting | **NON** | Opportunite de lateral movement |
| `ExecuteDCOM` | Execution DCOM | **NON** | Opportunite de lateral movement |
| `DCOM` | Alias ExecuteDCOM | **NON** | Identique |

#### Sessions (purement opportunistes)

| Droit | Effet | Tier 0 direct ? | Utilisation |
|-------|-------|-----------------|-------------|
| `HasSession` | Utilisateur a une session sur machine | **NON** | Opportunite de credential theft |
| `LoggedOn` | Utilisateur actuellement connecte | **NON** | Opportunite de credential theft |

**Justification** : Ces droits necessitent qu'un utilisateur privilegie soit connecte. Ce n'est pas deterministe.

---

### DROITS POUR LA CONSTRUCTION DU GRAPHE

Ces droits sont utilises pour creer les edges du graphe (chemins d'attaque) :

```python
ALL_PRIVILEGE_RIGHTS = {
    # DCSync
    "DCSync", "GetChanges", "GetChangesAll", "GetChangesInFilteredSet",
    # Controle direct
    "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns",
    "AllExtendedRights", "ForceChangePassword", "ResetPassword",
    "AddMember", "WriteMember",
    # Credentials
    "ReadLAPSPassword", "ReadGMSAPassword",
    # Shadow Credentials
    "AddKeyCredentialLink", "WriteKeyCredentialLink",
    # GPO
    "WriteGPO", "EditGPO",
}
```

---

### PHASE 3 : Classification Tier 1/2/3

**Algorithme** : BFS (Breadth-First Search) depuis chaque noeud VERS les noeuds Tier 0

Pour chaque noeud non-Tier 0, on calcule la distance minimale vers le Tier 0 le plus proche en suivant les edges du graphe.

**Types d'edges utilises pour le BFS** :

| Kind | Right | Description |
|------|-------|-------------|
| `ace` | Droits ACL (ALL_PRIVILEGE_RIGHTS) | GenericAll, WriteDacl, DCSync, etc. |
| `memberOf` | MemberOf | Appartenance aux groupes |
| `local_admin` | AdminTo | Admin local sur machine |
| `rdp` | CanRDP | Acces RDP |
| `psremote` | CanPSRemote | Acces PowerShell Remote |
| `dcom` | DCOM | Acces DCOM |

```python
# Pseudo-code
def shortest_distance_to_tier0(node_id):
    if node_id in tier0_nodes:
        return 0

    visited = {node_id}
    queue = deque([(node_id, 0)])

    while queue:
        current, dist = queue.popleft()

        if dist >= max_distance:  # max_distance = 10
            continue

        for neighbor in get_neighbors(current):
            if neighbor in tier0_nodes:
                return dist + 1  # Trouve le Tier 0 le plus proche

            if neighbor not in visited:
                visited.add(neighbor)
                queue.append((neighbor, dist + 1))

    return 999  # Unreachable

# Classification basee sur la distance
for node in all_nodes:
    distance = shortest_distance_to_tier0(node)
    if distance <= 2:
        tier = 1      # Tier 1 : 1-2 hops
    elif distance <= 5:
        tier = 2      # Tier 2 : 3-5 hops
    else:
        tier = 3      # Tier 3 : 6+ hops ou unreachable
```

**Noeuds unreachable** : Tier 3 par defaut (distance = 999)

**Fonction** : `classify_objects_by_tier()`

---

### PHASE 4 : Selection des chemins

| Mode | Cible | Limite | Justification |
|------|-------|--------|---------------|
| 0 | Tier 0 | **Aucune** | Chaque chemin = compromission potentielle |
| 1 | Tier 1 | 30 | Hauts privileges, vue significative |
| 2 | Tier 2 | 30 | Infrastructure, vue large |
| 3 | Tier 3 | 40 | Objets isoles, vue exhaustive |

---

### RESUME : Tableau complet des droits

| Droit | Tier 0 direct | Tier 0 indirect (DC) | Affecte distance | Dans graphe |
|-------|---------------|---------------------|------------------|-------------|
| GenericAll | ✅ | ✅ (GPO DC) | ✅ | ✅ |
| WriteDacl | ✅ | ✅ (GPO DC) | ✅ | ✅ |
| WriteOwner | ✅ | ✅ (GPO DC) | ✅ | ✅ |
| Owns | ✅ | - | ✅ | ✅ |
| AddMember | ✅ | - | ✅ | ✅ |
| WriteMember | ✅ | - | ✅ | ✅ |
| ForceChangePassword | ✅ | - | ✅ | ✅ |
| ResetPassword | ✅ | - | ✅ | ✅ |
| AddKeyCredentialLink | ✅ | - | ✅ | ✅ |
| WriteKeyCredentialLink | ✅ | - | ✅ | ✅ |
| DCSync | ✅ (Domain) | - | ✅ | ✅ |
| GetChanges | ✅ (Domain) | - | ✅ | ✅ |
| GetChangesAll | ✅ (Domain) | - | ✅ | ✅ |
| GetChangesInFilteredSet | ✅ (Domain) | - | ✅ | ✅ |
| AdminTo | ❌ | ✅ (DC) | ✅ | ✅ |
| ReadLAPSPassword | ❌ | ✅ (DC/OU DC) | ✅ | ✅ |
| ReadGMSAPassword | ❌ | ❌ | ✅ | ✅ |
| WriteGPO | ❌ | ✅ (GPO DC) | ✅ | ✅ |
| EditGPO | ❌ | ✅ (GPO DC) | ✅ | ✅ |
| GenericWrite | ❌ | ❌ | ✅ | ✅ |
| AllExtendedRights | ❌ | ❌ | ✅ | ✅ |
| CanRDP | ❌ | ❌ | ✅ | ✅ |
| CanPSRemote | ❌ | ❌ | ✅ | ✅ |
| DCOM | ❌ | ❌ | ✅ | ✅ |
| HasSession | ❌ | ❌ | ✅ | ❌ (optionnel) |
| LoggedOn | ❌ | ❌ | ✅ | ❌ (optionnel) |
| ChangePassword | ❌ | ❌ | ❌ | ❌ |

### Format de sortie JSON

```json
{
  "mode": "0",
  "tier": 0,
  "tier_name": "Tier 0",
  "tier_classification": {
    "tier0_count": 15,
    "tier1_count": 143,
    "tier2_count": 892,
    "tier3_count": 3421
  },
  "paths": [
    {
      "goal": "domain",
      "target_name": "DOMAIN.LOCAL",
      "target_id": "S-1-5-21-...",
      "length": 2,
      "tier": 0,
      "is_shortest": true,
      "nodes": ["S-1-5-21-...-user", "S-1-5-21-...-512", "S-1-5-21-..."]
    }
  ],
  "nodes": [
    {
      "id": "S-1-5-21-...",
      "type": "User",
      "name": "user@domain.local",
      "tier": 2,
      "is_target": false
    }
  ],
  "edges": [
    {
      "source": "S-1-5-21-...",
      "target": "S-1-5-21-...",
      "label": "MemberOf",
      "kind": "ad"
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
| AllExtendedRights ignore | Faux negatifs possibles | Analyse manuelle |
| GenericWrite ignore | Faux negatifs possibles | Analyse attribut-aware (futur) |




