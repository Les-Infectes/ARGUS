# Algorithme de Découverte Réseau — ARGUS

## Table des matières

1. [Contexte et objectifs](#1-contexte-et-objectifs)
2. [Les deux modes d'accès](#2-les-deux-modes-daccès)
3. [Mode Direct — découverte réseau complète](#3-mode-direct--découverte-réseau-complète)
4. [Mode Direct — machine ciblée (single-host)](#4-mode-direct--machine-ciblée-single-host)
5. [Mode Indirect (Pivot) — scan via SOCKS](#5-mode-indirect-pivot--scan-via-socks)
6. [Résumé des modes et flags CLI](#6-résumé-des-modes-et-flags-cli)
7. [Limites et cas particuliers](#7-limites-et-cas-particuliers)

---

## 1. Contexte et objectifs

### Contexte

BloodHound collecte les données du LDAP Active Directory : utilisateurs, groupes, GPOs, ACLs, sessions. Mais il est **aveugle à la couche réseau** — il ne sait pas quelles machines sont allumées, quels ports sont ouverts, quels VLANs existent, ni comment les sous-réseaux communiquent entre eux.

Or en pentest, la couche réseau est indispensable pour :
- repérer les services exposés (SMB, RDP, WinRM, LDAP, Kerberos...),
- comprendre la segmentation réseau (quel VLAN peut joindre quel DC),
- détecter des machines non-AD (imprimantes, NAS, équipements réseau),
- vérifier l'accès effectif aux machines identifiées dans le graphe AD.

### Problème

**Comment découvrir la topologie réseau quand on ne connaît que son propre VLAN ?**

En situation de pentest, l'attaquant est positionné sur un segment réseau et n'a aucune connaissance de l'infrastructure au-delà. Il doit répondre à trois questions :

```
  ┌───────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │                                                                                                           │
  │  1. Quelles machines sont sur MON segment réseau ?              → Découverte L2 (ARP)                     │
  │                                                                                                           │
  │  2. Quels sous-réseaux existent AU-DELÀ de mon segment ?       → Découverte L3 (traceroute multi-méthode) │
  │                                                                                                           │
  │  3. Quels services sont accessibles sur ces machines ?          → Scan de ports TCP                        │
  │                                                                                                           │
  └───────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### Solution : `argus_network.py`

Le module `argus_network.py` automatise cette découverte réseau. Il fonctionne selon deux modes d'accès (direct ou indirect via pivot) et produit un fichier JSON structuré utilisé par les autres modules ARGUS (mapping hostname → IP, cartographie visuelle).

---

## 2. Les deux modes d'accès

L'accès au réseau cible détermine ce qu'ARGUS peut faire :

```
  ┌───────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │                                                                                                           │
  │  MODE DIRECT                                                                                              │
  │  L'attaquant est physiquement sur le réseau interne.                                                      │
  │                                                                                                           │
  │  ┌──────────┐                                                    ┌──────────┐                             │
  │  │ Attacker │ ──────────────────────────────────────────────────▶│ Cibles   │                             │
  │  │ (interne)│              accès réseau complet                  │          │                             │
  │  └──────────┘                                                    └──────────┘                             │
  │                                                                                                           │
  │  Protocoles disponibles : ARP ✔   ICMP ✔   UDP ✔   TCP ✔                                                │
  │  → Découverte réseau complète possible (ARP, traceroute, ICMP, port scan)                                 │
  │                                                                                                           │
  ├───────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │                                                                                                           │
  │  MODE INDIRECT (PIVOT)                                                                                    │
  │  L'attaquant passe par un tunnel SOCKS après compromission d'une machine.                                 │
  │                                                                                                           │
  │  ┌──────────┐     SOCKS5      ┌──────────┐                      ┌──────────┐                             │
  │  │ Attacker │ ═══════════════▶│  Pivot   │ ════════════════════▶│ Cibles   │                             │
  │  │ (externe)│    TCP only     │  (pwn)   │                      │          │                             │
  │  └──────────┘                 └──────────┘                      └──────────┘                             │
  │                                                                                                           │
  │  Protocoles disponibles : ARP ✘   ICMP ✘   UDP ✘   TCP ✔ (via proxychains4)                             │
  │  → Pas de découverte réseau, scan TCP uniquement sur des IPs connues                                      │
  │                                                                                                           │
  └───────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Mode Direct — découverte réseau complète

En accès direct, ARGUS exécute **4 phases séquentielles**. Chaque phase alimente la suivante en données.

```
  ┌───────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │                                                                                                           │
  │  Phase 1 : ARP scan         Découvre les machines du VLAN local (L2)                                      │
  │       │                                                                                                   │
  │       ▼                                                                                                   │
  │  Phase 2 : Traceroute       Découvre les routeurs et sous-réseaux au-delà du VLAN (L3)                    │
  │       │                                                                                                   │
  │       ▼                                                                                                   │
  │  Phase 3 : ICMP scan        Découvre les machines dans les sous-réseaux distants                          │
  │       │                                                                                                   │
  │       ▼                                                                                                   │
  │  Phase 4 : Port scan TCP    Identifie les services exposés sur toutes les machines découvertes            │
  │                                                                                                           │
  └───────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### Phase 1 — Découverte ARP du VLAN local

**Objectif** : Identifier toutes les machines actives sur le segment L2 (même VLAN).

**Technique** : Nmap ARP scan (`-sn -PR -T4`). Envoie des requêtes ARP (broadcast L2) et collecte les réponses. Ne traverse pas les routeurs.

```
  Machine ARGUS (10.0.1.50/24)
       │
       │  ARP Request: Who has 10.0.1.x ?
       │  (broadcast sur le segment L2)
       ▼
  ┌───────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │                                         VLAN LOCAL (10.0.1.0/24)                                          │
  │                                                                                                           │
  │  10.0.1.1 (gw)     ✔ ARP reply + MAC               10.0.1.20 (srv)   ✔ ARP reply + MAC                    │
  │  10.0.1.10 (DC)    ✔ ARP reply + MAC               10.0.1.30 (pc)    ✔ ARP reply + MAC                    │
  │  10.0.1.99 (off)   ✘ pas de réponse                                                                       │
  └───────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

**Pourquoi ARP et pas ICMP ?** L'ARP fonctionne en L2, il ne peut pas être bloqué par un pare-feu. Un hôte qui filtre les pings répondra quand même à l'ARP (obligatoire pour la communication Ethernet). En revanche, l'ARP ne traverse pas les routeurs — d'où la Phase 2.

### Phase 2 — Traceroute multi-méthode

**Objectif** : Découvrir les routeurs et les sous-réseaux accessibles au-delà du VLAN local.

**Technique** : Trois traceroutes vers chaque cible (8.8.8.8 + DNS interne), avec des protocoles différents pour maximiser la couverture :

```
  ┌───────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │  MÉTHODE          COMMANDE                                          AVANTAGE                              │
  ├───────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │  UDP              traceroute -n {target}                             Standard, le plus compatible          │
  │                                                                                                           │
  │  ICMP             traceroute -n -I {target}                          Passe les FW qui autorisent le ping  │
  │                                                                                                           │
  │  TCP/80           traceroute -n -T -p 80 {target}                   Passe les FW qui autorisent HTTP     │
  └───────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

**Pourquoi trois méthodes ?** Chaque méthode peut échouer sur certains hops (routeur qui ne répond pas en UDP mais répond en ICMP, pare-feu qui bloque TCP mais laisse passer ICMP, etc.). La fusion des trois résultats comble les `***` (hops muets) de chaque méthode individuelle.

**Algorithme de fusion** : Pour chaque numéro de hop, on conserve la ligne qui révèle le plus d'adresses IP.

```
  Hop   UDP                ICMP               TCP/80             FUSIONNÉ
  ────  ─────────────────  ─────────────────  ─────────────────  ─────────────────
   1    10.0.1.1           10.0.1.1           10.0.1.1           10.0.1.1
   2    * * *              10.0.2.1           * * *              10.0.2.1          ◄ ICMP comble
   3    10.0.3.1           * * *              10.0.3.1           10.0.3.1
   4    * * *              * * *              142.250.x.x        142.250.x.x
```

**Filtre de sécurité** : Seules les IPs privées (RFC1918) sont conservées. Les IPs publiques apparaissant dans le traceroute vers 8.8.8.8 sont silencieusement ignorées — on ne veut pas scanner l'internet.

### Phase 3 — Scan ICMP des sous-réseaux distants

**Objectif** : Découvrir les machines actives dans les sous-réseaux des routeurs identifiés en Phase 2.

**Technique** : Pour chaque routeur découvert, on déduit son /24 et on lance un ping scan ICMP (`-sn -PE -T4`).

```
  Phase 2 a trouvé : 10.0.2.1 (routeur)
                              │
                              ▼
               network_from_ip("10.0.2.1") → "10.0.2.0/24"
                              │
                              ▼
                    run_nmap_icmp_scan("10.0.2.0/24")
                              │
                              ▼
  ┌───────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │                                       10.0.2.0/24 (ICMP)                                                  │
  │                                                                                                           │
  │  10.0.2.1    ✔ up               10.0.2.20   ✔ up                                                         │
  │  10.0.2.10   ✔ up               10.0.2.55   ✘ down                                                       │
  └───────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

**Pourquoi ICMP et pas ARP ?** Ces sous-réseaux sont au-delà d'un routeur (L3). L'ARP est limité au segment L2 local. ICMP (ping) traverse les routeurs. En contrepartie, les hôtes qui filtrent ICMP ne seront pas détectés — c'est une limitation acceptée.

**Filtre de sécurité** : Les sous-réseaux publics déduits des traceroutes sont écartés avant le scan. Seuls les /24 privés sont scannés.

### Phase 4 — Scan de ports TCP

**Objectif** : Identifier les services exposés sur chaque machine découverte.

**Technique** : Nmap TCP scan (`-Pn -n --top-ports 100 -T4`) sur l'ensemble consolidé des hôtes (VLAN local + sous-réseaux distants + routeurs + gateway + DNS).

```
  Consolidation de toutes les machines découvertes :
       │
       │  ├── VLAN local       (Phase 1 — ARP)
       │  ├── Sous-réseaux     (Phase 3 — ICMP)
       │  ├── Routeurs         (Phase 2 — traceroute)
       │  └── Gateway + DNS    (fournis par l'utilisateur)
       │
       ▼
  Liste dédupliquée d'IPs → scan de ports
       │
       ▼
  ┌───────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │  10.0.1.10 : 53/dns, 88/kerberos, 389/ldap, 445/microsoft-ds, 636/ldaps                                  │
  │  10.0.1.20 : 80/http, 443/https, 3389/ms-wbt                                                             │
  │  10.0.2.10 : 22/ssh, 445/microsoft-ds                                                                    │
  └───────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

**Options de ports** :
- Par défaut : `--top-ports 100` (les 100 ports TCP les plus courants)
- Personnalisé : `--port-list "22,80,88,135,389,445,636,3389,5985"`
- Le scan est **optionnel** (`--port-scan` pour l'activer), mais **automatique** si `--port-list` est spécifié

**Pourquoi `-Pn -n` ?** Les hôtes ont déjà été découverts (ARP/ICMP), pas besoin de re-vérifier leur disponibilité (`-Pn`). La résolution DNS est désactivée (`-n`) pour éviter les fuites DNS et accélérer le scan.

### Dépendances (mode direct)

| Outil          | Rôle                                      |
|----------------|-------------------------------------------|
| `nmap`         | Scanner de ports et découverte réseau      |
| `traceroute`   | Découverte des routeurs inter-VLANs        |
| `sudo`         | Requis pour les scans ARP (raw sockets)    |

---

## 4. Mode Direct — machine ciblée (single-host)

Quand on connaît déjà le réseau (ex: un seul DC dans un lab HTB) on n'a pas besoin de découvrir. Le mode `--single-host` **saute les phases 1-3** et lance directement un scan de ports TCP sur l'IP fournie.

```
  argus_network.py --single-host --ip-cidr 10.10.11.42/32 --port-scan

  → Pas d'ARP, pas de traceroute, pas d'ICMP
  → Scan de ports TCP directement sur 10.10.11.42
```

Ce mode est utile pour les labs ou quand on veut simplement ajouter les données de ports d'une machine connue au JSON réseau.

---

## 5. Mode Indirect (Pivot) — scan via SOCKS

### Contexte

Après compromission d'une première machine, l'attaquant met en place un serveur SOCKS (3proxy, SSH -D...) pour accéder au réseau interne depuis sa machine d'attaque.

### Pourquoi pas de découverte réseau en pivot ?

Un proxy SOCKS ne transporte que du **TCP**. Les protocoles utilisés pour la découverte réseau en mode direct ne fonctionnent pas :

```
  ┌───────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │  Protocole              Mode direct                      Mode indirect (SOCKS)                            │
  ├───────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │  ARP (L2)               ✔ Phase 1                        ✘ impossible                                     │
  │  ICMP (ping)            ✔ Phase 3                        ✘ impossible                                     │
  │  UDP                    ✔ traceroute                     ✘ impossible                                     │
  │  TCP                    ✔ port scan                      ✔ seul protocole disponible                      │
  └───────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

Faire une découverte réseau en TCP pur (scan d'un /24 complet port par port) serait **beaucoup trop lent** via un tunnel SOCKS : chaque connexion TCP doit traverser le tunnel, le proxy, puis atteindre la cible. Sur un /24 avec 100 ports, cela représente ~25 000 connexions séquentielles.

ARGUS considère donc que l'opérateur a **déjà identifié ses cibles** avant de lancer le scan pivot — via une reconnaissance préalable (ping sweep depuis la machine compromise, analyse des résultats BloodHound, connaissance du périmètre, etc.). Le wizard demande uniquement la liste d'IPs à scanner.

### Fonctionnement technique

Le mode pivot utilise `proxychains4` + `nmap -sT` (TCP connect scan).

**Pourquoi `-sT` et pas `-sS` ?** Le scan SYN (`-sS`) envoie des paquets forgés via des raw sockets, ce qui contourne l'API socket standard. Or `proxychains4` fonctionne en interceptant les appels `connect()` via `LD_PRELOAD` — il ne peut rediriger que des connexions TCP normales. Avec `-sS`, les paquets partiraient en direct sans passer par le tunnel SOCKS. Le scan TCP connect (`-sT`) utilise l'API socket standard, donc proxychains peut l'intercepter et le rediriger correctement dans le tunnel.

```
  ┌───────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │                                                                                                           │
  │  -sS (SYN scan)     raw socket → paquet SYN forgé → CONTOURNE proxychains → scan local, pas le réseau    │
  │                                                                                                           │
  │  -sT (TCP connect)  connect() → intercepté par LD_PRELOAD → proxychains → tunnel SOCKS → cible distante  │
  │                                                                                                           │
  └───────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 6. Résumé

```
  ┌───────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │                                                                                                           │
  │  DIRECT — réseau complet          ARP → traceroute → ICMP → port scan TCP                                 │
  │  --gateway 10.0.1.1 --dns 10.0.1.10                                                                      │
  │                                                                                                           │
  │  DIRECT — machine ciblée          port scan TCP uniquement                                                │
  │  --single-host -i 10.10.11.42/32                                                                          │
  │                                                                                                           │
  │  INDIRECT — pivot SOCKS           port scan TCP via proxychains sur IPs connues                            │
  │  --proxychains-conf pivot.conf --targets 172.16.1.5,172.16.1.20                                           │
  │                                                                                                           │
  └───────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

Tous les modes produisent un fichier JSON unique (`global_network_scan_results.json`) consommé par `argus_enrich.py` (mapping) et `cartographie.html` (visualisation).

---

## 7. Limites et cas particuliers

### Hôtes invisibles (mode direct)

Certaines machines ne répondent ni à l'ARP (hors VLAN) ni à l'ICMP (filtré par le pare-feu Windows). Ces hôtes sont **indétectables** par les phases de découverte. Ils apparaîtront quand même dans le port scan si on connaît leur IP (gateway et DNS sont inclus d'office).

### Hypothèse /24 (mode direct)

Le module suppose que chaque routeur est dans un sous-réseau /24. C'est l'hypothèse la plus courante en réseau d'entreprise, mais elle peut être fausse (ex: /16 en datacenter, /30 pour les liens point-à-point). Un /16 ne sera scanné que partiellement (le /24 du routeur).

### Traceroute et pare-feu (mode direct)

Les traceroutes échouent si tous les protocoles (UDP, ICMP, TCP/80) sont bloqués par un pare-feu intermédiaire. Dans ce cas, aucun routeur n'est découvert et le scan se limite au VLAN local.

### Résolution hostname (mode pivot)

La résolution hostname → IP dépend de `smb-os-discovery`. Si le port 445 est filtré ou si le service SMB ne répond pas, le hostname restera inconnu et le lien avec les objets Computer BloodHound ne pourra pas être établi.
