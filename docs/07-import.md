# Mode Import — Intégration de scans externes

## Table des matières

1. [Contexte et objectifs](#1-contexte-et-objectifs)
2. [Pourquoi un mode import ?](#2-pourquoi-un-mode-import-)
3. [Les trois sous-modes](#3-les-trois-sous-modes)
4. [Conversion nmap XML → format ARGUS](#4-conversion-nmap-xml--format-argus)
5. [Mapping hostname sans rescanner](#5-mapping-hostname-sans-rescanner)
6. [Workflow pentester type](#6-workflow-pentester-type)

---

## 1. Contexte et objectifs

ARGUS intègre ses propres modules de scan réseau (`argus_network.py`) et s'appuie sur des collecteurs AD externes (BloodHound, Certipy). En pratique, un pentester ou un red teamer a souvent **déjà réalisé ses scans** avant de découvrir ARGUS, ou utilise ses propres outils et méthodologies pour la reconnaissance.

Le mode Import permet d'utiliser ARGUS **sans relancer de scan** : le pentester fournit ses fichiers existants (nmap XML, données BloodHound) et ARGUS génère la cartographie unifiée à partir de ces données. L'objectif est de rendre l'outil utilisable à n'importe quel moment de l'audit, pas seulement au début.

---

## 2. Pourquoi un mode import ?

### Le problème de portabilité

Dans un audit réel, les scans sont rarement lancés depuis un seul outil. Le pentester utilise ses propres commandes nmap, ses propres options, ses propres scripts. Il a déjà un fichier XML nmap qu'il exploite avec d'autres outils (Metasploit, CrackMapExec, etc.). Lui demander de relancer un scan via ARGUS est une friction inutile.

De la même façon, la collecte BloodHound est souvent faite en amont, parfois par une autre personne de l'équipe. Les données JSON sont déjà disponibles dans un dossier.

### Ce que le mode import résout

```
  AVANT : le pentester doit utiliser ARGUS depuis le début

    nmap (ARGUS) ─────────────┐
    bloodhound-python (ARGUS) ─┼──▶ ARGUS pipeline ──▶ cartographie
    certipy (ARGUS) ──────────┘

  APRÈS : le pentester branche ses fichiers existants

    nmap -oX scan.xml (déjà fait)  ─────────────┐
    bloodhound-python (déjà fait)  ──────────────┼──▶ ARGUS import ──▶ cartographie
    certipy find -json (optionnel) ──────────────┘
```

Le pentester conserve sa méthodologie de scan, ses options nmap préférées, ses scripts personnalisés. ARGUS se positionne comme un outil d'**analyse et de visualisation**, pas comme un remplaçant de ses outils de reconnaissance.

---

## 3. Les trois sous-modes

Le mode Import est accessible depuis le wizard (`argus.py`) comme troisième choix après Direct et Pivot :

```
  ACCESS MODE

    [1]  Direct   — Direct access to target network
    [2]  Pivot    — Access via SOCKS tunnel / proxychains
    [3]  Import   — Build cartography from existing files

  IMPORT TYPE

    [1]  Network only    nmap XML → network cartography
    [2]  AD only         BloodHound folder → tier graphs
    [3]  Full import     nmap XML + BloodHound → unified cartography
```

### 3.1 Network only

Convertit un fichier nmap XML (`-oX`) en `network_scan.json` au format ARGUS. Le résultat est chargeable dans `cartographie.html` pour visualiser la couche réseau (IPs, ports, services, sous-réseaux).

```
  Entrée :  scan.xml (nmap -oX)
  Sortie :  network_scan.json

  Commande :
    python3 argus_import.py --nmap-xml scan.xml --output-dir results/import
```

**Cas d'usage** : visualiser rapidement un scan réseau existant dans l'interface ARGUS, sans données AD.

### 3.2 AD only

Génère les graphes de classification en tiers à partir d'un dossier BloodHound existant. C'est le mode le plus simple : aucun scan, aucun accès réseau requis. Le pentester fournit ses JSON BloodHound et un noeud de départ (le compte compromis).

```
  Entrée :  bloodhound_data/ + start node
  Sortie :  graph_tier0.json, graph_tier1.json, graph_tier2.json

  Commande :
    python3 argus_graph.py --data-dir bloodhound_data/ --start user@domain.local --output-dir results/import
```

Optionnel : un fichier Certipy JSON (`--certipy-json`) pour inclure les vulnérabilités ADCS dans l'analyse.

**Cas d'usage** : analyser les chemins d'attaque AD sans avoir besoin de la couche réseau. Le pentester a déjà collecté les données BloodHound et veut la classification en tiers d'ARGUS.

### 3.3 Full import

Combine les deux couches en une cartographie unifiée. Le pentester fournit son nmap XML et son dossier BloodHound. Si le DC est encore accessible, ARGUS peut faire le mapping hostname → IP pour créer les ponts entre les couches réseau et identité.

```
  Entrée :  scan.xml + bloodhound_data/ + start node
  Sortie :  network_scan.json + graph_tier0/1/2.json + hostname_mapping.json (si DC accessible)

  Commande (sans mapping) :
    python3 argus_import.py --nmap-xml scan.xml --bh-dir bloodhound_data/ --start user@domain.local

  Commande (avec mapping DNS direct) :
    python3 argus_import.py --nmap-xml scan.xml --bh-dir bloodhound_data/ --start user@domain.local --dc-ip 10.0.1.10

  Commande (avec mapping DNS pivot) :
    python3 argus_import.py --nmap-xml scan.xml --bh-dir bloodhound_data/ --start user@domain.local --dc-ip 10.0.1.10 --dns-tcp --proxychains-conf proxy.conf
```

**Mapping hostname → IP** : pour relier les machines réseau aux objets Computer AD, ARGUS a besoin de résoudre les hostnames AD en adresses IP. Cela nécessite un accès DNS au Domain Controller. Deux options :

```
  ┌──────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │  DC accessible ?                                                                                        │
  │                                                                                                         │
  │  OUI, accès direct  ──▶  --dc-ip 10.0.1.10                 DNS UDP direct, rapide                       │
  │  OUI, via tunnel    ──▶  --dc-ip 10.0.1.10 --dns-tcp       DNS TCP via proxychains                      │
  │  NON                ──▶  (pas de --dc-ip)                   Pas de ponts, couches indépendantes          │
  └──────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

Si le DC n'est plus accessible (fin de mission, tunnel fermé), les deux couches sont générées mais restent indépendantes dans la cartographie — pas de ponts entre les IPs et les objets Computer AD.

---

## 4. Conversion nmap XML → format ARGUS

### Format d'entrée

Le parseur accepte tout fichier XML produit par nmap avec l'option `-oX`. Les options de scan du pentester n'ont pas d'importance : `-sS`, `-sT`, `-sV`, `-A`, scripts personnalisés — tout est supporté. Le parseur extrait les informations suivantes de chaque `<host>` :

```
  Fichier XML nmap                                        Format ARGUS (network_scan.json)
  ┌──────────────────────────────────────────────┐       ┌──────────────────────────────────────────────┐
  │ <host>                                       │       │ {                                            │
  │   <address addr="10.0.1.10" addrtype="ipv4"/>│       │   "ip": "10.0.1.10",                        │
  │   <ports>                                    │       │   "status": "up",                            │
  │     <port portid="445" protocol="tcp">       │  ───▶ │   "services": [                              │
  │       <state state="open"/>                  │       │     {"port": 445, "service": "microsoft-ds"} │
  │       <service name="microsoft-ds"/>         │       │   ],                                         │
  │     </port>                                  │       │   "hostname": "DC01.corp.local"               │
  │   </ports>                                   │       │ }                                            │
  │   <hostscript>                               │       └──────────────────────────────────────────────┘
  │     <script id="smb-os-discovery">           │
  │       <elem key="fqdn">DC01.corp.local</elem>│
  │     </script>                                │
  │   </hostscript>                              │
  │ </host>                                      │
  └──────────────────────────────────────────────┘
```

### Hostname SMB

Si le pentester a lancé nmap avec `--script=smb-os-discovery` (ou `-A` qui l'inclut), le XML contient les hostnames découverts via SMB. Le parseur les extrait automatiquement et les associe aux IPs correspondantes. Ces hostnames sont utilisables par `argus_enrich.py` pour construire le mapping **sans requête DNS au DC** (lookup local dans l'index SMB).

En pratique, peu de pentesters lancent ce script spécifiquement. Le mapping via DNS reste la méthode principale.

### Réutilisation du parseur existant

`argus_import.py` réutilise directement le parseur XML d'`argus_network.py` (`_parse_nmap_xml`). C'est le même code qui parse les résultats nmap en mode Direct et Pivot — il est éprouvé et gère tous les cas de figure (ports fermés, hôtes sans services, scripts absents, etc.).

---

## 5. Mapping hostname sans rescanner

Le mapping hostname → IP est le point critique de la fusion réseau/identité. Voici les options selon la situation du pentester :

```
  Situation du pentester                                    Solution mapping
  ┌──────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │                                                                                                         │
  │  Encore en ligne, accès direct au DC          ──▶  --dc-ip <IP>                                         │
  │    → DNS UDP, résolution rapide                     ARGUS résout chaque hostname AD via le DC            │
  │                                                                                                         │
  │  Encore en ligne, accès via tunnel SOCKS      ──▶  --dc-ip <IP> --dns-tcp --proxychains-conf <conf>     │
  │    → DNS TCP via proxychains, plus lent              Même résolution, à travers le tunnel                │
  │                                                                                                         │
  │  Nmap lancé avec --script=smb-os-discovery    ──▶  Le XML contient les hostnames                        │
  │    → Mapping automatique depuis le XML               Pas besoin du DC, lookup local                     │
  │                                                                                                         │
  │  Plus d'accès au réseau cible                 ──▶  Pas de mapping possible                              │
  │    → Couches réseau et AD indépendantes              Cartographie en deux parties non reliées            │
  │                                                                                                         │
  └──────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 6. Workflow pentester type

### Scénario 1 — Pendant l'audit (DC accessible)

Le pentester a déjà fait ses scans et veut générer une cartographie unifiée pour son rapport.

```
  1. Le pentester a déjà :
     - nmap -sT -Pn -oX scan.xml 10.0.1.0/24           (son scan habituel)
     - bloodhound-python -u user -d domain -c All       (collecte BH)

  2. Il lance ARGUS en mode import :
     python3 argus.py → Import → Full import
       nmap-xml :  scan.xml
       bh-dir :    bloodhound_data/
       start :     user@domain.local
       mapping :   oui → dc-ip : 10.0.1.10 → Direct

  3. Résultat :
     results/import/
       ├── network_scan.json
       ├── hostname_mapping.json
       ├── graph_tier0.json
       ├── graph_tier1.json
       └── graph_tier2.json

  4. Ouvrir cartographie.html → charger les fichiers → cartographie unifiée
```

### Scénario 2 — Après l'audit (offline)

Le pentester analyse ses données après la mission, sans accès au réseau cible.

```
  1. Il lance ARGUS en mode import sans mapping :
     python3 argus_import.py --nmap-xml scan.xml --bh-dir bloodhound_data/ --start user@domain.local

  2. Résultat : deux couches indépendantes
     - Couche réseau : IPs, ports, services
     - Couche identité : chemins d'attaque AD classifiés en tiers
     - Pas de ponts entre les deux (pas de mapping)

  3. Utile pour : classification des chemins d'attaque, rédaction du rapport, présentation des risques
```

### Scénario 3 — AD seul

Le pentester n'a pas fait de scan réseau (ou ne veut pas l'inclure). Il veut juste la classification ARGUS sur ses données BloodHound.

```
  1. Il lance ARGUS en mode import AD :
     python3 argus.py → Import → AD only
       bh-dir : bloodhound_data/
       start :  user@domain.local

  2. Résultat : graph_tier0/1/2.json → chemins d'attaque classifiés
```
