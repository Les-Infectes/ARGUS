# Données brutes — Intégration de scans externes

## Table des matières

1. [Contexte et objectifs](#1-contexte-et-objectifs)
2. [Pourquoi un mode import ?](#2-pourquoi-un-mode-import-)
3. [Les trois sous-modes](#3-les-trois-sous-modes)
4. [Sélection interactive du noeud de départ](#4-sélection-interactive-du-noeud-de-départ)
5. [Conversion nmap XML → format ARGUS](#5-conversion-nmap-xml--format-argus)
6. [Mapping hostname sans rescanner](#6-mapping-hostname-sans-rescanner)
7. [Workflow pentester type](#7-workflow-pentester-type)

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

Le mode **Données brutes** est accessible depuis l'interface web (`argus_server.py`) ou en ligne de commande :

```
  ┌──────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │  TYPE D'IMPORT                                                                                          │
  │                                                                                                         │
  │  AD (BloodHound + Certipy)     Dossier BloodHound JSON + Certipy optionnel                              │
  │  Réseau (nmap XML)             Fichier nmap -oX → cartographie réseau                                   │
  │  Complet (Réseau + AD)         nmap XML + BloodHound → cartographie unifiée                             │
  └──────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 3.1 AD (BloodHound + Certipy)

Génère les graphes de classification en tiers à partir d'un dossier BloodHound existant. C'est le mode le plus simple : aucun scan, aucun accès réseau requis. Le pentester fournit ses JSON BloodHound et le noeud de départ se choisit interactivement dans la cartographie.

```
  Entrée :  bloodhound_data/ + certipy_data.json (optionnel)
  Sortie :  graph_tier0.json, graph_tier1.json, graph_tier2.json

  CLI :
    python3 argus_graph.py --data-dir bloodhound_data/ --start user@domain.local --output-dir results/
```

**Cas d'usage** : analyser les chemins d'attaque AD sans avoir besoin de la couche réseau. C'est probablement le mode le plus utile en pratique — le pentester a collecté ses données BloodHound et veut la classification en tiers d'ARGUS.

### 3.2 Réseau (nmap XML)

Convertit un fichier nmap XML (`-oX`) en `network_scan.json` au format ARGUS. Le résultat est affiché dans la cartographie réseau.

```
  Entrée :  scan.xml (nmap -oX)
  Sortie :  network_scan.json

  CLI :
    python3 argus_import.py --nmap-xml scan.xml --output-dir results/
```

**Cas d'usage** : visualiser rapidement un scan réseau existant dans l'interface ARGUS, sans données AD.

### 3.3 Complet (Réseau + AD)

Combine les deux couches en une cartographie unifiée. Le pentester fournit son nmap XML et son dossier BloodHound. Si le DC est encore accessible, ARGUS peut faire le mapping hostname → IP pour créer les ponts entre les couches réseau et identité.

```
  Entrée :  scan.xml + bloodhound_data/ + certipy_data.json (optionnel)
  Sortie :  network_scan.json + graph_tier0/1/2.json + hostname_mapping.json (si DC accessible)

  CLI (sans mapping) :
    python3 argus_import.py --nmap-xml scan.xml --bh-dir bloodhound_data/ --start user@domain.local

  CLI (avec mapping DNS direct) :
    python3 argus_import.py --nmap-xml scan.xml --bh-dir bloodhound_data/ --start user@domain.local --dc-ip 10.0.1.10

  CLI (avec mapping DNS pivot) :
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

## 4. Sélection interactive du noeud de départ

Le noeud de départ (le compte compromis à partir duquel on explore les chemins d'attaque) n'est plus demandé dans le formulaire d'import. Il se choisit **interactivement** dans la barre d'outils de la cartographie, après le chargement des données.

```
  ┌──────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │                                                                                                         │
  │  1. L'utilisateur importe ses données (BH, nmap, certipy)                                               │
  │  2. Les graphes sont générés avec un start node par défaut                                               │
  │  3. La cartographie s'affiche avec les boutons T0/T1/T2 désactivés                                      │
  │  4. L'utilisateur choisit son noeud de départ dans le sélecteur                                          │
  │     → Autocomplétion + filtres (Chemins vers T0, Users, Groups, etc.)                                   │
  │  5. Les graphes sont recalculés côté serveur pour ce nouveau start                                       │
  │  6. Les boutons T0/T1/T2 deviennent actifs                                                              │
  │                                                                                                         │
  │  Le changement de noeud de départ est instantané — pas besoin de re-importer les données.                │
  │                                                                                                         │
  └──────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

Le filtre **Chemins vers T0** est particulièrement utile : il identifie tous les objets qui ont au moins un chemin d'attaque vers un objet Tier 0. Sur un domaine inconnu, ce filtre permet de trouver rapidement les noeuds de départ les plus intéressants.

---

## 5. Conversion nmap XML → format ARGUS

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

## 6. Mapping hostname sans rescanner

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

## 7. Workflow pentester type

### Scénario 1 — AD seul (le plus courant)

Le pentester a collecté ses données BloodHound et veut la classification ARGUS.

```
  1. Le pentester a déjà :
     - bloodhound-python -u user -d domain -c All       (collecte BH)

  2. Dans l'interface ARGUS :
     - Mode « Données brutes » → AD (BloodHound + Certipy)
     - Sélectionner le dossier BloodHound
     - Cliquer « Générer »

  3. Dans la cartographie :
     - Choisir le noeud de départ (ex: user@domain.local)
     - Cliquer T0 pour voir les chemins d'attaque déterministes
     - Changer de noeud de départ à tout moment
```

### Scénario 2 — Import complet (DC encore accessible)

Le pentester a déjà fait ses scans et veut une cartographie unifiée réseau + AD.

```
  1. Le pentester a déjà :
     - nmap -sT -Pn -oX scan.xml 10.0.1.0/24           (son scan habituel)
     - bloodhound-python -u user -d domain -c All       (collecte BH)

  2. Dans l'interface ARGUS :
     - Mode « Données brutes » → Complet (Réseau + AD)
     - Fournir le nmap XML, le dossier BloodHound
     - Optionnel : DC IP pour le mapping hostname → IP
     - Cliquer « Générer »

  3. Dans la cartographie :
     - Le réseau s'affiche immédiatement
     - Choisir le noeud de départ pour afficher les chemins AD
     - Les ponts relient les machines réseau aux objets Computer AD
```

### Scénario 3 — Après l'audit (offline)

Le pentester analyse ses données après la mission, sans accès au réseau cible.

```
  1. Même procédure que le scénario 2, mais sans DC IP
  2. Résultat : deux couches indépendantes
     - Couche réseau : IPs, ports, services
     - Couche identité : chemins d'attaque AD classifiés en tiers
     - Pas de ponts entre les deux (pas de mapping)
  3. Le noeud de départ se choisit interactivement dans la cartographie
```
