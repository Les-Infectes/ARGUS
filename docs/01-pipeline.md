# Pipeline ARGUS — Orchestration des scripts

## Table des matières

1. [Contexte et objectifs](#1-contexte-et-objectifs)
2. [Point d'entrée : argus.py](#2-point-dentrée--arguspy)
3. [Architecture du pipeline](#3-architecture-du-pipeline)
4. [Exécution des scripts](#4-exécution-des-scripts)
5. [Le générateur multi-tiers (argus_graph.py)](#5-le-générateur-multi-tiers-argus_graphpy)
6. [Modes d'accès et combinaisons](#6-modes-daccès-et-combinaisons)
7. [Authentification et virtualenv](#7-authentification-et-virtualenv)
8. [Gestion des erreurs et résilience](#8-gestion-des-erreurs-et-résilience)

---

## 1. Contexte et objectifs

### Contexte

ARGUS est composé de plusieurs modules indépendants, chacun avec ses propres arguments CLI. Exécuter manuellement chaque module dans le bon ordre, avec les bons chemins de fichiers, est fastidieux et source d'erreurs.

### Solution : orchestration à deux niveaux

```
  argus.py                              Wizard interactif (point d'entrée)
       │                                Questions → construit la ligne de commande
       ▼
  argus_pipeline.py                     Orchestrateur séquentiel — 5 étapes dans l'ordre — Gestion des erreurs + options de saut
       │
       ├── argus_network.py             Scan réseau (ARP, traceroute, ports)
       ├── bloodhound-python            Collecte AD (users, groups, computers, domains)
       ├── argus_enrich.py              Mapping hostname → IP
       ├── argus_certipy.py             Énumération ADCS (templates, vulns ESC)
       └── argus_graph.py               Génération des graphes par tier
                │
                └── argus_builder.py    Appelé ×3 (tier 0, tier 1, tier 2)
```

---

## 2. Point d'entrée : argus.py

### Rôle

`argus.py` est le wizard interactif d'ARGUS. Il pose une série de questions à l'utilisateur (mode, cibles, identifiants, options) et construit la commande `argus_pipeline.py` correspondante. L'utilisateur n'a pas besoin de connaître les flags CLI.

### Fonctionnement

```
  Utilisateur
       │
       │  sudo .env/bin/python3 argus.py
       ▼
  ┌──────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │  1. Mode ?              → Direct / Pivot                                                               │
  │  2. Type de scan ?      → DC only / Network / AD+ADCS / Full / Network+mapping                        │
  │  3. Cibles ?            → IP, CIDR, gateway...                                                         │
  │  4. Identifiants ?      → user, password/hash                                                          │
  │  5. Options ?           → port-scan, timeout...                                                        │
  └──────────────────────────────────────────────────────┬───────────────────────────────────────────────────┘
                                                         │
                                                         ▼
  argus_pipeline.py --ip-cidr ... --domain ... --start ...
```

Le wizard traduit chaque choix en flags CLI :

| Choix utilisateur     | Flags générés                                  |
|-----------------------|------------------------------------------------|
| DC only               | `--single-host --skip-certipy`                 |
| Network only          | `--skip-bloodhound --skip-certipy --start x@x` |
| AD + ADCS             | `--skip-network`                               |
| Full (single machine) | `--single-host --port-scan`                    |
| Full (network)        | `--port-scan`                                  |
| Pivot                 | `--proxychains-conf ... --dns-tcp`             |

Une fois la commande construite, `argus.py` l'affiche et la lance automatiquement. Le reste de l'exécution est géré par `argus_pipeline.py`.

---

## 3. Architecture du pipeline

### Les 5 étapes séquentielles

```
  Step 1                Step 2                Step 3                Step 4                Step 5
  ┌───────────────┐    ┌───────────────┐    ┌───────────────┐    ┌───────────────┐    ┌───────────────┐
  │ Network scan  │───▶│ BloodHound    │───▶│ Mapping       │───▶│ Certipy       │───▶│ Graph build   │
  │ (ARP + ports) │    │ collect (AD)  │    │ host → IP     │    │ ADCS enum     │    │ (3 tiers)     │
  └───────────────┘    └───────────────┘    └───────────────┘    └───────────────┘    └───────────────┘
         │                    │                    │                    │                    │
         ▼                    ▼                    ▼                    ▼                    ▼
  network_scan.json    bloodhound_data/     hostname_mapping    certipy_data.json    graph_tier{0,1,2}
                       *.json               .json                                    .json
```

### Dépendances entre les étapes

```
  Étape 1 (Network)     → indépendant, peut être sautée
  Étape 2 (BloodHound)  → indépendant, BLOQUANT si échec (pas de données AD = pas de graphe)
  Étape 3 (Mapping)     → dépend de l'Étape 2 (BH data) + optionnel Étape 1 (SMB index)
  Étape 4 (Certipy)     → dépend de l'Étape 2 (BH data pour name → SID)
  Étape 5 (Graph)       → dépend de l'Étape 2 + optionnel Étape 4 (certipy_data)
```

Seul l'échec de l'Étape 2 (BloodHound) est bloquant. Les autres étapes sont résilientes : un échec produit un avertissement mais n'arrête pas le pipeline.

### Fichiers produits

```
  output_dir/
  ├── network_scan.json                    Étape 1 — topologie réseau
  ├── bloodhound_data/                     Étape 2 — données AD brutes
  │   ├── *_users.json
  │   ├── *_groups.json
  │   ├── *_computers.json
  │   ├── *_domains.json
  │   └── ...
  ├── hostname_mapping.json                Étape 3 — hostname → IP
  ├── certipy_data.json                    Étape 4 — templates ADCS
  ├── graph_tier0.json                     Étape 5 — Tier 0 (déterministe)
  ├── graph_tier1.json                     Étape 5 — Tier 1 (1-7 hops)
  └── graph_tier2.json                     Étape 5 — Tier 2 (8+ hops)
```

---

## 4. Exécution des scripts

### Vérifications préalables

Avant de lancer les étapes, le pipeline vérifie :

1. **Privilèges root** (si scan réseau activé) — `os.geteuid() == 0`
2. **Dépendances** :
   - `nmap` (binaire système)
   - `traceroute` (binaire système)
   - `bloodhound` (module Python — `import bloodhound`)
   - `dnspython` (module Python — `import dns.resolver`)

### Lancement des sous-scripts

Chaque étape lance un sous-processus Python via `subprocess.run()` avec le même interpréteur que le pipeline (`sys.executable`). Cela garantit que le virtualenv est respecté.

```
  cmd = [sys.executable, str(script), "--data-dir", bh_dir, ...]
  subprocess.run(cmd, check=True)
```

### Résolution de bloodhound-python

Le pipeline cherche `bloodhound-python` dans le **même répertoire bin que le Python courant**, pas dans le PATH système. Cela garantit que le virtualenv est respecté même sous `sudo` (qui modifie le PATH).

```
  PYTHON_BIN_DIR = Path(sys.executable).parent
  bh_executable = PYTHON_BIN_DIR / "bloodhound-python"
  if not bh_executable.exists():
      bh_executable = shutil.which("bloodhound-python")   # fallback PATH
```

Le collecteur BloodHound produit un `.zip` automatiquement extrait dans `bloodhound_data/` puis supprimé.

### Options d'omission (skip)

| Flag                 | Effet                                            |
|----------------------|--------------------------------------------------|
| `--skip-network`     | Saute l'étape 1 (scan réseau)                    |
| `--skip-bloodhound`  | Saute l'étape 2 (utilise `--bh-dir` existant)    |
| `--skip-enrichment`  | Saute l'étape 3 (mapping hostname→IP)             |
| `--skip-certipy`     | Saute l'étape 4 (énumération ADCS)               |

**Cas spécial `x@x`** : Si `--start x@x` est passé (convention "network-only"), le pipeline saute la génération de graphes (Étape 5) car il n'y a pas de noeud de départ valide pour le BFS.

---

## 5. Le générateur multi-tiers (argus_graph.py)

### Rôle

`argus_graph.py` est un wrapper qui appelle `argus_builder.py` trois fois, une par tier :

```
  argus_graph.py
    │
    ├── mode 0  ──▶  argus_builder.py --mode 0  ──▶  graph_tier0.json
    ├── mode 1  ──▶  argus_builder.py --mode 1  ──▶  graph_tier1.json
    └── mode 2  ──▶  argus_builder.py --mode 2  ──▶  graph_tier2.json
```

### Contenu de chaque tier

| Mode | Fichier            | Contenu                                          |
|------|--------------------|--------------------------------------------------|
| 0    | `graph_tier0.json` | **Tous** les chemins vers Tier 0 (déterministe)  |
| 1    | `graph_tier1.json` | 30 chemins, distance BFS 1-7 hops                |
| 2    | `graph_tier2.json` | 40 chemins, ego-graph exploration (8+ hops)      |

Si `--certipy-json` est disponible, il est transmis à chaque invocation pour inclure les noeuds CertTemplate dans tous les tiers.

---

## 6. Modes d'accès et combinaisons

### Scénarios courants

**HTB / Lab — une seule machine :**
```
  sudo .env/bin/python3 argus_pipeline.py \
    --single-host --ip-cidr 10.10.11.42 \
    --gateway 10.10.11.42 --dns 10.10.11.42 \
    --domain corp.local --dc-ip 10.10.11.42 \
    --user admin --password 'pass' --start admin@corp.local --port-scan
```

**Réseau d'entreprise — scan complet :**
```
  sudo .env/bin/python3 argus_pipeline.py \
    --ip-cidr 192.168.1.0/24 --gateway 192.168.1.1 --dns 192.168.1.10 \
    --domain corp.local --dc-ip 192.168.1.10 \
    --user scanner --password 'secret' --start scanner@corp.local --port-scan
```

**Pivot via chisel — en deux passes :**
```
  # Phase 1 : collecte AD via SOCKS (pas besoin de sudo)
  proxychains4 -f pivot.conf .env/bin/python3 argus_pipeline.py \
    --skip-network --domain dante.local --dc-ip 172.16.1.20 \
    --user xadmin --password 'pass' --start xadmin@dante.local \
    --dns-tcp --output-dir results/dante

  # Phase 2 : scan réseau via SOCKS (besoin de sudo)
  sudo .env/bin/python3 argus_pipeline.py \
    --ip-cidr 172.16.1.0/24 --proxychains-conf pivot.conf \
    --targets 172.16.1.5,172.16.1.20,172.16.1.100 \
    --skip-bloodhound --bh-dir results/dante/bloodhound_data \
    --skip-certipy --output-dir results/dante \
    --domain x --dc-ip x --user x --password x --start x@x
```

**Ajout réseau à un scan AD existant :**
```
  sudo .env/bin/python3 argus_pipeline.py \
    --ip-cidr 10.0.1.0/24 --gateway 10.0.1.1 --dns 10.0.1.10 \
    --skip-bloodhound --bh-dir results/scan/bloodhound_data \
    --skip-certipy --output-dir results/scan \
    --domain x --dc-ip x --user x --password x --start x@x --port-scan
```

### Combinaison de scans individuels

Les scans individuels peuvent être combinés en utilisant le même `--output-dir`. Le pipeline détecte les fichiers existants :
- Si `network_scan.json` existe → le mapping utilise l'index SMB
- Si `certipy_data.json` existe d'une précédente exécution → réutilisé

---

## 7. Authentification et virtualenv

### Modes d'authentification

| Mode         | Flag CLI                  | Transmis à           |
|--------------|---------------------------|----------------------|
| Mot de passe | `--password 'P@ss'`       | BH, certipy, DNS     |
| Hash NTLM    | `-H 31d6cfe0d16...`      | BH, certipy          |

Le hash est transmis au format attendu par chaque outil :
- **bloodhound-python** : `--hashes aad3b435b51404eeaad3b435b51404ee:{NT}` (LM vide + NT hash)
- **certipy** : `-hashes :{NT}` (NT hash seul)

### Virtualenv et sudo

Le pipeline est conçu pour fonctionner avec `sudo` tout en utilisant le virtualenv Python :

```
  sudo .env/bin/python3 argus_pipeline.py ...
```

Le chemin absolu du Python du venv garantit que `sudo` utilise les dépendances installées dans le virtualenv et non le Python système.

---

## 8. Gestion des erreurs et résilience

### Étapes bloquantes vs non-bloquantes

| Étape            | En cas d'échec                              |
|------------------|---------------------------------------------|
| Scan réseau      | Avertissement + continue (AD still works)   |
| BloodHound       | **STOP** — pas de données AD = pas de graphe|
| Mapping          | Avertissement + continue (pas de liens hostname) |
| Certipy          | Avertissement + continue (pas de CertTemplates) |
| Génération graphe| Erreur finale reportée                      |

### Code de retour

Le pipeline retourne `0` si la génération de graphes réussit (ou est sautée intentionnellement), `1` sinon.
