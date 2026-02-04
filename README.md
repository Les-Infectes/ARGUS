# CartoAD — Cartographie Unifiee Reseau & Identite AD

**CartoAD** est un outil de cartographie qui fusionne dans une interface interactive :
- **Cartographie reseau** : infrastructure physique (IP, MAC, services, topologie)
- **Cartographie Active Directory** : identites, permissions, chemins d'attaque

## Innovation

Premiere solution open source fusionnant automatiquement :
- Infrastructure physique (scan reseau nmap)
- Graphe identite (analyse BloodHound)
- Ponts intelligents (Computer AD <-> Machine reseau)

---

## Structure du projet

```
cartographie/
├── run_full_scan.py              # Pipeline complet (une seule commande)
├── global_network_scan_classeC.py   # Scan reseau classe C
├── global_network_scan_classeAB.py  # Scan reseau classe A/B
├── enrich_network_mapping.py     # Mapping hostname -> IP
├── graph_builder.py              # Generateur de graphes tier-based
├── run_all_modes.py              # Lance les 4 modes d'analyse
├── cartographie.html             # Interface de visualisation
├── results/                      # Fichiers JSON generes
├── bh/                           # Donnees BloodHound (input)
├── requirements.txt              # Dependances Python
└── TECHNICAL.md                  # Documentation technique
```

---

## Installation

### Pre-requis
- Python 3.8+
- nmap, traceroute (avec sudo)
- bloodhound-python

### Installation

```bash
# 1. Creer environnement virtuel
python3 -m venv .env
source .env/bin/activate

# 2. Installer dependances
pip install -r requirements.txt

# 3. Verifier nmap
nmap --version
```

---

## Usage

### Pipeline complet (recommande)

Une seule commande pour executer tout le workflow :

```bash
# IMPORTANT: Utiliser le Python du virtualenv avec sudo
sudo .env/bin/python3 run_full_scan.py \
    --ip-cidr 192.168.30.0/24 \
    --gateway 192.168.30.1 \
    --dns 192.168.30.254 \
    --domain domain.local \
    --dc-ip 192.168.30.254 \
    --user admin \
    --password 'P@ssw0rd' \
    --start "admin@domain.local" \
    --port-scan
```

**Etapes executees automatiquement** :
1. Scan reseau -> `network_scan.json`
2. Collecte BloodHound -> `bloodhound_data/`
3. Mapping hostname -> `hostname_mapping.json`
4. Generation graphes -> `graph_tier0.json` ... `graph_tier3.json`

**Options** :
| Option | Description |
|--------|-------------|
| `--skip-network` | Sauter le scan reseau |
| `--skip-bloodhound --bh-dir <path>` | Utiliser des donnees BH existantes |
| `--skip-enrichment` | Sauter le mapping hostname |
| `--output-dir <path>` | Dossier de sortie |
| `--port-scan` | Activer le scan de ports |
| `--port-list "22,80,443"` | Ports specifiques |

---

### Scripts individuels

#### 1. Scan reseau

**Classe C** (192.168.x.0/24) :
```bash
sudo python3 global_network_scan_classeC.py \
    --ip_cidr 192.168.30.0/24 \
    --gateway 192.168.30.1 \
    --dns 192.168.30.254 \
    --port-scan \
    --output results/network_scan.json
```

**Classe A/B** (10.0.0.0/8) :
```bash
sudo python3 global_network_scan_classeAB.py \
    --ip_cidr 10.100.50.0/20 \
    --gateway 10.100.50.1 \
    --dns 10.100.50.2 \
    --port-scan \
    --output results/network_scan.json
```

#### 2. Collecte BloodHound

```bash
bloodhound-python -u user@domain.local -p password \
    -d domain.local -ns 192.168.30.254 -c All --zip

mkdir -p bh/jsonBoxDomain
unzip *_bloodhound.zip -d bh/jsonBoxDomain/
```

#### 3. Mapping hostname -> IP

```bash
python3 enrich_network_mapping.py \
    --bh-dir bh/jsonBoxDomain \
    --dc-ip 192.168.30.254 \
    --domain domain.local \
    --output results/hostname_mapping.json
```

#### 4. Generation des graphes

**Tous les tiers** :
```bash
python3 run_all_modes.py \
    --data-dir bh/jsonBoxDomain \
    --start "user@domain.local" \
    --output-dir results
```

**Un seul tier** :
```bash
python3 graph_builder.py \
    --data-dir bh/jsonBoxDomain \
    --start "user@domain.local" \
    --mode 0 \
    --out results/graph_tier0.json
```

---

## Les 4 modes d'analyse

| Mode | Tier | Chemins | Cibles | Cas d'usage |
|------|------|---------|--------|-------------|
| 0 | Tier 0 | Tous | Domain, DCs, DA, KRBTGT | Pentest rapide |
| 1 | Tier 1 | 30 | Comptes hauts privileges (1-2 hops) | Escalade |
| 2 | Tier 2 | 30 | Serveurs/postes (3-5 hops) | Mouvement lateral |
| 3 | Tier 3 | 40 | Objets isoles (6+ hops) | Vue exhaustive |

---

## Visualisation

```bash
python3 -m http.server 8000
# Ouvrir http://localhost:8000/cartographie.html
```

**Etapes** :
1. Charger `network_scan.json` (reseau)
2. Charger `hostname_mapping.json` (optionnel, ameliore les ponts)
3. Charger un ou plusieurs `graph_tierX.json` (AD) - selection multiple possible
4. Utiliser les boutons Tier 0/1/2/3 pour switcher rapidement entre les tiers
5. Cliquer "Afficher AD" pour activer/desactiver l'overlay

**Changement de tier rapide** :
- Charger plusieurs fichiers tier en une seule selection (Ctrl+clic)
- Les boutons Tier apparaissent automatiquement
- Cliquer sur un tier pour switcher sans recharger le reseau

**Organisation visuelle** :
- Partie haute : Cartographie reseau (IP, MAC, services)
- Partie basse : Chemins AD (identites, permissions)
- Ponts : Liens entre machines physiques et Computer AD

---

## Workflow pentest

```bash
# 1. Pipeline complet (utiliser le Python du virtualenv)
sudo .env/bin/python3 run_full_scan.py \
    --ip-cidr 192.168.30.0/24 \
    --gateway 192.168.30.1 \
    --dns 192.168.30.254 \
    --domain domain.local \
    --dc-ip 192.168.30.254 \
    --user compromised.user \
    --password 'P@ssw0rd' \
    --start "compromised.user@domain.local" \
    --port-scan

# 2. Visualisation
python3 -m http.server 8000

# 3. Analyse des resultats
cat results/*/graph_tier0.json | jq '.tier_classification'
cat results/*/graph_tier0.json | jq '.paths[0]'
```

---

## Documentation technique

Voir [TECHNICAL.md](TECHNICAL.md) pour :
- Algorithmes de scan reseau
- Collecte BloodHound et donnees AD
- Algorithme de mapping hostname/IP
- Classification Tier et calcul des chemins
- Fusion reseau/identite dans l'UI

---

## Licence

A definir (GPL/MIT/Apache)

**CartoAD** - *Cartographie Unifiee pour la Cybersecurite*
