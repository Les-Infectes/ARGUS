<p align="center">
  <img src="img/logo.png" alt="ARGUS" width="400">
</p>
<h3 align="center">Cartographie Réseau & Objet Active Directory</h3>

ARGUS fusionne automatiquement l'infrastructure reseau (IPs, services, topologie) et le graphe d'identite Active Directory (utilisateurs, groupes, permissions, chemins d'attaque) dans une interface de visualisation interactive unique.

---

## Qu'est-ce qu'ARGUS ?

Dans un audit Active Directory, deux mondes coexistent sans se parler :

- **Le reseau** : des machines identifiees par leurs adresses IP, leurs ports ouverts, leurs services.
- **L'identite** : des utilisateurs, des groupes, des permissions — relies par des chemins d'attaque potentiels.

ARGUS est le pont entre ces deux mondes. A partir d'un compte utilisateur AD compromis, l'outil :

1. **Scanne le reseau** pour decouvrir les machines actives, les sous-reseaux et les services exposes.
2. **Collecte les donnees AD** via BloodHound (identites, ACLs, sessions) et Certipy (vulnerabilites ADCS).
3. **Classifie les objets AD en tiers** (Tier 0, 1, 2) selon leur proximite aux actifs critiques du domaine.
4. **Fusionne les deux couches** en reliant chaque machine reseau a son objet Computer AD correspondant.
5. **Visualise le tout** dans une cartographie interactive HTML — reseau en haut, identite en bas, ponts entre les deux.

---

## Cartographie

ARGUS produit une visualisation interactive a deux couches. La partie superieure affiche la topologie reseau (sous-reseaux, machines, passerelles). La partie inferieure affiche les chemins d'attaque AD avec les permissions entre objets. Les ponts relient les machines physiques a leurs objets Computer AD.

**Tier 0 — Forest (HTB)** : graphe complexe avec Exchange, groupes privilegies et multiples chemins d'escalade vers le domaine.

![Cartographie Tier 0 — Forest](img/exempleCarto1.png)

**Tier 0 — Administrator (HTB)** : chemin d'attaque lineaire emily → ethan → DCSync avec la couche reseau associee.

![Cartographie Tier 1 — Administrator](img/exempleCarto2.png)

**Wizard interactif** : interface CLI guidee avec choix des modes et des scans.

![Interface CLI — Wizard interactif](img/exempleCLI.png)

---

## Fonctionnalites

- **Mode direct et pivot** : acces direct au reseau cible ou a travers un tunnel SOCKS/proxychains.
- **Scan reseau** : decouverte ARP, traceroute, detection de services via nmap — adapte automatiquement les techniques selon le mode.
- **Collecte AD et ADCS** : integration BloodHound (identites, ACLs, sessions) et Certipy (vulnerabilites ESC1-ESC16).
- **Classification en 3 tiers** : Tier 0 deterministe (DC, Domain Admins, KRBTGT, Cert Publishers...), Tier 1 a proximite (1-7 hops), Tier 2 eloigne (8+ hops).
- **Fusion reseau/identite** : resolution DNS des hostnames AD vers les IPs pour creer les ponts dans la cartographie.
- **Wizard interactif** : interface CLI guidee pour construire les commandes sans memoriser les options.

---

## Quick Start

### Prerequis

- Python 3.8+
- `nmap` et `traceroute` installes (avec acces sudo pour le scan reseau)
- `bloodhound-python` et `certipy-ad` (collecteurs AD)

### Installation

```bash
git clone <repository-url> && cd argus
python3 -m venv .env
source .env/bin/activate
pip install -r requirements.txt
```

### Premier lancement

```bash
# Wizard interactif (recommande)
python3 argus.py

# Ou directement : scan AD + ADCS depuis un compte compromis
sudo .env/bin/python3 argus_pipeline.py \
    --domain corp.local \
    --dc-ip 10.0.1.10 \
    --user john.doe \
    --password 'P@ssw0rd' \
    --start "john.doe@corp.local" \
    --ip-cidr 10.0.1.0/24 \
    --gateway 10.0.1.1 \
    --dns 10.0.1.10 \
    --output-dir results/corp
```

### Visualisation

Ouvrir `cartographie.html` dans un navigateur (double-clic) et charger les fichiers generes (`network_scan.json`, `graph_tierX.json`, `hostname_mapping.json`) pour afficher la cartographie complete.

---

## Modes d'utilisation

### Mode direct

L'attaquant est directement connecte au reseau cible. ARGUS effectue une decouverte complete : ARP, traceroute, ICMP, scan de ports TCP. La resolution des hostnames AD se fait par requetes DNS directes au Domain Controller.

```bash
# Scan complet (reseau + AD + ADCS)
sudo .env/bin/python3 argus_pipeline.py \
    --ip-cidr 10.0.1.0/24 --gateway 10.0.1.1 --dns 10.0.1.10 \
    --domain corp.local --dc-ip 10.0.1.10 \
    --user john.doe --password 'P@ssw0rd' \
    --start "john.doe@corp.local"
```

### Mode pivot

L'attaquant accede au reseau cible a travers un tunnel SOCKS (proxychains). Le scan reseau est limite au TCP (`nmap -sT`) car proxychains intercepte les appels `connect()` via `LD_PRELOAD` — les raw sockets (ARP, ICMP, SYN) ne passent pas par le tunnel. Les IPs cibles doivent etre connues a l'avance.

```bash
# Passe 1 — AD + ADCS via proxychains
proxychains4 -f proxy.conf .env/bin/python3 argus_pipeline.py \
    --skip-network \
    --domain corp.local --dc-ip 10.0.1.10 --dc-hostname dc01.corp.local \
    --user john.doe -H ':<NT_HASH>' \
    --start "john.doe@corp.local" --dns-tcp \
    --output-dir results/corp

# Passe 2 — Scan reseau pivot (sudo, IPs connues)
sudo .env/bin/python3 argus_pipeline.py \
    --ip-cidr 10.0.1.0/24 \
    --proxychains-conf proxy.conf --targets '10.0.1.10,10.0.1.20,10.0.1.30' \
    --domain x --dc-ip x --user x --password x --start "x@x" \
    --skip-bloodhound --bh-dir results/corp/bloodhound_data \
    --skip-certipy --skip-enrichment \
    --output-dir results/corp
```

---

## Scripts

| Script | Role |
|--------|------|
| `argus.py` | Wizard interactif — point d'entree principal |
| `argus_pipeline.py` | Orchestrateur du pipeline complet |
| `argus_network.py` | Scan reseau (ARP, traceroute, ports) |
| `argus_enrich.py` | Resolution hostname AD → IP (DNS / SMB) |
| `argus_builder.py` | Generateur de graphes avec classification en tiers |
| `argus_graph.py` | Execution des 3 modes de tiers |
| `argus_certipy.py` | Traducteur Certipy → format ARGUS |

---

## Documentation

La documentation technique detaillee est disponible dans le dossier [docs/](docs/) :

| Document | Contenu |
|----------|---------|
| [01 — Pipeline](docs/01-pipeline.md) | Architecture et enchainement des etapes |
| [02 — Reseau](docs/02-network.md) | Algorithmes de decouverte reseau (direct et pivot) |
| [03 — Classification](docs/03-classification.md) | Algorithme de classification en tiers (SEED, CLOSURE, BFS) |
| [04 — Mapping](docs/04-mapping-reseau-ad.md) | Resolution hostname → IP (DNS, SMB) |
| [05 — Collecteurs](docs/05-collecteurs.md) | BloodHound et Certipy : collecte et traduction |
| [06 — Cartographie](docs/06-cartographie.md) | Interface de visualisation HTML |

---

## Dependances

| Paquet | Usage |
|--------|-------|
| `python-nmap` | Interface Python pour nmap |
| `bloodhound` | Collecteur BloodHound Python (LDAP + SMB) |
| `dnspython` | Resolution DNS directe vers le DC |
| `certipy-ad` | Enumeration ADCS (installe separement) |

Outils systeme requis : `nmap`, `traceroute`, `proxychains4` (mode pivot uniquement).

---

## Auteurs

- Laurent MINATCHY
- Maxime HERRY
- Albert BRAME

---

**ARGUS** — *Cartographie unifiee pour l'audit Active Directory*
