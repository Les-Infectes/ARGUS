# Commandes CLI — ARGUS

L'interface graphique (`argus_server.py`) couvre toutes les fonctionnalités d'ARGUS. Cette page documente les commandes backend pour ceux qui préfèrent travailler en ligne de commande.

---

## Scripts

| Script | Rôle |
|--------|------|
| `argus_server.py` | Serveur web Flask — interface graphique |
| `argus_pipeline.py` | Orchestrateur du pipeline complet (scan + collecte + graphes) |
| `argus_network.py` | Scan réseau (ARP, traceroute, ports) |
| `argus_enrich.py` | Résolution hostname AD → IP (DNS / SMB) |
| `argus_builder.py` | Classification en tiers et génération de graphes |
| `argus_graph.py` | Exécution des 3 modes de tiers (0, 1, 2) |
| `argus_certipy.py` | Traducteur Certipy → format ARGUS |
| `argus_import.py` | Import de scans externes (nmap XML + BloodHound) |

---

## Import

Générer des cartographies à partir de données existantes, sans lancer de scan.

### AD seul

Générer les chemins d'attaque à partir de données BloodHound (collectées avec n'importe quel outil).

```bash
python3 argus_graph.py \
    --data-dir bloodhound_data/ \
    --start user@domain.local \
    --output-dir results/import
```

Avec analyse ADCS (Certipy) :

```bash
python3 argus_graph.py \
    --data-dir bloodhound_data/ \
    --start user@domain.local \
    --certipy-json certipy.json \
    --output-dir results/import
```

**Fichiers générés** : `graph_tier0.json`, `graph_tier1.json`, `graph_tier2.json`

### Réseau seul

Convertir un fichier nmap XML en cartographie réseau ARGUS.

```bash
python3 argus_import.py \
    --nmap-xml scan.xml \
    --output-dir results/import
```

**Fichier généré** : `network_scan.json`

### Import complet (réseau + AD)

Fusionner nmap XML et données BloodHound dans une cartographie unifiée.

```bash
python3 argus_import.py \
    --nmap-xml scan.xml \
    --bh-dir bloodhound_data/ \
    --start user@domain.local \
    --output-dir results/import
```

Avec mapping hostname (nécessite un accès au DC) :

```bash
python3 argus_import.py \
    --nmap-xml scan.xml \
    --bh-dir bloodhound_data/ \
    --start user@domain.local \
    --dc-ip 10.0.1.10 \
    --output-dir results/import
```

Mapping via pivot (DNS en TCP via proxychains) :

```bash
python3 argus_import.py \
    --nmap-xml scan.xml \
    --bh-dir bloodhound_data/ \
    --start user@domain.local \
    --dc-ip 10.0.1.10 \
    --dns-tcp \
    --proxychains-conf proxy.conf \
    --output-dir results/import
```

**Fichiers générés** : `network_scan.json`, `graph_tier0/1/2.json`, `hostname_mapping.json` (si mapping activé)

---

## Scan — Mode direct

L'attaquant est directement connecté au réseau cible. Les commandes utilisent `argus_pipeline.py` qui orchestre les différentes étapes automatiquement.

### DC seul

Scan de ports + collecte AD + ADCS sur une seule machine (le DC).

```bash
sudo .env/bin/python3 argus_pipeline.py \
    --single-host \
    --ip-cidr 10.10.11.42 \
    --gateway 10.10.11.42 --dns 10.10.11.42 \
    --domain corp.local --dc-ip 10.10.11.42 \
    --user john.doe --password 'P@ssw0rd' \
    --start "john.doe@corp.local" \
    --port-scan \
    --output-dir results/corp
```

### Réseau seul

Découverte réseau (ARP, traceroute, ports). Pas d'authentification AD.

```bash
sudo .env/bin/python3 argus_pipeline.py \
    --ip-cidr 192.168.1.0/24 \
    --gateway 192.168.1.1 --dns 192.168.1.10 \
    --domain x --dc-ip x --user x --password x --start "x@x" \
    --skip-bloodhound --skip-certipy --skip-enrichment \
    --port-scan \
    --output-dir results/corp
```

> Les flags `--domain x --dc-ip x ...` sont des valeurs factices requises par argparse mais non utilisées quand les étapes AD sont skippées.

### AD / ADCS seul

Collecte BloodHound + Certipy. Pas de scan réseau.

```bash
sudo .env/bin/python3 argus_pipeline.py \
    --skip-network \
    --domain corp.local --dc-ip 10.0.1.10 \
    --user john.doe --password 'P@ssw0rd' \
    --start "john.doe@corp.local" \
    --output-dir results/corp
```

Avec NT hash au lieu du mot de passe :

```bash
sudo .env/bin/python3 argus_pipeline.py \
    --skip-network \
    --domain corp.local --dc-ip 10.0.1.10 \
    --user john.doe -H '649f65073a6672a9898cb4eb61f9684a' \
    --start "john.doe@corp.local" \
    --output-dir results/corp
```

### Complet — DC et AD

Scan du DC + collecte AD/ADCS + mapping. Idéal quand seul le DC est accessible.

```bash
sudo .env/bin/python3 argus_pipeline.py \
    --single-host \
    --ip-cidr 10.0.1.10 \
    --gateway 10.0.1.10 --dns 10.0.1.10 \
    --domain corp.local --dc-ip 10.0.1.10 \
    --user john.doe --password 'P@ssw0rd' \
    --start "john.doe@corp.local" \
    --port-scan \
    --output-dir results/corp
```

### Complet — Réseau et AD

Scan de tout le sous-réseau + collecte AD/ADCS + mapping. Cartographie complète.

```bash
sudo .env/bin/python3 argus_pipeline.py \
    --ip-cidr 192.168.1.0/24 \
    --gateway 192.168.1.1 --dns 192.168.1.10 \
    --domain corp.local --dc-ip 192.168.1.10 \
    --user john.doe --password 'P@ssw0rd' \
    --start "john.doe@corp.local" \
    --port-scan \
    --output-dir results/corp
```

### Réseau + mapping AD existant

Scan réseau + liaison avec des données BloodHound déjà collectées.

```bash
sudo .env/bin/python3 argus_pipeline.py \
    --ip-cidr 192.168.1.0/24 \
    --gateway 192.168.1.1 --dns 192.168.1.10 \
    --domain x --dc-ip x --user x --password x --start "x@x" \
    --skip-bloodhound --bh-dir results/corp/bloodhound_data \
    --skip-certipy \
    --port-scan \
    --output-dir results/corp
```

Machine unique :

```bash
sudo .env/bin/python3 argus_pipeline.py \
    --single-host \
    --ip-cidr 10.0.1.10 \
    --gateway 10.0.1.10 --dns 10.0.1.10 \
    --domain x --dc-ip x --user x --password x --start "x@x" \
    --skip-bloodhound --bh-dir results/corp/bloodhound_data \
    --skip-certipy \
    --port-scan \
    --output-dir results/corp
```

---

## Scan — Mode pivot

L'attaquant passe par un tunnel SOCKS (proxychains). Le scan est en 2 passes car le proxy SOCKS ne transporte que du TCP.

### Passe 1 — Collecte AD + ADCS via proxychains

```bash
proxychains4 -f proxy.conf .env/bin/python3 argus_pipeline.py \
    --skip-network \
    --domain corp.local --dc-ip 172.16.1.20 \
    --dc-hostname dc01.corp.local \
    --user john.doe -H '649f65073a6672a9898cb4eb61f9684a' \
    --start "john.doe@corp.local" \
    --dns-tcp \
    --output-dir results/corp
```

### Passe 2 — Scan réseau via proxychains

```bash
sudo .env/bin/python3 argus_pipeline.py \
    --ip-cidr 172.16.1.20 \
    --domain x --dc-ip x --user x --password x --start "x@x" \
    --proxychains-conf proxy.conf \
    --targets '172.16.1.5,172.16.1.20,172.16.1.100' \
    --skip-bloodhound --bh-dir results/corp/bloodhound_data \
    --skip-certipy --skip-enrichment \
    --output-dir results/corp
```

> Les deux passes utilisent le même `--output-dir` pour fusionner les résultats.

---

## Référence des flags

### argus_pipeline.py

| Flag | Description |
|------|-------------|
| `--domain` | Nom du domaine AD |
| `--dc-ip` | Adresse IP du Domain Controller |
| `--dc-hostname` | FQDN du DC (recommandé en mode pivot) |
| `--user` | Nom d'utilisateur AD |
| `--password` | Mot de passe |
| `-H` | NT hash (alternative au mot de passe) |
| `--start` | Nœud de départ pour l'analyse de chemins |
| `--ip-cidr` | Plage réseau cible (ex: 192.168.1.0/24) |
| `--gateway` | Passerelle réseau |
| `--dns` | Serveur DNS (généralement le DC) |
| `--single-host` | Scan d'une seule machine (pas de découverte réseau) |
| `--port-scan` | Activer le scan de ports TCP (top-100) |
| `--port-list` | Liste de ports personnalisée (ex: "22,80,445") |
| `--skip-network` | Passer l'étape scan réseau |
| `--skip-bloodhound` | Passer la collecte BloodHound |
| `--skip-certipy` | Passer la collecte Certipy |
| `--skip-enrichment` | Passer le mapping hostname |
| `--bh-dir` | Répertoire de données BloodHound existant |
| `--dns-tcp` | Résolution DNS en TCP (mode pivot) |
| `--proxychains-conf` | Fichier de configuration proxychains4 |
| `--targets` | Liste d'IPs cibles (mode pivot, séparées par des virgules) |
| `--output-dir` | Répertoire de sortie |

### argus_graph.py

| Flag | Description |
|------|-------------|
| `--data-dir` | Répertoire contenant les JSON BloodHound |
| `--start` | Nœud de départ |
| `--certipy-json` | Fichier JSON Certipy (optionnel) |
| `--output-dir` | Répertoire de sortie |

### argus_import.py

| Flag | Description |
|------|-------------|
| `--nmap-xml` | Fichier XML nmap (-oX) |
| `--bh-dir` | Répertoire BloodHound (optionnel) |
| `--start` | Nœud de départ (requis avec --bh-dir) |
| `--certipy-json` | Fichier JSON Certipy (optionnel) |
| `--dc-ip` | IP du DC pour le mapping hostname (optionnel) |
| `--dns-tcp` | DNS en TCP (pivot) |
| `--proxychains-conf` | Config proxychains (pivot) |
| `--output-dir` | Répertoire de sortie |
