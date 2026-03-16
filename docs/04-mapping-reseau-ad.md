# Mapping Réseau ↔ AD — Résolution hostname → IP

## Table des matières

1. [Contexte et objectifs](#1-contexte-et-objectifs)
2. [Mode direct — résolution DNS](#2-mode-direct--résolution-dns)
3. [Mode pivot — optimisation SMB](#3-mode-pivot--optimisation-smb)
4. [Schéma de décision](#4-schéma-de-décision)
5. [Limites](#5-limites)

---

## 1. Contexte et objectifs

ARGUS produit deux couches de données indépendantes :
- **Couche identité** (BloodHound) : objets AD identifiés par des hostnames (ex: `DC01.corp.local`)
- **Couche réseau** (argus_network.py) : machines identifiées par des IPs (ex: `10.0.1.10`)

Pour fusionner ces deux couches dans la cartographie, il faut associer chaque hostname AD à son adresse IP réseau.

```
  COUCHE IDENTITÉ (BloodHound)                                         COUCHE RÉSEAU (scan)
  ┌──────────────────────────────────────────┐                         ┌──────────────────────────────────────────┐
  │ DC01.corp.local                          │                         │ 10.0.1.10                                │
  │ SRV01.corp.local                         │              ?          │ 10.0.1.20                                │
  │ PC-ALICE.corp.local                      │ ───────────────────────▶│ 10.0.1.30                                │
  │ PC-BOB.corp.local                        │                         │ 10.0.2.15                                │
  └──────────────────────────────────────────┘                         └──────────────────────────────────────────┘

  Comment associer DC01.corp.local → 10.0.1.10 ?
```

Le module `argus_enrich.py` résout ce problème : il prend les hostnames des objets Computer BloodHound et trouve leur adresse IP. Le résultat est un fichier `hostname_mapping.json` utilisé par `cartographie.html` pour créer les ponts entre les noeuds Computer (AD) et les noeuds Machine (réseau).

---

## 2. Mode direct — résolution DNS

C'est le cas le plus courant. L'attaquant est sur le réseau, il a accès au DC qui est l'autorité DNS du domaine AD. La résolution est simple et fiable : une requête DNS de type A directement au DC pour chaque hostname.

```
  Pour chaque Computer BloodHound :

  argus_enrich.py → DNS A "DC01.corp.local"  → DC (10.0.1.10) → réponse : 10.0.1.10 ✔
  argus_enrich.py → DNS A "SRV01.corp.local" → DC (10.0.1.10) → réponse : 10.0.1.20 ✔
  argus_enrich.py → DNS A "PC-OLD.corp.local" → DC (10.0.1.10) → NXDOMAIN ✘ (machine supprimée de l'AD)
```

Le module utilise `dnspython` pour envoyer les requêtes directement au DC via `--dc-ip`, sans passer par `/etc/resolv.conf`. C'est la méthode la plus fiable : le DC connaît tous les enregistrements A de ses machines.

---

## 3. Mode pivot — optimisation SMB

En mode pivot, la résolution DNS fonctionne aussi (via `--dns-tcp` à travers le tunnel SOCKS), mais chaque requête doit traverser le tunnel, ce qui est lent (2-5 sec par hostname).

Pour accélérer, ARGUS exploite une donnée déjà collectée : pendant le scan pivot ([doc réseau, section 5](02-network.md)), nmap exécute le script `--script=smb-os-discovery` sur chaque cible. Ce script interroge le service SMB (port 445) et extrait le FQDN de la machine. Ces hostnames sont stockés dans le JSON du scan réseau.

`argus_enrich.py` construit un **index hostname → IP** à partir de ces données :

```
  Pendant le scan pivot, nmap a déjà collecté :
    10.0.1.10 → hostname SMB : "DC01.corp.local"
    10.0.1.20 → hostname SMB : "SRV01.corp.local"

  argus_enrich.py construit l'index inverse :
    "dc01.corp.local"  → 10.0.1.10
    "srv01.corp.local" → 10.0.1.20
```

Quand un Computer BloodHound doit être résolu, le module cherche d'abord dans cet index (instantané, lookup local). Si le hostname n'est pas dans l'index (machine non scannée ou port 445 filtré), il tombe en fallback sur le DNS via le tunnel.

C'est une **optimisation** : on réutilise des données déjà collectées pour éviter des requêtes réseau supplémentaires à travers le tunnel SOCKS.

---

## 4. Schéma de décision

```
  Pour chaque Computer BloodHound :
       │
       ├── Mode direct :
       │   │
       │   └── Requête DNS A vers DC (--dc-ip, UDP)
       │       ├── Réponse ────────────────────────────────────────────────────────────────────▶ IP trouvée ✔
       │       └── NXDOMAIN / timeout ─────────────────────────────────────────────────────────▶ Non résolu ✘
       │
       ├── Mode pivot :
       │   │
       │   ├── 1. Chercher dans l'index SMB (instantané, pas de requête réseau)
       │   │   └── Trouvé ─────────────────────────────────────────────────────────────────────▶ IP trouvée ✔
       │   │
       │   └── 2. Sinon : requête DNS A vers DC (--dns-tcp, via tunnel SOCKS)
       │       ├── Réponse ────────────────────────────────────────────────────────────────────▶ IP trouvée ✔
       │       └── NXDOMAIN / timeout ─────────────────────────────────────────────────────────▶ Non résolu ✘
       │
```

---

## 5. Limites

### Machines éteintes ou filtrées

Les machines qui ne répondent ni au DNS ni au SMB ne peuvent pas être résolues. Leur entrée dans le mapping aura `ips: []` et elles n'apparaîtront pas dans la couche réseau de la cartographie.

### Port 445 filtré (mode pivot)

Si le port SMB est filtré sur les cibles, l'index hostname sera vide et la résolution devra se faire entièrement par DNS via le tunnel (plus lent mais fonctionnel).

### Timeout

Le timeout par défaut est de 2 secondes par requête DNS. Via un tunnel SOCKS lent, `--timeout 5` peut être nécessaire.
