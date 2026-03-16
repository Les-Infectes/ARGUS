# Collecteurs AD et ADCS — BloodHound et Certipy

## Table des matières

1. [Contexte et objectifs](#1-contexte-et-objectifs)
2. [BloodHound Collector (bloodhound-python)](#2-bloodhound-collector-bloodhound-python)
3. [Certipy Collector (certipy-ad)](#3-certipy-collector-certipy-ad)
4. [Traduction certipy → format ARGUS (argus_certipy.py)](#4-traduction-certipy--format-argus-argus_certipypy)
5. [Résolution des principaux (name → SID)](#5-résolution-des-principaux-name--sid)
6. [Intégration avec argus_builder.py](#6-intégration-avec-argus_builderpy)
7. [Limites et cas particuliers](#7-limites-et-cas-particuliers)

---

## 1. Contexte et objectifs

### Contexte

ARGUS ne collecte pas lui-même les données Active Directory. Il s'appuie sur deux collecteurs externes qui interrogent le domaine via LDAP et SMB :

```
  ┌──────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │                                        DOMAINE ACTIVE DIRECTORY                                        │
  │                                                                                                        │
  │         LDAP (389/636)                         SMB (445)                             ADCS            │
  └──────────────┬──────────────────────────┬──────────────────────────────────────────────────┬────────────┘
                 │                          │                                                  │
                 ▼                          ▼                                                  ▼
  ┌────────────────────────┐    ┌────────────────────────┐                       ┌────────────────────────┐
  │  bloodhound-python     │    │  bloodhound-python     │                       │     certipy find       │
  │  (identité)            │    │  (sessions)            │                       │     (certificats)      │
  └───────────┬────────────┘    └───────────┬────────────┘                       └───────────┬────────────┘
              │                             │                                                │
              ▼                             ▼                                                ▼
  users.json                    computers.json                                       Certipy.json
  groups.json                   sessions                                             (format propre)
  domains.json                                                                             │
  gpos.json                                                                                ▼
  ous.json                                                                          argus_certipy.py
  containers.json                                                                   (traducteur)
                                                                                           │
                                                                                           ▼
                                                                                    certipy_data.json
                                                                                    (format BH-like)
```

### Pourquoi deux collecteurs ?

BloodHound collecte les objets AD classiques, y compris les templates de certificats (ce sont des objets AD dans `CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration`). Cependant, **BloodHound ne détecte pas les vulnérabilités ESC** sur ces templates — il se contente de lister les objets et leurs ACLs.

Certipy est un collecteur **spécialisé ADCS** qui analyse la configuration de chaque template et identifie directement les vulnérabilités (ESC1 à ESC16). Le résultat est déjà interprété : pas besoin de traiter les données brutes, on obtient directement la liste des templates exploitables.

---

## 2. BloodHound Collector (bloodhound-python)

### Fonctionnement

`bloodhound-python` est un collecteur Python qui interroge le domaine via plusieurs protocoles :

```
  ┌──────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │  PROTOCOLE              DONNÉES COLLECTÉES                                                             │
  ├──────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │  LDAP (389/636)         Users, Groups, Computers, GPOs, OUs, Containers, Domains, Trusts,              │
  │                         CertTemplates + ACLs (DACLs de chaque objet)                                   │
  │                                                                                                        │
  │  SMB (445)              Sessions actives sur les machines (qui est connecté où),                        │
  │                         admins locaux, Remote Desktop Users, DCOM Users                                │
  │                                                                                                        │
  │  DNS                    Résolution de noms pour joindre les DCs                                        │
  └──────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### Données collectées — les fichiers JSON

Le collecteur produit un fichier JSON par type d'objet :

| Fichier            | Contenu                                               |
|--------------------|-------------------------------------------------------|
| `*_users.json`     | Comptes utilisateurs + propriétés + ACEs              |
| `*_groups.json`    | Groupes + membres + ACEs                              |
| `*_computers.json` | Machines + propriétés (OS, enabled) + ACEs            |
| `*_domains.json`   | Domaines + trusts + GPO links                         |
| `*_gpos.json`      | Group Policy Objects + ACEs                           |
| `*_ous.json`       | Organizational Units + liens GPO + ACEs               |
| `*_containers.json`| Containers AD + ACEs                                  |

Chaque fichier a la structure `{ "meta": {...}, "data": [...] }`. Le préfixe `*` est un timestamp (ex: `20260118185834`).

### Structure d'un objet BloodHound

```json
{
  "ObjectIdentifier": "S-1-5-21-...-1104",
  "Properties": {
    "name": "JOHN.DOE@CORP.LOCAL",
    "domain": "CORP.LOCAL",
    "samaccountname": "john.doe",
    "enabled": true,
    "admincount": false,
    "pwdneverexpires": false,
    "lastlogontimestamp": 133512345678900000
  },
  "Aces": [
    {
      "PrincipalSID": "S-1-5-21-...-512",
      "PrincipalType": "Group",
      "RightName": "GenericAll",
      "IsInherited": false
    }
  ],
  "Members": [ ... ],
  "SPNTargets": [ ... ]
}
```

### Permissions collectées (RightName)

BloodHound résout les ACEs binaires du DACL en edges nommés. Voici les 15 RightNames distincts exportés :

```
  ┌──────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │  DROITS GÉNÉRIQUES                                  DROITS ÉTENDUS                                     │
  ├──────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │  GenericAll                                         ForceChangePassword                                │
  │  GenericWrite                                       AllExtendedRights                                  │
  │  WriteDacl                                          AddKeyCredentialLink                               │
  │  WriteOwner                                         WriteAccountRestrictions                           │
  │  Owns                                               ReadLAPSPassword                                   │
  │                                                     ReadGMSAPassword                                   │
  ├──────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │  DROITS D'ÉCRITURE                                  DROITS ADCS                                        │
  ├──────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │  AddMember (WriteMember)                            Enroll                                             │
  │                                                     AutoEnroll                                         │
  └──────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

**Important** : BloodHound ne résout que 3 GUIDs WriteProperty en edges distincts (AddKeyCredentialLink, WriteAccountRestrictions, AddMember). Les autres WriteProperty sont regroupés sous `GenericWrite` — voir `03-classification.md` §8.5 pour le détail.

### Invocation dans le pipeline

```
  bloodhound-python \
    -u user@domain.local \
    -d domain.local \
    -ns 10.0.1.10 \            # DNS = DC IP
    -c All \                    # Collecter toutes les catégories
    --zip                       # Produire un .zip
```

Le pipeline extrait automatiquement le `.zip` dans `bloodhound_data/`.

---

## 3. Certipy Collector (certipy-ad)

### Fonctionnement

`certipy` (paquet `certipy-ad`) énumère l'infrastructure ADCS du domaine : Certificate Authorities (CA), templates de certificats, et leurs permissions.

```
  certipy find -json -vulnerable \
    -u user@domain.local \
    -dc-ip 10.0.1.10 \
    -timeout 10
```

L'option `-vulnerable` filtre pour ne garder que les templates présentant des vulnérabilités connues (ESC1 à ESC16).

### Données collectées

La sortie JSON de certipy contient :

```
  Certipy.json
  ├── Certificate Authorities
  │   └── CA name, hostname, permissions...
  │
  └── Certificate Templates
      ├── Template Name, Display Name
      ├── Enabled, Schema Version
      ├── Client Authentication (PKINIT)
      ├── Enrollee Supplies Subject (SAN → ESC1)
      ├── Extended Key Usage
      ├── [!] Vulnerabilities → ESC1, ESC4, ...
      └── Permissions
          ├── Enrollment Permissions
          │   ├── Enrollment Rights → [DOMAIN\Domain Users, ...]
          │   └── All Extended Rights → [...]
          └── Object Control Permissions
              ├── Owner → DOMAIN\Enterprise Admins
              ├── Full Control Principals → [...]
              ├── Write Owner Principals → [...]
              ├── Write Dacl Principals → [...]
              └── Write Property * → [...]
```

### Vulnérabilités ESC

| ESC   | Condition                                            | Impact                    |
|-------|------------------------------------------------------|---------------------------|
| ESC1  | Enrollee Supplies Subject + Client Auth              | Usurpation d'identité    |
| ESC2  | Any Purpose EKU + Client Auth                        | Usurpation d'identité    |
| ESC3  | Certificate Request Agent EKU                        | Enrollment pour autrui   |
| ESC4  | Write sur le template (WriteDacl/WriteOwner/GenAll)  | Modifier → ESC1          |
| ESC8  | HTTP enrollment endpoint (Web Enrollment)            | NTLM relay → cert        |

---

## 4. Traduction certipy → format ARGUS (argus_certipy.py)

### Le problème

Certipy produit un JSON dans son propre format, incompatible avec `argus_builder.py` qui attend des noeuds au format BloodHound.

### La solution

`argus_certipy.py` traduit chaque template vulnérable en un noeud `CertTemplate` avec des edges ACE au format BloodHound :

```
  certipy JSON                                                    certipy_data.json
  ┌──────────────────────────────────────────────┐                ┌──────────────────────────────────────────────┐
  │ Template "CorpVPN"                           │                │ ObjectIdentifier:                            │
  │   ESC1                                       │   traduction   │   certtemplate-CorpVPN                       │
  │   Enrollment Rights:                         │ ─────────────▶ │ Properties:                                  │
  │     DOMAIN\DomUsers                          │                │   name: CorpVPN [ESC1]                       │
  │   Full Control:                              │                │ Aces:                                        │
  │     DOMAIN\EntAdmins                         │                │   [{SID, Enroll}, {SID, GenericAll}]         │
  └──────────────────────────────────────────────┘                └──────────────────────────────────────────────┘
```

### Mapping des permissions certipy → RightName ARGUS

```
  ┌──────────────────────────────────────────────────────────┬──────────────────────────────────────────────┐
  │  Catégorie certipy                                       │  RightName ARGUS                             │
  ├──────────────────────────────────────────────────────────┼──────────────────────────────────────────────┤
  │  Enrollment Rights                                       │  Enroll                                      │
  │  All Extended Rights                                     │  AllExtendedRights                           │
  │  Full Control Principals                                 │  GenericAll                                  │
  │  Write Owner Principals                                  │  WriteOwner                                  │
  │  Write Dacl Principals                                   │  WriteDacl                                   │
  │  Owner                                                   │  Owns                                        │
  │  Write Property Enroll                                   │  Enroll                                      │
  │  Write Property AutoEnroll                               │  AutoEnroll                                  │
  │  Write Property (autre)                                  │  GenericWrite                                │
  └──────────────────────────────────────────────────────────┴──────────────────────────────────────────────┘
```

### Deux modes d'utilisation

| Mode                   | Cas d'usage                              | Commande                          |
|------------------------|------------------------------------------|-----------------------------------|
| **Parse existant**     | Certipy déjà exécuté, JSON disponible    | `--certipy-json results/Cert.json`|
| **Run + parse**        | Exécuter certipy puis parser             | `--domain ... --username ...`     |

---

## 5. Résolution des principaux (name → SID)

### Le problème de traduction

Certipy identifie les principaux au format `DOMAIN\samAccountName` (ex: `SEQUEL\Domain Admins`). ARGUS travaille avec des **ObjectIdentifiers** BloodHound (SIDs, ex: `S-1-5-21-...-512`). Il faut un index de traduction.

### Construction de l'index (`build_name_to_sid`)

La fonction parcourt **tous les fichiers JSON** du dossier BloodHound et indexe chaque objet par plusieurs clés (tout en lowercase) :

```
  Objet BH :
    ObjectIdentifier = "S-1-5-21-...-512"
    Properties.name = "DOMAIN ADMINS@SEQUEL.HTB"
    Properties.samaccountname = "Domain Admins"
    Properties.domain = "SEQUEL.HTB"

  Index :
    "domain admins@sequel.htb"     → "S-1-5-21-...-512"
    "sequel.htb\domain admins"     → "S-1-5-21-...-512"
    "domain admins@sequel.htb"     → "S-1-5-21-...-512"
```

### Résolution en 3 étapes (`resolve_principal`)

```
  Certipy donne : "SEQUEL\Domain Admins"
       │
       ├── 1. Recherche directe : "sequel\domain admins" → trouvé ? ✔
       ├── 2. Conversion BH :     "DOMAIN ADMINS@SEQUEL" → trouvé ? ✔
       └── 3. Recherche partielle : "domain admins" dans toutes les clés
             (fallback si domaine NetBIOS ≠ FQDN)
```

---

## 6. Intégration avec argus_builder.py

### Cycle de vie d'un CertTemplate dans ARGUS

```
  1. CHARGEMENT
     argus_builder.py lit certipy_data.json → crée des noeuds de type "CertTemplate"
     → crée des edges ACE (Enroll, GenericAll...) vers les SIDs BH

  2. CLASSIFICATION (Phase 1 — SEED)
     Template avec vulnérabilité ESC → Tier 0 direct (critère 6)
     Les ca_names identifient les machines Enterprise CA → Tier 0 (critère 8)

  3. INCLUSION DANS LE GRAPHE
     Les CertTemplates Tier 0 sont forcément inclus dans le graphe de sortie, même non atteignables par BFS depuis le noeud start

  4. VISUALISATION
     Noeuds CertTemplate affichés en magenta (#e879f9)
```

### Exemple concret : ESC1 sur Escape (HTB)

```
  ryan.cooper
       │ MemberOf
       ▼
  Domain Users (S-1-5-...-513)
       │ Enroll                    ◄── edge depuis certipy_data.json
       ▼
  CorpVPN [ESC1]                   ◄── CertTemplate, Tier 0
```

Le chemin d'attaque ESC1 est **implicite** : il nécessite `MachineAccountQuota > 0` pour ajouter un ordinateur, puis s'inscrire au template en spécifiant un SAN arbitraire (ex: `Administrator`).

---

## 7. Limites et cas particuliers

### BloodHound Collector

- **Sessions** : Les données de sessions (`HasSession`) sont un snapshot à un instant T. Une session peut avoir expiré entre la collecte et l'analyse.
- **ACLs héritées** : Le collecteur marque `IsInherited` mais ARGUS les traite de la même façon que les ACLs directes.
- **GenericWrite** : Regroupe des WriteProperty critiques et inoffensifs sous le même nom (voir `03-classification.md` §8.5).

### Certipy

- **Principaux non résolus** : Si un principal certipy n'existe pas dans les données BloodHound, l'edge ACE est silencieusement ignoré.
- **Templates sans vulnérabilité** : Ignorés — seuls les templates exploitables apparaissent dans le graphe.
- **Prompt "Overwrite?"** : Certipy demande confirmation avant d'écraser un fichier. Le module supprime le fichier existant avant lancement.
- **Authentification par hash** : Supporté via `--hashes` (format `:{NT}`).
