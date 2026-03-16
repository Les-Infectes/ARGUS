# Visualisation — ARGUS (cartographie.html)

## Table des matières

1. [Contexte et objectifs](#1-contexte-et-objectifs)
2. [Choix technologiques](#2-choix-technologiques)
3. [Architecture de la page](#3-architecture-de-la-page)
4. [Couche réseau — construction du graphe](#4-couche-réseau--construction-du-graphe)
5. [Couche identité AD — intégration du graphe](#5-couche-identité-ad--intégration-du-graphe)
6. [Fusion des deux couches (bridges)](#6-fusion-des-deux-couches-bridges)
7. [Interactions utilisateur](#7-interactions-utilisateur)
8. [Conventions visuelles](#8-conventions-visuelles)

---

## 1. Contexte et objectifs

### Contexte

ARGUS produit des fichiers JSON structurés : graphes de tiers (chemins d'attaque AD), scans réseau (topologie IP), mappings hostname. Ces données sont exploitables programmatiquement, mais un auditeur a besoin d'une **visualisation interactive** pour :
- comprendre la topologie réseau et les chemins d'attaque en un coup d'oeil,
- présenter les résultats à un client ou une équipe sécurité,
- explorer interactivement les relations entre objets AD.

### Problème

Les outils existants (BloodHound GUI, Neo4j) nécessitent une installation lourde (base de données, application desktop) et ne combinent pas les couches réseau et identité. On voulait créer un outil de visualisation **simple et portable** qui fonctionne sur n'importe quelle machine.

### Solution : un fichier HTML autonome

```
  ┌──────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │  cartographie.html                                                                                       │
  │                                                                                                          │
  │  Ouvrir dans un navigateur → visualisation immédiate                                                     │
  │                                                                                                          │
  │  Pas de backend    ·    Pas d'installation    ·    Pas de base de données    ·    Un seul fichier         │
  └──────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Choix technologiques

### Pourquoi un fichier HTML ?

| Critère            | HTML standalone          | Application desktop       | Webapp + backend          |
|--------------------|--------------------------|---------------------------|---------------------------|
| **Portabilité**    | Tout OS avec navigateur  | Installation requise      | Serveur à déployer        |
| **Déploiement**    | Copier 1 fichier         | Installer + configurer    | Docker / serveur          |
| **Partage**        | Envoyer par mail/Teams   | Impossible sans install   | Donner l'URL              |
| **Offline**        | Fonctionne partout       | Oui                       | Non                       |
| **Prérequis**      | Navigateur (tout le monde en a un) | Runtime spécifique | Serveur + réseau  |

En pentest, on travaille souvent sur des VMs temporaires, des machines de lab, ou directement chez le client. Le fichier HTML se copie, s'ouvre, et fonctionne. Pas besoin de demander au client d'installer quoi que ce soit pour voir les résultats.

### Pourquoi Cytoscape.js ?

Pour afficher des graphes interactifs dans un navigateur, plusieurs bibliothèques existent :

| Bibliothèque   | Type          | Avantage                        | Inconvénient                    |
|-----------------|---------------|----------------------------------|---------------------------------|
| **Cytoscape.js**| Graph dédié   | Conçu pour les graphes, layouts  | Moins de graphiques généraux    |
|                 |               | intégrés, performant (1000+ noeuds) |                              |
| D3.js           | Généraliste   | Très flexible, communauté large  | Bas niveau, tout à coder        |
| vis.js          | Graph dédié   | Simple, bon rendu                | Moins performant sur gros graphs|
| Sigma.js        | Graph dédié   | Performant (WebGL)               | API moins intuitive             |

Cytoscape.js a été choisi car :
- **Layouts intégrés** : algorithmes de positionnement (BFS, grid, force) prêts à l'emploi, essentiels pour disposer les noeuds sans chevauchement
- **API graphe native** : sélecteurs CSS-like sur les noeuds/edges, events, compound nodes (groupes)
- **Performance** : gère plusieurs centaines de noeuds sans problème dans un navigateur
- **Pas de dépendance** : un seul fichier JS chargé via CDN

### Architecture zéro-build

```
  ┌──────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │  cartographie.html                                                                                       │
  │  ├── <style>           CSS intégré (JetBrains Mono, palette, layout)                                     │
  │  ├── <body>            Toolbar + zone graphe + tooltips                                                  │
  │  └── <script>                                                                                            │
  │      ├── Cytoscape.js        (CDN: unpkg.com)                                                            │
  │      └── Code ARGUS          (~1000 lignes JS vanilla)                                                   │
  │          ├── Parsing JSON              (réseau, AD, mapping)                                              │
  │          ├── Construction noeuds/edges (éléments Cytoscape)                                               │
  │          ├── Détection de rôle         (DC, serveur, poste...)                                            │
  │          ├── Layout et positionnement                                                                     │
  │          └── Interactions              (tooltip, node card, toggle)                                       │
  └──────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

Pas de framework (React, Vue...), pas de bundler (webpack, vite...), pas de transpilation. Du JavaScript vanilla qui fonctionne dans tout navigateur moderne. Cela simplifie la maintenance et évite les dépendances obsolètes.

---

## 3. Architecture de la page

### Inputs utilisateur (toolbar)

La toolbar contient 3 uploads de fichiers et des boutons de contrôle :

```
  ┌──────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │  Réseau [fichier ▼]        Mapping [fichier ▼]        Graphe AD [fichier(s) ▼]                           │
  │                                                                                                          │
  │  [T0] [T1] [T2]                    [Afficher AD]                              status message             │
  └──────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

| Upload       | Fichier attendu               | Rôle                           |
|--------------|-------------------------------|--------------------------------|
| Réseau       | `network_scan.json`           | Topologie réseau (IPs, ports)  |
| Mapping      | `hostname_mapping.json`       | Association hostname → IP      |
| Graphe AD    | `graph_tier{0,1,2}.json`      | Chemins d'attaque AD (multi)   |

L'upload AD supporte le **multi-fichier** : on peut charger les 3 tiers d'un coup. Chaque tier est indexé et accessible via les boutons T0/T1/T2.

### Disposition générale

```
  ┌──────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │                                                                                                          │
  │   ZONE RÉSEAU (en haut)                              Layout horizontal par sous-réseau                   │
  │                                                                                                          │
  │   [VLAN local]              [Subnet 1]                [Subnet 2]              [Subnet 3]                 │
  │                                                                                                          │
  ├──────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │                                                                                                          │
  │   ZONE IDENTITÉ (en bas)                             Layout BFS horizontal                               │
  │                                                                                                          │
  │   [start] ────▶ [hop1] ────▶ [hop2] ────▶ [hop3] ────▶ ... ────▶ [Tier 0 targets]                       │
  │                                                                                                          │
  └──────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Couche réseau — construction du graphe

### Détection de rôle automatique

Chaque machine réseau reçoit un rôle basé sur ses **ports ouverts** :

```
  ┌──────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │  RÔLE                    CRITÈRES DE DÉTECTION                                                           │
  ├──────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │  Domain Controller       Port 88 (Kerberos) + port 389 ou 636 (LDAP/LDAPS) ouverts                      │
  │                                                                                                          │
  │  Routeur                 Flag isRouter (depuis traceroute)                                                │
  │                                                                                                          │
  │  Serveur                 Au moins un port serveur ouvert : 21, 22, 25, 53, 80, 443, 445, 389, 636,      │
  │                          1433, 3306, 5432, 8080...                                                       │
  │                                                                                                          │
  │  Poste                   Tous les ports ouverts sont dans le set workstation (135, 139, 445, 3389, 5985) │
  │                                                                                                          │
  │  Inconnu                 Aucun service détecté                                                           │
  └──────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

Priorité : Domain Controller > Routeur > Serveur > Poste > Inconnu.

### Groupement par sous-réseau

Les machines sont groupées visuellement par sous-réseau (compound nodes Cytoscape) :

```
  ┌─ VLAN 10.0.1.0/24 ────────────────────────────────────────────────────────────────────────────────────┐
  │                                                                                                        │
  │  [10.0.1.1]                    [10.0.1.10]                    [10.0.1.20]                              │
  │   Routeur                       DC01                           SRV01                                    │
  │                                                                                                        │
  └────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 5. Couche identité AD — intégration du graphe

### Multi-tier

Les boutons T0/T1/T2 permettent de basculer entre les tiers sans recharger. Chaque tier est pré-parsé au chargement et stocké en mémoire. Le switch :
1. Supprime les éléments AD du graphe courant
2. Charge les éléments du nouveau tier
3. Relance le layout

### Types d'edges AD

| Style                     | Signification                              |
|---------------------------|--------------------------------------------|
| Rouge plein               | Shortest path (chemin d'attaque confirmé)  |
| Gris foncé tirets         | Chemin secondaire                          |
| Gris foncé tirets (viaPC) | Chemin via un Computer (incertain)         |

Les edges via un Computer restent en tirets même sur le shortest path : traverser un Computer nécessite d'être admin local de cette machine pour hériter de ses identités — ce n'est pas un chemin garanti.

---

## 6. Fusion des deux couches (bridges)

### Mécanisme de pont

Quand les deux couches sont chargées, la cartographie crée des **edges bridge** entre les noeuds Computer AD et les noeuds Machine réseau. Le lien est établi via le **hostname** :

```
  Noeud AD                                                            Noeud Réseau
  ┌────────────────────────────────────┐                             ┌────────────────────────────────────┐
  │ DC01.CORP.LOCAL                    │ ──── bridge (hostname) ──▶ │ 10.0.1.10                          │
  │ (Computer, Tier 0)                 │         match               │ DC01.CORP.LOCAL                    │
  └────────────────────────────────────┘                             └────────────────────────────────────┘
```

### Sources de résolution

1. **Fichier mapping** : `hostname_mapping.json` (produit par `argus_enrich.py`)
2. **Index SMB nmap** : hostnames dans `network_scan.json` (smb-os-discovery)

Le mapping est appliqué dynamiquement : charger le fichier mapping après le réseau met à jour les labels des noeuds et crée les associations hostname→IP en temps réel.

---

## 7. Interactions utilisateur

### Node card (sélection)

Au clic sur un noeud, une carte détaillée apparaît :

- **Noeud réseau** : IP, hostname, rôle, tableau des services ouverts (port, protocole, état, service, produit, version)
- **Noeud AD** : nom, type, tier, propriétés AD

La carte suit le noeud lors du pan/zoom.

### Edge tooltip (survol/clic)

Au survol d'un edge AD, un tooltip affiche :
- La permission principale (label de l'edge)
- Toutes les permissions consolidées (`allRights`)
- Note si la permission affichée est synthétique (ex: DCSync)

Le tooltip peut être **épinglé** au clic pour rester visible.

### Toggle AD

Le bouton "Afficher/Masquer AD" ajoute ou supprime la couche identité sans la perdre. Cela permet de voir le réseau seul pour comprendre la topologie, puis superposer les chemins d'attaque.

---

## 8. Conventions visuelles

### Noeuds

Les noeuds utilisent un code couleur par type pour distinguer les rôles d'un coup d'oeil. Les types AD (User, Group, Computer, GPO, CertTemplate...) et réseau (DC, Serveur, Routeur, Poste...) ont chacun leur couleur.

Le **tier** est indiqué par la couleur de bordure du noeud (rouge = T0, orange = T1, jaune = T2). Exception : les Computer ont toujours un fond violet quel que soit le tier.

Le **noeud start** (utilisateur compromis initial) est affiché en vert.

### Edges

Les edges réseau sont des lignes grises sans flèche (connexion bidirectionnelle). Les edges AD utilisent des flèches directionnelles : rouge plein pour le shortest path, tirets gris pour les chemins secondaires.

### Direction des edges

Le graphe est **orienté** : `src → dst`. Un chemin `A → B → C` signifie qu'un attaquant contrôlant A peut potentiellement atteindre C en passant par B.

```
  ┌──────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │  MemberOf :          membre ─────────────────▶ groupe                                                    │
  │  ACE :               principal ──────────────▶ cible (celui qui a le droit → objet ciblé)                 │
  │  AdminTo :           principal ──────────────▶ machine                                                   │
  │  HasSession :        utilisateur ────────────▶ machine (où il est connecté)                               │
  └──────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### Consolidation des edges AD

Pour chaque paire (principal, cible), un seul edge est affiché avec le **droit le plus fort**. Le champ `allRights` conserve toutes les permissions (visible au survol dans le tooltip).

> **Note** : Cette hiérarchie sert uniquement à l'**affichage**. Quand un principal a plusieurs permissions sur la même cible, on n'affiche que la plus forte pour éviter les doublons visuels. L'ordre exact des permissions en bas de liste (à partir de ~ReadLAPSPassword) est un choix d'affichage — en réalité, leur dangerosité dépend du contexte (type de cible, attributs, configuration).

```
  Hiérarchie des droits pour l'affichage (du plus fort au plus faible) :
  ──────────────────────────────────────────────────────────────────────────────────────────────────────────

  Contrôle total / quasi-total (ordre clair) :
  1. GenericAll                    Contrôle total
  2. WriteDacl                     Peut s'accorder GenericAll
  3. WriteOwner                    Peut devenir propriétaire
  4. Owns                          Est propriétaire

  Contrôle ciblé (ordre clair) :
  5. ForceChangePassword           Reset du mot de passe
  6. ResetPassword                 Idem
  7. AddMember                     Modification de groupe
  8. WriteMember                   Idem

  Reste (ordre choisi pour l'affichage, dangerosité variable) :
  9. ReadLAPSPassword              Lecture credentials
  10. ReadGMSAPassword             Lecture credentials
  11. AddKeyCredentialLink         Shadow Credentials
  12. WriteKeyCredentialLink       Idem
  13. WriteGPO                     Contrôle GPO
  14. EditGPO                      Idem
  15. GenericWrite                 Écriture limitée
  16. AllExtendedRights            Droits étendus (inclut DCSync)
  17. Enroll                       Inscription ADCS
  18. AutoEnroll                   Inscription auto ADCS
```

### Cas spécial DCSync

```
  ┌──────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │  Si un principal a AllExtendedRights sur un objet Domain :                                               │
  │    → On ajoute synthétiquement GetChanges + GetChangesAll                                                │
  │    → L'edge affiché devient "DCSync"                                                                     │
  │                                                                                                          │
  │  Si un principal a GetChanges ET GetChangesAll :                                                          │
  │    → L'edge affiché est "DCSync" (consolidé)                                                             │
  │                                                                                                          │
  │  Si un principal a seulement GetChanges :                                                                │
  │    → L'edge reste "GetChanges" (incomplet, pas exploitable seul)                                         │
  └──────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```
