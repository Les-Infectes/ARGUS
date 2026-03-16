# Algorithme de Classification des Identités — ARGUS

## Table des matières

1. [Contexte et objectifs](#1-contexte-et-objectifs)
2. [Architecture de l'algorithme](#2-architecture-de-lalgorithme)
3. [Détail des phases de classification](#3-détail-des-phases-de-classification)
4. [Référence technique](#4-référence-technique)
5. [Format des données](#5-format-des-données)
6. [Limites et cas particuliers](#6-limites-et-cas-particuliers)
7. [Annexe A — Cartographie complète des RIDs Active Directory](#7-annexe-a--cartographie-complète-des-rids-active-directory)
8. [Annexe B — Cartographie complète des permissions AD (DACL)](#8-annexe-b--cartographie-complète-des-permissions-ad-dacl)

---

## 1. Contexte et objectifs

### Contexte

Dans un domaine Active Directory, tous les objets (utilisateurs, groupes, machines, GPO, templates de certificat...) ne se valent pas. Un compte **Domain Admin** a un impact radicalement différent d'un compte utilisateur standard. Si un attaquant compromet un objet "proche" du contrôle total du domaine, l'impact est critique.

### Problème

Les collecteurs BloodHound extraient des milliers d'objets et de relations, mais ne fournissent **aucune classification de criticité**. On se retrouve avec un graphe brut, sans hiérarchie, où un utilisateur lambda côtoie un contrôleur de domaine sans distinction.

### Solution : le modèle Tier

ARGUS classe chaque objet AD dans un **tier de criticité** basé sur deux critères :

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                                                                                         │
│  TIER 0 — Contrôle DÉTERMINISTE du domaine                                                              │
│           Un attaquant qui compromet un objet Tier 0 peut prendre le contrôle total du domaine          │
│           IMMÉDIATEMENT. Classification : algorithme déterministe (5 phases)                            │
│                                                                                                         │
│  TIER 1 — Proximité (1-7 hops depuis Tier 0)                                                            │
│           Objets proches du contrôle du domaine. Un ou quelques sauts suffisent pour atteindre Tier 0.  │
│           Classification : distance BFS                                                                 │
│                                                                                                         │
│  TIER 2 — Éloigné (8+ hops ou inaccessible)                                                             │
│           Objets distants, utilisateurs standards, ou objets sans chemin connu vers Tier 0.             │
│           Classification : distance BFS ou absence de chemin                                            │
│                                                                                                         │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### Pourquoi 3 tiers ?

| Critère           | Tier 0         | Tier 1            | Tier 2            |
| ----------------- | -------------- | ----------------- | ----------------- |
| Type de contrôle  | Déterministe   | Par proximité     | Distant/inconnu   |
| Impact compromis  | Domaine entier | Escalade probable | Escalade probable |
| Méthode de calcul | 5 phases fixes | BFS (1-7 hops)    | BFS (8+) ou ∞     |


---

## 2. Architecture de l'algorithme

### Vue d'ensemble

L'algorithme classe les objets AD en tiers de criticité via **5 phases séquentielles**. Les 4 premières déterminent le Tier 0 (contrôle du domaine), la dernière mesure la distance de tous les autres objets.

```
  ┌───────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │                                  QUI CONTRÔLE LE DOMAINE ?                                            │
  │                                  (Tier 0 — déterministe)                                              │
  │                                                                                                       │
  │  Phase 1                          Phase 2                          Phase 3                            │
  │  ATTRIBUTION DIRECTE              HÉRITAGE DIRECT                  HÉRITAGE INDIRECT                  │
  │  ┌───────────────────────┐        ┌───────────────────────┐        ┌───────────────────────┐          │
  │  │ Objets dont le        │        │ Qui a un contrôle ACE │        │ Qui a un accès direct │          │
  │  │ contrôle est CERTAIN  │───────▶│ sur un objet déjà     │───────▶│ aux machines Tier 0 ? │          │
  │  │ par nature            │        │ Tier 0 ?              │        │ (admin, RDP, LAPS,    │          │
  │  └───────────────────────┘        └───────────────────────┘        │  GPO, PSRemote, DCOM) │          │
  │   Domain Admins                    GenericAll sur DA               └───────────────────────┘          │
  │   Enterprise Admins                WriteDacl sur DC                                                   │
  │   KRBTGT, DCs                      WriteOwner sur EA                AdminTo sur T0                    │
  │   DCSync holders                   Owns sur KRBTGT                  ReadLAPS sur T0                   │
  │   CertTemplates ESC                ...itère jusqu'à stabilisation   GPO liée à T0                     │
  │                                    (point fixe)                     CanPSRemote / CanRDP / DCOM T0    │
  │                                                                                                       │
  │  Phase 4                                                                                              │
  │  MEMBRES DES GROUPES T0                                                                               │
  │  ┌───────────────────────────────────────────────────┐                                                │
  │  │ Membres des groupes déjà classés T0               │    Un membre de Domain Admins EST Tier 0,      │
  │  │                                                   │    pas "1 hop de distance".                    │
  │  └───────────────────────────────────────────────────┘                                                │
  │                                                                                                       │
  └──────────────────────────────────────────────┬────────────────────────────────────────────────────────┘
                                                 │
                                                 │  Tier 0 complet et final
                                                 ▼
  ┌───────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │                                  À QUELLE DISTANCE DU CONTRÔLE ?                                      │
  │                                  (Tier 1 & 2 — distance BFS)                                          │
  │                                                                                                       │
  │  Phase 5                                                                                              │
  │  CALCUL DE DISTANCE                                                                                   │
  │  ┌───────────────────────────────────────────────────────────────────────────────────────────┐        │
  │  │ BFS (parcours en largeur) depuis tous les noeuds Tier 0                                   │        │
  │  │                                                                                           │        │
  │  │    1 à 7 hops         ──▶  Tier 1 (proximité)                                             │        │
  │  │    8+ hops            ──▶  Tier 2 (éloigné)                                               │        │
  │  │    ∞ (aucun chemin)   ──▶  Tier 2                                                         │        │ 
  │  └───────────────────────────────────────────────────────────────────────────────────────────┘        │
  │                                                                                                       │
  └───────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### Pourquoi cet ordre ?

Chaque phase dépend du résultat de la précédente. Inverser deux phases produit des classifications incorrectes :

```
  Phase 1 → 2    L'attribution directe crée la base. L'héritage direct cherche qui contrôle CETTE base
                 → il faut qu'elle existe d'abord.

  Phase 2 → 3    Un utilisateur avec GenericAll sur Domain Admins doit être Tier 0 AVANT qu'on évalue les accès
                 aux machines Tier 0. Sinon, sa machine ne serait pas encore T0 et on raterait les accès
                 indirects dessus.

  Phase 3 → 4    Un admin local du DC doit être Tier 0 AVANT qu'on déplie les membres des groupes. Sinon,
                 un groupe contenant cet admin ne serait pas correctement classé.

  Phase 4 → 5    Les membres des groupes Tier 0 SONT Tier 0 (pas "à 1 hop"). Le BFS doit partir du Tier 0
                 COMPLET pour calculer des distances correctes.
```


---

## 3. Détail des phases de classification

### Phase 1 : Attribution directe Tier 0

**Objectif** : Identifier les objets dont le contrôle du domaine est **certain et immédiat**, sans analyse de relations.

**Critères d'inclusion** :

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                CRITÈRES D'ATTRIBUTION DIRECTE TIER 0                                     │
├──────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                                          │
│  1. Objets Domain (type == "Domain")                                                                     │
│     → Le domaine lui-même est Tier 0 par définition                                                      │
│                                                                                                          │
│  2. Groupes/comptes critiques par RID (SID suffix) :                                                     │
│     -500  Administrator (compte builtin)                 -518  Schema Admins                             │
│     -502  KRBTGT (clé de chiffrement Kerberos)           -519  Enterprise Admins                         │
│     -512  Domain Admins                                  -520  Group Policy Creator Owners               │
│     -516  Domain Controllers (groupe)                    -526  Key Admins (Shadow Credentials WHfB)      │
│     -517  Cert Publishers (PKI — attaques ESC)           -527  Enterprise Key Admins (forêt entière)     │
│     -544  Administrators (BUILTIN)                       -549  Server Operators                          │
│     -548  Account Operators                              -550  Print Operators                           │
│     -551  Backup Operators                                                                               │
│                                                                                                          │
│  3. Contrôleurs de domaine (machines) :                                                                  │
│     → Détection primaire : userAccountControl & 0x2000 (flag SERVER_TRUST_ACCOUNT)                       │
│     → Fallback : PrimaryGroupSID se terminant par -516 (groupe Domain Controllers)                       │
│                                                                                                          │
│  4. AdminSDHolder (objet spécial AD)                                                                     │
│     → CN=AdminSDHolder dans le distinguishedName                                                         │
│                                                                                                          │
│  5. Détenteurs de droits DCSync sur le domaine :                                                         │
│     → Recherche d'ACE avec RightName ∈ {DCSync, GetChanges, GetChangesAll, GetChangesInFilteredSet}      │
│       sur un objet de type Domain                                                                        │
│                                                                                                          │
│  6. CertTemplates avec vulnérabilités ESC :                                                              │
│     → Tout template ayant esc_vulnerabilities non vide (ESC1, ESC2, ..., ESC16)                          │
│     → Source : certipy_data.json (analysé par argus_certipy)                                             │
│                                                                                                          │
│  7. GPO critiques du domaine :                                                                           │
│     → Default Domain Policy / Default Domain Controllers Policy                                          │
│     → Contrôlent les paramètres de sécurité globaux. En les classant Tier 0, la Phase 2 promeut          │
│       automatiquement quiconque a GenericAll/WriteDacl dessus — sans logique spécifique GPO en Phase 3.  │
│                                                                                                          │
│  8. Machine hébergeant l'Enterprise CA :                                                                 │
│     → Identifiée via le champ ca_names des CertTemplates                                                 │
│     → Compromission = forge de certificats, extraction de la clé privée CA, approbation de requêtes      │
│     → Note : dépend des données certipy (BloodHound ne collecte pas les objets EnterpriseCA nativement)  │
│                                                                                                          │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

**Détection des DCs — pourquoi deux méthodes ?**

```
  Méthode 1 : userAccountControl & 0x2000
  ────────────────────────────────────────────────────────────────────────────────────────────────────
  Le flag SERVER_TRUST_ACCOUNT (bit 13, valeur 8192) est positionné sur tous les comptes machine DC.
  C'est la méthode la plus fiable.

  Problème : certains exports BloodHound ont UAC = 0 (collecte partielle ou bug de l'outil).

  Méthode 2 (fallback) : PrimaryGroupSID = *-516
  ────────────────────────────────────────────────────────────────────────────────────────────────────
  En AD, le PrimaryGroupSID d'un DC est toujours le groupe "Domain Controllers" (RID 516).
  Ce champ est rarement vide dans BloodHound.

  Combinaison : on utilise les DEUX méthodes pour maximiser la détection (union des résultats).
```


### Phase 2 : Héritage direct Tier 0

**Objectif** : Tout objet ayant un **contrôle direct** sur un objet déjà Tier 0 devient lui-même Tier 0.

**Principe** : on parcourt toutes les permissions (ACE) du domaine. Si quelqu'un a un droit de contrôle sur un objet déjà Tier 0, il devient Tier 0 à son tour. On répète tant qu'il y a de nouveaux promus.

```
  ┌───────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │                                                                                                       │
  │  Tour 1 : On parcourt toutes les permissions du domaine                                               │
  │                                                                                                       │
  │    UserX ──GenericAll──▶ Domain Admins (Tier 0)                                                       │
  │    │                                                                                                  │
  │    └──▶ UserX a le contrôle total sur un objet Tier 0 → UserX devient Tier 0                          │
  │                                                                                                       │
  │  Tour 2 : On recommence avec les nouveaux Tier 0                                                      │
  │                                                                                                       │
  │    GroupeY ──WriteDacl──▶ UserX (nouveau Tier 0)                                                      │
  │    │                                                                                                  │
  │    └──▶ GroupeY contrôle un objet devenu Tier 0 au tour 1 → GroupeY devient Tier 0                    │
  │                                                                                                       │
  │  Tour 3 : On recommence... Aucun nouveau Tier 0 trouvé → on s'arrête.                                 │
  │                                                                                                       │
  └───────────────────────────────────────────────────────────────────────────────────────────────────────┘

  L'algorithme s'arrête quand un tour n'ajoute plus personne (point fixe), ou après 10 tours maximum
  par sécurité.
```

**Droits de la whitelist** (seuls ces droits provoquent la promotion Tier 0) :

```
  ┌───────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │  DROITS DE PROMOTION TIER 0 (Phase 2)                                                                 │
  ├───────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │                                                                                                       │
  │  Contrôle total :                                          Modification de groupe :                   │
  │    GenericAll        → Tous les droits sur l'objet           AddMember     → Ajouter un membre        │
  │    WriteDacl         → Peut se donner GenericAll             WriteMember   → Alias de AddMember       │
  │    WriteOwner        → Peut devenir owner → DACL                                                      │
  │    Owns              → Propriétaire = contrôle             Prise de contrôle de compte :              │
  │                                                              ForceChangePassword → Reset sans mdp     │
  │  Shadow Credentials :                                        ResetPassword       → Alias              │
  │    AddKeyCredentialLink    → msDS-KeyCredentialLink                                                   │
  │    WriteKeyCredentialLink  → Alias                                                                    │
  │                                                                                                       │
  ├───────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │                                                                                                       │
  │  EXCLUS (faux positifs, nécessitent analyse d'attribut) :                                             │
  │    GenericWrite      → dépend de l'attribut modifié        ChangePassword → nécessite l'ancien mdp    │
  │    AllExtendedRights → trop large                                                                     │
  │    WriteProperty     → attribute-aware requis                                                         │
  │                                                                                                       │
  └───────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### Phase 3 : Héritage indirect Tier 0

**Objectif** : Tout objet ayant un **accès à une machine Tier 0** (DCs et toute autre machine classée Tier 0 par les phases précédentes) devient Tier 0.

**Justification** : Un accès à une machine Tier 0 (même limité comme RDP) permet d'élever ses privilèges localement et d'extraire des secrets (credentials en mémoire, NTDS.dit sur un DC, SAM). La phase s'applique à **toutes** les machines Tier 0, pas uniquement aux DCs.

```
  ┌───────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │                                  ACCÈS MACHINE TIER 0 → TIER 0                                        │
  ├───────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │                                                                                                       │
  │  1. AdminTo sur machine Tier 0                                                                        │
  │     → Admin local = contrôle total de la machine. Source : collecteur LocalAdmins de BloodHound       │
  │                                                                                                       │
  │  2. ReadLAPSPassword sur machine Tier 0 ou son OU                                                     │
  │     → Permet de lire le mot de passe admin local. Recherche sur la machine ET sur l'OU parente        │
  │                                                                                                       │
  │  3. Accès distant à une machine Tier 0                                                                │
  │     → CanRDP (Remote Desktop)     → CanPSRemote (PowerShell Remoting / WinRM)     → DCOM (Dist. COM)  │
  │                                                                                                       │
  │  4. WriteGPO sur GPO liée à l'OU d'une machine Tier 0                                                 │
  │     → Droits vérifiés : WriteGPO, EditGPO, GenericAll, WriteDacl, WriteOwner                          │
  │     → Permet d'exécuter du code sur la machine via GPO                                                │
  │                                                                                                       │
  └───────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

**Comment fonctionne le vecteur GPO ?**

Dans Active Directory, les GPO (Group Policy Objects) s'appliquent aux machines via les OUs (Organizational Units) auxquelles elles sont liées. Si quelqu'un peut modifier une GPO qui s'applique à une machine Tier 0, il peut exécuter du code dessus (par exemple via un script de démarrage).

Le problème : il faut remonter la chaîne pour trouver quelles GPO s'appliquent aux machines Tier 0.

```
  ┌───────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │                                                                                                       │
  │  1. Où sont les machines Tier 0 dans l'arborescence AD ?                                              │
  │                                                                                                       │
  │     DC01 est dans l'OU "Domain Controllers"        SRV-PKI est dans l'OU "Servers"                    │
  │     (visible via leur distinguishedName)                                                              │
  │                                                                                                       │
  │  2. Quelles GPO s'appliquent à ces OUs ?                                                              │
  │                                                                                                       │
  │     OU "Domain Controllers" ← GPO "Default DC Policy"        Domaine corp.local ← GPO "Default DP"    │
  │     OU "Servers"            ← GPO "Server Hardening"         (les GPO domaine → toutes les machines)  │
  │                                                                                                       │
  │  3. Qui peut modifier ces GPO ?                                                                       │
  │                                                                                                       │
  │     UserX ──WriteGPO──▶ "Server Hardening"                                                            │
  │     → UserX peut injecter du code sur SRV-PKI via GPO → UserX devient Tier 0                          │ 
  │                                                                                                       │
  └───────────────────────────────────────────────────────────────────────────────────────────────────────┘
```


### Phase 4 : Membres des groupes Tier 0

**Objectif** : Si un groupe est Tier 0, tous ses **membres directs** sont Tier 0.

**Justification** : Être membre de Domain Admins signifie **être** Domain Admin. Ce n'est pas un "chemin vers" Tier 0, c'est Tier 0 directement.

```
  Domain Admins (Tier 0) → ses membres AdminUser, ServiceAccount → tous deviennent Tier 0
```

**Note** : Cette phase ne fait qu'une seule passe (pas de récursion). Les appartenances transitives (membre d'un groupe membre d'un groupe T0) sont gérées par la Phase 2 (héritage direct) en amont (si le groupe intermédiaire a des droits de contrôle sur le groupe T0).


### Phase 5 : Calcul de distance (BFS)

**Objectif** : Pour tous les objets restants (non Tier 0), calculer leur **distance minimale** jusqu'à un objet Tier 0 dans le graphe AD.

**Important** : Les chemins identifiés par le BFS sont des chemins **potentiels**, pas garantis. Contrairement au Tier 0 (déterministe), un objet Tier 1 a un chemin **théorique** vers le contrôle du domaine, mais son exploitation peut nécessiter des conditions supplémentaires (attribut spécifique pour GenericWrite, session active pour HasSession, template vulnérable pour Enroll, etc.).

### Pourquoi le BFS utilise toutes les permissions

Le BFS parcourt un graphe où **chaque permission AD = un edge**. Il utilise **toutes** les permissions, pas seulement celles de la Phase 2 :

```
  ┌───────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │                                  EDGES UTILISÉS PAR LE BFS                                            │
  │                                                                                                       │
  │  PERMISSIONS ACE (toutes, pas juste celles de Phase 2) :                                              │
  │    GenericAll, GenericWrite, WriteDacl, WriteOwner, Owns, ForceChangePassword, AddMember,             │
  │    AddKeyCredentialLink, AllExtendedRights, WriteAccountRestrictions, Enroll, AutoEnroll,             │
  │    ReadLAPSPassword, ReadGMSAPassword                                                                 │
  │                                                                                                       │
  │  RELATIONS DE GROUPE :                        ACCÈS MACHINE :                                         │
  │    MemberOf         (membre → groupe)           AdminTo      (admin local → machine)                  │
  │    PrimaryGroupSID  (objet → groupe primaire)   CanRDP       (RDP → machine)                          │
  │                                                 CanPSRemote  (PowerShell → machine)                   │
  │  SESSIONS :                                     DCOM         (DCOM → machine)                         │
  │    HasSession  (utilisateur connecté → machine)                                                       │
  │                                                                                                       │
  └───────────────────────────────────────────────────────────────────────────────────────────────────────┘

  C'est le même jeu d'edges que les chemins d'attaque visuels dans la cartographie.
```

Le BFS part de chaque objet non-Tier-0 et cherche le chemin le plus court jusqu'à un objet Tier 0. La distance en nombre de sauts détermine le tier.

**Classification finale** :

```
  ┌──────────┬────────────────────────────────────────────────────────────────────────────────────────────┐
  │ Distance │ Tier                                                                                       │
  ├──────────┼────────────────────────────────────────────────────────────────────────────────────────────┤
  │    0     │ Tier 0 — Déterministe                                                                      │
  │          │ Contrôle garanti sur le domaine. Les phases 1-4 ont identifié tous les chemins             │
  │          │ d'escalade possibles et les ont consolidés dans ce tier.                                   │
  ├──────────┼────────────────────────────────────────────────────────────────────────────────────────────┤
  │   1-7    │ Tier 1 — Chemins incertains                                                                │
  │          │ Chemin potentiel vers le Tier 0, mais l'exploitation dépend de conditions non garanties    │
  │          │ (attribut modifiable, session active, template vulnérable, etc.).                          │
  ├──────────┼────────────────────────────────────────────────────────────────────────────────────────────┤
  │  8+ / ∞  │ Tier 2 — Reste du domaine                                                                  │
  │          │ Objets éloignés ou sans chemin connu vers le Tier 0. Faible risque d'escalade directe.     │
  └──────────┴────────────────────────────────────────────────────────────────────────────────────────────┘
```

**Pourquoi le Tier 0 couvre déjà les chemins d'escalade importants ?**

Notre algorithme de classification (Phases 1-4) est conçu pour être **exhaustif sur les chemins déterministes**. Contrairement à un simple BFS qui compterait les hops, les 4 premières phases identifient et consolident tous les objets qui ont un **contrôle garanti** sur le domaine :

- Phase 1 : objets nativement critiques (Domain Admins, DC, etc.)
- Phase 2 : objets qui contrôlent un objet T0 via des ACE forts (WriteDacl, GenericAll, etc.)
- Phase 3 : accès directs aux machines T0 (AdminTo, LAPS, GPO, accès distants)
- Phase 4 : membres des groupes promus T0

Résultat : tout ce qui **peut avec certitude** atteindre le Tier 0 est **déjà dans le Tier 0**. Le BFS ne trouve donc que des chemins **incertains** — c'est ce qui distingue notre approche d'un simple comptage de hops.

**Pourquoi 7 comme seuil T1/T2 ?**

En pratique, dans la plupart des domaines AD :
- 1-3 hops : accès très direct (membre → groupe T0, admin local → DC)
- 4-7 hops : chaîne d'escalade réaliste (2-3 groupes + 1-2 ACE)
- 8+ hops : chaîne longue, peu probable en exploitation réelle

Le seuil de 7 offre un bon compromis entre granularité et lisibilité.

### Exemples concrets de chemins Tier 1

Les Phases 1 à 4 ne promeuvent en Tier 0 que les objets ayant un **contrôle direct** (GenericAll, WriteDacl, WriteOwner, Owns, AddMember, ForceChangePassword, AddKeyCredentialLink). Le BFS utilise **toutes** les permissions, y compris celles qui représentent un accès **potentiel mais incertain**. C'est là que le Tier 1 apparaît :

```
  Exemple 1 — GenericWrite
  ──────────────────────────────────────────────────────────────────────────────────────────────────
  UserA ──GenericWrite──▶ Domain Admins (T0)

  GenericWrite permet de modifier certains attributs, mais pas forcément de prendre le contrôle
  total. Phase 2 ne le promeut pas en T0, mais le BFS le voit à 1 hop → Tier 1.


  Exemple 2 — Enroll sur un CertTemplate vulnérable
  ──────────────────────────────────────────────────────────────────────────────────────────────────
  UserB ──Enroll──▶ CertTemplate-ESC1 (T0)

  Le droit Enroll permet de demander un certificat, mais l'exploitation dépend de la configuration
  du template. Le BFS le voit à 1 hop → Tier 1.


  Exemple 3 — HasSession (session active)
  ──────────────────────────────────────────────────────────────────────────────────────────────────
  SRV-APP ◀──HasSession── AdminDC (T0)

  Un administrateur T0 a une session ouverte sur SRV-APP. Si un attaquant compromet SRV-APP, il
  pourrait voler le token. Mais la session peut être terminée à tout moment → chemin incertain,
  Tier 1.


  Exemple 4 — AllExtendedRights
  ──────────────────────────────────────────────────────────────────────────────────────────────────
  UserC ──AllExtendedRights──▶ Domain (T0)

  AllExtendedRights inclut DCSync, mais aussi d'autres droits. L'impact réel dépend du contexte
  → Tier 1.


  Exemple 5 — ReadGMSAPassword
  ──────────────────────────────────────────────────────────────────────────────────────────────────
  GroupeX ──ReadGMSAPassword──▶ gMSA-SQL (T0)

  Lire le mot de passe d'un gMSA Tier 0 donne un accès potentiel, mais le gMSA doit être utilisé
  sur une machine T0 → Tier 1.
```

### Pourquoi le Tier 1 peut être vide

Dans les petits domaines AD (labs HTB, environnements de test), il est fréquent que le Tier 1 soit **vide**. C'est normal :

- **Peu d'objets** : 10-50 objets au total, presque tous liés directement au T0
- **Pas de délégation** : pas de GenericWrite, AllExtendedRights, etc. sur des objets normaux
- **Pas de sessions** : les sessions HasSession sont rares dans les labs
- **Pas d'ADCS** : pas de CertTemplates avec Enroll

Dans un **domaine d'entreprise** (1000+ objets), le Tier 1 contiendra typiquement :
- Des comptes de service avec des droits partiels (GenericWrite, Enroll)
- Des machines où des admins T0 ont des sessions ouvertes
- Des groupes avec AllExtendedRights sur le domaine
- Des opérateurs avec ReadGMSAPassword ou ReadLAPSPassword sur des machines T0


---

## 4. Référence technique

```
  argus_builder.py
  ├── Constantes
  │   ├── TIER0_RID_SUFFIXES         # RIDs des groupes/comptes critiques
  │   ├── TIER0_DCSYNC_RIGHTS        # Droits DCSync
  │   ├── TIER0_CLOSURE_RIGHTS       # Whitelist droits héritage direct (Ph.2)
  │   ├── ALL_PRIVILEGE_RIGHTS        # Tous les droits significatifs
  │   └── ACE_RIGHTS_HIERARCHY        # Hiérarchie pour consolidation
  │
  ├── Détection
  │   ├── get_dc_computers()            # Identifie les DCs (UAC + PrimaryGroupSID)
  │   ├── get_tier0_computers()         # Machines Tier 0 (DCs + autres)
  │   ├── get_ous_containing_machines() # OUs contenant des machines Tier 0
  │   └── get_gpos_linked_to_ous()     # GPOs liées aux OUs de machines T0
  │
  ├── Classification Tier 0
  │   ├── identify_tier0_seed()       # Phase 1 : attribution directe
  │   ├── expand_tier0_closure()      # Phase 2 : héritage direct (point fixe)
  │   ├── expand_tier0_indirect()     # Phase 3 : héritage indirect (machines T0)
  │   └── expand_tier0_members()      # Phase 4 : membres des groupes T0
  │
  ├── Classification BFS
  │   ├── classify_objects_by_tier()   # Phase 5 : distance BFS
  │   └── compute_full_tier_classification()  # Pipeline complète
  │
  ├── Recherche de chemins
  │   ├── k_shortest_loopless_paths()  # Yen's algorithm (k-plus courts)
  │   └── get_tier_targets()           # Cibles par tier
  │
  └── Construction du graphe
      ├── build_node_index()           # Index des noeuds par OID
      ├── build_observed_edges()       # Edges depuis BloodHound
      └── select_strongest_right()     # Consolidation ACE
```


---

## 5. Format des données

### Entrée : données BloodHound (JSON)

```
  data_dir/
  ├── *_users.json        # Utilisateurs + ACEs
  ├── *_groups.json       # Groupes + Members[] + ACEs
  ├── *_computers.json    # Machines + LocalAdmins/Sessions/RDP/PSR
  ├── *_domains.json      # Domaines + ACEs
  ├── *_gpos.json         # GPOs + Links + ACEs
  ├── *_ous.json          # OUs + Links + ACEs
  └── *_containers.json   # Containers AD
```

**Structure d'un objet BloodHound** (simplifié) :

```json
  {
    "ObjectIdentifier": "S-1-5-21-...-1234",
    "Properties": {
      "name": "USER@DOMAIN.HTB",
      "samaccountname": "user",
      "domain": "DOMAIN.HTB",
      "objectsid": "S-1-5-21-...-1234",
      "useraccountcontrol": 512
    },
    "PrimaryGroupSID": "S-1-5-21-...-513",
    "Aces": [
      {
        "PrincipalSID": "S-1-5-21-...-512",
        "RightName": "GenericAll",
        "IsInherited": false
      }
    ],
    "Members": [...]
  }
```

### Entrée optionnelle : certipy_data.json

```json
  {
    "meta": {"type": "certtemplates"},
    "data": [
      {
        "ObjectIdentifier": "certtemplate-CorpVPN",
        "Properties": {
          "name": "CorpVPN [ESC1]",
          "esc_vulnerabilities": ["ESC1"]
        },
        "Aces": [
          {"PrincipalSID": "S-1-5-21-...-515", "RightName": "Enroll"}
        ]
      }
    ]
  }
```

### Sortie : graph_tierX.json

```json
  {
    "nodes": [
      {
        "id": "S-1-5-21-...-1234",
        "type": "User",
        "name": "USER@DOMAIN.HTB",
        "tier": 0,
        "is_target": true
      }
    ],
    "edges": [
      {
        "src": "S-1-5-21-...-1234",
        "dst": "S-1-5-21-...-512",
        "kind": "ace",
        "right": "GenericAll",
        "all_rights": ["GenericAll", "WriteDacl"],
        "is_shortest": true
      }
    ],
    "tier_classification": {"0": 18, "1": 5, "2": 42},
    "paths": [...]
  }
```


---

## 6. Limites connues

### Accès distant et héritage des droits machine

En Phase 3, ARGUS promeut en Tier 0 les objets ayant un accès distant (CanRDP, CanPSRemote, DCOM) vers une machine Tier 0. Or, en réalité, **seul AdminTo permet d'hériter des droits du compte machine** (dump de credentials, utilisation du compte AD de la machine).

Un accès RDP ou WinRM donne une session interactive sur la machine mais **pas le contrôle du compte machine AD** — il faudrait d'abord réaliser une élévation de privilèges locale (privilege escalation) pour devenir administrateur.

Ce comportement est **volontaire** : on préfère montrer ces chemins car un accès distant sur une machine Tier 0 reste une position stratégique. L'attaquant peut tenter une élévation locale pour ensuite hériter des droits. Afficher ces chemins donne une motivation pour investiguer les possibilités de privilege escalation sur ces machines.

```
  Exemple :
  UserA ──CanRDP──▶ DC01 (Tier 0)

  En réalité : UserA a une session RDP sur le DC mais n'est PAS admin local. Il ne peut pas dumper
  les credentials ni utiliser le compte machine DC01$.

  Dans ARGUS : UserA est promu Tier 0 car l'accès au DC est une position critique — une élévation
  locale suffirait à compromettre le domaine. Le chemin est montré pour alerter sur ce risque.
```

---

## 7. Annexe A — Cartographie complète des RIDs Active Directory

Cette annexe référence **tous les RIDs standard** d'Active Directory et justifie pour chacun son inclusion ou exclusion du Tier 0 (Phase 1) dans ARGUS.

Légende :
- `T0` = inclus dans l'attribution directe Tier 0 (Phase 1)
- `--` = exclu (géré dynamiquement par une phase ultérieure ou sans impact offensif)

### 7.1 RIDs du domaine (S-1-5-21-\<DomainSID\>-RID)

Ces SIDs sont spécifiques à chaque domaine. Ils identifient les comptes et groupes globaux créés ou intégrés par défaut lors de la promotion d'un DC.

```
  RID   Nom                              ARGUS    Justification
  ────  ───────────────────────────────   ──────   ──────────────────────────────────────────────────────────────────
  500   Administrator                    T0       Compte administrateur racine. Contrôle total natif sur le domaine.

  501   Guest                            --       Compte invité. Désactivé par défaut, aucun droit offensif.

  502   KRBTGT                           T0       Clé de chiffrement du service Kerberos. Sa compromission permet de
                                                   forger des Golden Tickets (accès permanent au domaine).

  512   Domain Admins                    T0       Groupe d'administration globale. Membres = contrôle total du domaine.

  513   Domain Users                     --       Tous les utilisateurs du domaine. Groupe par défaut sans privilège.

  514   Domain Guests                    --       Invités du domaine. Aucun impact.

  515   Domain Computers                 --       Toutes les machines jointes au domaine. Pas de privilège direct
                                                   (mais peut être vecteur ADCS via Enroll, cf. ESC1).

  516   Domain Controllers               T0       Groupe des contrôleurs de domaine. Détient la base NTDS.dit.

  517   Cert Publishers                  T0       Publie les certificats dans l'AD. Vecteur très courant pour les
                                                   attaques ESC (ADCS). Contrôle de la PKI interne.

  518   Schema Admins                    T0       Peut modifier le schéma (structure) de la base AD. Modification
                                                   irréversible.

  519   Enterprise Admins                T0       Contrôle absolu sur l'ensemble de la forêt AD (tous les domaines).

  520   Group Policy Creator Owners      T0       Peuvent créer des GPOs et en sont propriétaires (Owns). Une GPO
                                                   liée à une OU critique = exécution de code. Cible de rebond
                                                   fréquente en CTF.

  521   Read-only Domain Controllers     --       RODC (lecture seule). Ne permet pas de compromettre le domaine
                                                   principal directement. Secrets limités.

  522   Cloneable Domain Controllers     --       Indique quelles machines DC peuvent être clonées (virtualisation).
                                                   Pas d'impact offensif direct.

  525   Protected Users                  --       Groupe DÉFENSIF (empêche la délégation Kerberos, force AES).
                                                   Aucun droit offensif — protège ses membres.

  526   Key Admins                       T0       Peut lire/écrire les attributs de clés publiques
                                                   (msDS-KeyCredentialLink) sur TOUT le domaine. Permet les attaques
                                                   Shadow Credentials sur n'importe quel compte, y compris les DCs.
                                                   (Windows Server 2016+, WHfB)

  527   Enterprise Key Admins            T0       Équivalent de Key Admins pour l'ensemble de la forêt AD. Même
                                                   impact, portée multi-domaine.
```

### 7.2 RIDs Built-In locaux (S-1-5-32-RID)

Ces SIDs sont **génériques** et identiques sur tous les systèmes Windows. Sur un contrôleur de domaine, ces groupes locaux ont un impact particulièrement critique car ils s'appliquent à la machine qui détient l'annuaire.

```
  RID   Nom                              ARGUS    Justification
  ────  ───────────────────────────────   ──────   ──────────────────────────────────────────────────────────────────
  544   Administrators                   T0       Administrateurs locaux. Sur un DC, équivaut à Domain Admins
                                                   (accès NTDS.dit, SAM, credentials mémoire).

  545   Users                            --       Utilisateurs locaux standards.

  546   Guests                           --       Invités locaux. Aucun impact.

  547   Power Users                      --       Reliquat obsolète de Windows XP/2003. Aucun privilège réel sur
                                                   un DC moderne.

  548   Account Operators                T0       Peuvent créer, modifier et supprimer des comptes (y compris reset
                                                   de mot de passe). Escalade facile vers un compte privilégié.

  549   Server Operators                 T0       Peuvent gérer les services sur les DCs (démarrer/arrêter). Pivot
                                                   classique : remplacement d'un binaire de service → exécution
                                                   en SYSTEM.

  550   Print Operators                  T0       Peuvent charger des pilotes d'imprimante sur le DC. Vecteur
                                                   d'attaque PrintNightmare / Spooler (CVE-2021-1675,
                                                   CVE-2021-34527).

  551   Backup Operators                 T0       Peuvent ignorer toutes les ACLs pour sauvegarder/restaurer des
                                                   fichiers. Dump direct de NTDS.dit et du registre SAM/SYSTEM
                                                   possible.

  552   Replicators                      --       Service de réplication de fichiers (FRS, obsolète). Remplacé
                                                   par DFS-R.

  553   RAS and IAS Servers              --       Droit de lire certaines propriétés d'accès distant. Pas d'impact
                                                   offensif.

  554   Pre-Windows 2000 Compatible...   --       Rétrocompatibilité NT4. Accès en lecture sur certains attributs.
                                                   Faible risque sauf si enum anonyme activée.

  555   Remote Desktop Users             --       Accès RDP. Géré dynamiquement par Phase 3 : CanRDP vers un
                                                   DC → promotion T0 automatique.

  556   Network Configuration Operators  --       Changement de configuration réseau locale. Pas d'escalade AD.

  557   Incoming Forest Trust Builders   --       Peuvent créer des approbations de forêt (Trusts). Dangereux mais
                                                   pas T0 immédiat — nécessite un domaine externe malveillant.

  558   Performance Monitor Users        --       Monitoring de performances. Aucun droit d'écriture.

  559   Performance Log Users            --       Lecture de logs de performance.

  560   Windows Authorization Access     --       Droit de lire les token groups évalués. Lecture seule.

  561   Terminal Server License Servers  --       Gestionnaire de licences RDS.

  562   Distributed COM Users            --       Accès DCOM. Géré dynamiquement par Phase 3 : DCOM vers un
                                                   DC → promotion T0 automatique.

  568   IIS_IUSRS                        --       Identités des processus IIS (Web). Pas de lien direct avec l'AD.

  569   Cryptographic Operators          --       Opérations crypto locales (IPsec). Ne donne pas accès à ADCS ni
                                                   aux clés de l'annuaire.

  573   Event Log Readers                --       Lecture locale du journal d'événements. Informatif uniquement.

  574   Certificate Service DCOM Access  --       Accès DCOM aux services de certificat. Impact dépend de la
                                                   configuration ADCS spécifique — pas T0 par défaut.

  578   Hyper-V Administrators           --       Admin Hyper-V local. Critique si le DC tourne en VM sur cet
                                                   hyperviseur, mais relation hors-AD (pas modélisable dans le
                                                   graphe BloodHound).

  580   Remote Management Users          --       Accès WinRM / PowerShell Remoting. Géré dynamiquement par
                                                   Phase 3 : CanPSRemote vers un DC → promotion T0 automatique.

  582   Storage Replica Administrators   --       Gestion de la réplication du stockage local. Pas d'impact AD.
```

### 7.3 Résumé des choix de design

```
  ┌───────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │                                                                                                       │
  │  14 RIDs inclus dans l'attribution directe Tier 0 (Phase 1)                                           │
  │  ──────────────────────────────────                                                                   │
  │  Domaine : 500, 502, 512, 516, 517, 518, 519, 520, 526, 527                                           │
  │  Built-In : 544, 548, 549, 550, 551                                                                   │
  │                                                                                                       │
  │  Critère d'inclusion :                                                                                │
  │  "Un attaquant membre de ce groupe peut-il compromettre le domaine SANS dépendre d'une autre          │
  │   relation dans le graphe ?"                                                                          │
  │                                                                                                       │
  │  Exclusions notables et leur gestion :                                                                │
  │  ─────────────────────────────────────                                                                │
  │  555 (RDP Users)    → Phase 3 : CanRDP vers DC = T0                                                   │
  │  562 (DCOM Users)   → Phase 3 : DCOM vers DC = T0                                                     │
  │  580 (WinRM Users)  → Phase 3 : CanPSRemote vers DC = T0                                              │
  │  515 (Domain Comp.) → Pas de droit direct, mais vecteur ADCS implicite via MachineAccountQuota        │
  │  521 (RODC)         → Secrets limités, pas de compromission directe du domaine principal              │
  │                                                                                                       │
  └───────────────────────────────────────────────────────────────────────────────────────────────────────┘
```


---

## 8. Annexe B — Cartographie complète des permissions AD (DACL)

Cette annexe référence **toutes les permissions AD** exploitables offensivement, leur traitement dans ARGUS, et la correspondance entre les droits réels AD et ce que le collecteur BloodHound exporte.

### 8.1 Droits génériques (Generic Access Rights)

Les droits génériques sont des flags binaires dans la DACL de chaque objet AD. Ils sont posés **sans GUID** et s'appliquent à l'objet entier.

```
  Droit AD                Promotion     Phase    Justification
  ──────────────────────  ─────────     ──────   ──────────────────────────────────────────────────────────────────
  GenericAll (GA)         Hér. direct   Ph.2     Contrôle total sur l'objet. Lecture + écriture + suppression
                                                  + modification DACL. C'est le droit le plus puissant.

  WriteDacl (WD)          Hér. direct   Ph.2     Modifier les permissions (ACL) de l'objet. Peut s'accorder
                                                  GenericAll en une opération.

  WriteOwner (WO)         Hér. direct   Ph.2     Changer le propriétaire de l'objet → devenir owner → WriteDacl
                                                  implicite.

  Owns                    Hér. direct   Ph.2     Être propriétaire. Le owner a toujours WriteDacl implicite sur
                                                  son objet.

  GenericWrite (GW)       BFS           Ph.5     Écriture d'attributs. Problème : inclut des attributs critiques
                                                  ET inoffensifs (voir §8.5). Trop ambigu pour la Phase 2.

  GenericRead (GR)        EXCLU         --       Lecture seule. Aucun impact offensif sur la topologie.

  GenericExecute (GE)     EXCLU         --       Exécution (hérité de NTFS). Pas d'impact dans le contexte AD.
```

### 8.2 Droits étendus et attributs spécifiques

Ces droits correspondent à des **Extended Rights** ou des **WriteProperty ciblés** (avec un GUID d'attribut spécifique). BloodHound traduit certains GUIDs en noms synthétiques (ex: `AddMember`), d'autres sont regroupés.

```
  Droit (nom BloodHound)         ARGUS         Phase    Justification
  ─────────────────────────────  ─────────     ──────   ──────────────────────────────────────────────────────────
  ForceChangePassword            Hér. direct   Ph.2     Droit étendu User-Force-Change-Password. Reset du mot de
                                                        passe SANS connaître l'ancien. Prise de contrôle de compte
                                                        immédiate.

  AddMember / WriteMember        Hér. direct   Ph.2     WriteProperty sur l'attribut member (GUID bf9679c0-...).
                                                        Ajouter un utilisateur à un groupe. Sur un groupe T0 =
                                                        devenir T0.

  AddKeyCredentialLink           Hér. direct   Ph.2     WriteProperty sur l'attribut msDS-KeyCredentialLink
                                                        (GUID 5b47d60f-...). Attaque Shadow Credentials : forger
                                                        un certificat pour le compte cible via PKINIT. Prise de
                                                        contrôle totale.

  WriteAccountRestrictions       BFS           Ph.5     WriteProperty sur l'attribut userAccountControl
                                                        (GUID bf967a68-...). Manipulation des flags UAC : activer
                                                        DONT_REQ_PREAUTH (AS-REPRoasting) ou désactiver un compte.
                                                        BFS car nécessite une étape d'exploitation supplémentaire.

  AllExtendedRights              BFS           Ph.5     Accorde TOUS les droits étendus sur l'objet (inclut
                                                        Force-Change-Password, etc.). Trop large pour la Phase 2 :
                                                        inclut aussi des droits sans impact sécurité. Sur un objet
                                                        Domain → synthétisé en DCSync.

  ReadLAPSPassword               Phase 3 +     Ph.3     Lecture du mot de passe admin local (LAPS). Sur un DC ou
                                 BFS           Ph.5     une OU contenant un DC → promotion T0 (Phase 3). Sur les
                                                        autres machines → BFS uniquement.

  ReadGMSAPassword               BFS           Ph.5     Lecture du hash NT du compte gMSA (Group Managed Service
                                                        Account). Permet de s'authentifier en tant que ce service
                                                        account.
```

### 8.3 Droits d'infrastructure (GPO, DCSync, ADCS)

```
  Droit (nom BloodHound)         ARGUS         Phase    Justification
  ─────────────────────────────  ─────────     ──────   ──────────────────────────────────────────────────────────
  DCSync                         Attr. dir.    Ph.1     Droit synthétique : GetChanges + GetChangesAll sur un objet
  GetChanges                                            Domain = réplication de l'annuaire. Dump de tous les hash
  GetChangesAll                                         NT. Identifié directement dans l'attribution directe (Ph.1).
  GetChangesInFilteredSet

  WriteGPO / EditGPO             Phase 3       Ph.3     Modifier le contenu d'une GPO liée à l'OU des DCs. Permet
                                                        d'exécuter du code sur les DCs au prochain gpupdate.
                                                        Promotion T0 dans Phase 3 (hér. indirect).

  Enroll / AutoEnroll            BFS           Ph.5     Inscription à un template de certificat ADCS. Impact dépend
                                                        du template (ESC1 = critique, template standard = aucun
                                                        impact). BFS car exploitabilité conditionnelle.
```

### 8.4 Droits d'accès machine (collecteurs BloodHound)

Ces droits ne proviennent pas des ACEs mais des **collecteurs** de BloodHound (LocalAdmins, Sessions, RemoteDesktopUsers, etc.).

```
  Droit (edge BloodHound)        ARGUS         Phase    Justification
  ─────────────────────────────  ─────────     ──────   ──────────────────────────────────────────────────────────
  AdminTo                        Phase 3 +     Ph.3     Admin local de la machine. Sur un DC → Phase 3 (T0).
                                 BFS           Ph.5     Sinon → BFS. Admin local = dump credentials, héritage
                                                        du compte machine.

  CanRDP                         Phase 3 +     Ph.3     Remote Desktop. Sur un DC → Phase 3 (T0). Sinon → BFS.
                                 BFS           Ph.5     Accès interactif à la machine.

  CanPSRemote                    Phase 3 +     Ph.3     PowerShell Remoting / WinRM. Sur un DC → Phase 3 (T0).
                                 BFS           Ph.5     Sinon → BFS. Exécution de commandes à distance.

  ExecuteDCOM / DCOM             Phase 3 +     Ph.3     Distributed COM. Sur un DC → Phase 3 (T0). Sinon → BFS.
                                 BFS           Ph.5     Exécution de code via objets COM distants.

  HasSession / LoggedOn          BFS           Ph.5     Session active sur la machine. Non-déterministe (la session
                                                        peut avoir expiré). BFS uniquement.

  MemberOf                       Phase 4 +     Ph.4     Appartenance à un groupe. Phase 4 : membre d'un groupe
                                 BFS           Ph.5     T0 → T0. BFS : calcul de distance pour les autres groupes.
```

### 8.5 Le problème GenericWrite — limitation du collecteur BloodHound

C'est une **limitation de Bloodhound-python**, pas d'ARGUS. Le collecteur BloodHound résout certains WriteProperty ciblés (GUID d'attribut) en edges nommés, mais **regroupe les autres sous GenericWrite**. Cela fait perdre la granularité de droits critiques pour l'exploitation.

ARGUS travaille avec les données que le collecteur fournit. Recoder et maintenir un collecteur AD complet est hors périmètre — on s'appuie sur l'écosystème BloodHound existant.

```
  ┌───────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │  GUIDS RÉSOLUS PAR BLOODHOUND → edge distinct                                                         │
  ├───────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │  msDS-KeyCredentialLink   5b47d60f-...  → AddKeyCredentialLink                                        │
  │  userAccountControl       bf967a68-...  → WriteAccountRestrictions                                    │
  │  member                   bf9679c0-...  → AddMember                                                   │
  ├───────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │                                                                                                       │
  │  GUIDS NON RÉSOLUS → noyés dans GenericWrite                                                          │
  ├───────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │                                                                                                       │
  │  servicePrincipalName     f3a64788-...     Targeted Kerberoasting                                     │
  │    → Ajouter un SPN sur un compte → demander un ticket Kerberos (TGS) → cracker le hash hors-ligne.   │
  │      Succès dépend de la force du mot de passe.                                                       │
  │                                                                                                       │
  │  msDS-AllowedToActOn...   3f78c3e5-...     RBCD                                                       │
  │    → Resource-Based Constrained Delegation. Configurer la cible pour accepter la délégation depuis    │
  │      un compte qu'on contrôle → impersonation via S4U2Self + S4U2Proxy. Contrôle total.               │
  │                                                                                                       │
  │  gPLink                   f30e3bbe-...     GPO Link manipulation                                      │
  │    → Lier une GPO malveillante à une OU critique. Si l'attaquant contrôle une GPO + a ce droit sur    │
  │      l'OU des DCs → exécution de code sur les DCs.                                                    │
  │                                                                                                       │
  │  scriptPath               bf967a7c-...     Logon script injection                                     │
  │    → Modifier le script de logon d'un utilisateur. Exécution de code au prochain login de la cible.   │
  │      Discret et efficace.                                                                             │
  │                                                                                                       │
  │  msDS-GroupMSAMembership  888eedd6-...     gMSA reader hijack                                         │
  │    → Modifier la liste des principals autorisés à lire le hash du compte gMSA → lecture du mot de     │
  │      passe du service account.                                                                        │
  │                                                                                                       │
  ├───────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │                                                                                                       │
  │  CONSÉQUENCE POUR ARGUS :                                                                             │
  │  GenericWrite est dans le BFS (Phase 5) mais EXCLU de la Phase 2 car on ne peut pas distinguer un     │
  │  WriteProperty sur servicePrincipalName (critique) d'un WriteProperty sur description (inoffensif).   │
  │  Si BloodHound CE décompose ces GUIDs à l'avenir, ils pourront être ajoutés individuellement.         │
  │                                                                                                       │
  └───────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 8.6 Résumé — Matrice permissions × phases ARGUS

```
  ┌─────────────────────────────┬───────┬─────────┬──────────┬─────────┬───────┐
  │ Permission                  │ Attr. │  Hér.   │   Hér.   │ Membres │  BFS  │
  │                             │ dir.  │ direct  │ indirect │ grp. T0 │       │
  │                             │ Ph.1  │  Ph.2   │   Ph.3   │  Ph.4   │ Ph.5  │
  ├─────────────────────────────┼───────┼─────────┼──────────┼─────────┼───────┤
  │ GenericAll                  │       │    ●    │          │         │   ●   │
  │ WriteDacl                   │       │    ●    │          │         │   ●   │
  │ WriteOwner                  │       │    ●    │          │         │   ●   │
  │ Owns                        │       │    ●    │          │         │   ●   │
  │ ForceChangePassword         │       │    ●    │          │         │   ●   │
  │ AddMember / WriteMember     │       │    ●    │          │         │   ●   │
  │ AddKeyCredentialLink        │       │    ●    │          │         │   ●   │
  ├─────────────────────────────┼───────┼─────────┼──────────┼─────────┼───────┤
  │ DCSync (GetChanges...)      │   ●   │         │          │         │   ●   │
  ├─────────────────────────────┼───────┼─────────┼──────────┼─────────┼───────┤
  │ AdminTo                     │       │         │  ● (T0)  │         │   ●   │
  │ CanRDP                      │       │         │  ● (T0)  │         │   ●   │
  │ CanPSRemote                 │       │         │  ● (T0)  │         │   ●   │
  │ DCOM                        │       │         │  ● (T0)  │         │   ●   │
  │ ReadLAPSPassword            │       │         │  ● (T0)  │         │   ●   │
  │ WriteGPO / EditGPO          │       │         │  ● (T0)  │         │   ●   │
  ├─────────────────────────────┼───────┼─────────┼──────────┼─────────┼───────┤
  │ MemberOf                    │       │         │          │    ●    │   ●   │
  ├─────────────────────────────┼───────┼─────────┼──────────┼─────────┼───────┤
  │ GenericWrite                │       │         │          │         │   ●   │
  │ AllExtendedRights           │       │         │          │         │   ●   │
  │ WriteAccountRestrictions    │       │         │          │         │   ●   │
  │ ReadGMSAPassword            │       │         │          │         │   ●   │
  │ Enroll / AutoEnroll         │       │         │          │         │   ●   │
  │ HasSession / LoggedOn       │       │         │          │         │   ●   │
  ├─────────────────────────────┼───────┼─────────┼──────────┼─────────┼───────┤
  │ GenericRead / Execute       │       │         │          │         │       │
  └─────────────────────────────┴───────┴─────────┴──────────┴─────────┴───────┘

  ● = pris en compte dans cette phase
  ● (T0) = pris en compte uniquement si la cible est un Domain Controller
         ou une machine déjà classée Tier 0
```
