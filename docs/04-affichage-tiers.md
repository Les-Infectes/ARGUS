# Affichage des chemins d'attaque — ARGUS

## Table des matières

1. [Classification vs Affichage](#1-classification-vs-affichage)
2. [Déterministe → T0](#2-déterministe--t0)
3. [Non-déterministe → T0](#3-non-déterministe--t0)
4. [Éloigné → T0](#4-éloigné--t0)
5. [Filtre de nœuds de départ → T0](#5-filtre-de-nœuds-de-départ--t0)
6. [Cohérence classification / affichage](#6-cohérence-classification--affichage)

---

## 1. Classification vs Affichage

ARGUS distingue deux concepts indépendants :

**Classification des objets** (propriété fixe) : l'algorithme en 5 phases (voir [03-classification-object.md](03-classification-object.md)) attribue un tier à chaque objet du domaine. Le tier est une propriété intrinsèque de l'objet, indépendante du nœud de départ.

```
  Tier 0 : contrôle déterministe du domaine
           (attribution directe, héritage direct, héritage indirect, membres groupes T0)
  Tier 1 : distance BFS 1-7 hops depuis Tier 0
  Tier 2 : distance BFS 8+ hops ou inaccessible
```

**Modes d'affichage** (dépend du nœud de départ) : à partir d'un nœud de départ choisi par l'auditeur, ARGUS affiche les chemins d'attaque vers les objets Tier 0 selon la **nature des droits utilisés** dans le chemin, pas selon le tier des objets traversés.

```
  ┌───────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │                                                                                                       │
  │  Classification = QUI est dans quel tier (propriété de chaque objet, fixe)                            │
  │  Affichage      = COMMENT atteindre Tier 0 (nature du chemin, dépend du nœud de départ)              │
  │                                                                                                       │
  │  Les 3 modes d'affichage :                                                                           │
  │    Déterministe → T0  : chemins utilisant uniquement des droits certains (whitelist)                  │
  │    Non-déterministe → T0        : chemins utilisant au moins un droit incertain                                │
  │    Éloigné → T0       : chemins depuis des objets distants (8+ hops)                                 │
  │                                                                                                       │
  └───────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Déterministe → T0

**Bouton** : `Déterministe → T0`

**Principe** : affiche les chemins depuis le nœud de départ vers les objets Tier 0, en utilisant uniquement les droits de la whitelist déterministe. Chaque droit utilisé dans le chemin garantit un contrôle effectif sur la cible.

```
  ┌───────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │  DROITS AUTORISÉS (whitelist déterministe)                                                            │
  ├───────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │                                                                                                       │
  │  TIER0_DCSYNC_RIGHTS (attribution directe — Phase 1) :                                                │
  │    DCSync, GetChanges, GetChangesAll, GetChangesInFilteredSet                                         │
  │                                                                                                       │
  │  TIER0_CLOSURE_RIGHTS (héritage direct — Phase 2) :                                                   │
  │    GenericAll, WriteDacl, WriteOwner, Owns, AddMember, WriteMember,                                   │
  │    ForceChangePassword, ResetPassword, AddKeyCredentialLink, WriteKeyCredentialLink                    │
  │                                                                                                       │
  │  ADMIN_ACCESS_RIGHTS (héritage indirect — Phase 3) :                                                  │
  │    AdminTo                                                                                            │
  │                                                                                                       │
  │  REMOTE_ACCESS_RIGHTS (héritage indirect — Phase 3) :                                                 │
  │    CanRDP, CanPSRemote, ExecuteDCOM, DCOM                                                             │
  │                                                                                                       │
  │  TIER0_READPASS_RIGHTS (héritage indirect — Phase 3) :                                                │
  │    ReadLAPSPassword, ReadGMSAPassword                                                                 │
  │                                                                                                       │
  │  Relations structurelles :                                                                            │
  │    MemberOf                                                                                           │
  │                                                                                                       │
  └───────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

**Propriété clé** : tous les nœuds affichés sont eux-mêmes classifiés Tier 0. C'est garanti par la synchronisation entre les droits d'affichage et les droits de classification (voir §6).

**Exemple** :

```
  MS01 (T0) ──MemberOf──▶ DOMAIN SECURE SERVERS (T0) ──ReadGMSAPassword──▶ GMSA_ADCS (T0) ──CanPSRemote──▶ DC01 (T0)
```

Chaque intermédiaire a été promu T0 par la classification :
- DOMAIN SECURE SERVERS : ReadGMSAPassword sur un objet T0 → héritage indirect (Phase 3)
- MS01 : membre d'un groupe T0 → membres groupes T0 (Phase 4)

---

## 3. Non-déterministe → T0

**Bouton** : `Non-déterministe → T0`

**Principe** : affiche les chemins depuis le nœud de départ vers les objets Tier 0 qui utilisent **au moins un droit non déterministe**. Ces chemins existent mais ne sont pas affichés en mode déterministe car les droits utilisés ne garantissent pas un contrôle certain — ils nécessitent une vérification manuelle par l'auditeur.

```
  ┌───────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │  DROITS AMBIGUS (exclus du mode déterministe, visibles ici)                                           │
  ├───────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │                                                                                                       │
  │  GenericWrite             — dépend de l'attribut modifié                                              │
  │  AllExtendedRights        — inclut plusieurs droits, faux positifs possibles                         │
  │  WriteProperty            — attribute-aware requis                                                    │
  │  WriteSPN                 — Targeted Kerberoasting, dépend du crackage                               │
  │  WriteAccountRestrictions — modification flags UAC                                                    │
  │  WriteGPO, EditGPO        — modification de GPO                                                      │
  │  Enroll, AutoEnroll       — ADCS enrollment                                                          │
  │  HasSession, LoggedOn     — sessions actives (non-déterministe)                                      │
  │                                                                                                       │
  └───────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

**Profondeur maximale** : 7 hops (cohérent avec la classification Tier 1 = 1-7 hops BFS).

**Construction des chemins** :

```
  Étape 1 : Trouver tous les chemins  départ → objet T0  (tous les droits, max 7 hops)
  Étape 2 : Ne garder que les chemins utilisant au moins un droit hors whitelist déterministe
  Résultat : départ → ... → objet T0  (via au moins un droit non déterministe)
```

**Les nœuds affichés** peuvent être de n'importe quel tier (T0, T1, T2). Un chemin non déterministe peut passer par un objet T0 qui a lui-même un droit non déterministe vers un autre T0. Le critère est la **nature du droit**, pas le **tier de l'objet**.

**Exemple** :

```
  EMILY (T0) ──GenericWrite──▶ ETHAN (T0) ──DCSync──▶ ADMINISTRATOR.HTB (T0)
```

Emily a GenericWrite sur Ethan — ce droit dépend de l'attribut modifié. Ce chemin n'apparaît pas en mode déterministe car GenericWrite n'est pas dans la whitelist, mais il représente une voie d'attaque potentielle que l'auditeur doit vérifier manuellement.

---

## 4. Éloigné → T0

**Bouton** : `Éloigné → T0`

**Principe** : affiche les objets Tier 2 (distance 8+ hops ou inaccessibles depuis Tier 0) accessibles depuis le nœud de départ, puis prolonge vers les objets Tier 0 si un chemin existe.

**Droits utilisés** : tous les droits (`ALL_PRIVILEGE_RIGHTS`).

**Construction du chemin** :

```
  Étape 1 : Trouver les objets classifiés T2 accessibles depuis le nœud de départ
  Étape 2 : Pour chaque objet T2 atteint, prolonger vers un objet T0 (si possible)

  Résultat : départ → ... → objet T2 → ... → objet T0  (si chemin existe)
             départ → ... → objet T2                    (si aucun chemin vers T0)
```

**Différence avec Non-déterministe** : le mode Éloigné cible les objets classifiés Tier 2 (distance ≥ 8 hops). Ces objets peuvent ne pas avoir de chemin vers T0 du tout. Ce mode montre l'environnement éloigné du nœud de départ.

---

## 5. Filtre de nœuds de départ → T0

**Bouton** : `départ → X → T0`

Ce filtre apparaît dans la barre de sélection du nœud de départ. Il identifie tous les objets qui ont **au moins un chemin d'attaque vers un objet Tier 0**, quel que soit le tier de l'objet lui-même.

```
  ┌───────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │  CONSTRUCTION DU FILTRE                                                                               │
  ├───────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │                                                                                                       │
  │  1. Classification complète (attribution directe → héritage → membres) → ensemble Tier 0              │
  │                                                                                                       │
  │  2. Construction du graphe global :                                                                   │
  │     - ACE rights (ALL_PRIVILEGE_RIGHTS)                                                               │
  │     - Appartenances aux groupes (MemberOf)                                                            │
  │     - Accès machine (AdminTo, CanRDP, CanPSRemote, DCOM)                                              │
  │     - Sessions (HasSession)                                                                           │
  │                                                                                                       │
  │  3. Reverse BFS depuis tous les objets Tier 0                                                         │
  │     → trouve tous les objets qui peuvent atteindre T0                                                 │
  │                                                                                                       │
  │  4. Ajout des objets T0 qui ont un edge vers un autre T0                                              │
  │     → car ils produisent un graphe déterministe non vide comme nœud de départ                         │
  │                                                                                                       │
  └───────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

**Utilité** : sur un domaine inconnu, ce filtre permet d'identifier rapidement les nœuds de départ les plus intéressants pour explorer les chemins d'attaque vers le contrôle du domaine.

---

## 6. Cohérence classification / affichage

La règle fondamentale qui garantit la cohérence entre classification et affichage :

```
  ┌───────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │                                                                                                       │
  │  Le mode Déterministe n'utilise que des droits de la classification T0.                               │
  │  Sinon, des intermédiaires non-T0 apparaîtraient dans le graphe — incohérent.                        │
  │                                                                                                       │
  │  Le mode Non-déterministe utilise tous les droits, mais ne garde que les chemins                                │
  │  contenant au moins un droit hors whitelist. Ces chemins sont le complément                           │
  │  exact du mode Déterministe : même cibles (T0), droits différents.                                   │
  │                                                                                                       │
  └───────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

Les constantes correspondantes dans `argus_builder.py` :

```
  Classification T0                                  Affichage Déterministe (tier0_valid_rights)
  ─────────────────────────────────────────          ─────────────────────────────────────────────
  TIER0_DCSYNC_RIGHTS   (attribution directe)  ←→   TIER0_DCSYNC_RIGHTS
  TIER0_CLOSURE_RIGHTS  (héritage direct)      ←→   TIER0_CLOSURE_RIGHTS
  ADMIN_ACCESS_RIGHTS   (héritage indirect)    ←→   ADMIN_ACCESS_RIGHTS
  REMOTE_ACCESS_RIGHTS  (héritage indirect)    ←→   REMOTE_ACCESS_RIGHTS
  TIER0_READPASS_RIGHTS (héritage indirect)    ←→   TIER0_READPASS_RIGHTS
```

**Ajout d'un nouveau droit** : si un nouveau droit doit apparaître dans les chemins déterministes, il faut l'ajouter simultanément dans :
1. La constante appropriée (héritage direct, héritage indirect, etc.)
2. La phase de classification correspondante (Phase 2, 3, etc.)
3. Il sera automatiquement inclus dans `tier0_valid_rights` via l'union des constantes

**Droits non déterministes** : les droits comme GenericWrite, WriteSPN, Enroll, HasSession ne sont dans aucune constante T0. Ils n'apparaissent que dans `ALL_PRIVILEGE_RIGHTS` et donc uniquement dans les modes Non-déterministe et Éloigné.
