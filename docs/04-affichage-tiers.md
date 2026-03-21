# Affichage des chemins d'attaque par Tier — ARGUS

## Table des matières

1. [Classification vs Affichage](#1-classification-vs-affichage)
2. [Mode T0 — Chemins déterministes](#2-mode-t0--chemins-déterministes)
3. [Mode T1 — Chemins incertains](#3-mode-t1--chemins-incertains)
4. [Mode T2 — Chemins éloignés](#4-mode-t2--chemins-éloignés)
5. [Filtre de nœuds de départ → T0](#5-filtre-de-nœuds-de-départ--t0)
6. [Cohérence classification / affichage](#6-cohérence-classification--affichage)

---

## 1. Classification vs Affichage

L'algorithme ARGUS produit deux résultats distincts qu'il ne faut pas confondre :

**Classification des objets** : l'algorithme en 5 phases (voir [03-classification-object.md](03-classification-object.md)) attribue un tier à chaque objet du domaine :

```
  Tier 0 : contrôle déterministe du domaine
           (attribution directe, héritage direct, héritage indirect, membres groupes T0)
  Tier 1 : distance BFS 1-7 hops depuis Tier 0
  Tier 2 : distance BFS 8+ hops ou inaccessible
```

**Affichage des chemins** : à partir d'un nœud de départ choisi par l'utilisateur, ARGUS affiche les chemins d'attaque vers les objets Tier 0, organisés en 3 vues (T0, T1, T2). Chaque vue montre des chemins de nature différente.

```
  ┌───────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │                                                                                                       │
  │  Classification = QUI est dans quel tier (propriété de chaque objet)                                  │
  │  Affichage      = COMMENT atteindre les objets Tier 0 depuis un nœud de départ                        │
  │                                                                                                       │
  └───────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Mode T0 — Chemins déterministes

**Bouton** : `départ → T0 → T0`

**Principe** : affiche les chemins depuis le nœud de départ vers les objets Tier 0, en utilisant uniquement les droits qui provoquent une promotion Tier 0 dans la classification.

```
  ┌───────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │  DROITS AUTORISÉS DANS LES CHEMINS T0                                                                 │
  ├───────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │                                                                                                       │
  │  TIER0_DCSYNC_RIGHTS (attribution directe — Phase 1) :                                                 │
  │    DCSync, GetChanges, GetChangesAll, GetChangesInFilteredSet                                         │
  │                                                                                                       │
  │  TIER0_CLOSURE_RIGHTS (héritage direct — Phase 2) :                                                    │
  │    GenericAll, WriteDacl, WriteOwner, Owns, AddMember, WriteMember,                                   │
  │    ForceChangePassword, ResetPassword, AddKeyCredentialLink, WriteKeyCredentialLink                    │
  │                                                                                                       │
  │  ADMIN_ACCESS_RIGHTS (héritage indirect — Phase 3) :                                                   │
  │    AdminTo                                                                                            │
  │                                                                                                       │
  │  REMOTE_ACCESS_RIGHTS (héritage indirect — Phase 3) :                                                  │
  │    CanRDP, CanPSRemote, ExecuteDCOM, DCOM                                                             │
  │                                                                                                       │
  │  TIER0_READPASS_RIGHTS (héritage indirect — Phase 3) :                                                 │
  │    ReadLAPSPassword, ReadGMSAPassword                                                                 │
  │                                                                                                       │
  │  Relations structurelles :                                                                            │
  │    MemberOf                                                                                           │
  │                                                                                                       │
  └───────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

**Propriété clé** : tous les nœuds affichés dans le graphe T0 sont eux-mêmes classifiés Tier 0. C'est garanti par la synchronisation entre les droits d'affichage et les droits de classification (voir §6).

**Exemple** :

```
  MS01 (T0) ──MemberOf──▶ DOMAIN SECURE SERVERS (T0) ──ReadGMSAPassword──▶ GMSA_ADCS (T0) ──CanPSRemote──▶ DC01 (T0)
```

Chaque intermédiaire a été promu T0 par la classification :
- DOMAIN SECURE SERVERS : ReadGMSAPassword sur un objet T0 → héritage indirect (Phase 3)
- MS01 : membre d'un groupe T0 → membres groupes T0 (Phase 4)

---

## 3. Mode T1 — Chemins incertains

**Bouton** : `départ → T1 → T0`

**Principe** : affiche deux types de chemins d'attaque non déterministes :

1. **Chemins via objets Tier 1** : chemins depuis le nœud de départ vers les objets classifiés Tier 1 (distance 1-7 hops depuis Tier 0), prolongés jusqu'aux objets Tier 0 qu'ils atteignent.

2. **Chemins ambigus vers Tier 0** : chemins depuis le nœud de départ vers des objets Tier 0 qui utilisent au moins un droit non déterministe (GenericWrite, AllExtendedRights, etc.). Ces chemins existent mais ne sont pas affichés en T0 car les droits utilisés ne garantissent pas un contrôle certain.

```
  ┌───────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │  DROITS AUTORISÉS DANS LES CHEMINS T1                                                                 │
  ├───────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │                                                                                                       │
  │  ALL_PRIVILEGE_RIGHTS — tous les droits significatifs :                                                │
  │    Inclut tous les droits T0 PLUS les droits incertains :                                             │
  │    GenericWrite, WriteSPN, AllExtendedRights, WriteAccountRestrictions,                                │
  │    Enroll, AutoEnroll, HasSession, LoggedOn                                                           │
  │                                                                                                       │
  │  DROITS AMBIGUS (exclus du T0, visibles en T1) :                                                      │
  │    GenericWrite      — dépend de l'attribut modifié                                                   │
  │    AllExtendedRights — inclut plusieurs droits, faux positifs possibles                                │
  │    WriteProperty     — attribute-aware requis                                                          │
  │    WriteSPN          — Targeted Kerberoasting, dépend du crackage                                     │
  │                                                                                                       │
  └───────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

**Les nœuds affichés** peuvent être de n'importe quel tier (T0, T1, T2) car les droits incertains ne provoquent pas de promotion T0.

**Construction des chemins** :

```
  Type 1 — Via objets Tier 1 :
    Étape 1 : Trouver les chemins  départ → objet T1
    Étape 2 : Pour chaque objet T1 atteint, prolonger vers un objet T0
    Résultat : départ → ... → objet T1 → ... → objet T0

  Type 2 — Chemins ambigus vers T0 :
    Étape 1 : Trouver les chemins  départ → objet T0  (en utilisant tous les droits)
    Étape 2 : Ne garder que les chemins utilisant au moins un droit hors whitelist T0
    Résultat : départ → ... → objet T0  (via droit ambigu)
```

**Exemple — chemin via objet T1** :

```
  A.WHITE_ADM (T1) ──MemberOf──▶ IT (T1) ──WriteSPN──▶ DC01 (T0) ──MemberOf──▶ DOMAIN CONTROLLERS (T0)
```

WriteSPN est un droit incertain (Targeted Kerberoasting — dépend du crackage du hash), donc IT reste T1. Le chemin complet montre comment un attaquant pourrait potentiellement atteindre T0 via des droits non déterministes.

**Exemple — chemin ambigu vers T0** :

```
  EMILY (T0) ──GenericWrite──▶ ETHAN (T0) ──DCSync──▶ ADMINISTRATOR.HTB (T0)
```

Emily a GenericWrite sur Ethan (droit ambigu — dépend de l'attribut modifié). Ce chemin n'apparaît pas en T0 car GenericWrite n'est pas dans la whitelist déterministe, mais il représente une voie d'attaque potentielle que l'auditeur doit vérifier.

---

## 4. Mode T2 — Chemins éloignés

**Bouton** : `départ → T2 → T0`

**Principe** : affiche les objets Tier 2 (distance 8+ hops ou inaccessibles) reliés au nœud de départ, puis prolonge vers les objets Tier 0 si un chemin existe.

**Droits utilisés** : identiques au mode T1 (`ALL_PRIVILEGE_RIGHTS`).

**Construction du chemin** :

```
  Étape 1 : Trouver les objets T2 accessibles depuis le nœud de départ
  Étape 2 : Pour chaque objet T2 atteint, prolonger vers un objet T0 (si possible)

  Résultat : départ → ... → objet T2 → ... → objet T0  (si chemin existe)
             départ → ... → objet T2                    (si aucun chemin vers T0)
```

**Différence avec T1** : les objets T2 peuvent ne pas avoir de chemin vers T0 (distance infinie). Dans ce cas, seul le lien direct depuis le nœud de départ est affiché.

---

## 5. Filtre de nœuds de départ → T0

**Bouton** : `départ → X → T0`

Ce filtre apparaît dans le formulaire d'import lors de la sélection du nœud de départ. Il identifie tous les objets qui ont **au moins un chemin d'attaque vers un objet Tier 0**, quel que soit le tier de l'objet lui-même.

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
  │     → car ils produisent un graphe T0 non vide comme nœud de départ                                   │
  │                                                                                                       │
  └───────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

**Le filtre inclut** :
- Des objets T0 (qui ont des edges vers d'autres T0) → produisent un graphe T0 intéressant
- Des objets T1 (chemins incertains vers T0) → produisent un graphe T1
- Des objets T2 (chemins éloignés vers T0) → produisent un graphe T2

**Utilité** : sur un domaine inconnu, ce filtre permet d'identifier rapidement les nœuds de départ les plus intéressants pour explorer les chemins d'attaque vers le contrôle du domaine.

---

## 6. Cohérence classification / affichage

La règle fondamentale qui garantit la cohérence entre classification et affichage :

```
  ┌───────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │                                                                                                       │
  │  Si un droit est utilisé dans l'affichage T0, il DOIT être dans la classification T0.                 │
  │                                                                                                       │
  │  Sinon, des intermédiaires non-T0 apparaîtraient dans le graphe T0 — incohérent.                     │
  │                                                                                                       │
  └───────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

Les constantes correspondantes dans `argus_builder.py` :

```
  Classification T0                                  Affichage T0 (tier0_valid_rights)
  ─────────────────────────────────────────          ─────────────────────────────────
  TIER0_DCSYNC_RIGHTS   (attribution directe)  ←→   TIER0_DCSYNC_RIGHTS
  TIER0_CLOSURE_RIGHTS  (héritage direct)      ←→   TIER0_CLOSURE_RIGHTS
  ADMIN_ACCESS_RIGHTS   (héritage indirect)    ←→   ADMIN_ACCESS_RIGHTS
  REMOTE_ACCESS_RIGHTS  (héritage indirect)    ←→   REMOTE_ACCESS_RIGHTS
  TIER0_READPASS_RIGHTS (héritage indirect)    ←→   TIER0_READPASS_RIGHTS
```

**Ajout d'un nouveau droit T0** : si un nouveau droit doit apparaître dans les chemins T0, il faut l'ajouter simultanément dans :
1. La constante appropriée (héritage direct, héritage indirect, etc.)
2. La phase de classification correspondante (Phase 2, 3, etc.)
3. Il sera automatiquement inclus dans `tier0_valid_rights` via l'union des constantes

**Droits T1/T2 uniquement** : les droits comme GenericWrite, WriteSPN, Enroll, HasSession ne sont dans aucune constante T0. Ils n'apparaissent que dans `ALL_PRIVILEGE_RIGHTS` et donc uniquement dans les graphes T1/T2.

**Chemins ambigus vers T0 en mode T1** : lorsqu'un chemin vers un objet T0 utilise un droit hors whitelist (ex: GenericWrite), ce chemin est exclu du graphe T0 (pas déterministe) et affiché dans le graphe T1 (à vérifier par l'auditeur). L'objet cible reste classifié T0, mais le chemin emprunté est ambigu.
