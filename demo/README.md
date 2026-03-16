# Cas de demonstration — Soutenance ARGUS

Ces 5 cas sont pre-generes et prets a charger dans `cartographie.html`.
Chaque dossier contient les fichiers `graph_tier0/1/2.json` et, quand disponibles, `network_scan.json` et `hostname_mapping.json`.

---

## 1. Cicada — Cas simple

**Point de depart** : `emily.oscars` | **Domaine** : CICADA.HTB

Cas introductif, petit domaine avec un chemin lineaire vers le DC. Ideal pour une premiere demonstration du fonctionnement de l'outil et de la classification en tiers.

- Tier 0 : 6 noeuds, 6 edges
- Chemin : emily.oscars → groupes → DC

**Ce que ca montre** : classification de base, detection du DC, groupes privilegies.

---

## 2. Administrator — Chemin DCSync lineaire

**Point de depart** : `emily` | **Domaine** : ADMINISTRATOR.HTB

Chemin d'attaque classique et lisible : emily possede GenericWrite sur ethan, qui possede GetChanges/GetChangesAll (DCSync) sur le domaine. Parfait pour expliquer comment un droit d'ecriture sur un utilisateur mene au controle total du domaine.

- Tier 0 : 6 noeuds, 7 edges
- Chemin : emily → GenericWrite → ethan → DCSync → ADMINISTRATOR.HTB

**Ce que ca montre** : escalade de privileges via ACL, DCSync, distances BFS.

---

## 3. Forest — Graphe complexe avec Exchange

**Point de depart** : `svc-alfresco` | **Domaine** : HTB.LOCAL

Cas le plus riche : environnement avec Microsoft Exchange installe. Multiples groupes privilegies (Organization Management, Exchange Trusted Subsystem, Exchange Windows Permissions) qui creent de nombreux chemins d'escalade vers le domaine. Inclut le scan reseau et le mapping hostname.

- Tier 0 : 15 noeuds, 32 edges
- Reseau : scan complet avec fusion IP ↔ Computer AD
- Chemin : svc-alfresco → Service Accounts → ... → WriteDacl → HTB.LOCAL

**Ce que ca montre** : graphe dense, fusion reseau/identite, ponts IP↔Computer, impact d'Exchange sur la securite AD.

---

## 4. Timelapse — Detection LAPS

**Point de depart** : `svc_deploy` | **Domaine** : TIMELAPSE.HTB

Cas qui illustre la detection des droits LAPS. svc_deploy est membre de LAPS_READERS (Tier 0 par INDIRECT) et possede CanPSRemote sur le DC. Le chemin combine lecture du mot de passe admin local (LAPS) et acces distant (PSRemote).

- Tier 0 : 6 noeuds, 7 edges
- Chemin : svc_deploy → MemberOf → LAPS_READERS → ReadLAPSPassword → DC01
- Aussi : svc_deploy → CanPSRemote → DC01

**Ce que ca montre** : detection LAPS, phase INDIRECT, acces distant au DC.

---

## 5. Escape — Vulnerabilite ADCS (ESC1)

**Point de depart** : `ryan.cooper` | **Domaine** : SEQUEL.HTB

Cas qui demontre l'integration ADCS. Le template UserAuthentication est vulnerable a ESC1 (Enrollee Supplies Subject + Client Authentication). Domain Users possede le droit Enroll, ce qui permet a tout utilisateur du domaine de demander un certificat au nom d'un autre (ex: Administrator).

- Tier 0 : 10 noeuds, 10 edges (dont 1 CertTemplate)
- Chemin : ryan.cooper → MemberOf → Domain Users → Enroll → UserAuthentication [ESC1]
- Template CertTemplate affiche en magenta dans la cartographie

**Ce que ca montre** : detection ADCS, classification CertTemplate en Tier 0, traduction certipy → format ARGUS.

---

## Comment presenter

1. **Ouvrir** `cartographie.html` dans un navigateur
2. **Charger** les fichiers du cas choisi (graph_tier0.json en premier)
3. Pour le cas Forest, charger aussi `network_scan.json` et `hostname_mapping.json` pour montrer la fusion

**Ordre de presentation suggere** :
1. Cicada (intro, expliquer l'interface)
2. Administrator (chemin simple, expliquer tiers et BFS)
3. Timelapse (LAPS, expliquer la phase INDIRECT)
4. Escape (ADCS, expliquer l'integration certipy)
5. Forest (cas complet avec reseau, montrer la fusion)
