# Reconnaissance Locale - CartoAD

Ce module permet d'effectuer une reconnaissance locale sur la machine où le script est exécuté. Il est conçu pour identifier les comptes utilisateurs, les configurations réseau et les vecteurs d'attaque potentiels (credentials, tickets Kerberos).

## Fonctionnalités

- **Informations Système** : OS, Hostname, Architecture.
- **Utilisateurs** : Utilisateur actuel, groupes, liste des utilisateurs locaux.
- **Réseau** : Interfaces, DNS, routes.
- **Comptes AD (Linux)** : Détection si la machine est jointe au domaine (SSSD/Winbind) et énumération des comptes de domaine via `getent`.
- **Secrets & Credentials** :
  - Recherche de mots de passe/tokens dans les fichiers d'historique (`.bash_history`, etc.).
  - Identification de fichiers sensibles (`.ssh/id_*`, `.aws/credentials`, keytabs Kerberos).
  - Détection de tickets Kerberos actifs (`klist`).

## Utilisation

```bash
python3 local/local_recon.py
```

Les résultats sont sauvegardés dans `local_recon.json` à la racine du projet (ou dans le dossier courant).

## Intégration

Les comptes identifiés (ex: `user@DOMAIN.LOCAL`) peuvent être utilisés comme paramètres pour le script principal `run_full_scan.py` :

```bash
python3 run_full_scan.py --user <trouve_localement> --password <trouve_localement> ...
```
