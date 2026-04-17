.. Authors :
.. mviewer team

.. _secruity_scan:

Scan de sécurité
================

Cette page décrit le scan de sécurité JavaScript intégré au dépôt.
Le scan repose sur `Retire.js <https://retirejs.github.io/retire.js/>`_ et sur
le script ``security-scripts/security-audit.js``.

Objectif
--------

Le scan permet de :

- détecter les bibliothèques JavaScript connues par Retire.js ;
- identifier les versions détectées dans les fichiers du dépôt ;
- remonter les vulnérabilités connues, leur sévérité et les CVE associées lorsqu'elles existent ;
- générer un rapport texte exploitable en local et dans GitHub Actions.

Exécution locale
----------------

Prérequis :

- Node.js 24 ;
- les dépendances du projet installées.

Depuis la racine du dépôt ::

    npm ci
    npm run scan

La commande ``npm run scan`` exécute le script ``security-scripts/security-audit.js``.

Fichiers générés
----------------

L'exécution locale produit deux fichiers à la racine du dépôt :

- ``retire-develop.json`` : sortie JSON brute de Retire.js ;
- ``security-report.txt`` : rapport texte généré à partir du JSON.

Le rapport contient notamment :

- un résumé exécutif ;
- un tableau détaillé avec le nom du composant, le fichier source, la version détectée,
  le statut de vulnérabilité, le niveau de risque, les CVE et l'action recommandée ;
- la liste des scripts HTML détectés ;
- des recommandations générales.

Workflow GitHub Actions
-----------------------

Le workflow ``.github/workflows/security-audit.yml`` exécute le même scan :

- sur chaque ``push`` vers la branche ``develop`` ;
- chaque lundi via une planification hebdomadaire.

Dans GitHub Actions :

- ``npm ci`` installe les dépendances ;
- ``npm run scan`` lance l'audit ;
- le rapport est généré avec un nom daté :
  ``security-report-YYYY-MM-DD.txt`` ;
- le rapport est publié comme artefact ``security-audit-report``.

Personnalisation
----------------

Le script accepte plusieurs variables d'environnement utiles :

- ``REPORT_DATE`` : date affichée dans le rapport ;
- ``REPORT_BASENAME`` : nom du fichier de rapport ;
- ``REPORT_FILE`` : chemin complet du rapport généré ;
- ``RETIRE_OUTPUT_FILE`` : chemin du JSON produit par Retire.js.

En local, le comportement par défaut est :

- ``security-report.txt`` pour le rapport ;
- ``retire-develop.json`` pour la sortie brute Retire.js.

Dans GitHub Actions, le workflow force un nom daté pour le rapport généré.

Limites
-------

Ce scan reste un audit automatisé de premier niveau.

- Retire.js ne couvre que les signatures et vulnérabilités qu'il connaît ;
- certaines vulnérabilités dépendent du contexte d'usage de la bibliothèque ;
- les bundles minifiés ou fortement transformés peuvent limiter la détection ;
- un résultat ``Non`` ne remplace pas une revue de sécurité manuelle.

Pour les cas ambigus, le fichier ``retire-develop.json`` doit être utilisé comme
source de vérité technique, puis complété si nécessaire par une analyse manuelle.
