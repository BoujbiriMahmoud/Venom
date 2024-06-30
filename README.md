# 🐍 Venom
Bienvenue dans Venom ! Ce projet est conçu pour générer du shellcode polymorphe destiné aux tests de sécurité et à l'audit de vulnérabilités.

## 📖 Aperçu

**Auteur :** _Mahmoud BOUJBIRI_

Ce projet, créé par **Mahmoud BOUJBIRI**, est conçu pour offrir une solution complète de génération de shellcode pour les professionnels de la sécurité. Venom permet de créer des payloads de reverse shell personnalisés et polymorphes pour tester la résilience des systèmes contre les attaques de type shellcode.

### 🌟 Inspiration du Projet

L'inspiration pour Venom provient de la nécessité de disposer d'un outil flexible et puissant pour les tests de pénétration et les audits de sécurité. Avec un intérêt marqué pour la sécurité réseau et les systèmes, ce projet vise à fournir une solution polyvalente et éducative pour les professionnels de la sécurité.

### ⚠️ Avertissement

Ce projet est conçu à des fins éducatives et pour des tests de sécurité autorisés uniquement. Il n'est pas destiné à être utilisé en production ou sur des systèmes sans consentement explicite. **L'auteur et toute autre partie associée** ne sont pas responsables des conséquences d'une utilisation non éthique ou illégale de ce code. En utilisant ce logiciel, **vous acceptez** les risques et responsabilités associés.

### 🎯 Objectif

Venom est conçu pour générer et tester des shellcodes polymorphes. Il comprend des fonctionnalités pour encoder/décoder des adresses IP et des ports, générer des payloads C, et compiler des exécutables pour tester la sécurité des systèmes.

## 🧩 Composants

1. **Authentification sécurisée :** Hachage bcrypt pour sécuriser les identifiants utilisateur.
2. **Génération de shellcode polymorphe :** Instructions polymorphes pour rendre la détection plus difficile.
3. **Conversion IP/Port en hexadécimal :** Encodage et décodage faciles des adresses IP et des ports.
4. **Création de fichiers C :** Génération de fichiers C contenant le shellcode pour une compilation facile.
5. **Journalisation :** Enregistrement détaillé des tentatives d'authentification et des attaques pour un suivi et une analyse.

## 🏗️ Structure du Code

Le code est organisé en plusieurs sections principales :

1. **Authentification :** Gestion des identifiants utilisateur et sécurisation.
2. **Génération de shellcode :** Création de shellcode polymorphe basé sur les entrées utilisateur.
3. **Conversion d'adresses :** Fonctions pour encoder et décoder les adresses IP et les ports.
4. **Compilation et exécution :** Génération de fichiers C et compilation en exécutables.
5. **Journalisation :** Enregistrement des activités et des tentatives d'attaque.

## 🚀 Utilisation

### Configuration
Par défaut, le projet fonctionne avec les identifiants spécifiés sur le code. Vous pouvez modifier ces valeurs dans le script principal.

### Journalisation
Les logs fournissent des informations détaillées sur les tentatives d'authentification et les attaques générées.

## 🏃 Lancer Venom

1. Clonez le dépôt :
```
https://github.com/BoujbiriMahmoud/Venom
```

2. Naviguez dans le répertoire du projet :
```
cd Venom
```

3. Assurez-vous que Python3 et GCC sont installés.
   
5. Lancez le script :
```
sudo python3 venom.py
```

6. Rentrez les identifiants par défaut:
   ```
   Username : admin
   Password : password
   ```
   
8. Choisissez une option dans le menu interactif :
   _Option 1 :_ Entrez l'adresse IP cible puis le numéro de port
   _Option 2 :_ Ouvrez une session écouteur Netcat
   _Option 3 :_ Visualisez les journaux
   _option 4 :_ Quitter le programme

🎉 **Enjoy Hacking Responsibly!** 🎉
