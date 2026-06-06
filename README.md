OSINT PRO – Plateforme d’Analyse OSINT et de Cybersécurité
Présentation

OSINT PRO est une plateforme web développée avec Python et Django permettant d'effectuer plusieurs analyses liées à l'OSINT (Open Source Intelligence) et à la sécurité réseau à travers une interface moderne et intuitive.

Le système centralise plusieurs fonctionnalités d'investigation numérique afin de faciliter la collecte et l'analyse des informations.

Fonctionnalités principales
IP Intelligence

Recherche des informations d'une adresse IP grâce à l'API Shodan :

Adresse IP
Organisation
Pays
Ville
Fournisseur Internet (ISP)
Système d'exploitation
Ports ouverts
Score de sécurité
Username Search

Recherche d'un nom d'utilisateur sur différentes plateformes.

Email Lookup

Analyse d'une adresse email via l'API Hunter.io :

Domaine associé
Validité de l'email
Informations publiques
Score de sécurité
Local Network Scan

Scan du réseau local grâce à Nmap :

Machines connectées
Ports ouverts
Ports fermés
Services actifs
Score de sécurité
Génération QR Code

Possibilité de générer un QR Code contenant les résultats obtenus.

Téléchargement des résultats

Export des résultats des analyses.

Technologies utilisées
Backend
Python 3.12
Django
Frontend
HTML5
CSS3
JavaScript
APIs et outils
Shodan API
Hunter.io API
Nmap
Configuration requise
Logiciels nécessaires
Python 3.10 ou supérieur
VS Code (optionnel)
Git
Nmap
Installation du projet
1. Cloner le projet
git clone https://github.com/votre_compte/OSINT-PRO.git

Puis :

cd OSINT-PRO
2. Créer un environnement virtuel

Sous Windows :

python -m venv venv

Activation :

venv\Scripts\activate

Sous Linux :

python3 -m venv venv
source venv/bin/activate
3. Installer les dépendances
pip install -r requirements.txt
4. Installer Nmap

Télécharger :

https://nmap.org/download.html

Vérifier l'installation :

nmap --version
5. Appliquer les migrations
python manage.py migrate
6. Lancer le serveur
python manage.py runserver
7. Accéder à l'application

Ouvrir :

http://127.0.0.1:8000/
Architecture du projet
OSINT_PROJECT
│
├── manage.py
├── requirements.txt
│
├── osint_project/
│
├── app/
│     ├── views.py
│     ├── urls.py
│     ├── models.py
│     └── templates/
│            dashboard.html
│
├── static/
│      ├── css
│      ├── js
│      └── images
│
└── media/
Utilisation
Recherche IP
Sélectionner IP Intelligence.
Saisir l'adresse IP.
Cliquer sur Search.
Les informations récupérées seront affichées.
Recherche Email
Cliquer sur Email Lookup.
Saisir l'adresse email.
Cliquer sur Search.
Les informations associées seront affichées.
Scan réseau local
Cliquer sur Local Network Scan.
Entrer le réseau :
192.168.1.0/24
Cliquer sur Scan.
Les machines connectées ainsi que leurs ports ouverts seront affichés.
Génération QR Code

Après une recherche :

Cliquer sur :
Generate QR

Un QR Code contenant les résultats sera généré.

Téléchargement des résultats

Cliquer sur :

Download Results

pour enregistrer les informations obtenues.

Compte administrateur

Créer un super utilisateur :

python manage.py createsuperuser

Puis accéder :

http://127.0.0.1:8000/admin
Auteur

Azzddin Ou

Étudiant en Ingénierie Informatique et Réseaux

École Marocaine des Sciences de l'Ingénieur (EMSI)

Année universitaire : 2025-2026

Encadrant

M. .....................................

Projet de Fin d'Année (PFA)

Développement d'une Plateforme OSINT et d'Analyse de Sécurité Réseau Basée sur Django

Remarque

Cette plateforme a été développée dans un cadre pédagogique et doit être utilisée uniquement dans le respect des lois et de l'éthique en matière de cybersécurité.
