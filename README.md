# 🔐 Projet PKI – Infrastructure à Clé Publique

Projet de Fin de Master – **Modélisation Mathématique et Science des Données (MMSD)**  
Université Abdelmalek Essaâdi – FST Tanger  
Année universitaire : 2024–2025

---

## 📌 Description du projet

Ce projet vise à développer une application web complète simulant une **Infrastructure à Clé Publique (PKI)** à l’aide de **Flask** (Python) et de la bibliothèque **cryptography**.  
Il permet de générer, signer, révoquer et vérifier des certificats numériques, le tout via une interface simple et intuitive.

---

## 🧱 Fonctionnalités principales

- 🔑 Génération de clés RSA 2048 bits
- 📜 Création de demandes de certificat (CSR)
- ✅ Signature des CSR avec une autorité intermédiaire
- ❌ Révocation des certificats et gestion de la CRL
- 🔍 Vérification de validité des certificats
- 📊 Visualisation de statistiques via un dashboard (Chart.js)

---

## ⚙️ Technologies utilisées

| Technologie   | Description                            |
|---------------|----------------------------------------|
| Flask         | Framework web Python                   |
| Cryptography  | Bibliothèque de cryptographie X.509    |
| Bootstrap     | Interface utilisateur responsive       |
| Chart.js      | Graphiques statistiques interactifs    |

---

## 📂 Structure du projet

PKI_PROJET/
├── app_cryptography.py # Code principal de l'application
├── templates/ # Pages HTML (Jinja2)
├── static/ # Fichier CSS et JS
├── pki/
│ ├── intermediateCA/ # Certificat + clé de la CA intermédiaire
│ ├── final-certs/ # CSR, clés privées, certificats
│ └── crl/ # Liste de révocation
├── README.md # Ce fichier de documentation


---

## ▶️ Lancer le projet en local

```bash
# Étape 1 : Installer les dépendances
pip install flask cryptography

# Étape 2 : Exécuter l'application
python app_cryptography.py
---
## 👤 Réalisé par
Étudiant : [Akhdim Abdesalam]

Encadrante : [Pr.LECHHAB OUADRASSI Nihad]

Master : MMSD – Modélisation Mathématique et Science des Données

Université : Université Abdelmalek Essaâdi – FST Tanger
