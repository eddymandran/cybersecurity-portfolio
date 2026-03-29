# 🚩 Snapped Phish-ing Line — TryHackMe Writeup

> **Platform :** [TryHackMe](https://tryhackme.com)
> **Room :** [Snapped Phish-ing Line](https://tryhackme.com/room/snappedphishingline)
> **Difficulty / Difficulté :** 🟢 Easy
> **Category / Catégorie :** Phishing, Email Analysis, SOC, CTI (Cyber Threat Intelligence)
> **Date :** 29/03/2026
> **Status / Statut :** ✅ Completed (100%)

---

## 📋 Summary / Résumé

> 🇬🇧 As an IT department personnel of SwiftSpend Financial, several employees report receiving a suspicious email. Some have already submitted their credentials and can no longer log in. The goal is to analyze the phishing emails, identify the attacker's infrastructure, retrieve and analyze the phishing kit, and find who fell victim to the attack.
>
> 🇫🇷 En tant que membre du département IT de SwiftSpend Financial, plusieurs employés signalent avoir reçu un email suspect. Certains ont déjà soumis leurs identifiants et ne peuvent plus se connecter. L'objectif est d'analyser les emails de phishing, identifier l'infrastructure de l'attaquant, récupérer et analyser le kit de phishing (phishing kit), et déterminer qui a été victime de l'attaque.

> ⚠️ **Note :** Le kit de phishing utilisé dans ce scénario provient d'une vraie campagne de phishing. Toutes les interactions avec les artefacts doivent être effectuées uniquement dans la VM isolée fournie par TryHackMe.

---

## 🎯 Objectives / Objectifs

- [x] Identifier qui a reçu une pièce jointe PDF
- [x] Identifier l'adresse email de l'attaquant
- [x] Retrouver l'URL de redirection vers la page de phishing
- [x] Récupérer et analyser le kit de phishing
- [x] Identifier les victimes ayant soumis leurs identifiants
- [x] Retrouver le flag caché

---

## 🧰 Tools Used / Outils Utilisés

| Tool | Usage / Utilisation |
|---|---|
| [Thunderbird Mail](https://www.thunderbird.net/) | Lecture et analyse des emails / Email reading and analysis |
| [CyberChef](https://gchq.github.io/CyberChef/) | Décodage Base64, défangage d'URLs / Base64 decoding, URL defanging |
| [VirusTotal](https://www.virustotal.com/) | Analyse du hash SHA256 du kit / Phishing kit hash analysis |
| `grep` | Recherche dans les fichiers du kit / Searching through kit files |
| `sha256sum` | Calcul du hash du kit / Kit hash calculation |
| `wget` | Téléchargement du kit de phishing / Phishing kit download |

---

## 🔍 Reconnaissance & Analyse des emails

> 🇫🇷 Les emails suspects sont disponibles dans le dossier `phish-emails/` sur le Bureau de la VM. Ils sont au format `.eml` et s'ouvrent avec Thunderbird Mail.
> 🇬🇧 The suspicious emails are available in the `phish-emails/` folder on the VM Desktop. They are in `.eml` format and can be opened with Thunderbird Mail.

### Identification de l'email avec pièce jointe PDF

Pour trouver rapidement quel email contient une pièce jointe PDF sans ouvrir chaque email manuellement :

```bash
grep -i -l "\.pdf" ~/Desktop/phish-emails/*
```

> 🇫🇷 L'email intitulé *"Quote for Services Rendered"* envoyé à **William McClean** est le seul contenant une pièce jointe PDF.
> 🇬🇧 The email titled *"Quote for Services Rendered"* sent to **William McClean** is the only one containing a PDF attachment.

### Identification de l'expéditeur

En inspectant l'en-tête `From` de l'email PDF :

```
From: Accounts.Payable@groupmarketingonline.icu
```

---

## 🗺️ Enumeration / Énumération

### URL de redirection — Zoe Duncan

L'email de Zoe Duncan contient une pièce jointe HTML (`Direct Credit Advice.html`). Pour accéder au source :

```
Thunderbird → View → Message Source (Ctrl+U)
```

Le contenu HTML est encodé en **Base64** (indiqué par `Content-Transfer-Encoding: base64`). On décode avec CyberChef :

```
CyberChef → From Base64 → copier le résultat HTML
```

Dans le code HTML décodé, on trouve l'URL de redirection dans la balise `<meta>`. On la **défange** (defang) ensuite avec CyberChef pour la rendre inoffensive :

```
URL défangée / Defanged URL :
hxxp[://]kennaroads[.]buzz/data/Update365/office365/40e7baa2f826a57fcf04e5202526f8bd/?email=zoe[.]duncan@swiftspend[.]finance&error
```

> 🇫🇷 Le **défangage** (defanging) est une technique qui consiste à rendre une URL ou une adresse IP non-cliquable en remplaçant `://` par `[://]` et les `.` par `[.]`. Cela permet de partager des IOCs (Indicators of Compromise) sans risque de clic accidentel.

### Récupération du kit de phishing

En raccourcissant l'URL jusqu'à `/data`, on accède au répertoire ouvert du serveur. On y trouve l'archive du kit :

```
http://kennaroads.buzz/data/Update365.zip
```

URL défangée / Defanged :
```
hxxp[://]kennaroads[.]buzz/data/Update365[.]zip
```

Téléchargement du kit :
```bash
wget http://kennaroads.buzz/data/Update365.zip
```

Calcul du hash SHA256 :
```bash
sha256sum Update365.zip
```

**Hash SHA256 :**
```
ba3c15267393419eb08c7b2652b8b6b39b406ef300ae8a18fee4d16b19ac9686
```

---

## ⚔️ Analyse du kit de phishing (Phishing Kit Analysis)

### Soumission sur VirusTotal

- Soumettre le hash sur [VirusTotal](https://www.virustotal.com/)
- Onglet **Details** → Section **History** :
  - **Première soumission / First submission :** `2020-04-08 21:55:50 UTC`
- Recherche du domaine `kennaroads.buzz` sur VirusTotal :
  - **Certificat SSL / SSL Certificate first logged :** `2020-06-25`

> 💡 **Note personnelle :** Pour cette question, j'ai utilisé l'indice (hint) de la room — je ne savais pas qu'il était possible de rechercher un domaine directement sur VirusTotal pour obtenir les informations de certificat SSL. VirusTotal permet non seulement d'analyser des fichiers via leur hash, mais aussi de rechercher des domaines et d'obtenir leur historique complet (DNS passif, certificats SSL, soumissions...) dans l'onglet **Relations**.

### Analyse des logs de victimes

En naviguant dans le répertoire du kit :

```
http://kennaroads.buzz/data/Update365/log.txt
```

Téléchargement et analyse :
```bash
wget http://kennaroads.buzz/data/Update365/log.txt
grep -i "Email" log.txt | sort | uniq -c
```

> 🇫🇷 L'utilisateur ayant soumis ses identifiants **deux fois** est identifiable grâce au comptage des occurrences avec `uniq -c`.

**Victime ayant soumis deux fois / User who submitted twice :**
```
michael.ascot@swiftspend.finance
```

### Analyse du script de collecte (submit.php)

Dans le kit dézippé, le fichier `submit.php` contient l'adresse email utilisée par l'attaquant pour collecter les identifiants volés :

```bash
grep -r "mail" ./Update365/
```

**Email de collecte de l'attaquant / Adversary collection email :**
```
m3npat@yandex.com
```

### Recherche des autres adresses email

```bash
grep -r "@gmail.com" ./Update365/
```

**Email Gmail de l'attaquant / Adversary Gmail address :**
```
jamestanner2299@gmail.com
```

### Récupération du flag caché

En naviguant manuellement dans les répertoires exposés via Firefox dans la VM :

```
http://kennaroads.buzz/data/
└── Update365/
    └── office365/
        └── flag.txt   ← ajouté manuellement à l'URL
```

URL complète :
```
http://kennaroads.buzz/data/Update365/office365/flag.txt
```

Le contenu retourné est encodé en **Base64 inversé**. Décodage avec CyberChef :

```
CyberChef → From Base64 → Reverse
```

**Flag :**
```
THM{pL4y_w1Th_tH3_URL}
```

---

## 🚩 Flags / Réponses aux questions

| Question | Réponse |
|---|---|
| Destinataire de la pièce jointe PDF | `William McClean` |
| Email de l'attaquant (expéditeur) | `Accounts.Payable@groupmarketingonline.icu` |
| URL de redirection — Zoe Duncan (défangée) | `hxxp[://]kennaroads[.]buzz/data/Update365/office365/40e7baa2f826a57fcf04e5202526f8bd/?email=zoe[.]duncan@swiftspend[.]finance&error` |
| URL du kit de phishing (défangée) | `hxxp[://]kennaroads[.]buzz/data/Update365[.]zip` |
| Hash SHA256 du kit | `ba3c15267393419eb08c7b2652b8b6b39b406ef300ae8a18fee4d16b19ac9686` |
| Première soumission du kit | `2020-04-08 21:55:50 UTC` |
| Certificat SSL — première entrée | `2020-06-25` |
| Victime ayant soumis deux fois | `michael.ascot@swiftspend.finance` |
| Email de collecte de l'attaquant | `m3npat@yandex.com` |
| Email Gmail de l'attaquant | `jamestanner2299@gmail.com` |
| Flag caché | `THM{pL4y_w1Th_tH3_URL}` |

---

## 📚 Lessons Learned / Ce que j'ai appris

- **VirusTotal ne sert pas qu'à analyser des fichiers** — on peut aussi y rechercher des domaines et obtenir leur historique complet : DNS passif, certificats SSL, URLs associées, fichiers soumis... C'est un outil CTI à part entière
- Le **défangage** (defanging) est une pratique standard en CTI pour partager des IOCs sans risque — toujours utiliser CyberChef pour ça
- Un serveur web mal configuré peut exposer ses répertoires publiquement (directory listing) — c'est ce qui a permis de télécharger le kit de phishing
- La commande `grep -r` combinée à `sort | uniq -c` est très efficace pour analyser des logs et identifier des comportements répétés
- Un **phishing kit** (kit de phishing) contient toute l'infrastructure de l'attaque : pages HTML imitant des services légitimes, scripts de collecte (`submit.php`), et logs des victimes
- Le flag était encodé en **Base64 inversé** — toujours tester plusieurs décodages quand un résultat semble illisible
- Les attaquants utilisent souvent plusieurs adresses email (Yandex, Gmail) pour cloisonner leurs activités malveillantes

---

## 🔗 Resources / Ressources

- [TryHackMe — Snapped Phish-ing Line](https://tryhackme.com/room/snappedphishingline)
- [CyberChef — Décodage & Défangage](https://gchq.github.io/CyberChef/)
- [VirusTotal — Hash & Domain Analysis](https://www.virustotal.com/)
- [Thunderbird Mail](https://www.thunderbird.net/)
- [Qu'est-ce qu'un phishing kit ? (Cloudflare)](https://www.cloudflare.com/learning/email-security/what-is-email-fraud/)
- [SPF, DKIM et DMARC expliqués (Cloudflare)](https://www.cloudflare.com/learning/email-security/dmarc-dkim-spf/)

---

*✍️ Writeup by [Eddy M.](https://github.com/eddymandran) — [cybersecurity-portfolio](https://github.com/eddymandran/cybersecurity-portfolio)*