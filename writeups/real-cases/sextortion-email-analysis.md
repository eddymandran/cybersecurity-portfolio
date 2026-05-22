# 🚩 Campagne de Sextorsion par Email - Analyse de Cas Réel

> **Type de cas :** Incident réel (anonymisé)

> **Catégorie :** Social Engineering / Threat Intelligence / Email Forensics

> **Vecteur d'attaque :** Email (Phishing de masse / Sextorsion)

> **Date de l'incident :** 17/05/2026

> **Date d'analyse :** 18/05/2026

> **Statut :** Analysé - Menace non avérée (Bluff confirmé) ✅

---

## 📋 Résumé

Un particulier a reçu un email de sextorsion affirmant qu'un cheval de Troie à accès distant (Remote Access Trojan - RAT) avait été installé sur ses appareils. L'attaquant réclamait 800 USD en Bitcoin sous 12 heures, menaçant sinon de divulguer des vidéos compromettantes à l'ensemble de ses contacts.

L'analyse technique des en-têtes SMTP (Simple Mail Transfer Protocol), du corps du message encodé en Base64, ainsi que du comportement anormal du mail dans la boîte de réception permet de démanteler intégralement le bluff et de qualifier précisément les techniques utilisées par l'attaquant.

> ⚠️ Les données personnelles de la victime ont été anonymisées dans ce writeup conformément aux bonnes pratiques de publication.

---

## 🎯 Objectifs de l'analyse

- [x] Qualifier le type de menace et évaluer sa réalité technique
- [x] Analyser les en-têtes SMTP pour identifier l'infrastructure de l'attaquant
- [x] Décoder et examiner le corps du message (payload Base64)
- [x] Expliquer le comportement anormal du mail (apparition dans les brouillons, réapparition après suppression)
- [x] Vérifier les indicateurs de compromission (IoC - Indicators of Compromise) sur la blockchain
- [x] Produire un plan de remédiation

---

## 🧰 Outils Utilisés

| Outil | Utilisation |
|---|---|
| [CyberChef](https://gchq.github.io/CyberChef/) | Décodage du corps du message encodé en Base64, via la recette *"From Base64"* |
| [Have I Been Pwned](https://haveibeenpwned.com) | Vérification des fuites de données (data leaks) associées à l'adresse email |
| [Blockchain.com Explorer](https://www.blockchain.com/explorer) | Vérification de l'adresse Bitcoin de l'attaquant |
| [Signal-Spam](https://www.signal-spam.fr) | Signalement du message malveillant |
| [Cybermalveillance.gouv.fr](https://www.cybermalveillance.gouv.fr) | Signalement officiel et ressources pour les victimes |

---

## 🔍 Collecte des Preuves et Première Analyse

### 1. Le fichier source - Format EML

La victime a transmis le mail au format `.eml` (fichier brut exporté depuis Outlook), ce qui constitue la méthode correcte de préservation d'une preuve numérique. Ce format contient deux parties exploitables :

- Les **en-têtes SMTP complets** : les métadonnées de routage du message, invisibles dans l'interface classique d'un client mail
- Le **corps du message encodé** : ici au format HTML, encodé en Base64 avec le champ `Content-Transfer-Encoding: base64`

```
X-Mozilla-Status: 0001
Subject: [VICTIME] - I have hacked you, stolen your information and photos
Date: Sun, 17 May 2026 13:17:54 +0200
Message-ID: <DB9PR01MB11644A42D64311CD51C86CB26EC022
            @DB9PR01MB11644.eurprd01.prod.exchangelabs.com>
Content-Type: text/html; charset="utf-8"
Content-Transfer-Encoding: base64
```

### 2. Décodage du corps du message avec CyberChef

Le corps du mail est encodé en Base64. L'encodage Base64 est couramment utilisé dans les emails pour transporter du contenu HTML ou binaire sans risque de corruption. Il est également utilisé par les attaquants pour rendre leur contenu moins lisible à l'œil nu et contourner certains filtres anti-spam basés sur des mots-clés.

**Outil utilisé :** [CyberChef](https://gchq.github.io/CyberChef/) - outil web open-source développé par le GCHQ (renseignement britannique), permettant d'effectuer des opérations de transformation de données sans installation. La recette utilisée :

```
Input  : [bloc Base64 extrait du fichier .eml]
Recette: From Base64 > Render HTML
```

Une fois décodé, le contenu HTML révèle le message complet de l'attaquant, structuré en plusieurs sections :

| Section | Contenu |
|---|---|
| *"What happened here?"* | Prétend avoir accès aux appareils de la victime depuis plusieurs mois |
| *"What's next?"* | Décrit l'installation prétendue d'un RAT sur tous les appareils |
| *"What should I worry?"* | Affirme avoir enregistré des vidéos compromettantes |
| *"What are you going to do?"* | Menace de diffusion aux contacts, collègues et famille |
| *"Can we solve this problem?"* | Demande de 800 USD en Bitcoin ou USDT |
| *"What you should avoid"* | Tente d'isoler la victime (ne pas contacter la police, ne pas chercher l'attaquant) |

---

## 🗺️ Analyse des En-Têtes SMTP

### Qu'est-ce qu'un en-tête SMTP ?

Un en-tête SMTP est l'équivalent d'une enveloppe postale pour un email. Il contient des informations techniques sur l'expéditeur réel, le chemin parcouru entre les serveurs, la date d'envoi, et des mécanismes d'authentification. Ces informations sont normalement masquées dans l'interface d'un client mail : il faut les afficher explicitement pour les analyser.

### Indicateur clé - Le Message-ID révèle l'infrastructure

```
Message-ID: <DB9PR01MB11644A42D64311CD51C86CB26EC022
            @DB9PR01MB11644.eurprd01.prod.exchangelabs.com>
```

Le domaine `prod.exchangelabs.com` est l'infrastructure de **Microsoft Exchange Online (Microsoft 365)**. Le message n'a donc pas été envoyé depuis une machine piratée ou un serveur clandestin : il a été envoyé depuis un compte Microsoft 365 valide, probablement un compte d'entreprise, d'étudiant ou d'essai gratuit obtenu frauduleusement.

**Pourquoi l'attaquant utilise cette infrastructure :**

Les serveurs Exchange de Microsoft jouissent d'une excellente réputation auprès des autres serveurs de messagerie. En envoyant depuis cette infrastructure, l'attaquant s'assure que son mail passe les mécanismes d'authentification SPF (Sender Policy Framework - cadre de politique d'expéditeur) et DKIM (DomainKeys Identified Mail - identification du mail par clés de domaine), qui valident la légitimité du serveur d'envoi. Un serveur malveillant inconnu serait immédiatement bloqué ou signalé comme spam.

**Concernant la zone géographique :** Le préfixe `eurprd01` (European Production 01) et la référence `DUB05` indiquent une infrastructure hébergée en Europe, vraisemblablement à Dublin (Irlande), hub européen principal de Microsoft.

### Le "spoofing" psychologique démystifié

Dans le corps du message, l'attaquant écrit :

> *"I sent this email from your mailbox. By the way, it allows you to make sure that I am really telling the truth."*

C'est un mensonge technique. Le Message-ID prouve que l'email a transité par les serveurs globaux d'Exchange Online, et non depuis une session authentifiée sur la boîte de la victime. L'attaquant mise sur l'ignorance technique de la victime pour créer un effet de choc psychologique.

---

## ⚔️ Analyse de la Menace - Démantèlement du Bluff

### La vraie technique utilisée - Credential Stuffing (Bourrage d'identifiants)

L'élément le plus révélateur du mail se trouve dans la section *"Some of your hacked credentials"*. L'attaquant présente des identifiants supposément volés pour "prouver" sa présence sur la machine de la victime :

```
URL:      https://eu.battle.net/
Username: [adresse email de la victime - anonymisée]
Password: [mot de passe - anonymisé]
```

**Ce que cela prouve réellement :**

Ces identifiants ne proviennent pas d'un enregistreur de frappe (keylogger) ou d'un RAT actif. Ils sont issus d'une **fuite de données historique (data leak)**, probablement liée à Blizzard/Battle.net ou à un autre service où la victime utilisait les mêmes identifiants.

Le modèle d'attaque réel est le suivant :

```
[Achat ou téléchargement d'une "combo list" sur le darkweb]
         ↓
[Script automatisé filtre les adresses email actives et valides]
         ↓
[Injection dans le template du mail de sextorsion :
 1 ligne de la base de données = "preuve" simulée de piratage local]
         ↓
[Envoi en masse via un compte Exchange Online compromis]
```

**Note sur la mise en scène de crédibilité :** Dans le corps du mail, l'attaquant insère un lien vers une vraie page de documentation d'un éditeur de cybersécurité expliquant ce qu'est un RAT. En incluant un lien légitime et technique, il cherche à donner l'impression que sa menace est documentée et sérieuse. Cette sophistication dans la mise en scène révèle un template soigneusement préparé pour un envoi de masse.

### Pourquoi le scénario du RAT s'effondre techniquement

**L'incohérence financière :** Un attaquant capable de maintenir un RAT non détecté sur une machine (persistance, évasion antivirus, mise à jour des signatures de drivers comme le prétend le mail) ne réclamerait pas 800 USD. Ce niveau de compétence technique ciblerait des entreprises pour des rançons de plusieurs dizaines ou centaines de milliers d'euros via des attaques de rançongiciel (ransomware).

**L'ultimatum de 12 heures :** Cette contrainte temporelle est une technique d'ingénierie sociale classique, appelée "création d'urgence artificielle". Elle vise à court-circuiter le raisonnement logique de la victime pour la pousser à payer avant qu'elle ne consulte un expert.

**L'absence de preuve concrète :** L'attaquant ne fournit aucune capture d'écran de la machine, aucune vidéo de démonstration, aucune donnée issue du système local. Seul un mot de passe datant d'une fuite passée est présenté.

---

## 🔄 Analyse du Comportement Anormal - Brouillons et Réapparition

### Observation

Le mail est apparu dans le **dossier Brouillons** (Drafts) de la boîte Outlook de la victime, et après suppression, **réapparaissait quelques minutes plus tard**. Ce comportement a considérablement amplifié la panique, renforçant la croyance en un contrôle total de la machine.

### Hypothèse A - Script de persistance avec jeton OAuth (la plus probable)

C'est l'hypothèse que je retiens comme la plus vraisemblable dans ce cas, car elle est la seule qui explique à la fois l'apparition du mail dans les Brouillons **et** sa réapparition après suppression. Une injection unique ne suffirait pas à recréer le message en boucle.

L'attaquant a obtenu les identifiants Hotmail/Outlook de la victime via la même fuite que les identifiants Battle.net, si le mot de passe était réutilisé. Il s'est connecté une première fois pour créer le message, et a maintenu un accès persistant via un **jeton d'authentification OAuth (Open Authorization)**. OAuth est un protocole standard qui permet à une application tierce d'accéder à un compte sans avoir besoin du mot de passe à chaque connexion, grâce à un jeton (token) de session longue durée.

```
[Connexion initiale avec les identifiants volés]
      ↓
  Obtention d'un jeton OAuth longue durée
      ↓
  Création du message dans "Brouillons" ou "Boîte de réception"
      ↓
  Script tourne en boucle toutes les X minutes via le jeton actif
      ↓
  Si le mail est absent : il le recrée immédiatement
      ↓
  La victime supprime > le script recrée > boucle infinie
```

Tant que la **session OAuth n'est pas révoquée à la racine**, supprimer le mail manuellement est inefficace. C'est le script qui a le dernier mot.

### Hypothèse B - Injection directe sans persistance (moins probable)

Cette hypothèse expliquerait l'apparition du mail dans les Brouillons, mais pas sa réapparition systématique après suppression. Elle reste possible si la réapparition était en réalité due à un conflit de synchronisation avec un appareil local (cache d'un client mail comme Thunderbird ou l'application Courrier de Windows ayant conservé le message).

Dans ce scénario, l'attaquant se serait connecté une seule fois via **IMAP (Internet Message Access Protocol)** ou l'**API Microsoft Graph** pour déposer le message, sans maintenir de session active par la suite.

```
[Connexion unique via IMAP/API Graph avec les identifiants volés]
      ↓
  Création du message directement dans "Brouillons" ou "Boîte de réception"
      ↓
  Avantage : le mail ne passe jamais par les filtres anti-spam entrants
  car il est créé de l'intérieur du compte - il est perçu comme "local"
```

---

## 📊 Évaluation des Risques

| Vecteur | Niveau de Risque | Impact Réel |
|---|---|---|
| Intégrité du système (machine locale) | 🟢 Très Faible | Aucun indice de compromission locale - pas de RAT |
| Confidentialité des données personnelles | 🟡 Faible | Uniquement des données issues de fuites passées |
| Accès au compte de messagerie | 🔴 Élevé | Accès non autorisé probable via identifiants réutilisés |
| Impact psychologique | 🔴 Élevé | Objectif principal de l'attaquant - largement atteint |

---

## 🔗 Indicateurs de Compromission (IoC)

Les IoC (Indicators of Compromise - Indicateurs de Compromission) sont les empreintes digitales techniques laissées par un attaquant lors d'un incident. Dans un SOC (Security Operations Center - Centre opérationnel de sécurité), ces données sont partagées entre équipes afin qu'une même menace soit détectée et bloquée partout dès qu'un premier analyste l'identifie.

| Type d'IoC | Valeur | Utilité |
|---|---|---|
| Adresse Bitcoin | `bc1qsd62jcw4x2l8a2sqwt0hs5nlavtrtwy0dgr7l6` | Traçage des paiements reçus sur la blockchain et mesure de l'impact financier de la campagne |
| Infrastructure d'envoi | `DB9PR01MB11644.eurprd01.prod.exchangelabs.com` | Identification du compte Microsoft 365 utilisé pour l'envoi |
| Zone géographique | Dublin, Irlande (DUB05) | Localisation du datacenter de l'infrastructure utilisée |
| Origine des identifiants | `eu.battle.net` (Blizzard) | Source probable de la fuite de données exploitée par l'attaquant |

### Vérification Blockchain

L'adresse Bitcoin `bc1qsd62jcw4x2l8a2sqwt0hs5nlavtrtwy0dgr7l6` peut être vérifiée en temps réel sur un explorateur de bloc public :

- [Blockchain.com Explorer](https://www.blockchain.com/explorer/addresses/btc/bc1qsd62jcw4x2l8a2sqwt0hs5nlavtrtwy0dgr7l6)
- [Blockchair](https://blockchair.com/bitcoin/address/bc1qsd62jcw4x2l8a2sqwt0hs5nlavtrtwy0dgr7l6)

> Si le solde affiche **0 transaction** : la campagne est un échec total, ce qui confirme son caractère de spam de masse non ciblé.
> Si des transactions apparaissent : elles documentent le préjudice financier causé à d'autres victimes par cette même campagne.

---

## 📈 Plan de Remédiation

### Actions immédiates (J0 - Dans l'heure)

**Étape 1 - Couper l'accès de l'attaquant au compte de messagerie**

Depuis un **appareil sûr** (pas celui potentiellement impliqué dans la fuite) :
- Changer le mot de passe du compte Hotmail/Outlook
- Accéder au [tableau de bord de sécurité du compte Microsoft](https://account.microsoft.com/security)
- Faire défiler jusqu'à "Se déconnecter partout" puis valider

> C'est cette action précise qui stoppe la réapparition du mail. Elle invalide immédiatement tous les jetons OAuth et sessions actives. Selon la documentation Microsoft, la révocation est généralement effective en moins de 24 heures.

**Étape 2 - Vérifier et purger les règles de messagerie**

Dans Outlook Web, aller dans Paramètres puis Règles et vérifier l'absence de règles malveillantes, par exemple :
- "Transférer tous les mails entrants vers [adresse inconnue]"
- "Si le sujet contient [mot-clé], supprimer immédiatement" (pour masquer les alertes de sécurité Microsoft)

**Étape 3 - Activer la 2FA**

Activer l'authentification à deux facteurs (2FA / MFA - Multi-Factor Authentication) sur le compte Microsoft. Même si l'attaquant récupère le mot de passe à l'avenir, il ne pourra pas se connecter sans le second facteur (application Authenticator, SMS, etc.).

### Actions à court terme (J1 à J7)

**Vérifier l'étendue de la fuite :** Utiliser [Have I Been Pwned](https://haveibeenpwned.com) pour identifier toutes les fuites de données associées à l'adresse email de la victime.

**Changer tous les mots de passe réutilisés :** Si le mot de passe exposé dans le mail était utilisé sur d'autres services, les changer immédiatement. L'utilisation d'un gestionnaire de mots de passe (Bitwarden, 1Password) est recommandée pour éviter toute réutilisation à l'avenir.

**Analyse antivirus de routine :** Lancer une analyse complète avec Windows Defender ou [Malwarebytes](https://www.malwarebytes.com), non pas parce qu'un RAT est suspecté, mais pour rassurer psychologiquement la victime et valider formellement l'absence de menace dormante.

**Signalement officiel :**
- [Signal-Spam](https://www.signal-spam.fr) - signalement du spam et du phishing
- [Cybermalveillance.gouv.fr](https://www.cybermalveillance.gouv.fr) - portail officiel français d'assistance aux victimes

---

## 📚 Ce que j'ai appris

- Un **email dans les Brouillons** n'est pas la preuve d'un piratage de la machine locale : c'est la preuve d'un accès non autorisé au **compte de messagerie**, ce qui est différent et moins grave.
- Le **Credential Stuffing** est la méthode réelle derrière la quasi-totalité des campagnes de sextorsion actuelles. Les RAT n'y jouent aucun rôle.
- Analyser un **Message-ID** permet de localiser l'infrastructure d'envoi et de démystifier les affirmations de l'attaquant sur l'origine du mail.
- La **réapparition d'un mail** après suppression indique une session active maintenue via un jeton OAuth : la solution est de **révoquer les sessions**, pas de supprimer le mail.
- Les **IoC** extraits d'un incident (adresse Bitcoin, infrastructure d'envoi, origine des fuites) permettent de tracer l'attaquant et d'évaluer l'ampleur d'une campagne.
- Face à une menace qui joue sur la peur et l'urgence, l'analyse méthodique des preuves techniques est la première réponse à apporter avant toute décision.

---

## 🔗 Ressources

- [CyberChef](https://gchq.github.io/CyberChef/) - Outil d'analyse et de transformation de données (GCHQ)
- [Have I Been Pwned](https://haveibeenpwned.com) - Vérification de fuites de données
- [Cybermalveillance.gouv.fr](https://www.cybermalveillance.gouv.fr) - Portail officiel français de signalement
- [Signal-Spam](https://www.signal-spam.fr) - Signalement de spams et phishing
- [Blockchain.com Explorer](https://www.blockchain.com/explorer) - Vérification d'adresses Bitcoin
- [Blockchair](https://blockchair.com) - Explorateur de blockchain alternatif
- [Tableau de bord de sécurité Microsoft](https://account.microsoft.com/security) - Révoquer les sessions et gérer la sécurité du compte
- [Malwarebytes](https://www.malwarebytes.com) - Outil d'analyse antivirus complémentaire

---

*✍️ Writeup by [Eddy M.](https://github.com/eddymandran) - [cybersecurity-portfolio](https://github.com/eddymandran/cybersecurity-portfolio)*