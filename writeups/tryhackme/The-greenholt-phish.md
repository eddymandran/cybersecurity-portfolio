# 🚩 The Greenholt Phish - TryHackMe Writeup

> **Platform :** [TryHackMe](https://tryhackme.com)
> **Room :** [The Greenholt Phish](https://tryhackme.com/room/phishingemails5fgjlzxc)
> **Difficulty / Difficulté :** 🟢 Easy
> **Category / Catégorie :** Phishing, Email Analysis, SOC, Forensics
> **Date :** 29/03/2026
> **Status / Statut :** ✅ Completed (100%)

---

## 📋 Summary / Résumé

> 🇬🇧 A Sales Executive at Greenholt PLC received a suspicious email from an alleged customer. The email contained an unexpected generic greeting ("Good day"), an unsolicited money transfer request via SWIFT, and an unrequested attachment. The email was forwarded to the SOC (Security Operations Center) department for investigation. The goal of this room is to analyze the email headers, verify the sender's authenticity, and examine the attachment to determine whether the email is legitimate or malicious.
>
> 🇫🇷 Un commercial de Greenholt PLC a reçu un email suspect d'un prétendu client. L'email contenait une salutation générique inhabituelle ("Good day"), une demande de transfert d'argent non sollicitée via SWIFT, et une pièce jointe non demandée. L'email a été transmis au département SOC (Centre des Opérations de Sécurité) pour investigation. L'objectif de cette room est d'analyser les en-têtes (headers) de l'email, vérifier l'authenticité de l'expéditeur, et examiner la pièce jointe afin de déterminer si l'email est légitime ou malveillant.

---

## 🎯 Objectives / Objectifs

- [x] Analyser les en-têtes (headers) de l'email pour identifier des anomalies
- [x] Identifier l'adresse IP d'origine et son propriétaire
- [x] Vérifier l'authenticité de l'expéditeur via SPF (Sender Policy Framework) et DMARC
- [x] Analyser la pièce jointe suspecte via son hash SHA256
- [x] Déterminer le vrai type de fichier de la pièce jointe

---

## 🧰 Tools Used / Outils Utilisés

| Tool | Usage / Utilisation |
|---|---|
| [Thunderbird Mail](https://www.thunderbird.net/) | Lecture et analyse visuelle de l'email / Email reading and visual analysis |
| [MXToolbox](https://mxtoolbox.com/) | Vérification SPF & DMARC / SPF & DMARC record lookup |
| [VirusTotal](https://www.virustotal.com/) | Analyse du hash SHA256 de la pièce jointe / Attachment hash analysis |
| [WHOIS Lookup](https://www.whois.com/whois/) | Identification du propriétaire de l'IP / IP owner identification |
| `sha256sum` | Calcul du hash de la pièce jointe / Attachment hash calculation |

---

## 🔍 Reconnaissance & Analyse de l'email

> 🇫🇷 Cette room ne nécessite pas de scan de ports. L'investigation porte sur l'analyse forensique (forensics) d'un email malveillant.
> 🇬🇧 This room does not require a port scan. The investigation focuses on forensic analysis of a malicious email.

### Ouverture de l'email (Opening the email)

L'email `challenge.eml` est disponible sur le Bureau (Desktop) de l'**AttackBox**. Il est ouvert avec **Thunderbird Mail** :

```bash
thunderbird challenge.eml
```

**Contenu du corps de l'email :**

```
Good day webmaster@redacted.org,

As instructed, funds has been transferred to your account this morning via SWIFT.
Details are as below and a receipt of payment is attached.

Interbank Transfer Reference Number: 09674321
Transaction Status: Successful
Transaction Date / Time: 10-06-2020 09:18:55
Transaction Description: Balance / Final Payment
From Account: 3105234819
Amount: 149,650
Currency: USD
Bank Charges: $146.05

Best regards,
Mr. James Jackson
Accounts Payable
SEC MARINE SERVICES PTE LTD
```

⚠️ **Signaux d'alerte immédiats / Immediate red flags :**
- Salutation générique : "Good day" — le vrai client ne l'utilise jamais
- Transfert d'argent non sollicité (149 650 USD via SWIFT)
- Pièce jointe non demandée
- Signature "SEC MARINE SERVICES" mais domaine expéditeur "mutawamarine.com" → incohérence

---

### Analyse des en-têtes (Header Analysis)

Pour accéder aux en-têtes complets dans Thunderbird :

```
View → Message Source   (ou / or Ctrl+U)
```

**Extrait des en-têtes pertinents / Relevant headers extract :**

```
Return-Path: <info@mutawamarine.com>
From: "Mr. James Jackson" <info@mutawamarine.com>
Reply-To: "Mr. James Jackson" <info.mutawamarine@mail.com>
Received: from hwsrv-737338.hostwindsdns.com ([192.119.71.157]:51810 helo=mutawamarine.com)
Received-SPF: fail (domain of mutawamarine.com does not designate x.x.x.x as permitted sender)
```

⚠️ **Anomalie clé / Key anomaly :** L'adresse `From` et l'adresse `Reply-To` sont **différentes** :
- `From` : `info@mutawamarine.com`
- `Reply-To` : `info.mutawamarine@mail.com`

> 🇫🇷 Si la victime répond à l'email, la réponse ira sur un compte **mail.com** contrôlé par l'attaquant — et non sur le vrai domaine.
> 🇬🇧 If the victim replies, the response goes to an attacker-controlled **mail.com** account — not the real domain.

---

## 🗺️ Enumeration / Énumération

### 1. Identification de l'IP d'origine

Dans les en-têtes, le champ `Received` révèle l'IP du serveur expéditeur :

```
Received: from hwsrv-737338.hostwindsdns.com ([192.119.71.157]:51810)
```

> **IP d'origine : `192.119.71.157`**

Recherche WHOIS sur cette IP → Propriétaire : **Hostwinds LLC**

**Outil utilisé :** [whois.com](https://www.whois.com/whois/192.119.71.157)

---

### 2. Vérification SPF (Sender Policy Framework)

> 🇫🇷 Le **SPF** est un enregistrement DNS (Domain Name System) qui liste les serveurs autorisés à envoyer des emails au nom d'un domaine. Il sert à détecter l'usurpation d'identité (email spoofing).
> 🇬🇧 **SPF** is a DNS record listing servers authorized to send emails on behalf of a domain. It helps detect email spoofing.

**Outil utilisé :** [MXToolbox — SPF Lookup](https://mxtoolbox.com/spf.aspx)

Domaine vérifié : `mutawamarine.com` (issu du `Return-Path`)

```
Enregistrement SPF complet / Full SPF Record :
v=spf1 include:spf.protection.outlook.com -all
```

Le résultat `fail` dans les en-têtes confirme que le serveur `192.119.71.157` (Hostwinds LLC) **n'est pas autorisé** à envoyer des emails pour le domaine `mutawamarine.com`.

---

### 3. Vérification DMARC

> 🇫🇷 Le **DMARC** (Domain-based Message Authentication, Reporting and Conformance) est une politique qui s'appuie sur SPF et DKIM (DomainKeys Identified Mail) pour protéger un domaine contre l'usurpation. La politique `quarantine` indique que les emails suspects doivent être mis en quarantaine.
> 🇬🇧 **DMARC** builds on SPF and DKIM to protect a domain. A `quarantine` policy means suspicious emails should be placed in spam/quarantine.

**Outil utilisé :** [MXToolbox — DMARC Lookup](https://mxtoolbox.com/dmarc.aspx)

Domaine vérifié : `mutawamarine.com`

```
Enregistrement DMARC complet / Full DMARC Record :
v=DMARC1; p=quarantine; fo=1
```

| Paramètre | Valeur | Signification |
|---|---|---|
| `v` | `DMARC1` | Version du protocole |
| `p` | `quarantine` | Les emails suspects doivent être mis en quarantaine |
| `fo` | `1` | Rapport envoyé si SPF ou DKIM échoue |

---

## ⚔️ Analyse de la pièce jointe (Attachment Analysis)

### Pièce jointe déguisée (Disguised Attachment)

**Nom du fichier / Filename :** `SWT_#09674321____PDF__.CAB`

> 🇫🇷 Le fichier est nommé pour imiter un PDF (avec `____PDF____` dans le nom), mais son extension réelle est `.CAB`. Les fichiers `.CAB` sont des archives Windows généralement associées aux pilotes système — totalement inhabituel pour une prétendue facture bancaire.
>
> 🇬🇧 The file is named to mimic a PDF (with `____PDF____` in the name), but its real extension is `.CAB`. `.CAB` files are Windows archives typically associated with system drivers — completely unusual for an alleged bank receipt.

**Étape 1 — Calcul du hash SHA256 :**

```bash
sha256sum SWT_#09674321____PDF__.CAB
```

**Résultat / Result :**
```
2e91c533615a9bb8929ac4bb76707b2444597ce063d84a4b33525e25074fff3f
```

**Étape 2 — Analyse sur VirusTotal :**

- Soumettre le hash sur [VirusTotal](https://www.virustotal.com/)
- Onglet **Details** → révèle les propriétés du fichier

**Résultats VirusTotal — Basic Properties :**

| Propriété | Valeur |
|---|---|
| **Détection** | ⚠️ **47/62** vendors ont marqué le fichier comme malveillant |
| MD5 | `f4dd3456cdb1976a145c1179a4d461ec` |
| SHA-1 | `5a2bb8188377c15c036843b4a6ab9b0c0f2c1607` |
| SHA-256 | `2e91c533615a9bb8929ac4bb76707b2444597ce063d84a4b33525e25074fff3f` |
| File type | `RAR` — RAR archive data, v5 |
| File size | `400.26 KB (409868 bytes)` |
| Tags | `rar`, `attachment`, `spreader` |

> 🇫🇷 Le fichier se fait passer pour un `.CAB` alors qu'il s'agit en réalité d'une **archive RAR v5** — technique courante pour contourner les filtres de sécurité basiques. Le tag **"spreader"** indique que ce fichier est connu pour se propager activement, ce qui en fait une menace sérieuse.
> 🇬🇧 The file pretends to be a `.CAB` while it is actually a **RAR v5 archive** — a common technique to bypass basic security filters. The **"spreader"** tag indicates the file is known to actively propagate, making it a serious threat.

---

## 🚩 Flags / Réponses aux questions

| Question | Réponse |
|---|---|
| Numéro de référence (Subject) | `09674321` |
| Nom affiché de l'expéditeur | `Mr. James Jackson` |
| Adresse email de l'expéditeur | `info@mutawamarine.com` |
| Adresse email de réponse (Reply-To) | `info.mutawamarine@mail.com` |
| IP d'origine | `192.119.71.157` |
| Propriétaire de l'IP | `Hostwinds LLC` |
| Enregistrement SPF complet | `v=spf1 include:spf.protection.outlook.com -all` |
| Enregistrement DMARC complet | `v=DMARC1; p=quarantine; fo=1` |
| Nom de la pièce jointe | `SWT_#09674321____PDF__.CAB` |
| Hash SHA256 de la pièce jointe | `2e91c533615a9bb8929ac4bb76707b2444597ce063d84a4b33525e25074fff3f` |
| Taille du fichier (VirusTotal) | `400.26 KB` |
| Vrai type de fichier | `RAR` |

---

## 📚 Lessons Learned / Ce que j'ai appris

- Le champ **Reply-To** peut différer du champ **From** — technique pour rediriger les réponses vers un compte contrôlé par l'attaquant
- **SPF** et **DMARC** sont des mécanismes d'authentification complémentaires : SPF vérifie si le serveur est autorisé, DMARC définit la politique à appliquer en cas d'échec
- Un fichier peut masquer son vrai type en changeant son extension — `sha256sum` + **VirusTotal** permet de révéler le vrai format
- Les **en-têtes d'email** tracent tout le chemin parcouru par un message et révèlent l'IP réelle d'origine, même quand l'expéditeur tente de se cacher
- Un email de **phishing** (hameçonnage) se reconnaît à plusieurs signaux cumulés : salutation générique, demande financière urgente, pièce jointe non sollicitée, discordance From/Reply-To
- `sha256sum` génère une empreinte unique d'un fichier — deux fichiers identiques ont toujours le même hash, ce qui permet de les identifier dans des bases de menaces comme VirusTotal

---

## 🔗 Resources / Ressources

- [TryHackMe — The Greenholt Phish](https://tryhackme.com/room/phishingemails5fgjlzxc)
- [MXToolbox — SPF & DMARC Lookup](https://mxtoolbox.com/)
- [VirusTotal — File & Hash Analysis](https://www.virustotal.com/)
- [WHOIS Lookup — IP & Domain Info](https://www.whois.com/whois/)
- [Thunderbird Mail](https://www.thunderbird.net/)
- [Qu'est-ce que le SPF ? (Cloudflare)](https://www.cloudflare.com/learning/dns/dns-records/dns-spf-record/)
- [Qu'est-ce que le DMARC ? (Cloudflare)](https://www.cloudflare.com/learning/dns/dns-records/dns-dmarc-record/)
- [SPF, DKIM et DMARC expliqués (Cloudflare)](https://www.cloudflare.com/learning/email-security/dmarc-dkim-spf/)

---

*✍️ Writeup by [Eddy M.](https://github.com/eddymandran) — [cybersecurity-portfolio](https://github.com/eddymandran/cybersecurity-portfolio)*