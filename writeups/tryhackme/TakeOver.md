# 🚩 TakeOver — TryHackMe Writeup

> **Platform :** [TryHackMe](https://tryhackme.com)
> **Room :** [TakeOver](https://tryhackme.com/room/takeover)
> **Difficulty / Difficulté :** 🟢 Easy
> **Category / Catégorie :** Reconnaissance, Subdomain Enumeration, DNS, Web
> **Date :** 29/03/2026
> **Status / Statut :** ✅ Completed (100%)

---

## 📋 Summary / Résumé

> 🇬🇧 As an IT consultant for FutureVera, a space research company, blackhat hackers claim they can take over part of the company's infrastructure and are demanding a ransom. The goal is to identify which subdomains are vulnerable to a subdomain takeover by performing DNS enumeration and SSL certificate analysis.
>
> 🇫🇷 En tant que consultant IT pour FutureVera, une entreprise de recherche spatiale, des hackers malveillants affirment pouvoir prendre le contrôle d'une partie de l'infrastructure et demandent une rançon. L'objectif est d'identifier quels sous-domaines sont vulnérables à une prise de contrôle (subdomain takeover) via l'énumération DNS et l'analyse des certificats SSL.

---

## 🎯 Objectives / Objectifs

- [x] Configurer le fichier `/etc/hosts` pour résoudre le domaine cible
- [x] Scanner les ports ouverts avec nmap
- [x] Énumérer les sous-domaines avec gobuster
- [x] Identifier `support.futurevera.thm` via la relecture de l'énoncé
- [x] Analyser le certificat SSL de `support.futurevera.thm` pour trouver un sous-domaine caché
- [x] Identifier le sous-domaine vulnérable au subdomain takeover
- [x] Récupérer le flag

---

## 🧰 Tools Used / Outils Utilisés

| Tool | Usage / Utilisation |
|---|---|
| `nmap` | Scan des ports ouverts / Open port scanning |
| `gobuster` | Énumération des sous-domaines / Subdomain enumeration |
| Firefox | Inspection visuelle des certificats SSL / Visual SSL cert inspection |

---

## 🔍 Reconnaissance

### Étape 1 — Configuration du fichier `/etc/hosts`

> 🇫🇷 Le domaine `futurevera.thm` est un domaine fictif local — il faut indiquer manuellement sa résolution DNS via `/etc/hosts`.
> 🇬🇧 `futurevera.thm` is a local fictional domain — we need to manually add its DNS resolution via `/etc/hosts`.

```bash
sudo nano /etc/hosts
# Ajouter / Add :
10.112.129.180 futurevera.thm
```

### Étape 2 — Scan nmap

```bash
nmap -sV -sC futurevera.thm
```

**Résultats / Results :**

| Port | Service |
|---|---|
| 22 | SSH |
| 80 | HTTP |
| 443 | HTTPS |

---

## 🗺️ Enumeration / Énumération

### Étape 3 — Énumération des sous-domaines avec gobuster

> 🇫🇷 Le **mode vhost** de gobuster teste des sous-domaines en modifiant le header HTTP `Host` de chaque requête.
> 🇬🇧 Gobuster's **vhost mode** tests subdomains by modifying the HTTP `Host` header of each request.

```bash
gobuster vhost -w /root/Desktop/Tools/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt \
               -u futurevera.thm \
               --append-domain
```

**Résultat / Result :**
```
Found: portal.futurevera.thm     Status: 200 [Size: 69]
Found: payroll.futurevera.thm    Status: 200 [Size: 70]
```

Ajout dans `/etc/hosts` :
```bash
sudo nano /etc/hosts
# Ajouter / Add :
10.112.129.180 portal.futurevera.thm
10.112.129.180 payroll.futurevera.thm
```

> 💡 **Note :** J'ai inspecté les certificats SSL de `portal.futurevera.thm` et `payroll.futurevera.thm` — aucun ne contenait de mention d'un sous-domaine `support` dans leurs champs SAN. C'est la **relecture attentive de l'énoncé** qui a permis d'identifier cette piste : *"we are rebuilding our support"* — un indice direct sur l'existence d'un sous-domaine `support`.

---

### Étape 4 — Identification de `support.futurevera.thm`

Ajout dans `/etc/hosts` :
```bash
sudo nano /etc/hosts
# Ajouter / Add :
10.112.129.180 support.futurevera.thm
```

---

### Étape 5 — Analyse du certificat SSL de `support.futurevera.thm`

> 🇫🇷 Un certificat SSL contient souvent un champ **Subject Alternative Names (SAN)** qui liste tous les sous-domaines couverts — même les sous-domaines non publics. C'est une **fuite d'information involontaire** très utile en reconnaissance.
> 🇬🇧 An SSL certificate often contains a **Subject Alternative Names (SAN)** field listing all covered subdomains — even non-public ones. This is an **unintentional information leak** very useful in recon.

Dans Firefox sur `https://support.futurevera.thm` :
```
Cadenas 🔒 → Show Certificate → Subject Alt Names
```

**Détails du certificat / Certificate details :**

| Champ | Valeur |
|---|---|
| Common Name | `support.futurevera.thm` |
| Organisation | Futurevera |
| Validité / Validity | 13/03/2022 → 12/03/2024 |
| **Subject Alt Name (SAN)** | **`secrethelpdesk934752.support.futurevera.thm`** |
| Algorithme | SHA-256 with RSA Encryption |

Le certificat révèle le sous-domaine caché : **`secrethelpdesk934752.support.futurevera.thm`**

Ajout dans `/etc/hosts` :
```bash
sudo nano /etc/hosts
# Ajouter / Add :
10.112.129.180 secrethelpdesk934752.support.futurevera.thm
```

---

## ⚔️ Exploitation — Subdomain Takeover

### Étape 6 — Accès au sous-domaine vulnérable

> ⚠️ **Important :** Visiter le sous-domaine sur le **port 80 (HTTP)** — pas HTTPS.

```
http://secrethelpdesk934752.support.futurevera.thm
```

Le navigateur redirige automatiquement vers une URL AWS S3 :
```
flag{beea0d6edfcee06a59b83fb50ae81b2f}.s3-website-us-west-3.amazonaws.com
```

> 🇫🇷 Ce sous-domaine pointe via DNS vers un **bucket AWS S3** qui n'existe plus. N'importe quel attaquant pourrait créer ce bucket et prendre le contrôle du sous-domaine — c'est exactement ce qu'on appelle un **subdomain takeover**. Le flag est visible directement dans l'URL de redirection AWS.
>
> 🇬🇧 This subdomain points via DNS to an **AWS S3 bucket** that no longer exists. Any attacker could create that bucket and take control of the subdomain — this is exactly what a **subdomain takeover** is. The flag is directly visible in the AWS redirect URL.

---

## 🚩 Flags / Réponses aux questions

| Question | Réponse |
|---|---|
| What's the value of the flag? | `flag{beea0d6edfcee06a59b83fb50ae81b2f}` |

---

## 📚 Lessons Learned / Ce que j'ai appris

- **Lire attentivement l'énoncé** avant de se lancer dans les outils — l'indice `"we are rebuilding our support"` pointait directement vers `support.futurevera.thm`, que gobuster n'avait pas trouvé
- Les certificats SSL contiennent un champ **Subject Alternative Names (SAN)** qui révèle des sous-domaines non publics — toujours inspecter les certificats lors d'une reconnaissance
- gobuster ne trouve que ce qui est dans sa wordlist — un sous-domaine absent de la liste restera invisible, d'où l'importance de **combiner plusieurs techniques** de reconnaissance
- Un **subdomain takeover** est possible quand un sous-domaine pointe via DNS vers un service externe (AWS S3, GitHub Pages, Heroku...) qui n'existe plus — l'attaquant peut alors créer ce service et prendre le contrôle
- Toujours tester sur **HTTP (port 80) ET HTTPS (port 443)** — certains comportements ne sont visibles que sur l'un ou l'autre

---

## 🔗 Resources / Ressources

- [TryHackMe — TakeOver](https://tryhackme.com/room/takeover)
- [HackTricks — Subdomain Takeover](https://book.hacktricks.xyz/pentesting-web/domain-subdomain-takeover)
- [HackerOne — Guide to Subdomain Takeovers](https://www.hackerone.com/application-security/guide-subdomain-takeovers)
- [MDN — Subdomain Takeovers](https://developer.mozilla.org/en-US/docs/Web/Security/Subdomain_takeovers)
- [gobuster — Documentation](https://github.com/OJ/gobuster)

---

*✍️ Writeup by [Eddy M.](https://github.com/eddymandran) — [cybersecurity-portfolio](https://github.com/eddymandran/cybersecurity-portfolio)*