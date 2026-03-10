# 🎣 The Greenholt Phish — Write-Up

**Plateforme :** TryHackMe  
**Catégorie :** SOC / Phishing Analysis  
**Difficulté :** Easy  
**Date :** Mars 2026  
**Auteur :** Dryoko

---

## 📌 Contexte & Objectif

Un employé a transféré un email suspect au SOC. L'objectif est d'analyser cet email de phishing en profondeur : examiner les headers, identifier l'IP d'origine, vérifier les enregistrements DNS de sécurité (SPF, DMARC) et analyser la pièce jointe malveillante.

Ce challenge simule une tâche quotidienne d'un analyste SOC Niveau 1 : le triage et l'investigation d'un email suspect.

---

## 🧰 Outils Utilisés

| Outil | Usage |
|-------|-------|
| Thunderbird | Lecture et export de l'email + pièce jointe |
| Google Admin Toolbox – Message Header Analyzer | Analyse des headers et identification de l'IP d'origine |
| ipinfo.io | Renseignement sur l'IP (ASN, organisation) |
| MXToolbox – SPF Lookup | Récupération de l'enregistrement SPF |
| MXToolbox – DMARC Lookup | Récupération de l'enregistrement DMARC |
| `sha256sum` (CLI Linux) | Calcul du hash SHA256 de la pièce jointe |
| Talos Intelligence | Réputation du hash SHA256 |
| VirusTotal | Taille et extension réelle du fichier |

---

## 🔍 Analyse Pas-à-Pas

### Question 1 — Quel est le numéro de référence de transfert dans le sujet de l'email ?

L'information est directement visible dans le corps de l'email, sans aucune manipulation nécessaire.

> **Réponse : `09674321`**

---

### Question 2 — Qui est l'expéditeur de l'email ?

L'information se trouve dans le header de l'email, dans le champ **From**.

> **Réponse : `Mr. James Jackson`**

---

### Question 3 — Quelle est son adresse email ?

Toujours dans le header, à droite du nom de l'expéditeur.

> **Réponse : `info@mutawamarine.com`**

---

### Question 4 — Quelle adresse email recevra la réponse à cet email ?

Dans le header, le champ **Reply-To** est distinct du champ **From** — premier indicateur de phishing : l'expéditeur affiché et l'adresse de réponse sont différents.

> **Réponse : `info.mutawamarine@mail.com`**

---

### Question 5 — Quelle est l'IP d'origine de l'email ?

**⚠️ Erreur commise au 1er essai :** J'ai d'abord répondu `10.201.192.162`, visible en haut du header brut. C'était une erreur : il s'agit d'une **adresse IP privée (RFC 1918)**, qui correspond à un relais interne — elle ne peut donc pas être l'IP d'origine externe de l'attaquant.

**Méthode correcte :** En utilisant **Google Admin Toolbox – Message Header Analyzer**, les headers sont analysés et classés chronologiquement. L'IP d'origine est celle présente dans le **premier "Received" header** (le plus ancien dans la chaîne de relais).

> **Leçon SOC :** Toujours lire les headers de bas en haut. Le premier `Received:` (en bas) est le plus ancien et correspond au vrai point d'envoi.

> **Réponse : `192.119.71.157`**

---

### Question 6 — Quel est le nom de l'organisation associée à l'IP d'origine ?

Recherche de l'IP `192.119.71.157` sur **ipinfo.io**. L'ASN (Autonomous System Number) et l'organisation sont affichés en première ligne.

> **Réponse : `Hostwinds LLC`**

---

### Question 7 — Quel est l'enregistrement SPF pour le domaine Return-Path ?

**Domaine extrait du Return-Path :** `mutawamarine.com`

Un enregistrement SPF (Sender Policy Framework) est un **enregistrement DNS de type TXT** qui liste les serveurs autorisés à envoyer des emails au nom d'un domaine. Il ne se trouve pas sur urlscan.io ou Talos — il faut un outil de **DNS Lookup**.

**Méthode :**
- Via **MXToolbox → SPF Record Lookup** avec le domaine `mutawamarine.com`
- Équivalent en ligne de commande sur Kali :

```bash
dig TXT mutawamarine.com
```

> **Leçon SOC :** Ne pas confondre les outils. SPF = enregistrement DNS TXT → utiliser un DNS/SPF Lookup, pas un scanner d'URL. Penser également à n'entrer que le domaine (pas l'adresse email complète).

> **Réponse : `v=spf1 include:spf.protection.outlook.com -all`**

---

### Question 8 — Quel est l'enregistrement DMARC pour le domaine Return-Path ?

Même domaine `mutawamarine.com`, même outil MXToolbox, en passant cette fois sur **DMARC Lookup**.

DMARC (Domain-based Message Authentication, Reporting & Conformance) définit la politique à appliquer si SPF ou DKIM échouent. Ici `p=quarantine` signifie que les emails non conformes sont envoyés en spam.

> **Réponse : `v=DMARC1; p=quarantine; fo=1`**

---

### Question 9 — Quel est le nom de la pièce jointe ?

Visible directement en bas de l'email dans Thunderbird.

> **Réponse : `SWT_#09674321____PDF__.CAB`**

> **Note :** Le nom tente de faire croire à un fichier PDF. L'extension `.CAB` (Cabinet, archive Windows) est un premier signal d'alarme.

---

### Question 10 — Quel est le hash SHA256 de la pièce jointe ?

La pièce jointe est exportée depuis Thunderbird sur le bureau de la VM, puis le hash est calculé en ligne de commande :

```bash
sha256sum SWT_#09674321____PDF__.CAB
```

Le hash est ensuite recherché sur **Talos Intelligence** pour vérification de réputation.

> **Réponse : `2e91c533615a9bb8929ac4bb76707b2444597ce063d84a4b33525e25074fff3f`**

---

### Question 11 — Quelle est la taille de la pièce jointe ?

**⚠️ Piège :** La valeur affichée sur Talos Intelligence ne correspondait pas à la réponse attendue. C'est la valeur indiquée sur **VirusTotal** qui était correcte.

> **Réponse : `400.26 KB`**

---

### Question 12 — Quelle est la vraie extension du fichier ?

Malgré le nom `...PDF__.CAB`, l'analyse sur VirusTotal et Talos révèle que le fichier est en réalité une **archive RAR** — technique classique de dissimulation de malware.

> **Réponse : `.RAR`**

---

## 🚨 Indicateurs de Compromission (IOC)

| Type | Valeur | Source |
|------|--------|--------|
| IP d'origine | `192.119.71.157` | Received Header |
| Organisation | Hostwinds LLC | ipinfo.io |
| Domaine expéditeur | `mutawamarine.com` | From Header |
| Reply-To suspect | `info.mutawamarine@mail.com` | Reply-To Header |
| Nom de fichier | `SWT_#09674321____PDF__.CAB` | Pièce jointe |
| SHA256 | `2e91c533615a9bb8929ac4bb76707b2444597ce063d84a4b33525e25074fff3f` | sha256sum |
| Extension réelle | `.RAR` | VirusTotal / Talos |

---

## 🔴 Signaux d'Alerte Identifiés

- **From ≠ Reply-To** : adresse de réponse différente de l'expéditeur affiché
- **Nom de fichier trompeur** : extension `.CAB` masquant un fichier `.RAR`
- **IP d'origine** hébergée chez Hostwinds LLC (hébergeur souvent utilisé pour des infrastructures malveillantes)
- **SPF `-all`** : le domaine rejette tout serveur non autorisé — pourtant l'email a quand même été reçu, ce qui suggère une usurpation ou un relais compromis

---

## 💡 Leçons Retenues

1. **Lire les headers de bas en haut** : le premier `Received:` en bas est l'IP d'origine réelle. Une IP privée (`10.x.x.x`) est toujours un relais interne, jamais une source externe.

2. **SPF = DNS TXT record** : utiliser un SPF/DNS Lookup (MXToolbox, `dig TXT`), pas un scanner d'URL. Toujours entrer le domaine seul, sans le préfixe de l'adresse email.

3. **Ne pas faire confiance au nom de fichier** : `.CAB` affiché, `.RAR` réel — toujours vérifier l'extension réelle via l'analyse de fichier (magic bytes, VirusTotal).

4. **Croiser les sources** : Talos et VirusTotal ne donnent pas toujours les mêmes métadonnées. La réponse attendue peut dépendre d'un outil spécifique.

5. **From ≠ Reply-To = red flag immédiat** en analyse phishing.

---

## 🔗 Ressources Utilisées

- [Google Admin Toolbox – Message Header Analyzer](https://toolbox.googleapps.com/apps/messageheader/)
- [MXToolbox](https://mxtoolbox.com)
- [ipinfo.io](https://ipinfo.io)
- [Talos Intelligence](https://talosintelligence.com)
- [VirusTotal](https://www.virustotal.com)

---

*Write-up réalisé dans le cadre d'une reconversion vers la cybersécurité (SOC Analyst). Toutes les analyses ont été effectuées dans un environnement isolé fourni par TryHackMe.*
