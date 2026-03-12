# 🎣 Snapped Phish-ing Line — Write-Up

**Platform:** TryHackMe  
**Category:** SOC / Phishing Analysis  
**Difficulty:** Medium  
**Date:** March 2026  
**Author:** [Dryoko](https://github.com/Dryoko) | [Hodge10](https://tryhackme.com/p/Hodge10)

---

## 📌 Context & Objective

As an IT department employee of SwiftSpend Financial, several colleagues reported receiving a suspicious email. Some had already submitted their credentials and could no longer log in. The objective is to investigate by:

- Analysing the email samples provided by colleagues
- Analysing the phishing URL(s) using Firefox
- Retrieving the phishing kit used by the adversary
- Using CTI-related tooling to gather more information about the adversary
- Analysing the phishing kit to gather more information about the adversary

---

## 🧰 Tools Used

| Tool | Usage |
|------|-------|
| CLI — `cat` | Safe reading of HTML email attachments without browser execution |
| CyberChef | URL defanging + Base64 decoding + String reverse |
| `sha256sum` (Linux CLI) | SHA256 hash calculation of the phishing kit archive |
| VirusTotal | First submission date + file metadata |
| crt.sh / Censys / URLScan.io | SSL certificate lookup |
| `grep` | Email address extraction from phishing kit source files |
| Manual URL enumeration | Discovery of hidden paths on the phishing server |

---

## 🔍 Step-by-Step Analysis

### Question 1 — Who received an email attachment containing a PDF?

The `phish-emails` folder contains several emails. Each one was opened and inspected for attachments. The email titled **"Quote for services rendered: processed on June 29, 2020, 10:01:32 AM"** was the only one containing a PDF attachment.

> **Answer: `William McClean`**

<details>
<summary>📸 View screenshot</summary>

![PDF attachment in William McClean's email](screenshots/01_attachment_PDF.png)

</details>

---

### Question 2 — What email address did the adversary use to send the phishing emails?

The sender's address is visible in the **From** field of the email headers.

> **Answer: `Accounts.Payable@groupmarketingonline.icu`**

<details>
<summary>📸 View screenshot</summary>

![Sender address in email header](screenshots/02_sender_in_the_header.png)

</details>

---

### Question 3 — What is the redirection URL to the phishing page for Zoe Duncan? (defanged format)

Zoe Duncan's email contains an HTML attachment. 

> ⚠️ **Important:** Never open a suspicious HTML file directly in a browser — it could execute malicious code.

The safe approach is to read the file contents via CLI:

```bash
cat zoe_duncan_email.html
```

The URL was extracted from the source code and defanged using CyberChef's **Defang URL** operation.

> **Answer: `hxxp[://]kennaroads[.]buzz/data/Update365/office365/40e7baa2f826a57fcf04e5202526f8bd/?email=zoe[.]duncan@swiftspend[.]finance&error`**

<details>
<summary>📸 View screenshot</summary>

![CyberChef defang URL operation](screenshots/03_cyberchef_defang_url.png)

</details>

---

### Question 4 — What is the URL to the .zip archive of the phishing kit? (defanged format)

The phishing kit `.zip` archive is hosted on the same server as the phishing page. Since Gobuster was not available on the THM VM, manual URL enumeration was required by navigating up the directory structure and testing common paths.

```
http://kennaroads.buzz/data/Update365.zip
```

> **Lesson:** When automated fuzzing tools are unavailable, always try to manually navigate the directory tree — attackers often forget to remove their kit archive after deployment.

> **Answer: `hxxp[://]kennaroads[.]buzz/data/Update365[.]zip`**

<details>
<summary>📸 View screenshot</summary>

![Manual URL enumeration to find the zip archive](screenshots/04_url_enumeration.png)

</details>

---

### Question 5 — What is the SHA256 hash of the phishing kit archive?

After downloading the `.zip` file, the SHA256 hash was calculated using the CLI:

```bash
sha256sum Update365.zip
```

> **Answer: `ba3c15267393419eb08c7b2652b8b6b39b406ef300ae8a18fee4d16b19ac9686`**

<details>
<summary>📸 View screenshot</summary>

![SHA256 hash calculation in CLI](screenshots/05_sha256_update365_zip.png)

</details>

---

### Question 6 — When was the phishing kit archive first submitted? (format: YYYY-MM-DD HH:MM:SS UTC)

The SHA256 hash was searched on **VirusTotal**. The first submission date is available under the **Details** tab.

> **Answer: `2020-04-08 21:55:50 UTC`**

<details>
<summary>📸 View screenshot</summary>

![VirusTotal first submission date](screenshots/06_VirusTotal_first_submission.png)

</details>

---

### Question 7 — When was the SSL certificate first logged? (format: YYYY-MM-DD)

> ⚠️ **Note:** The SSL certificate was no longer accessible at the time of writing this write-up. The expected answer is `2020-06-25` according to the official THM hint.

The recommended tools for this type of SSL certificate research are:
- **[crt.sh](https://crt.sh)** — Certificate Transparency Logs database
- **[Censys](https://search.censys.io)** — Internet-wide scanning with certificate indexing
- **[URLScan.io](https://urlscan.io)** — Web scanner with certificate details in scan reports

> **SOC Lesson:** SSL Certificate Transparency Logs are public records — every certificate issued must be logged. This makes them a valuable source of historical data during threat hunting, even for domains that no longer exist.

> **Answer: `2020-06-25`**

---

### Question 8 — What was the email address of the user who submitted their password twice?

After extracting the phishing kit, a `log.txt` file was discovered on the server. This file contains credentials collected by the attacker, including email addresses and passwords submitted by victims. Analysing the log reveals a user who submitted their credentials twice.

> **Answer: `michael.ascot@swiftspend.finance`**

<details>
<summary>📸 View screenshot</summary>

![log.txt file with collected credentials](screenshots/08_logtxt.png)

</details>

---

### Question 9 — What email address did the adversary use to collect compromised credentials?

The phishing kit `.zip` was extracted and its contents analysed.

**❌ Poor initial approach:**  
Running `grep -r "@"` was too broad — it returned every occurrence of the `@` symbol across the entire kit, including validation regex patterns, CSS rules, and unrelated email addresses, making the results very difficult to analyse.

**✅ Correct approach:**  
In a PHP phishing kit, the credential collection email is located in the file that **actually sends the data** to the attacker. The right approach is to target the `mail()` function directly:

```bash
grep -r "mail(" .
```

This immediately identifies `submit.php` as the active collector and reveals the real destination address.

> **SOC Lesson:** Always distinguish between the *sender* address (the `From:` field, often fake) and the *recipient* address (the `$to` variable inside `mail()`) — only the latter belongs to the attacker.

> **Answer: `m3npat@yandex.com`**

<details>
<summary>📸 View screenshot</summary>

![grep mail() in submit.php](screenshots/09_grep_mail_submit_php.png)

</details>

---

### Question 10 — What is the other email address used by the adversary ending in "@gmail.com"?

A targeted `grep` was used to search for Gmail addresses across the entire kit:

```bash
grep -r "@gmail.com" .
```

> **Answer: `jamestanner2299@gmail.com`**

<details>
<summary>📸 View screenshot</summary>

![grep @gmail.com result](screenshots/10_grep_@gmail.png)

</details>

---

### Question 11 — What is the hidden flag?

**❌ What I tried (unsuccessfully):**  
The search focused on the extracted `.zip` contents — I inspected the `.DS_Store` file (a macOS metadata artefact revealing the attacker developed the kit on a Mac), attempted steganography analysis on images, searched all PHP/HTML files, and checked ZIP metadata. None of these led to the flag.

**✅ Correct approach:**  
Switching strategy to direct URL enumeration on the phishing server. Since Gobuster was unavailable on the THM VM, paths were tested manually:

```
http://kennaroads.buzz/robots.txt          ✅ checked — no flag
http://kennaroads.buzz/data/Update365/office365/flag      ❌
http://kennaroads.buzz/data/Update365/office365/hidden    ❌
http://kennaroads.buzz/data/Update365/office365/flag.txt  ✅ FLAG FOUND
```

The retrieved value was Base64-encoded and reversed:

```
Raw value  : fUxSVV8zSHRfaFQxd195NExwe01IVAo=
After Base64 decode : }LRU_3Ht_hT1w_y4Lp{MHT
After Reverse       : THM{pL4y_w1Th_tH3_URL}
```

Decoded using **CyberChef** with chained operations: `From Base64` → `Reverse`.

> **CTF Lesson:** Always test these paths manually when automated tools are unavailable:
> - `/robots.txt` ← **always first reflex** ✅
> - `/flag.txt`
> - `/flag.php`
> - `/secret.txt`
> - `/.htaccess`

> **Answer: `THM{pL4y_w1Th_tH3_URL}`**

<details>
<summary>📸 View screenshot — URL enumeration</summary>

![Manual URL enumeration to find flag.txt](screenshots/11_enumerate_url_flag.png)

</details>

<details>
<summary>📸 View screenshot — CyberChef decode</summary>

![CyberChef Base64 + Reverse to decode the flag](screenshots/12_cyberchef_reverse_flag.png)

</details>

---

## 🚨 Indicators of Compromise (IOC)

| Type | Value | Source |
|------|-------|--------|
| Sender address | `Accounts.Payable@groupmarketingonline.icu` | Email header |
| Phishing domain | `kennaroads.buzz` | HTML attachment |
| Phishing kit URL | `http://kennaroads.buzz/data/Update365.zip` | Manual enumeration |
| SHA256 (kit) | `ba3c15267393419eb08c7b2652b8b6b39b406ef300ae8a18fee4d16b19ac9686` | sha256sum |
| Adversary email #1 | `m3npat@yandex.com` | submit.php — `mail()` |
| Adversary email #2 | `jamestanner2299@gmail.com` | Phishing kit source |

---

## 🔴 Red Flags Identified

- **Suspicious sender domain** — `.icu` TLD commonly associated with malicious infrastructure
- **HTML attachment** instead of a direct link — designed to bypass email gateway URL scanning
- **Fake Office 365 login page** — credential harvesting targeting corporate users
- **Kit developed on macOS** — `.DS_Store` file left behind by the attacker, revealing their development environment
- **Double credential submission** — victim submitted credentials twice, suggesting the phishing page displayed an error to appear legitimate

---

## 💡 Key Takeaways

1. **Never open suspicious HTML attachments in a browser** — always use `cat` or a text editor to inspect the source code safely.

2. **Targeting `mail()` in PHP kits** — `grep -r "mail("` is far more efficient than `grep -r "@"` when hunting for the adversary's collection address.

3. **`.DS_Store` as a forensic artefact** — its presence reveals the attacker's OS (macOS) and can expose directory structure metadata. Always check for hidden files with `find . -name ".*" -type f`.

4. **Manual URL enumeration checklist** — when Gobuster is unavailable, always test `/robots.txt`, `/flag.txt`, `/flag.php`, `/secret.txt` systematically.

5. **Chained encoding** — `Base64 + Reverse` is a classic CTF obfuscation technique. When a decoded value looks like garbage, try reversing it.

---

## 🔗 Resources Used

- [CyberChef](https://gchq.github.io/CyberChef/)
- [VirusTotal](https://www.virustotal.com)
- [crt.sh](https://crt.sh)
- [Censys](https://search.censys.io)
- [URLScan.io](https://urlscan.io)

---

*Write-up produced as part of a cybersecurity career transition (SOC Analyst L1). All analyses were conducted in the isolated environment provided by TryHackMe.*
