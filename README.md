# Phishing Email Analyzer

A web-based tool that inspects a suspicious email and explains, in plain language, whether it looks like phishing and why.

Upload a saved `.eml` file or paste an email's raw source. The analyzer parses the headers, checks sender authentication (SPF, DKIM, DMARC), extracts and inspects every link and attachment, scans the content for social engineering tactics, and combines the red flags into a risk score and a verdict: **Benign**, **Suspicious**, or **Malicious**.

**Live demo:** _add your Render link here_

> The free hosting tier sleeps after inactivity, so the first visit may take about a minute to load.

---

## Why I built it

Phishing is one of the most common ways attackers get into organizations, and triaging reported emails is a core task for SOC analysts. I wanted to understand what an analyst actually looks at when deciding whether an email is malicious, then automate those checks so every verdict comes with clear evidence instead of a black-box answer.

All detection logic is written by hand in Python. No AI or third-party detection API is involved, so every finding traces back to a specific, explainable rule.

---

## What it checks

### 1. Sender
| Check | Example |
|---|---|
| Brand name in the display name, but the address isn't that brand's domain | `"PayPal Security" <service@paypa1-secure.com>` |
| Lookalike domains, including swapped characters | `paypa1` (1 for l), `rnicrosoft` (rn for m), `docusign-review.net` |
| A company name sent from a free webmail account | `"UPS Delivery" <ups.delivery@gmail.com>` |
| An executive title sent from free webmail (CEO fraud) | `"James Martin - CEO" <ceo.jmartin@gmail.com>` |
| Reply-To or Return-Path belonging to a different organization | Sent from `paypa1-secure.com`, replies go to `protonmail-support.net` |

### 2. Authentication
Reads the `Authentication-Results` header written by the receiving mail server and flags failures:
- **SPF**: was the sending server authorized to send for this domain?
- **DKIM**: is there a valid digital signature from the domain?
- **DMARC**: does the visible From domain pass its owner's anti-spoofing policy?

### 3. Content
- Urgent or threatening language (`"within 24 hours"`, `"account suspended"`)
- Requests for credentials or personal information (`"verify your identity"`)
- Unusual payment requests such as gift cards, wire transfers, or crypto
- Secrecy tactics that discourage verifying the request (`"keep this confidential"`)
- Generic greetings (`"Dear Customer"`)

### 4. Links
Links are extracted from both the plain-text and HTML parts of the email, and each one is checked for:
- Raw IP addresses instead of domain names
- **Visible link text that doesn't match the real destination**, e.g. text showing `paypal.com` while the link goes to `verify-login.xyz`
- Lookalike or brand-impersonating domains
- High-risk top-level domains (`.xyz`, `.top`, `.click`, ...)
- URL shorteners that hide the destination
- The `@` trick (`http://paypal.com@evil.top` actually goes to `evil.top`)
- Punycode domains that can disguise lookalike characters
- Unencrypted `http` links

### 5. Attachments
- Executables, scripts, and macro-enabled Office files (`.exe`, `.js`, `.docm`, ...)
- HTML attachments, a common way to deliver fake login pages
- Double extensions (`invoice.pdf.exe`)
- Archives that can hide malware from email filters

---

## How the scoring works

Each red flag adds points weighted by how strongly it indicates phishing. For example, a DMARC failure adds 25 points, while an unencrypted link adds only 5. Repeated link problems are only counted once. The total is capped at 100.

| Score | Verdict |
|---|---|
| 0 – 24 | Benign |
| 25 – 59 | Suspicious |
| 60 – 100 | Malicious |

Findings are shown in order of severity, and each one explains exactly what was found.

---

## Tech stack

- **Python 3** with the standard-library `email` package for parsing (headers, multipart bodies, attachments, encodings)
- **Flask** for the web server
- **HTML, CSS, and JavaScript** for the front end
- **Gunicorn** and **Render** for deployment

---

## Project structure

```
phishing-analyzer/
├── analyzer.py        # All detection logic: parsing, checks, scoring
├── app.py             # Flask web server: serves the page, receives emails, returns JSON
├── templates/
│   └── index.html     # The web interface
├── samples/           # Fake test emails (safe to share)
└── requirements.txt
```

`analyzer.py` has no knowledge of the website, so the detection logic can be tested or reused on its own. `app.py` only handles web requests.

---

## Run it locally

```bash
git clone https://github.com/0xRizk/phishing-email-analyzer.git
cd phishing-email-analyzer
pip install -r requirements.txt
python app.py
```

Then open **http://127.0.0.1:5000**. On Windows, use `py` instead of `python` if needed.

### Try the samples

The `samples/` folder contains fake emails covering different attack types:

| File | Scenario | Expected verdict |
|---|---|---|
| `paypal_phish.eml` | Credential phishing with spoofed sender and disguised links | Malicious |
| `microsoft_password_phish.eml` | Password-expiry lure using the `@` trick and punycode | Malicious |
| `docusign_attachment_phish.eml` | Fake document with an HTML attachment | Malicious |
| `canadapost_scam.eml` | Delivery fee scam with a shortened link | Malicious |
| `ceo_giftcard_scam.eml` | CEO fraud asking for gift cards | Malicious |
| `shopnow_suspicious.eml` | Pushy "reward" email with weak warning signs | Suspicious |
| `github_legit.eml` | Real-style security notification | Benign |
| `spotify_legit.eml` | Real-style marketing email | Benign |

To test a real email from Gmail: open it → **⋮** → **Download message**, then upload the `.eml` file.

---

## Security considerations

Because this tool handles hostile input by design, the app was built to treat every email as untrusted:

- **No XSS from email content.** Everything taken from an email is inserted into the page as plain text, never as HTML, so a malicious email can't run scripts in the browser.
- **Links are never clickable.** Extracted URLs are displayed as text only.
- **Nothing is stored.** Emails are analyzed in memory and discarded. Nothing is saved to disk or a database.
- **Upload size limit.** Requests over 10 MB are rejected.
- **No error leakage.** Unexpected errors return a generic message to the browser instead of internal details.

---

## Limitations

This is a rule-based educational tool, not a replacement for an enterprise email security gateway.

- It relies on the `Authentication-Results` header added by the receiving server. If you paste only part of an email, SPF/DKIM/DMARC can't be checked.
- It doesn't check links or attachments against threat intelligence feeds, and it never visits links or opens attachments.
- Comparing organizations by the last two parts of a domain is simplified, so multi-part endings like `.co.uk` aren't handled perfectly.
- Keyword-based content checks can be evaded by attackers who avoid common phrases, and occasionally trigger on legitimate emails.

## Future improvements

- Check URLs and file hashes against threat intelligence (e.g. VirusTotal, URLhaus)
- Look up domain registration age, since newly registered domains are a strong phishing signal
- Use the Public Suffix List for accurate domain comparison
- Add automated tests for every rule using the sample emails
- Export results as a report for incident documentation

---

## Author

**Rizk Hyatt**
[r1zk.com](https://r1zk.com) · [GitHub](https://github.com/0xRizk) · [LinkedIn](https://www.linkedin.com/in/rizk-hyatt-a740a4317/)
