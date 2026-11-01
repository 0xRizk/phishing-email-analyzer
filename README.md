# Phishing Email Analyzer

A web-based tool that inspects a suspicious email and explains, in plain language, whether it looks like phishing and why.

Upload a saved `.eml` file or paste an email's raw source. The analyzer parses the headers, checks sender authentication (SPF, DKIM, DMARC), extracts and inspects every link and attachment, scans the content for social engineering tactics, and combines the red flags into a risk score and one of four verdicts: **Benign**, **Low Suspicion**, **High Suspicion**, or **Malicious**.

**Live demo:** [phishing-email-analyzer-xps9.onrender.com](https://phishing-email-analyzer-xps9.onrender.com/)

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
| A fake email address typed into the display name | `"security@paypal.com" <x@mailer.top>` |
| A brand named in the subject, sent from a domain that isn't that brand | Subject `Your Netflix payment failed` from `billing@account-notice.com` |
| A company name or executive title sent from a free webmail account | `"UPS Delivery" <ups.delivery@gmail.com>`, `"James Martin - CEO" <ceo.jmartin@gmail.com>` |
| A sender domain with a high-risk ending | `alerts@secure-login.top` |
| Reply-To or Return-Path belonging to a different organization | Sent from `paypa1-secure.com`, replies go to `protonmail-support.net` |

### 2. Authentication
Reads the `Authentication-Results` header written by the receiving mail server and flags failures:
- **SPF**: was the sending server authorized to send for this domain?
- **DKIM**: is there a valid digital signature from the domain? If an email carries several signatures (e.g. the company's and its mailing service's), one valid signature is enough.
- **DMARC**: does the visible From domain pass its owner's anti-spoofing policy? A domain with no DMARC policy at all is also noted.

Only the **top** `Authentication-Results` header is trusted (see [Security considerations](#security-considerations)). If it's missing, the `Received-SPF` header is used as a fallback.

### 3. Content
- Urgent or threatening language (`"within 24 hours"`, `"account suspended"`, `"password will expire"`)
- Requests for credentials or personal information (`"verify your identity"`, `"keep your password"`)
- Unusual payment requests such as gift cards, wire transfers, crypto, or payroll / direct-deposit changes
- Secrecy tactics that discourage verifying the request (`"keep this confidential"`)
- Bait to click or open something, when two or more phrases appear (`"click here"`, `"view document"`, `"refund"`)
- Generic greetings (`"Dear Customer"`, `"Hello user@example.com"`)
- **Forms inside the email itself**, especially password boxes. Legitimate companies send you to their website to log in; they never ask you to type into the email.

Phrases are matched as whole words, so `"urgent"` doesn't match "insurgent". Text inside `<style>` and `<script>` tags is ignored, since the reader never sees it.

### 4. Links
Links are extracted from the plain-text and HTML parts of the email (including bare `www.` links and form destinations), and each one is checked for:
- Raw IP addresses instead of domain names, including disguised forms like `http://3119138835/`
- **Visible link text that doesn't match the real destination**, e.g. text showing `paypal.com` while the link goes to `verify-login.xyz` (file names like `invoice.pdf` in link text are correctly ignored)
- Lookalike or brand-impersonating domains
- **Free hosting and form services** (`web.app`, `pages.dev`, `forms.gle`, ...), where most fake login pages are hosted today
- `javascript:` and `data:` links, which run code instead of opening a website
- High-risk top-level domains (`.xyz`, `.top`, `.click`, ...)
- URL shorteners that hide the destination
- The `@` trick (`http://paypal.com@evil.top` actually goes to `evil.top`)
- Punycode domains that can disguise lookalike characters
- Unencrypted `http` links
- An email that asks you to log in or confirm details, but links to a different organization than the sender

### 5. Attachments
- Executables, scripts, and macro-enabled Office files (`.exe`, `.js`, `.docm`, `.lnk`, `.iso`, `.one`, ...)
- HTML and SVG attachments, common ways to deliver fake login pages
- Double extensions (`invoice.pdf.exe`)
- Hidden right-to-left characters that make a file name display backwards (a file really named `inv[RLO]fdp.exe` displays as `invexe.pdf`)
- Archives that can hide malware from email filters

---

## How the scoring works

Each red flag adds points weighted by how strongly it indicates phishing. For example, a DMARC failure adds 25 points, while an unencrypted link adds only 5. Repeated link problems are only counted once. The total is capped at 100.

| Score | Verdict | Meaning |
|---|---|---|
| 0 | Benign | No significant red flags detected. |
| 1 – 19 | Low Suspicion | Minor phishing indicators detected. |
| 20 – 49 | High Suspicion | Significant indicators of potential phishing. |
| 50 – 100 | Malicious | Strong evidence of phishing or malicious intent. |

The bar is set low on purpose. For a phishing tool, flagging a safe email costs a few seconds of double-checking, but calling a phishing email "benign" can cost someone their account.

Findings are grouped by area (Sender, Authentication, Content, Links, Attachments) and shown as a score sheet: each one lists its severity, its points, and exactly what was found, with a running total at the bottom.

---

## Tech stack

- **Python 3** with the standard-library `email` package for parsing (headers, multipart bodies, attachments, encodings)
- **Flask** for the web server
- **HTML, CSS, and JavaScript** for the front end
- **Gunicorn** and **Render** for deployment

---

## Project structure

```
phishing-email-analyzer/
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
| `shopnow_suspicious.eml` | Pushy "reward" email with weak warning signs | High Suspicion |
| `github_legit.eml` | Real-style security notification | Benign |
| `spotify_legit.eml` | Real-style marketing email | Benign |

To test a real email from Gmail: open it → **⋮** → **Download message**, then upload the `.eml` file.

---

## Security considerations

Because this tool handles hostile input by design, the app was built to treat every email as untrusted:

- **No XSS from email content.** Everything taken from an email is inserted into the page as plain text, never as HTML, so a malicious email can't run scripts in the browser.
- **Links are never clickable.** Extracted URLs are displayed as text only.
- **Forged authentication headers are ignored.** Each mail server adds its `Authentication-Results` header above the existing ones, so only the top header comes from the user's own mail provider. An attacker can write a fake `spf=pass dkim=pass dmarc=pass` header into the email, so anything below the top one is never trusted.
- **Nothing is stored.** Emails are analyzed in memory and discarded. Nothing is saved to disk or a database.
- **Upload size limit.** Requests over 10 MB are rejected.
- **No error leakage.** Unexpected errors return a generic message to the browser instead of internal details.

---

## Limitations

This is a rule-based educational tool, not a replacement for an enterprise email security gateway.

- It relies on the `Authentication-Results` header added by the receiving server. If you paste only part of an email, SPF/DKIM/DMARC can't be checked.
- It doesn't check links or attachments against threat intelligence feeds, and it never visits links or opens attachments.
- Domains are compared using a built-in list of common two-part endings (`.co.uk`, `.com.au`, ...). Less common endings aren't covered without the full Public Suffix List.
- Keyword-based content checks can be evaded by attackers who avoid common phrases. Because the scoring is deliberately strict, some legitimate emails (e.g. marketing mail without a DKIM signature) will show Low or High Suspicion.

## Future improvements

- Check URLs and file hashes against threat intelligence (e.g. VirusTotal, URLhaus)
- Look up domain registration age, since newly registered domains are a strong phishing signal
- Use the full Public Suffix List for accurate domain comparison
- Add automated tests for every rule using the sample emails
- Export results as a report for incident documentation

---

## Author

**Rizk Hyatt**
[r1zk.com](https://r1zk.com) · [GitHub](https://github.com/0xRizk) · [LinkedIn](https://www.linkedin.com/in/rizk-hyatt-a740a4317/)