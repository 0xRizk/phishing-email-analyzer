"""
analyzer.py - the "brain" of the Phishing Email Analyzer.

This file knows nothing about websites. It takes the raw bytes of an email,
runs a series of checks on it, and returns a dictionary describing what it
found. app.py (the web part) just passes the email in and shows the result.

How the scoring works
---------------------
Every check that finds a red flag adds a "finding" to a list. Each finding
carries some points. All the points are added up into a risk score (capped
at 100), and the score decides the verdict:

     0       -> Benign          No significant red flags detected.
     1 - 19  -> Low Suspicion   Minor phishing indicators detected.
    20 - 49  -> High Suspicion  Significant indicators of potential phishing.
    50 - 100 -> Malicious       Strong evidence of phishing or malicious intent.

The bar is set low on purpose: for a phishing tool, flagging a safe email
costs a few seconds of double-checking, but calling a phishing email
"benign" can cost someone their account.

The checks are grouped into five areas:
    1. Sender        - who the email claims to be vs. who actually sent it
    2. Authentication - did the email pass SPF, DKIM and DMARC?
    3. Content       - urgent / threatening language, requests for passwords,
                       gift card / wire transfer scams
    4. Links         - where every link really goes
    5. Attachments   - dangerous file types
"""

# ---------------------------------------------------------------------------
# Imports - everything here comes with Python, nothing extra to install.
# ---------------------------------------------------------------------------
import ipaddress                      # lets us tell if a string is an IP address
import re                             # regular expressions, for finding patterns in text
from email import policy              # "policy.default" = the modern way to decode emails
from email.parser import BytesParser  # turns raw email bytes into an email object
from email.utils import parseaddr     # splits '"Name" <a@b.com>' into ("Name", "a@b.com")
from html.parser import HTMLParser    # reads HTML so we can find <a href="..."> links
from urllib.parse import urlparse     # splits a URL into scheme, domain, path, etc.


# ---------------------------------------------------------------------------
# Reference data used by the checks.
# Keeping these lists at the top makes them easy to find and extend later.
# ---------------------------------------------------------------------------

# Brands that phishers love to impersonate, mapped to their real domains.
# Some brands have more than one legitimate domain, so each one is a set.
BRANDS = {
    "paypal": {"paypal.com"},
    "microsoft": {"microsoft.com", "outlook.com", "live.com", "office.com"},
    "office365": {"microsoft.com", "office.com"},
    "outlook": {"microsoft.com", "outlook.com"},
    "apple": {"apple.com", "icloud.com"},
    "icloud": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.ca"},
    "google": {"google.com", "gmail.com"},
    "netflix": {"netflix.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "dropbox": {"dropbox.com"},
    "linkedin": {"linkedin.com"},
    "facebook": {"facebook.com", "facebookmail.com"},
    "instagram": {"instagram.com"},
    "github": {"github.com"},
    "rbc": {"rbc.com", "rbcroyalbank.com"},
    "td bank": {"td.com"},
    "scotiabank": {"scotiabank.com"},
    "cibc": {"cibc.com"},
    "canada post": {"canadapost.ca", "postescanada.ca"},
    "fedex": {"fedex.com"},
    "dhl": {"dhl.com"},
    "ups": {"ups.com"},
}

# Characters attackers swap in to make a fake domain look real.
# e.g. "paypa1.com" (number one) or "rnicrosoft.com" ("r" + "n" looks like "m").
# We "undo" these swaps before comparing a domain to the brand names.
LOOKALIKE_SWAPS = [
    ("rn", "m"),
    ("vv", "w"),
    ("0", "o"),
    ("1", "l"),
    ("3", "e"),
    ("4", "a"),
    ("5", "s"),
    ("7", "t"),
]

# Free email providers. A "bank" emailing you from gmail.com is a big red flag.
FREE_EMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "live.com",
    "aol.com", "icloud.com", "protonmail.com", "proton.me", "gmx.com",
    "mail.com", "yandex.com", "zoho.com",
}

# Top-level domains that are cheap to register and heavily abused for phishing.
SUSPICIOUS_TLDS = {
    "xyz", "top", "zip", "mov", "click", "link", "work", "support", "rest",
    "country", "gq", "tk", "ml", "cf", "ga", "buzz", "monster", "cam",
    "icu", "cyou", "sbs", "cfd", "lol", "quest", "bond", "online", "site",
    "live", "shop", "info", "pw", "su", "ru",
}

# Domain endings made of two parts. Without this list, base_domain() would
# turn 'bbc.co.uk' into 'co.uk' and think every UK site is the same company.
# (A full solution is the Public Suffix List; this covers the common ones.)
MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.nz", "co.jp", "co.in", "co.za", "com.br", "com.mx", "com.cn",
    "com.tr", "com.sg", "co.kr", "gc.ca", "qc.ca", "on.ca",
}

# URL shorteners hide the real destination of a link.
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy", "tiny.cc", "t.ly",
    "s.id", "v.gd", "qrco.de", "lnkd.in", "shorturl.gg",
}

# Free website builders, file hosts and form services. Anyone can put a fake
# login page on these in minutes, and they get past filters because the
# main domain has a good reputation. A real bank doesn't host its login here.
FREE_HOSTING_DOMAINS = {
    "firebaseapp.com", "web.app", "pages.dev", "workers.dev", "r2.dev",
    "netlify.app", "vercel.app", "herokuapp.com", "glitch.me", "repl.co",
    "000webhostapp.com", "weebly.com", "wixsite.com", "blogspot.com",
    "square.site", "godaddysites.com", "webflow.io", "framer.app",
    "ngrok.io", "ngrok-free.app", "trycloudflare.com", "ipfs.io",
    "forms.gle", "jotform.com", "typeform.com", "formstack.com",
    "sites.google.com", "storage.googleapis.com", "blob.core.windows.net",
    "s3.amazonaws.com", "dropboxusercontent.com", "translate.goog",
}

# Phrases that create pressure or fear so the victim acts without thinking.
URGENCY_PHRASES = [
    "urgent", "urgently", "immediately", "immediate action", "action required",
    "action needed", "response required", "within 24 hours", "within 48 hours",
    "within 12 hours", "within 72 hours", "account has been limited",
    "account will be suspended", "account will be locked", "account has been locked",
    "account locked", "permanently suspended", "account suspended",
    "temporarily suspended", "has been suspended", "will be deactivated",
    "will be deleted", "will be terminated", "unusual activity",
    "suspicious activity", "unusual sign-in", "suspicious login", "final notice",
    "final reminder", "last warning", "last chance", "act now", "expires today",
    "expire today", "verify immediately", "failure to", "will be closed",
    "unauthorized login", "unauthorized access", "security alert",
    "password expires", "password will expire", "password has expired",
    "mailbox is full", "storage is full", "storage limit", "payment failed",
    "payment declined", "unpaid invoice", "outstanding balance", "overdue",
    "legal action", "avoid suspension", "avoid interruption",
    "service interruption", "delivery failed", "unable to deliver",
    "package is on hold", "customs fee", "pending delivery",
]

# Phrases that ask the victim to hand over credentials or sensitive data.
CREDENTIAL_PHRASES = [
    "verify your identity", "verify your account", "verify your email",
    "verify your information", "confirm your account", "confirm your identity",
    "confirm your details", "confirm your information", "confirm your password",
    "update your payment", "update your billing", "update your account",
    "update your information", "update your details", "enter your password",
    "enter your credentials", "reset your password", "keep your password",
    "keep the same password", "login to your account", "log in to your account",
    "sign in to your account", "login to verify", "log in to verify",
    "sign in to verify", "validate your account", "reactivate your account",
    "restore your account", "unlock your account", "re-enter your",
    "social insurance number", "social security number", "credit card number",
    "card details", "banking details", "bank details", "online banking",
    "one-time code", "verification code", "security questions",
    "date of birth", "mother's maiden name", "pin number",
]

# Payment requests used in "business email compromise" (BEC) scams, where the
# attacker pretends to be a boss or coworker and asks for money. These emails
# often have no links or attachments at all, so the other checks miss them.
PAYMENT_SCAM_PHRASES = [
    "gift card", "gift cards", "itunes card", "google play card", "steam card",
    "send me the codes", "photos of the codes", "scratch off", "wire transfer",
    "wire the funds", "bank transfer", "change of bank details",
    "new bank account", "bitcoin", "crypto wallet", "send payment",
    "update the bank details", "updated banking information", "direct deposit",
    "payroll change", "change my direct deposit", "usdt", "btc address",
    "wallet address", "western union", "moneygram", "e-transfer", "interac e-transfer",
]

# Phrases that try to stop the victim from double-checking with anyone else.
SECRECY_PHRASES = [
    "keep this confidential", "keep this between us", "don't tell anyone",
    "do not tell anyone", "i'm in a meeting", "stuck in a meeting",
    "in a board meeting", "can't talk right now", "cannot take calls",
    "can't take calls", "are you available", "quick favor", "quick favour",
    "do not discuss", "don't discuss", "strictly confidential",
    "text me your number", "send me your cell", "send me your number",
    "reply with your number",
]

# Phrases where the email itself admits you won't recognize the sender, or
# pushes you to open a link or file. Weak alone, but common in lure emails.
LURE_PHRASES = [
    "click here", "click below", "click the link", "click on the link",
    "open the attachment", "see attached", "view document", "view the document",
    "review document", "shared a document", "shared a file with you",
    "sent you a document", "you have received a document", "voicemail",
    "you have a new message", "pending messages", "claim your", "you have won",
    "congratulations", "you've been selected", "you have been selected",
    "refund", "tax refund", "reward",
]

# Job titles that BEC scammers put in the display name to sound important.
EXECUTIVE_TITLES = ["ceo", "cfo", "president", "director", "owner", "manager", "chairman"]

# File extensions that can run code when opened. Attackers attach these.
DANGEROUS_EXTENSIONS = {
    "exe", "scr", "bat", "cmd", "com", "pif", "js", "jse", "vbs", "vbe",
    "wsf", "wsh", "hta", "ps1", "msi", "msix", "appx", "jar", "lnk", "url",
    "iso", "img", "vhd", "vhdx", "cpl", "chm", "reg", "xll", "iqy", "one",
    "docm", "xlsm", "pptm", "dotm", "xlam",          # Office files with macros
    "html", "htm", "shtml", "xhtml", "mht", "mhtml",  # fake login pages
    "svg",   # SVG images can contain scripts - a fast-growing phishing trick
}

# Extensions that just hold other files - often used to sneak past filters.
ARCHIVE_EXTENSIONS = {"zip", "rar", "7z", "gz", "tar", "tgz", "bz2", "xz", "cab", "ace", "arj"}

# File extensions that look like domains to a regex ("invoice.pdf") but
# aren't websites. Used to avoid false alarms in the link-text check.
FILE_EXTENSIONS = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "csv", "rtf",
    "jpg", "jpeg", "png", "gif", "bmp", "webp", "mp3", "mp4", "wav", "mov",
    "zip", "rar", "7z", "exe", "msi", "html", "htm", "js", "json", "xml",
    "eml", "msg", "ics", "vcf",
}

# Finds anything that looks like a URL inside plain text, including links
# written without "https://" like "www.example.com/login".
URL_PATTERN = re.compile(r"""(?:https?://|www\.)[^\s<>"')\]]+""", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Small helper functions used by several checks.
# ---------------------------------------------------------------------------

def get_address(header_value):
    """
    Pull the display name and email address out of a header.
        '"PayPal Security" <service@paypa1-secure.com>'
        -> ("PayPal Security", "service@paypa1-secure.com")
    """
    name, address = parseaddr(str(header_value or ""))
    return name.strip(), address.strip().lower()


def get_domain(header_value):
    """
    Pull just the domain out of an address header.
        'PayPal <service@paypa1-secure.com>' -> 'paypa1-secure.com'
    Returns "" if there's no address.
    """
    _, address = get_address(header_value)
    return address.split("@")[-1] if "@" in address else ""


def base_domain(domain):
    """
    Reduce a domain to its last two parts, so subdomains of the same company
    count as the same organization:
        'mail.github.com' -> 'github.com'
        'out-21.smtp.github.com' -> 'github.com'

    Two-part endings like '.co.uk' keep three parts instead:
        'news.bbc.co.uk' -> 'bbc.co.uk'   (not 'co.uk')

    Note: MULTI_PART_SUFFIXES only covers common endings. A production tool
    would use the full Public Suffix List (the 'tldextract' package).
    """
    parts = domain.lower().strip(".").split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain.lower()


def find_phrases(phrases, text):
    """
    Return the phrases that appear in the text as whole words.
    Plain "p in text" would find "urgent" inside "insurgent" and
    "reward" inside "rewarding". The lookarounds make sure the phrase isn't
    glued to other letters or numbers on either side.
    """
    return [p for p in phrases
            if re.search(rf"(?<![a-z0-9]){re.escape(p)}(?![a-z0-9])", text)]


def is_official_domain(domain, official_domains):
    """
    True if 'domain' is one of the official domains OR a real subdomain of one.
        'paypal.com'         -> True
        'mail.paypal.com'    -> True   (ends with ".paypal.com")
        'evilpaypal.com'     -> False  (ends with "paypal.com" but not ".paypal.com")
        'paypa1-secure.com'  -> False
    The dot before the domain is what stops tricks like 'evilpaypal.com'.
    """
    domain = domain.lower()
    return any(domain == d or domain.endswith("." + d) for d in official_domains)


def undo_lookalikes(text):
    """
    Reverse common character swaps so a fake domain reveals what it's imitating.
        'paypa1-secure' -> 'paypal-secure'
        'rnicrosoft'    -> 'microsoft'
    """
    text = text.lower()
    for fake, real in LOOKALIKE_SWAPS:
        text = text.replace(fake, real)
    return text


def find_impersonated_brand(domain):
    """
    Check whether a domain is pretending to be a known brand.
    Returns (brand, how) or (None, None):
        how = "lookalike"   - brand only appears after undoing swaps (paypa1)
        how = "brand-in-domain" - brand appears as-is in an unrelated domain
                              (e.g. 'paypal.secure-login.xyz')
    Official domains of the brand are never flagged.
    """
    if not domain:
        return None, None
    domain = domain.lower()

    # If the domain officially belongs to ANY brand on our list, it's genuine.
    if any(is_official_domain(domain, official) for official in BRANDS.values()):
        return None, None

    # Two views of the domain:
    #   squashed - dots/dashes removed, so 'pay-pal.com' still contains 'paypal'
    #   tokens   - the separate words, so we can match short brand names exactly
    squashed = re.sub(r"[.\-_]", "", domain)
    tokens = re.split(r"[.\-_]", domain)

    for brand in BRANDS:
        key = brand.replace(" ", "")

        # Short names like "ups" or "td" appear inside normal words
        # ("startups", "groups"), so for them we only accept an exact word match.
        if len(key) < 5:
            if key in tokens:
                return brand, "brand-in-domain"
            if key in (undo_lookalikes(t) for t in tokens):
                return brand, "lookalike"
            continue

        # Longer names are distinctive enough to search for anywhere.
        if key in squashed:
            return brand, "brand-in-domain"
        if key in undo_lookalikes(squashed):
            return brand, "lookalike"

    return None, None


def brands_named_in(text):
    """
    Return the brands mentioned as whole words in some text (like a display name).
    Whole words only, so "Groups Team" doesn't count as a mention of "UPS".
    """
    text = text.lower()
    return [b for b in BRANDS if re.search(rf"\b{re.escape(b)}\b", text)]


def brand_label(brand):
    """
    Nicely formatted brand name for messages on the web page.
    Short names are acronyms (UPS, DHL, RBC); a few have special capitalization.
    """
    special = {"paypal": "PayPal", "github": "GitHub", "linkedin": "LinkedIn",
               "icloud": "iCloud", "docusign": "DocuSign", "td bank": "TD Bank",
               "office365": "Office 365"}
    if brand in special:
        return special[brand]
    return brand.upper() if len(brand) <= 4 else brand.title()


def is_ip_address(host):
    """
    True if the host is a raw IP instead of a domain name. Browsers also
    accept disguised forms of an IP, so those count too:
        185.234.72.19     normal
        3119138835        the same IP written as one big number
        0xb9.0xea.72.19   parts written in hexadecimal
    """
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        pass
    # Disguised forms: 1 to 4 parts, each a decimal or 0x-hex number.
    return bool(re.fullmatch(r"(?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+)){0,3}", host.lower()))


def looks_like_web_address(text):
    """
    Find a website address written in a link's visible text, or return None.
        "https://www.paypal.com/login" -> "paypal.com"
        "Visit paypal.com"             -> "paypal.com"
        "Download invoice.pdf"         -> None   (file name, not a website)
        "Version 2.0"                  -> None   (number, not a website)
    """
    match = re.search(r"(?:https?://)?(?:www\.)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)", text.lower())
    if not match:
        return None
    domain = match.group(1)
    tld = domain.rsplit(".", 1)[-1]
    # A real domain ending is letters only ("com", "ca"), at least 2 long.
    if not tld.isalpha() or len(tld) < 2:
        return None
    # "invoice.pdf" - only treat it as a website if it was clearly written as one.
    written_as_url = re.search(r"https?://|www\.", text.lower())
    if tld in FILE_EXTENSIONS and not written_as_url:
        return None
    return domain


def add_finding(findings, title, detail, points, severity, category):
    """
    Record one red flag. Every check uses this so all findings look the same.
        severity: "high", "medium" or "low" (controls the color on the web page)
        category: which of the five areas the finding belongs to
    """
    findings.append({
        "title": title,
        "detail": detail,
        "points": points,
        "severity": severity,
        "category": category,
    })


# ---------------------------------------------------------------------------
# Reading the email body and links.
# ---------------------------------------------------------------------------

class LinkExtractor(HTMLParser):
    """
    Walks through an HTML email and collects every <a> link along with the
    text the user actually sees. That pair matters: phishers write
    <a href="http://evil.xyz">https://www.paypal.com</a>
    so the text looks safe but the link goes somewhere else.
    """

    # Text inside these tags is never shown to the reader, so it's skipped.
    # Otherwise CSS or JavaScript code would be scanned as if it were words.
    HIDDEN_TAGS = {"style", "script"}

    def __init__(self):
        super().__init__()
        self.links = []          # list of (href, visible_text) pairs
        self.text_parts = []     # all visible text, used for the content checks
        self.has_form = False            # a <form> inside the email itself
        self.has_password_field = False  # an <input type="password">
        self._current_href = None
        self._current_text = []
        self._hidden_depth = 0   # > 0 while we're inside a hidden tag

    def handle_starttag(self, tag, attrs):
        # Called for every opening tag like <a href="...">.
        attrs = dict(attrs)
        if tag in self.HIDDEN_TAGS:
            self._hidden_depth += 1
        elif tag == "a":
            self._current_href = attrs.get("href")
            self._current_text = []
        elif tag == "form":
            self.has_form = True
        elif tag == "input" and (attrs.get("type") or "").lower() == "password":
            self.has_password_field = True

        # A form's destination counts as a link too: <form action="...">
        # posts whatever you type straight to the attacker's server.
        if tag == "form" and attrs.get("action"):
            self.links.append((attrs["action"].strip(), ""))

    def handle_data(self, data):
        # Called for every piece of text in the HTML.
        if self._hidden_depth:
            return
        self.text_parts.append(data)
        if self._current_href is not None:
            self._current_text.append(data)

    def handle_endtag(self, tag):
        if tag in self.HIDDEN_TAGS and self._hidden_depth:
            self._hidden_depth -= 1
        # Called at </a>: save the finished link with the text that was inside it.
        if tag == "a" and self._current_href is not None:
            self.links.append((self._current_href.strip(), "".join(self._current_text).strip()))
            self._current_href = None


def read_body(msg):
    """
    An email is a tree of "parts": plain text, HTML, attachments, nested inside
    each other. This walks every part and sorts out:
        - all the readable text (plain text + text inside the HTML)
        - every link, with its visible text when it came from HTML
        - every attachment's filename
        - whether the HTML contains a form or a password box
    """
    text_chunks = []
    links = []            # list of (url, visible_text) pairs
    attachments = []
    html_flags = {"form": False, "password_field": False}

    # msg.walk() visits the email and every part nested inside it.
    for part in msg.walk():
        # "multipart/..." parts are just containers holding other parts.
        if part.is_multipart():
            continue

        content_type = part.get_content_type()   # e.g. "text/plain", "text/html"
        filename = part.get_filename()

        # Anything with a filename, or marked as an attachment, is an attachment.
        if filename or part.get_content_disposition() == "attachment":
            attachments.append(filename or "(unnamed attachment)")
            continue

        # get_content() decodes base64 / quoted-printable for us.
        try:
            content = part.get_content()
        except Exception:
            # A badly formed part shouldn't crash the whole analysis.
            continue
        if not isinstance(content, str):
            continue

        if content_type == "text/plain":
            text_chunks.append(content)
            # Plain text has no <a> tags, so find URLs with the regex.
            for url in URL_PATTERN.findall(content):
                links.append((url.rstrip(".,;:!?"), ""))

        elif content_type == "text/html":
            parser = LinkExtractor()
            parser.feed(content)
            text_chunks.append(" ".join(parser.text_parts))
            links.extend(parser.links)
            html_flags["form"] |= parser.has_form
            html_flags["password_field"] |= parser.has_password_field

    return "\n".join(text_chunks), links, attachments, html_flags


# ---------------------------------------------------------------------------
# Check group 1: Sender
# ---------------------------------------------------------------------------

def check_sender(msg, findings):
    """Compare who the email claims to be from with where it really came from."""
    display_name, from_address = get_address(msg["From"])
    from_domain = get_domain(msg["From"])
    reply_domain = get_domain(msg["Reply-To"])
    return_domain = get_domain(msg["Return-Path"])

    # 1a. Display name claims a brand, but the address isn't from that brand.
    #     The display name is just text the sender typed - it proves nothing.
    named_brands = brands_named_in(display_name)
    fake_brands = [b for b in named_brands
                   if from_domain and not is_official_domain(from_domain, BRANDS[b])]
    if fake_brands:
        brand = fake_brands[0]   # one brand match is enough to report
        add_finding(
            findings,
            "Brand impersonation in sender name",
            f'The sender calls itself "{display_name}" but the address is '
            f"{from_address}, not an official {brand_label(brand)} domain.",
            30, "high", "sender",
        )

    # 1b. The sender's domain is a lookalike of a brand (paypa1.com, paypal-secure.com).
    brand, how = find_impersonated_brand(from_domain)
    if brand:
        if how == "lookalike":
            detail = (f"{from_domain} looks like {brand_label(brand)} but uses swapped "
                      f"characters (like 1 for l or 0 for o).")
        else:
            detail = f"{from_domain} uses the name {brand_label(brand)} but isn't an official {brand_label(brand)} domain."
        add_finding(findings, "Lookalike sender domain", detail, 25, "high", "sender")

    # 1c. A brand name in the display name, sent from a free webmail account.
    #     (fake_brands already excludes the brand's own domains, e.g. Google + gmail.com)
    if from_domain in FREE_EMAIL_PROVIDERS and fake_brands:
        add_finding(
            findings,
            "Company name sent from a free email account",
            f'"{display_name}" sent this from {from_domain}. Real companies use their own domain.',
            15, "medium", "sender",
        )

    # 1d. An executive title in the name, sent from a free webmail account.
    #     A real CEO emails from the company domain, not a personal Gmail.
    #     \b means "word boundary", so "director" matches but "directory" doesn't.
    titles = [t for t in EXECUTIVE_TITLES if re.search(rf"\b{t}\b", display_name.lower())]
    if from_domain in FREE_EMAIL_PROVIDERS and titles:
        add_finding(
            findings,
            "Executive title sent from a free email account",
            f'"{display_name}" claims to be a {titles[0].upper() if len(titles[0]) <= 3 else titles[0]} '
            f"but is writing from {from_domain}. This is a classic CEO-fraud setup.",
            15, "medium", "sender",
        )

    # 1e. An email address typed INTO the display name that differs from the
    #     real one: "security@paypal.com" <x@evil.top>. Many mail apps only
    #     show the display name, so the victim sees the fake address.
    shown_address = re.search(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)", display_name.lower())
    if shown_address and from_domain and base_domain(shown_address.group(1)) != base_domain(from_domain):
        add_finding(
            findings,
            "Fake address in sender name",
            f'The sender name shows "{shown_address.group(0)}", but the real address is {from_address}.',
            25, "high", "sender",
        )

    # 1f. The sender's own domain uses a cheap, frequently abused ending.
    if from_domain and from_domain.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
        add_finding(
            findings,
            "Sender uses a high-risk domain ending",
            f"{from_domain} ends in .{from_domain.rsplit('.', 1)[-1]}, which is commonly used for phishing.",
            10, "medium", "sender",
        )

    # 1g. The subject names a brand, but the sender isn't that brand.
    #     ("Your PayPal account is limited" from billing@secure-notice.com)
    #     Skipped for brands already reported in 1a, so it isn't counted twice.
    subject = str(msg["Subject"] or "")
    subject_brands = [b for b in brands_named_in(subject)
                      if b not in fake_brands and from_domain
                      and not is_official_domain(from_domain, BRANDS[b])]
    if subject_brands:
        add_finding(
            findings,
            "Subject mentions a brand the sender doesn't belong to",
            f'The subject mentions {brand_label(subject_brands[0])}, but the email comes from '
            f"{from_domain}, not an official {brand_label(subject_brands[0])} domain.",
            15, "medium", "sender",
        )

    # 1h. Replies go somewhere other than the sender.
    #     Compare base domains so 'mail.github.com' vs 'github.com' isn't flagged.
    if reply_domain and from_domain and base_domain(reply_domain) != base_domain(from_domain):
        add_finding(
            findings,
            "Reply-To doesn't match sender",
            f"Sent from {from_domain}, but replies would go to {reply_domain}.",
            15, "medium", "sender",
        )

    # 1i. The bounce address (Return-Path) is a different organization.
    #     This happens legitimately with mailing services, so it's worth fewer points.
    if return_domain and from_domain and base_domain(return_domain) != base_domain(from_domain):
        add_finding(
            findings,
            "Return-Path doesn't match sender",
            f"The From address is {from_domain}, but the server-level sender was {return_domain}.",
            10, "low", "sender",
        )


# ---------------------------------------------------------------------------
# Check group 2: Authentication (SPF, DKIM, DMARC)
# ---------------------------------------------------------------------------

def read_auth_results(msg):
    """
    The receiving mail server (e.g. Gmail) checks three things and writes the
    results into the "Authentication-Results" header:

        SPF   - was the sending server allowed to send for this domain?
        DKIM  - was the email digitally signed by the domain, and unchanged?
        DMARC - do SPF/DKIM line up with the domain in the visible From address?

    This pulls out "pass", "fail", "softfail", "none", etc. for each one.
    Returns a dict like {"spf": "fail", "dkim": "none", "dmarc": "fail"}.

    Only the TOP header is trusted. Each mail server adds its header above
    the existing ones, so the top one is from your own provider. Anything
    lower could have been written by the attacker - a phisher can simply add
    "Authentication-Results: spf=pass dkim=pass dmarc=pass" to the email.
    """
    # get_all() returns every copy of the header, top one first.
    headers = msg.get_all("Authentication-Results") or []
    top = str(headers[0]).lower() if headers else ""

    results = {}
    for mechanism in ("spf", "dmarc"):
        # Find text like "spf=fail" and capture the word after the "=".
        match = re.search(rf"\b{mechanism}=(\w+)", top)
        results[mechanism] = match.group(1) if match else "not found"

    # An email can carry several DKIM signatures (e.g. one from the company
    # and one from its mailing service). It only needs ONE valid signature,
    # so if any of them passed, DKIM passed.
    dkim_results = re.findall(r"\bdkim=(\w+)", top)
    if "pass" in dkim_results:
        results["dkim"] = "pass"
    else:
        results["dkim"] = dkim_results[0] if dkim_results else "not found"

    # Some servers record SPF in a separate "Received-SPF" header instead.
    if results["spf"] == "not found" and msg["Received-SPF"]:
        results["spf"] = str(msg["Received-SPF"]).split()[0].lower()

    return results


def check_authentication(msg, findings, auth):
    """Turn the SPF / DKIM / DMARC results into findings."""
    if not msg.get_all("Authentication-Results") and auth["spf"] == "not found":
        # Common when someone pastes only part of an email.
        add_finding(
            findings,
            "No authentication results",
            "The email has no Authentication-Results header, so SPF/DKIM/DMARC "
            "couldn't be checked. Paste the full original source to include it.",
            5, "low", "authentication",
        )
        return

    if auth["spf"] in ("fail", "softfail"):
        add_finding(
            findings,
            f"SPF {auth['spf']}",
            "The server that sent this email isn't authorized to send for the sender's domain.",
            20 if auth["spf"] == "fail" else 10,
            "high" if auth["spf"] == "fail" else "medium",
            "authentication",
        )

    if auth["dkim"] in ("fail", "none", "neutral", "permerror", "temperror", "policy"):
        add_finding(
            findings,
            f"DKIM {auth['dkim']}",
            "The email has no valid digital signature from the sending domain, "
            "so it could have been forged or altered.",
            15 if auth["dkim"] == "fail" else 5,
            "medium" if auth["dkim"] == "fail" else "low",
            "authentication",
        )

    if auth["dmarc"] == "fail":
        add_finding(
            findings,
            "DMARC fail",
            "The visible From domain didn't pass its own owner's anti-spoofing policy. "
            "This is a strong sign the sender is being faked.",
            25, "high", "authentication",
        )

    # The domain has no DMARC policy at all. Not proof of anything, but it
    # means nothing stops someone from faking that domain, and big brands
    # always have one.
    elif auth["dmarc"] == "none":
        add_finding(
            findings,
            "No DMARC protection",
            "The sender's domain has no DMARC policy, so anyone could send mail pretending to be it.",
            5, "low", "authentication",
        )


# ---------------------------------------------------------------------------
# Check group 3: Content
# ---------------------------------------------------------------------------

def check_content(subject, body, html_flags, findings):
    """
    Look for pressure tactics and requests for sensitive information.
    Returns True if the email asks for credentials, so the link checks can
    look harder at where those links go.
    """
    # Lowercase everything and collapse whitespace so phrases match reliably.
    # Curly apostrophes (’) are turned into straight ones (') so "don’t tell"
    # still matches "don't tell".
    text = re.sub(r"\s+", " ", f"{subject} {body}".lower()).replace("’", "'")

    urgency_hits = find_phrases(URGENCY_PHRASES, text)
    if urgency_hits:
        # More pressure phrases = more points, up to a cap of 20.
        points = min(5 + 5 * len(urgency_hits), 20)
        add_finding(
            findings,
            "Urgent or threatening language",
            "Pressure phrases found: " + ", ".join(f'"{p}"' for p in urgency_hits[:5]),
            points, "medium", "content",
        )

    credential_hits = find_phrases(CREDENTIAL_PHRASES, text)
    if credential_hits:
        add_finding(
            findings,
            "Asks for credentials or personal info",
            "Requests found: " + ", ".join(f'"{p}"' for p in credential_hits[:5]),
            15, "medium", "content",
        )

    # Requests for gift cards, wire transfers or crypto - the goal of most
    # CEO-fraud / business email compromise scams.
    payment_hits = find_phrases(PAYMENT_SCAM_PHRASES, text)
    if payment_hits:
        add_finding(
            findings,
            "Unusual payment request",
            "Asks for: " + ", ".join(f'"{p}"' for p in payment_hits[:5])
            + ". Gift cards and wire transfers can't be reversed, which is why scammers want them.",
            30, "high", "content",
        )

    # Attempts to keep the victim from checking with anyone else.
    secrecy_hits = find_phrases(SECRECY_PHRASES, text)
    if secrecy_hits:
        add_finding(
            findings,
            "Secrecy or isolation tactics",
            "Phrases found: " + ", ".join(f'"{p}"' for p in secrecy_hits[:5])
            + ". Scammers stop you from verifying the request with someone else.",
            10, "medium", "content",
        )

    # Generic greetings: real companies usually know your name.
    # Also catches "Dear user@example.com" - the scammer only had your address.
    if re.search(r"\b(dear|hello|hi) (customer|user|client|member|account holder|"
                 r"valued customer|sir|sir/madam|sir or madam|madam|beneficiary|"
                 r"recipient|employee|staff|colleague|[\w.+-]+@[\w.-]+)\b", text):
        add_finding(
            findings,
            "Generic greeting",
            'Uses a greeting like "Dear Customer" instead of your name.',
            5, "low", "content",
        )

    # Lure phrases ("click here", "view document", "refund") show up in real
    # emails too, so one alone proves nothing. Two or more is a pattern.
    lure_hits = find_phrases(LURE_PHRASES, text)
    if len(lure_hits) >= 2:
        add_finding(
            findings,
            "Bait to click or open something",
            "Phrases found: " + ", ".join(f'"{p}"' for p in lure_hits[:5]),
            10, "medium", "content",
        )

    # A form INSIDE the email. Legitimate companies send you to their
    # website to log in; they never ask you to type into the email itself.
    if html_flags["password_field"]:
        add_finding(
            findings,
            "Password box inside the email",
            "The email contains a form asking for a password. Whatever you type is sent straight to the sender.",
            35, "high", "content",
        )
    elif html_flags["form"]:
        add_finding(
            findings,
            "Form inside the email",
            "The email contains a fill-in form. Real companies don't collect information this way.",
            15, "medium", "content",
        )

    return bool(credential_hits)


# ---------------------------------------------------------------------------
# Check group 4: Links
# ---------------------------------------------------------------------------

def check_links(links, sender_domain, asks_for_credentials, findings):
    """
    Inspect every link. Each kind of problem is reported once, even if several
    links have it, so one email can't rack up points by repeating a link.
    Returns the list of unique URLs to show on the web page.

    sender_domain and asks_for_credentials let us spot a "log in here"
    email whose links lead to a different organization than the sender.
    """
    unique_urls = []
    flagged = set()   # which kinds of problems we've already reported
    offsite_hosts = []   # link hosts that belong to a different organization than the sender

    def flag(kind, title, detail, points, severity):
        if kind not in flagged:
            flagged.add(kind)
            add_finding(findings, title, detail, points, severity, "links")

    for url, visible_text in links:
        # Skip email links and in-page anchors - they don't go to a website.
        if not url or url.lower().startswith(("mailto:", "tel:", "#")):
            continue

        if url not in unique_urls:
            unique_urls.append(url)

        # 4a. "javascript:" and "data:" links run code or show a whole fake
        #     page straight from the link itself, with no website involved.
        if url.lower().startswith(("javascript:", "data:", "vbscript:")):
            flag("script-link", "Link runs code instead of opening a website",
                 f"A link starts with \"{url.split(':', 1)[0]}:\", which runs code or loads a hidden page when clicked.",
                 30, "high")
            continue

        # Links written without "https://" (www.example.com) have no scheme,
        # so add one before parsing, otherwise urlparse can't find the domain.
        parsed = urlparse(url if "://" in url or url.startswith("//") else "http://" + url)
        if url.lower().startswith("www."):
            parsed = parsed._replace(scheme="")   # we don't know it's http, so don't flag it
        host = (parsed.hostname or "").lower().rstrip(".")
        if not host:
            continue

        if sender_domain and base_domain(host) != base_domain(sender_domain):
            offsite_hosts.append(host)

        # 4b. Raw IP address instead of a domain name (including disguised forms).
        if is_ip_address(host):
            flag("ip", "Link points to a raw IP address",
                 f"{url} uses an IP address instead of a website name, which legitimate companies rarely do.",
                 20, "high")

        # 4c. The visible text shows one website, but the link goes to another.
        #     e.g. text says "https://www.paypal.com" but href is evil.xyz.
        #     looks_like_web_address() ignores file names like "invoice.pdf".
        shown_domain = looks_like_web_address(visible_text)
        if shown_domain and base_domain(shown_domain) != base_domain(host):
            flag("mismatch", "Link text doesn't match destination",
                 f'The link shows "{visible_text}" but actually goes to {host}.',
                 25, "high")

        # 4d. A free hosting or form service - a cheap home for fake login pages.
        if any(host == d or host.endswith("." + d) for d in FREE_HOSTING_DOMAINS):
            flag("free-hosting", "Link to a free hosting or form service",
                 f"{host} is a free website/form service. Attackers use these to host fake login pages.",
                 15, "medium")

        # 4e. A lookalike or brand-in-domain link (paypa1-secure.com.verify-login.xyz).
        brand, how = find_impersonated_brand(host)
        if brand:
            flag("lookalike", "Link to a lookalike domain",
                 f"{host} imitates {brand_label(brand)} but isn't one of its official domains.",
                 20, "high")

        # 4f. Cheap, frequently abused top-level domain.
        tld = host.rsplit(".", 1)[-1]
        if tld in SUSPICIOUS_TLDS:
            flag("tld", "Link uses a high-risk domain ending",
                 f"{host} ends in .{tld}, which is commonly used for phishing.",
                 10, "medium")

        # 4g. A URL shortener hides the real destination.
        if base_domain(host) in URL_SHORTENERS or host in URL_SHORTENERS:
            flag("shortener", "Shortened link",
                 f"{url} uses a link shortener, which hides where it really leads.",
                 10, "medium")

        # 4h. An "@" in the address part of a URL: everything before it is ignored.
        #     http://paypal.com@evil.xyz actually goes to evil.xyz.
        if "@" in parsed.netloc:
            flag("at-sign", "Link uses an @ trick",
                 f"In {url}, everything before the @ is ignored. The real destination is {host}.",
                 20, "high")

        # 4i. Punycode (xn--) can disguise lookalike letters from other alphabets.
        if "xn--" in host:
            flag("punycode", "Internationalized (punycode) domain",
                 f"{host} uses punycode, which can disguise lookalike characters.",
                 15, "medium")

        # 4j. Unencrypted link. Weak on its own, so it's only worth a few points.
        if parsed.scheme == "http":
            flag("http", "Unencrypted (http) link",
                 f"{url} doesn't use HTTPS.", 5, "low")

    # 4k. The email asks you to log in or confirm details, but its links lead
    #     to a different organization than the one that sent it. A real
    #     "verify your account" email links back to the sender's own site.
    if asks_for_credentials and offsite_hosts:
        flag("offsite-login", "Login request links to a different organization",
             f"The email asks for your details and is sent from {sender_domain}, "
             f"but its links go to {offsite_hosts[0]}.",
             15, "medium")

    return unique_urls


# ---------------------------------------------------------------------------
# Check group 5: Attachments
# ---------------------------------------------------------------------------

def check_attachments(attachments, findings):
    """Flag attachments that can run code or hide what they really are."""
    for name in attachments:
        # 5a. The "right-to-left override" character flips the text after it,
        #     so "invoice‮fdp.exe" displays as "invoiceexe.pdf".
        #     There's no honest reason for it to be in a file name.
        if any(c in name for c in "‮‭‏‎"):
            add_finding(findings, "Attachment name uses hidden text-direction characters",
                        f'"{name}" contains invisible characters that make the file type display backwards.',
                        35, "high", "attachments")
            continue

        # Spaces and dots at the end are ignored by Windows ("bill.exe  ."),
        # so strip them before reading the extension.
        lower = name.lower().rstrip(" .")
        parts = lower.split(".")
        ext = parts[-1] if len(parts) > 1 else ""

        # 5b. Double extension: "invoice.pdf.exe" pretends to be a PDF.
        #     Only counts when the fake part is a real file type, so
        #     "report.2026.html" is treated as a plain .html file.
        if len(parts) >= 3 and ext in DANGEROUS_EXTENSIONS and parts[-2] in FILE_EXTENSIONS:
            add_finding(findings, "Disguised attachment (double extension)",
                        f'"{name}" pretends to be a .{parts[-2]} file but is really .{ext}.',
                        35, "high", "attachments")

        # 5c. Executable / script / macro file.
        elif ext in DANGEROUS_EXTENSIONS:
            add_finding(findings, "Dangerous attachment type",
                        f'"{name}" is a .{ext} file, which can run code or show a fake login page when opened.',
                        30, "high", "attachments")

        # 5d. Archive: could be hiding an executable inside.
        elif ext in ARCHIVE_EXTENSIONS:
            add_finding(findings, "Compressed attachment",
                        f'"{name}" is an archive, which is often used to sneak malware past email filters.',
                        10, "medium", "attachments")


# ---------------------------------------------------------------------------
# Turning the score into a verdict.
# ---------------------------------------------------------------------------

# (lowest score, verdict id, label shown on the page, description)
# Checked from the top down; the first row the score reaches wins.
CLASSIFICATIONS = [
    (50, "malicious",      "Malicious",      "Strong evidence of phishing or malicious intent."),
    (20, "high-suspicion", "High Suspicion", "Significant indicators of potential phishing."),
    (1,  "low-suspicion",  "Low Suspicion",  "Minor phishing indicators detected."),
    (0,  "benign",         "Benign",         "No significant red flags detected."),
]


def classify(score):
    """
    Map a 0-100 score to (verdict id, label, description).
        0 -> benign, 1-19 -> low-suspicion, 20-49 -> high-suspicion, 50+ -> malicious
    """
    for minimum, verdict, label, description in CLASSIFICATIONS:
        if score >= minimum:
            return verdict, label, description
    return CLASSIFICATIONS[-1][1:]


# ---------------------------------------------------------------------------
# The main function: this is what app.py calls.
# ---------------------------------------------------------------------------

def analyze(raw_bytes):
    """
    Run every check on one email and return the results as a dictionary.
    app.py turns this dictionary into JSON for the web page.
    """
    # Step 1: Parse the raw bytes into an email object we can ask questions of.
    msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)

    # If none of the basic headers exist, this probably isn't an email at all.
    if not any(msg[h] for h in ("From", "To", "Subject", "Received", "Date")):
        raise ValueError("This doesn't look like an email. Paste the full raw source, including headers.")

    # Step 2: Pull out everything the checks need.
    subject = str(msg["Subject"] or "")
    body, links, attachments, html_flags = read_body(msg)
    auth = read_auth_results(msg)

    # Step 3: Run each group of checks. They all add to the same findings list.
    findings = []
    check_sender(msg, findings)
    check_authentication(msg, findings, auth)
    asks_for_credentials = check_content(subject, body, html_flags, findings)
    unique_links = check_links(links, get_domain(msg["From"]), asks_for_credentials, findings)
    check_attachments(attachments, findings)

    # Step 4: Add up the points, cap at 100, and pick a verdict.
    score = min(sum(f["points"] for f in findings), 100)
    verdict, classification, description = classify(score)

    # Show the most serious findings first.
    severity_order = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: (severity_order[f["severity"]], -f["points"]))

    # Step 5: Package everything up for the web page.
    headers = {
        "From": msg["From"],
        "To": msg["To"],
        "Subject": msg["Subject"],
        "Date": msg["Date"],
        "Reply-To": msg["Reply-To"],
        "Return-Path": msg["Return-Path"],
        "SPF": auth["spf"],
        "DKIM": auth["dkim"],
        "DMARC": auth["dmarc"],
        "Attachments": ", ".join(attachments) if attachments else None,
    }

    return {
        "verdict": verdict,                # short id, used for colors on the page
        "classification": classification, # the label shown to the user
        "description": description,       # one sentence explaining the label
        "score": score,
        # str() turns header objects into plain text; None stays None (shown as "—").
        "headers": {name: str(value) if value else None for name, value in headers.items()},
        "findings": findings,
        "links": unique_links,
    }