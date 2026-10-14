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

     0 - 24  -> benign
    25 - 59  -> suspicious
    60 - 100 -> malicious

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
}

# URL shorteners hide the real destination of a link.
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy", "tiny.cc",
}

# Phrases that create pressure or fear so the victim acts without thinking.
URGENCY_PHRASES = [
    "urgent", "immediately", "action required", "within 24 hours",
    "within 48 hours", "account has been limited", "account will be suspended",
    "permanently suspended", "account suspended", "unusual activity",
    "suspicious activity", "final notice", "last warning", "act now",
    "expires today", "verify immediately", "failure to", "will be closed",
    "unauthorized login", "security alert",
]

# Phrases that ask the victim to hand over credentials or sensitive data.
CREDENTIAL_PHRASES = [
    "verify your identity", "verify your account", "confirm your account",
    "confirm your identity", "update your payment", "update your billing",
    "enter your password", "reset your password", "login to your account",
    "log in to your account", "sign in to your account", "validate your account",
    "social insurance number", "social security number", "credit card number",
    "banking details", "one-time code", "security questions",
]

# Payment requests used in "business email compromise" (BEC) scams, where the
# attacker pretends to be a boss or coworker and asks for money. These emails
# often have no links or attachments at all, so the other checks miss them.
PAYMENT_SCAM_PHRASES = [
    "gift card", "gift cards", "itunes card", "google play card", "steam card",
    "send me the codes", "photos of the codes", "scratch off", "wire transfer",
    "wire the funds", "bank transfer", "change of bank details",
    "new bank account", "bitcoin", "crypto wallet", "send payment",
]

# Phrases that try to stop the victim from double-checking with anyone else.
SECRECY_PHRASES = [
    "keep this confidential", "keep this between us", "don't tell anyone",
    "do not tell anyone", "i'm in a meeting", "stuck in a meeting",
    "in a board meeting", "can't talk right now", "cannot take calls",
    "are you available", "quick favor",
]

# Job titles that BEC scammers put in the display name to sound important.
EXECUTIVE_TITLES = ["ceo", "cfo", "president", "director", "owner", "manager", "chairman"]

# File extensions that can run code when opened. Attackers attach these.
DANGEROUS_EXTENSIONS = {
    "exe", "scr", "bat", "cmd", "com", "pif", "js", "jse", "vbs", "vbe",
    "wsf", "hta", "ps1", "msi", "jar", "lnk", "iso", "img", "vhd",
    "docm", "xlsm", "pptm",      # Office files with macros enabled
    "html", "htm",               # fake login pages sent as attachments
}

# Extensions that just hold other files - often used to sneak past filters.
ARCHIVE_EXTENSIONS = {"zip", "rar", "7z", "gz", "tar"}

# Finds anything that looks like a URL inside plain text.
URL_PATTERN = re.compile(r"""https?://[^\s<>"')\]]+""", re.IGNORECASE)


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

    Note: this is a simplification. Domains like 'bbc.co.uk' would come out as
    'co.uk'. A production tool would use the Public Suffix List (the
    'tldextract' package) to get this exactly right.
    """
    parts = domain.lower().strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain.lower()


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
    """True if the host is a raw IP like 185.234.72.19 instead of a domain name."""
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


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

    def __init__(self):
        super().__init__()
        self.links = []          # list of (href, visible_text) pairs
        self.text_parts = []     # all visible text, used for the content checks
        self._current_href = None
        self._current_text = []

    def handle_starttag(self, tag, attrs):
        # Called for every opening tag like <a href="...">.
        if tag == "a":
            self._current_href = dict(attrs).get("href")
            self._current_text = []

    def handle_data(self, data):
        # Called for every piece of visible text in the HTML.
        self.text_parts.append(data)
        if self._current_href is not None:
            self._current_text.append(data)

    def handle_endtag(self, tag):
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
    """
    text_chunks = []
    links = []            # list of (url, visible_text) pairs
    attachments = []

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

    return "\n".join(text_chunks), links, attachments


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

    # 1e. Replies go somewhere other than the sender.
    #     Compare base domains so 'mail.github.com' vs 'github.com' isn't flagged.
    if reply_domain and from_domain and base_domain(reply_domain) != base_domain(from_domain):
        add_finding(
            findings,
            "Reply-To doesn't match sender",
            f"Sent from {from_domain}, but replies would go to {reply_domain}.",
            15, "medium", "sender",
        )

    # 1f. The bounce address (Return-Path) is a different organization.
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
    """
    # get_all() returns every copy of the header (there can be several).
    headers = msg.get_all("Authentication-Results") or []
    combined = " ".join(str(h) for h in headers).lower()

    results = {}
    for mechanism in ("spf", "dkim", "dmarc"):
        # Find text like "spf=fail" and capture the word after the "=".
        match = re.search(rf"\b{mechanism}=(\w+)", combined)
        results[mechanism] = match.group(1) if match else "not found"
    return results


def check_authentication(msg, findings, auth):
    """Turn the SPF / DKIM / DMARC results into findings."""
    if not msg.get_all("Authentication-Results"):
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

    if auth["dkim"] in ("fail", "none", "neutral", "permerror"):
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


# ---------------------------------------------------------------------------
# Check group 3: Content
# ---------------------------------------------------------------------------

def check_content(subject, body, findings):
    """Look for pressure tactics and requests for sensitive information."""
    # Lowercase everything and collapse whitespace so phrases match reliably.
    text = re.sub(r"\s+", " ", f"{subject} {body}".lower())

    urgency_hits = [p for p in URGENCY_PHRASES if p in text]
    if urgency_hits:
        # More pressure phrases = more points, up to a cap of 20.
        points = min(5 + 5 * len(urgency_hits), 20)
        add_finding(
            findings,
            "Urgent or threatening language",
            "Pressure phrases found: " + ", ".join(f'"{p}"' for p in urgency_hits[:5]),
            points, "medium", "content",
        )

    credential_hits = [p for p in CREDENTIAL_PHRASES if p in text]
    if credential_hits:
        add_finding(
            findings,
            "Asks for credentials or personal info",
            "Requests found: " + ", ".join(f'"{p}"' for p in credential_hits[:5]),
            15, "medium", "content",
        )

    # Requests for gift cards, wire transfers or crypto - the goal of most
    # CEO-fraud / business email compromise scams.
    payment_hits = [p for p in PAYMENT_SCAM_PHRASES if p in text]
    if payment_hits:
        add_finding(
            findings,
            "Unusual payment request",
            "Asks for: " + ", ".join(f'"{p}"' for p in payment_hits[:5])
            + ". Gift cards and wire transfers can't be reversed, which is why scammers want them.",
            30, "high", "content",
        )

    # Attempts to keep the victim from checking with anyone else.
    secrecy_hits = [p for p in SECRECY_PHRASES if p in text]
    if secrecy_hits:
        add_finding(
            findings,
            "Secrecy or isolation tactics",
            "Phrases found: " + ", ".join(f'"{p}"' for p in secrecy_hits[:5])
            + ". Scammers stop you from verifying the request with someone else.",
            10, "medium", "content",
        )

    # Generic greetings: real companies usually know your name.
    if re.search(r"\bdear (customer|user|client|member|account holder|valued customer)\b", text):
        add_finding(
            findings,
            "Generic greeting",
            'Uses a greeting like "Dear Customer" instead of your name.',
            5, "low", "content",
        )


# ---------------------------------------------------------------------------
# Check group 4: Links
# ---------------------------------------------------------------------------

def check_links(links, findings):
    """
    Inspect every link. Each kind of problem is reported once, even if several
    links have it, so one email can't rack up points by repeating a link.
    Returns the list of unique URLs to show on the web page.
    """
    unique_urls = []
    flagged = set()   # which kinds of problems we've already reported

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

        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if not host:
            continue

        # 4a. Raw IP address instead of a domain name.
        if is_ip_address(host):
            flag("ip", "Link points to a raw IP address",
                 f"{url} uses an IP address instead of a website name, which legitimate companies rarely do.",
                 20, "high")

        # 4b. The visible text shows one website, but the link goes to another.
        #     e.g. text says "https://www.paypal.com" but href is evil.xyz.
        text_match = re.search(r"(?:https?://)?(?:www\.)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)", visible_text.lower())
        if text_match:
            shown_domain = text_match.group(1)
            if base_domain(shown_domain) != base_domain(host):
                flag("mismatch", "Link text doesn't match destination",
                     f'The link shows "{visible_text}" but actually goes to {host}.',
                     25, "high")

        # 4c. A lookalike or brand-in-domain link (paypa1-secure.com.verify-login.xyz).
        brand, how = find_impersonated_brand(host)
        if brand:
            flag("lookalike", "Link to a lookalike domain",
                 f"{host} imitates {brand_label(brand)} but isn't one of its official domains.",
                 20, "high")

        # 4d. Cheap, frequently abused top-level domain.
        tld = host.rsplit(".", 1)[-1]
        if tld in SUSPICIOUS_TLDS:
            flag("tld", "Link uses a high-risk domain ending",
                 f"{host} ends in .{tld}, which is commonly used for phishing.",
                 10, "medium")

        # 4e. A URL shortener hides the real destination.
        if base_domain(host) in URL_SHORTENERS or host in URL_SHORTENERS:
            flag("shortener", "Shortened link",
                 f"{url} uses a link shortener, which hides where it really leads.",
                 10, "medium")

        # 4f. An "@" in the address part of a URL: everything before it is ignored.
        #     http://paypal.com@evil.xyz actually goes to evil.xyz.
        if "@" in parsed.netloc:
            flag("at-sign", "Link uses an @ trick",
                 f"In {url}, everything before the @ is ignored. The real destination is {host}.",
                 20, "high")

        # 4g. Punycode (xn--) can disguise lookalike letters from other alphabets.
        if "xn--" in host:
            flag("punycode", "Internationalized (punycode) domain",
                 f"{host} uses punycode, which can disguise lookalike characters.",
                 15, "medium")

        # 4h. Unencrypted link. Weak on its own, so it's only worth a few points.
        if parsed.scheme == "http":
            flag("http", "Unencrypted (http) link",
                 f"{url} doesn't use HTTPS.", 5, "low")

    return unique_urls


# ---------------------------------------------------------------------------
# Check group 5: Attachments
# ---------------------------------------------------------------------------

def check_attachments(attachments, findings):
    """Flag attachments that can run code or hide what they really are."""
    for name in attachments:
        lower = name.lower()
        parts = lower.split(".")
        ext = parts[-1] if len(parts) > 1 else ""

        # 5a. Double extension: "invoice.pdf.exe" pretends to be a PDF.
        if len(parts) >= 3 and ext in DANGEROUS_EXTENSIONS:
            add_finding(findings, "Disguised attachment (double extension)",
                        f'"{name}" pretends to be a .{parts[-2]} file but is really .{ext}.',
                        35, "high", "attachments")

        # 5b. Executable / script / macro file.
        elif ext in DANGEROUS_EXTENSIONS:
            add_finding(findings, "Dangerous attachment type",
                        f'"{name}" is a .{ext} file, which can run code or show a fake login page when opened.',
                        30, "high", "attachments")

        # 5c. Archive: could be hiding an executable inside.
        elif ext in ARCHIVE_EXTENSIONS:
            add_finding(findings, "Compressed attachment",
                        f'"{name}" is an archive, which is often used to sneak malware past email filters.',
                        10, "medium", "attachments")


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
    body, links, attachments = read_body(msg)
    auth = read_auth_results(msg)

    # Step 3: Run each group of checks. They all add to the same findings list.
    findings = []
    check_sender(msg, findings)
    check_authentication(msg, findings, auth)
    check_content(subject, body, findings)
    unique_links = check_links(links, findings)
    check_attachments(attachments, findings)

    # Step 4: Add up the points, cap at 100, and pick a verdict.
    score = min(sum(f["points"] for f in findings), 100)
    if score >= 60:
        verdict = "malicious"
    elif score >= 25:
        verdict = "suspicious"
    else:
        verdict = "benign"

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
        "verdict": verdict,
        "score": score,
        # str() turns header objects into plain text; None stays None (shown as "—").
        "headers": {name: str(value) if value else None for name, value in headers.items()},
        "findings": findings,
        "links": unique_links,
    }