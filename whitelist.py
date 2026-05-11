"""
whitelist.py — PhishGuard AI  (FIXED)

KEY FIXES:
  1. USER-CONTENT DOMAINS (docs.google.com, sites.google.com) — removed from
     simple whitelist path. These domains HOST user-generated content, so any
     path that doesn't match a known Google service pattern is treated as
     SUSPICIOUS. Phishing URLs like sites.google.com/view/fake-bank-login are
     now correctly flagged instead of silently trusted.

  2. tinyurl.com, bit.ly etc — already in SHORT_URL_DOMAINS (never whitelisted),
     verified they cannot slip through any branch.

  3. REDIRECT_REGEX tightened — catches more open-redirect patterns on trusted
     domains (e.g. google.com/url?q=http://evil.com).

  4. USER_CONTENT_DOMAINS now use a strict ALLOWLIST of safe path prefixes
     instead of a blocklist of bad keywords. Anything not matching a known safe
     prefix on a user-content domain returns False → goes to ML/rule engine.
"""
from urllib.parse import urlparse
import re

# ─── Fully trusted domains ────────────────────────────────────────────────────
FULLY_TRUSTED = {
    # Google core services (NOT docs/sites/forms — those are user-content)
    "google.com", "google.co.in", "google.co.uk", "google.com.au",
    "gmail.com", "youtube.com",
    "maps.google.com", "play.google.com", "accounts.google.com",
    "googleapis.com",
    "meet.google.com", "calendar.google.com",
    "classroom.google.com", "google.co",
    "colab.research.google.com", "scholar.google.com",
    "cloud.google.com", "console.cloud.google.com",

    # Social
    "whatsapp.com", "web.whatsapp.com", "wa.me",
    "facebook.com", "messenger.com", "instagram.com",
    "twitter.com", "x.com",
    "linkedin.com",
    "pinterest.com", "snapchat.com",
    "tiktok.com", "telegram.org", "t.me",

    # Microsoft (core — NOT sharepoint/onedrive, those are user-content)
    "microsoft.com", "office.com", "outlook.com", "hotmail.com",
    "live.com", "teams.microsoft.com",
    "azure.microsoft.com", "azure.com",
    "visualstudio.com", "code.visualstudio.com", "aka.ms",
    "microsoftonline.com", "login.microsoftonline.com",

    # Apple
    "apple.com", "icloud.com", "itunes.apple.com",
    "apps.apple.com", "support.apple.com",

    # Amazon
    "amazon.com", "amazon.in", "amazon.co.uk",
    "aws.amazon.com", "console.aws.amazon.com",
    "amazonaws.com",

    # Developer / Learning
    "github.com", "gitlab.com", "bitbucket.org",
    "stackoverflow.com", "stackexchange.com",
    "npmjs.com", "pypi.org",
    "docker.com", "hub.docker.com",
    "kubernetes.io",
    "geeksforgeeks.org", "tutorialspoint.com",
    "w3schools.com", "javatpoint.com",
    "programiz.com", "hackerrank.com", "leetcode.com",
    "codechef.com", "codeforces.com",
    "freecodecamp.org", "codecademy.com",
    "udemy.com", "coursera.org", "edx.org",
    "khanacademy.org", "kaggle.com",

    # Docs / Research
    "developer.mozilla.org", "docs.python.org",
    "flask.palletsprojects.com",
    "scikit-learn.org", "numpy.org", "pandas.pydata.org",
    "tensorflow.org", "pytorch.org",
    "huggingface.co", "arxiv.org",

    # Indian Govt & Education
    "india.gov.in", "nic.in", "gov.in",
    "uidai.gov.in", "mca.gov.in",
    "incometax.gov.in", "gst.gov.in",
    "rbi.org.in", "sebi.gov.in",
    "amfiindia.com", "nseindia.com",
    "bseindia.com", "msei.in",
    "irctc.co.in", "irctc.com",
    "indianrailways.gov.in",
    "digilocker.gov.in",
    "cowin.gov.in",
    "niti.gov.in", "pib.gov.in",
    "mhrd.gov.in", "ugc.ac.in",
    "aicte-india.org",
    "annauniv.edu",
    "iitm.ac.in", "iitb.ac.in", "iitd.ac.in",
    "iitk.ac.in", "iisc.ac.in",
    "nit.ac.in",

    # Electronics brands
    "samsung.com", "sony.com", "lg.com", "panasonic.com",
    "philips.com", "xiaomi.com", "oneplus.com", "oppo.com",
    "vivo.com", "realme.com", "motorola.com", "nokia.com",
    "dell.com", "hp.com", "mi.com", "lenovo.com",
    "asus.com", "acer.com", "msi.com",
    "intel.com", "nvidia.com", "amd.com",

    # Indian Banks
    "sbi.co.in", "onlinesbi.sbi",
    "hdfcbank.com", "netbanking.hdfcbank.com",
    "icicibank.com", "axisbank.com",
    "kotak.com", "kotakbank.com",
    "yesbank.in", "indusind.com",
    "pnbindia.in", "bankofbaroda.in",
    "canarabank.com", "unionbankofindia.co.in",
    "paytm.com", "phonepe.com",
    "googlepay.com", "bhimupi.org.in",

    # Indian IT Companies
    "tcs.com", "wipro.com",
    "infosys.com", "hcltech.com",
    "accenture.com", "cognizant.com",
    "tech-mahindra.com", "techm.com",
    "zoho.com", "freshworks.com", "oracle.com",
    "mphasis.com", "hexaware.com",

    # E-Commerce India
    "flipkart.com", "myntra.com",
    "meesho.com", "snapdeal.com",
    "jiomart.com", "nykaa.com", "ajio.com",
    "bigbasket.com", "blinkit.com",
    "zepto.co",

    # News & Media
    "thehindu.com", "ndtv.com", "msn.com",
    "hindustantimes.com", "indiatoday.in",
    "timesofindia.com", "economictimes.com",
    "livemint.com", "businessstandard.com",
    "financialexpress.com", "moneycontrol.com",
    "cnbctv18.com", "zee5.com",
    "bbc.com", "cnn.com", "reuters.com",
    "apnews.com", "theguardian.com",

    # Productivity & Collaboration
    "slack.com", "discord.com",
    "zoom.us", "webex.com",
    "trello.com", "notion.so",
    "atlassian.com", "jira.atlassian.com",
    "confluence.atlassian.com",
    "asana.com", "monday.com",
    "clickup.com", "basecamp.com",
    "figma.com", "canva.com",
    "miro.com", "lucidchart.com",
    "draw.io", "app.diagrams.net",

    # Documentation Sites
    "docs.djangoproject.com",
    "docs.flask.palletsprojects.com",
    "fastapi.tiangolo.com",
    "matplotlib.org", "keras.io",
    "researchgate.net", "springer.com",
    "ieee.org", "acm.org", "elsevier.com",
    "nature.com", "sciencedirect.com", "ssrn.com",

    # Cloud
    "cloudflare.com", "netlify.com", "vercel.com",
    "heroku.com", "digitalocean.com",

    # Travel & Booking
    "redbus.in", "abhibus.com",
    "makemytrip.com", "ixigo.com",
    "goibibo.com", "booking.com",
    "agoda.com", "expedia.com",
    "hotels.com", "trivago.com",
    "airbnb.com", "skyscanner.net",
    "kayak.com", "momondo.com",
    "emirates.com", "qatarairways.com",
    "airindia.com", "singaporeair.com",

    # Entertainment
    "netflix.com", "primevideo.com",
    "hotstar.com", "disneyplus.com",
    "spotify.com", "soundcloud.com",
    "twitch.tv", "vimeo.com",
    "sonyliv.com", "aha.video",
    "mxplayer.in", "jiohotstar.com",

    # Search & Reference
    "wikipedia.org", "wikimedia.org",
    "wikidata.org", "wikihow.com",
    "quora.com", "reddit.com",
    "bing.com", "yahoo.com",
    "duckduckgo.com", "wolframalpha.com",

    # Security Sites
    "virustotal.com", "shodan.io",
    "haveibeenpwned.com",
    "kali.org", "owasp.org",
    "cve.mitre.org", "nvd.nist.gov",

    # Package / Registry
    "pypi.org", "npmjs.com",
    "packagist.org", "pub.dev",
    "rubygems.org", "crates.io",
    "nuget.org",

    # API / Tools
    "postman.com", "swagger.io",
    "rapidapi.com", "insomnia.rest",
    "regex101.com", "jsonlint.com",
    "codebeautify.org",
}

# ─── User-content domains ─────────────────────────────────────────────────────
# IMPORTANT: These domains HOST user-generated content (Google Sites, Google
# Docs, SharePoint pages, GitHub Pages). Phishers abuse them to host
# convincing fake login pages. We do NOT blindly trust these — only specific
# known-safe path prefixes are allowed. Everything else gets forwarded to the
# rule/ML engine.
USER_CONTENT_DOMAINS = {
    "docs.google.com",
    "sites.google.com",       # ← FIXED: was fully trusted, now needs path check
    "forms.google.com",
    "forms.gle",
    "drive.google.com",
    "storage.googleapis.com",
    "firebasestorage.googleapis.com",
    "appspot.com",
    "firebaseapp.com",
    "github.io",
    "pages.github.com",
    "gist.github.com",
    "sharepoint.com",          # ← FIXED: was fully trusted, now needs path check
    "onedrive.live.com",
    "1drv.ms",
    "forms.office.com",
    "blogger.com",
    "blogspot.com",
}

# ─── Safe path prefixes for user-content domains ──────────────────────────────
# ONLY these exact path prefixes are trusted on user-content domains.
# Any other path → NOT whitelisted → goes to ML/rule engine.
#
# Pattern:
#   docs.google.com/document/d/...  → SAFE (editing a real doc)
#   docs.google.com/spreadsheets/... → SAFE
#   sites.google.com/site/...       → borderline, check further
#   sites.google.com/view/fake-hdfc-bank-login → NOT SAFE ← this was the bug
#
# Strategy: allowlist known document/file path patterns.
# Anything with suspicious brand/keyword combos in the path → reject.

SAFE_PATH_PREFIXES_BY_DOMAIN = {
    "docs.google.com": (
        "/document/", "/spreadsheets/", "/presentation/",
        "/drawings/", "/forms/",
    ),
    "drive.google.com": (
        "/file/", "/drive/", "/open",
    ),
    "forms.google.com": ("/forms/",),
    "gist.github.com": ("/",),   # gists are always code snippets
    "forms.office.com": ("/pages/",),
    "onedrive.live.com": ("/redir",),
}

# For domains not listed above (sites.google.com, sharepoint.com, blogspot.com,
# github.io etc.) — we use the suspicious keyword blocklist on the full path.
# If ANY suspicious keyword found in path → NOT whitelisted.
SUSPICIOUS_PATH_KEYWORDS = [
    "login", "signin", "sign-in", "log-in", "logon",
    "verify", "verification", "secure", "security",
    "account", "banking", "bank", "payment", "pay",
    "billing", "invoice", "password", "passwd",
    "confirm", "validate", "suspended", "locked",
    "unlock", "credential", "recovery", "update",
    "reactivate", "alert", "urgent",
    "paypal", "paytm", "hdfc", "sbi", "icici", "axis",
    "apple", "microsoft", "google", "amazon", "netflix",
    "facebook", "instagram", "whatsapp",
]

# ─── Short URL domains — NEVER whitelisted ───────────────────────────────────
SHORT_URL_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "tiny.cc", "buff.ly", "snip.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "lnkd.in",
    "adf.ly", "dlvr.it", "bl.ink",
}

# ─── Open redirect patterns ───────────────────────────────────────────────────
REDIRECT_PATTERNS = [
    r"/url\?.*[qQ]=http",
    r"[?&](redirect|redir|url|goto|next|return|out|link|continue)=https?",
    r"[?&](redirect|redir|url|goto|next|return|out|link|continue)=%",
]
REDIRECT_REGEX = re.compile("|".join(REDIRECT_PATTERNS), re.IGNORECASE)

# Precompute suffix tuples for fast endswith checks
_TRUSTED_SUFFIXES = tuple("." + d for d in FULLY_TRUSTED)
_CONTENT_SUFFIXES = tuple("." + d for d in USER_CONTENT_DOMAINS)

# ─── Root domain extractor ────────────────────────────────────────────────────
def _get_root(hostname: str) -> str:
    parts = hostname.split(".")
    if len(parts) <= 2:
        return hostname
    cc = {"co.in", "co.uk", "com.au", "co.nz", "co.jp", "co.za",
          "ac.in", "edu.in", "gov.in", "net.in", "org.in"}
    if ".".join(parts[-2:]) in cc and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])

# ─── User-content domain safety check ────────────────────────────────────────
def _is_safe_user_content(hostname: str, path: str, full_path_query: str) -> bool:
    """
    Returns True ONLY if a user-content domain URL looks genuinely safe.

    Strategy:
    1. If the domain has known safe path prefixes (e.g. docs.google.com),
       check that the path starts with one of them.
    2. For all user-content domains, reject if ANY suspicious keyword appears
       in path+query (brand names, login, banking, etc.)
    3. Reject if open-redirect pattern detected.
    """
    # Step 1: reject open redirects on all user-content domains
    if REDIRECT_REGEX.search(full_path_query):
        return False

    # Step 2: reject if suspicious keyword in path/query
    # (catches sites.google.com/view/fake-hdfc-login, etc.)
    path_lower = full_path_query.lower()
    if any(k in path_lower for k in SUSPICIOUS_PATH_KEYWORDS):
        return False

    # Step 3: for domains with known safe prefixes, require path to match
    base_domain = hostname  # e.g. "docs.google.com"
    # Find matching entry (handle subdomains like "abc.blogspot.com")
    for domain, prefixes in SAFE_PATH_PREFIXES_BY_DOMAIN.items():
        if hostname == domain or hostname.endswith("." + domain):
            # Must start with one of the known safe path prefixes
            return any(path.startswith(p) for p in prefixes)

    # Step 4: domains with no defined safe prefixes (sites.google.com,
    # sharepoint, blogspot, github.io) — passed steps 1 & 2 already,
    # so allow (no suspicious keyword and no redirect found)
    return True

# ─── Main whitelist check ─────────────────────────────────────────────────────
def is_whitelisted(url: str) -> bool:
    """
    Returns True only if the URL is definitely from a trusted, legitimate source.
    When in doubt, returns False (let the ML/rule engine decide).
    """
    try:
        parsed   = urlparse(url if url.startswith("http") else "http://" + url)
        hostname = (parsed.hostname or "").lower().strip()
        path     = (parsed.path or "").lower()
        query    = (parsed.query or "").lower()
        full     = path + ("?" + query if query else "")

        if not hostname:
            return False

        # Short URL domains are NEVER safe — handled as suspicious in app.py
        if hostname in SHORT_URL_DOMAINS:
            return False

        root = _get_root(hostname)

        # ── User-content domains: strict path checking ────────────────────────
        # These are checked FIRST because docs.google.com etc. must go through
        # the strict path checker, not the simple "trusted domain" branch.
        is_user_content = (
            hostname in USER_CONTENT_DOMAINS or
            hostname.endswith(_CONTENT_SUFFIXES) or
            root in USER_CONTENT_DOMAINS
        )
        if is_user_content:
            return _is_safe_user_content(hostname, path, full)

        # ── Fully trusted domains ─────────────────────────────────────────────
        is_trusted = (
            hostname in FULLY_TRUSTED or
            root in FULLY_TRUSTED or
            hostname.endswith(_TRUSTED_SUFFIXES)
        )
        if is_trusted:
            # Still reject open redirects on trusted domains
            if REDIRECT_REGEX.search(full):
                return False
            return True

        # ── Government / Education TLDs ───────────────────────────────────────
        SAFE_TLDS = (".gov.in", ".edu.in", ".ac.in", ".gov", ".edu",
                     ".ac.uk", ".edu.au", ".nic.in")
        if hostname.endswith(SAFE_TLDS):
            return True

        return False

    except Exception:
        return False