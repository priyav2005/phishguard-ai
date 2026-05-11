"""
feature_extraction.py — PhishGuard AI  (FIXED)

KEY FIXES:
  1. ALL 31 original features RESTORED — the trained .pkl models were trained
     on these exact 31 features. Removing any causes the model to receive 0s
     for missing columns → completely wrong predictions.
  2. has_suspicious_keyword now checks HOSTNAME only (not full URL path).
     Paths like /login, /account are normal on legitimate sites.
  3. has_suspicious_path added as a SEPARATE soft signal (32nd feature).
     train_models.py will pick this up on next retrain.
  4. Brand names REMOVED from SUSPICIOUS_KEYWORDS — brand names belong only
     in the rule-based brand check, not the ML keyword feature.
"""
import re
from urllib.parse import urlparse

# Brand names intentionally excluded here.
# They are handled by the rule-based engine brand check in app.py.
SUSPICIOUS_KEYWORDS = [
    "login","signin","sign-in","log-in","logon",
    "verify","verification","secure","security",
    "account","banking","bank","payment","pay",
    "billing","invoice","transaction","transfer",
    "wallet","crypto","update","confirm","validate",
    "reactivate","suspend","locked","unlock",
    "limited","expire","alert","urgent","immediately",
    "password","passwd","credential","support",
    "helpdesk","customer-care",
]

def extract_features(url: str) -> dict:
    url = str(url).strip()
    features = {}

    try:
        parsed   = urlparse(url if url.startswith("http") else "http://" + url)
        hostname = (parsed.hostname or "").lower()
        path     = parsed.path or ""
        scheme   = parsed.scheme or "http"
    except Exception:
        hostname = ""; path = ""; scheme = "http"

    # ── 1-19: character counts (ALL original features kept) ──────────────────
    features["url_length"]         = len(url)
    features["num_dots"]           = url.count(".")
    features["num_hyphens"]        = url.count("-")
    features["num_underscores"]    = url.count("_")
    features["num_slashes"]        = url.count("/")
    features["num_question_marks"] = url.count("?")
    features["num_equal_signs"]    = url.count("=")
    features["num_at"]             = url.count("@")
    features["has_at_symbol"]      = 1 if "@" in url else 0
    features["num_ampersand"]      = url.count("&")
    features["num_exclamation"]    = url.count("!")          # ← RESTORED
    features["num_spaces"]         = url.count(" ") + url.count("%20")  # ← RESTORED
    features["num_tilde"]          = url.count("~")          # ← RESTORED
    features["num_commas"]         = url.count(",")          # ← RESTORED
    features["num_plus"]           = url.count("+")          # ← RESTORED
    features["num_asterisk"]       = url.count("*")          # ← RESTORED
    features["num_hash"]           = url.count("#")          # ← RESTORED
    features["num_dollar"]         = url.count("$")          # ← RESTORED
    features["num_percent"]        = url.count("%")          # ← RESTORED

    # ── 20-21: protocol ───────────────────────────────────────────────────────
    features["has_https"] = 1 if scheme == "https" else 0
    features["has_http"]  = 1 if scheme == "http"  else 0

    # ── 22: IP as hostname (hostname only, not full URL) ──────────────────────
    ip_pat = r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
    if hostname and re.match(ip_pat, hostname):
        try:
            parts = [int(x) for x in hostname.split(".")]
            features["has_ip"] = 1 if all(0 <= p <= 255 for p in parts) else 0
        except:
            features["has_ip"] = 0
    else:
        features["has_ip"] = 0

    # ── 23-24: lengths ────────────────────────────────────────────────────────
    features["hostname_length"] = len(hostname)
    features["path_length"]     = len(path)

    # ── 25: subdomains (exclude www) ──────────────────────────────────────────
    h_parts = hostname.split(".")
    if len(h_parts) > 2:
        non_www = [p for p in h_parts[:-2] if p and p != "www"]
        features["num_subdomains"] = len(non_www)
    else:
        features["num_subdomains"] = 0

    # ── 26: www ───────────────────────────────────────────────────────────────
    features["has_www"] = 1 if hostname.startswith("www.") else 0

    # ── 27-28: character ratios ───────────────────────────────────────────────
    n = len(url) or 1
    features["digit_ratio"]  = sum(c.isdigit() for c in url) / n
    features["letter_ratio"] = sum(c.isalpha() for c in url) / n

    # ── 29: suspicious keyword — HOSTNAME ONLY (KEY FIX) ─────────────────────
    # Phishing sites embed suspicious words in the domain name itself.
    # Legitimate sites have these words only in URL paths (/login, /account).
    # Checking full URL caused massive false positives on real sites.
    hostname_lower = hostname.lower()
    features["has_suspicious_keyword"] = 1 if any(
        k in hostname_lower for k in SUSPICIOUS_KEYWORDS
    ) else 0

    # ── 30: TLD length ────────────────────────────────────────────────────────
    tld = h_parts[-1] if h_parts else ""
    features["tld_length"] = len(tld)

    # ── 31: non-standard port (80 and 443 are normal) ─────────────────────────
    try:
        port = parsed.port
        features["has_port"] = 1 if port and port not in (80, 443) else 0
    except:
        features["has_port"] = 0

    # ── 32: suspicious path (NEW — separate soft signal) ─────────────────────
    # This is an EXTRA feature for the next retrain.
    # Current models ignore it via reindex(columns=FEAT_NAMES).
    path_lower = (path or "").lower()
    features["has_suspicious_path"] = 1 if any(
        k in path_lower for k in SUSPICIOUS_KEYWORDS
    ) else 0

    return features


def get_feature_names():
    return list(extract_features("https://example.com").keys())