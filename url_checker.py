"""
url_checker.py — CyberShield URL Security Checker

Checks a public website URL for basic HTTPS usage and the presence of
common HTTP security response headers.

No Streamlit imports — this module is UI-independent and fully testable.

IMPORTANT: This tool only reads publicly visible HTTP response headers.
It does not scan ports, crawl content, test for vulnerabilities, or send
any data beyond a standard GET request. Only use it on sites you own or
have permission to inspect.
"""

import urllib.parse
import requests

# ── Security headers to check ────────────────────────────────────────────────
# Each entry: (header_name, short_label, why_it_matters)
#
# Headers are split into two groups:
#
# HEADERS_RECOMMENDED — widely expected on most public websites; absence is
#   worth noting, though not proof of a vulnerability.
#
# HEADERS_SITUATIONAL — context-dependent; may legitimately be absent because
#   the site uses an equivalent mechanism (e.g. CSP frame-ancestors instead of
#   X-Frame-Options) or because the feature is handled by a CDN/proxy that is
#   not visible in a single direct GET request.
#
# Both lists are combined into SECURITY_HEADERS for backward-compatibility
# with any code that iterates over all headers at once.

HEADERS_RECOMMENDED = [
    (
        "Strict-Transport-Security",
        "HSTS",
        "Tells browsers to always use HTTPS for this site.",
    ),
    (
        "X-Content-Type-Options",
        "X-Content-Type-Options",
        "Prevents browsers from guessing the content type (MIME sniffing).",
    ),
    (
        "Content-Security-Policy",
        "CSP",
        "Restricts which scripts, styles, and resources the page can load.",
    ),
]

HEADERS_SITUATIONAL = [
    (
        "X-Frame-Options",
        "X-Frame-Options",
        "Protects against clickjacking by controlling iframe embedding. "
        "May be superseded by the CSP frame-ancestors directive.",
    ),
    (
        "Referrer-Policy",
        "Referrer-Policy",
        "Controls how much referrer information is sent with requests.",
    ),
    (
        "Permissions-Policy",
        "Permissions-Policy",
        "Restricts access to browser features like camera and microphone. "
        "Not required for sites that do not use sensitive browser APIs.",
    ),
]

# Combined list — kept for any code that needs to iterate all headers.
SECURITY_HEADERS = HEADERS_RECOMMENDED + HEADERS_SITUATIONAL

REQUEST_TIMEOUT = 10   # seconds — enough for most public sites


def _normalise_url(raw_url: str) -> str:
    """
    Ensure the URL has a scheme so requests can connect.

    If no scheme is present, 'https://' is prepended. If 'http://' is
    given explicitly, it is kept — the HTTPS check will report that.

    Returns the normalised URL string.
    """
    raw_url = raw_url.strip()
    if not raw_url:
        raise ValueError("URL must not be empty.")
    parsed = urllib.parse.urlparse(raw_url)
    if not parsed.scheme:
        raw_url = "https://" + raw_url
    return raw_url


def check_url(raw_url: str) -> dict:
    """
    Check a public website URL for HTTPS usage and security headers.

    Parameters
    ----------
    raw_url : str
        The URL to check. A scheme ('https://') is added if missing.

    Returns
    -------
    dict with keys:

        url          : str   — the final URL that was fetched
        reachable    : bool  — True if a response was received
        error        : str | None — human-readable error if unreachable
        https        : bool  — True if the final response URL uses HTTPS
        redirected   : bool  — True if the server redirected the request
        final_url    : str   — URL after following redirects
        status_code  : int | None
        headers_found        : list[dict] — headers present in the response
        headers_missing      : list[dict] — headers absent from the response
        recommended_found    : list[dict] — subset of headers_found that are recommended
        recommended_missing  : list[dict] — subset of headers_missing that are recommended
        situational_found    : list[dict] — subset of headers_found that are situational
        situational_missing  : list[dict] — subset of headers_missing that are situational
        observed_count : int  — number of headers observed (excludes HTTPS)
        total_headers  : int  — always 6 (total headers checked)

    Each item in the header lists is:
        { "header": str, "label": str, "value": str|None, "description": str,
          "category": "recommended" | "situational" }
    """
    url = _normalise_url(raw_url)

    result = {
        "url":                  url,
        "reachable":            False,
        "error":                None,
        "https":                False,
        "redirected":           False,
        "final_url":            url,
        "status_code":          None,
        "headers_found":        [],
        "headers_missing":      [],
        "recommended_found":    [],
        "recommended_missing":  [],
        "situational_found":    [],
        "situational_missing":  [],
        "observed_count":       0,
        "total_headers":        len(SECURITY_HEADERS),
    }

    # ── 1. Fetch the URL ──────────────────────────────────────────────────────
    try:
        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            # Send a realistic User-Agent so servers don't reject the request
            headers={"User-Agent": "CyberShield-SecurityChecker/1.0 (educational tool)"},
        )
    except requests.exceptions.SSLError as exc:
        result["error"] = (
            f"SSL/TLS error: {exc}. "
            "The site may have an invalid or expired certificate."
        )
        return result
    except requests.exceptions.ConnectionError as exc:
        result["error"] = f"Could not connect to '{url}'. Check the URL and your network."
        return result
    except requests.exceptions.Timeout:
        result["error"] = (
            f"Request timed out after {REQUEST_TIMEOUT}s. "
            "The site may be slow or unreachable."
        )
        return result
    except requests.exceptions.InvalidURL as exc:
        result["error"] = f"Invalid URL: {exc}"
        return result
    except requests.exceptions.RequestException as exc:
        result["error"] = f"Request failed: {exc}"
        return result

    result["reachable"]    = True
    result["status_code"]  = response.status_code
    result["final_url"]    = response.url
    result["redirected"]   = response.url.rstrip("/") != url.rstrip("/")

    # ── 2. HTTPS check ────────────────────────────────────────────────────────
    result["https"] = response.url.startswith("https://")

    # ── 3. Security header checks ─────────────────────────────────────────────
    response_headers_lower = {k.lower(): v for k, v in response.headers.items()}

    # Determine which category each header belongs to for later grouping.
    recommended_names = {h[0].lower() for h in HEADERS_RECOMMENDED}

    observed = 0
    for header_name, label, description in SECURITY_HEADERS:
        value    = response_headers_lower.get(header_name.lower())
        category = "recommended" if header_name.lower() in recommended_names else "situational"
        entry = {
            "header":      header_name,
            "label":       label,
            "value":       value,
            "description": description,
            "category":    category,
        }
        if value is not None:
            result["headers_found"].append(entry)
            result[f"{category}_found"].append(entry)
            observed += 1
        else:
            result["headers_missing"].append(entry)
            result[f"{category}_missing"].append(entry)

    result["observed_count"] = observed

    return result
