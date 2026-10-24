import logging
from typing import Any

logger = logging.getLogger("ja4proxy")

# Bogdanfinn/tls-client v1.16.0 supported identifiers
SUPPORTED_PROFILES: list[str] = [
    "chrome_133",
    "chrome_131",
    "chrome_124",
    "chrome_120",
    "safari_16_0",
    "safari_15_6_1",
    "safari_ios_16_0",
    "safari_ios_17_0",
    "safari_ios_18_0",
    "firefox_133",
    "firefox_132",
    "firefox_120",
    "opera_90",
    "opera_89",
]

DEFAULT_PROFILE = "chrome_133"

# Map common user shorthand and version aliases to real native engine profiles
PROFILE_ALIASES: dict[str, str] = {
    "chrome": "chrome_133",
    "chrome-latest": "chrome_133",
    "chrome133": "chrome_133",
    "chrome_133": "chrome_133",
    "chrome131": "chrome_131",
    "chrome_131": "chrome_131",
    "chrome130": "chrome_131",
    "chrome_130": "chrome_131",
    "chrome124": "chrome_124",
    "chrome_124": "chrome_124",
    "chrome120": "chrome_120",
    "chrome_120": "chrome_120",
    "safari": "safari_16_0",
    "safari-latest": "safari_16_0",
    "safari18": "safari_16_0",
    "safari_18": "safari_16_0",
    "safari_18_0": "safari_16_0",
    "safari17": "safari_16_0",
    "safari_17": "safari_16_0",
    "safari_17_0": "safari_16_0",
    "safari16": "safari_16_0",
    "safari_16": "safari_16_0",
    "safari_16_0": "safari_16_0",
    "safari15": "safari_15_6_1",
    "safari_15_6_1": "safari_15_6_1",
    "firefox": "firefox_133",
    "firefox-latest": "firefox_133",
    "firefox133": "firefox_133",
    "firefox_133": "firefox_133",
    "firefox132": "firefox_132",
    "firefox_132": "firefox_132",
    "firefox120": "firefox_120",
    "firefox_120": "firefox_120",
    "opera": "opera_90",
    "opera90": "opera_90",
    "opera_90": "opera_90",
    "opera89": "opera_89",
    "opera_89": "opera_89",
}


def normalize_profile(name: str | None) -> str:
    """Normalizes alias or custom profile name to a supported native client identifier."""
    if not name:
        return DEFAULT_PROFILE
    raw = name.strip().lower()
    cleaned = raw.replace("-", "_")
    compact = raw.replace("-", "").replace("_", "")

    if raw in PROFILE_ALIASES:
        return PROFILE_ALIASES[raw]
    if cleaned in PROFILE_ALIASES:
        return PROFILE_ALIASES[cleaned]
    if compact in PROFILE_ALIASES:
        return PROFILE_ALIASES[compact]

    for p in SUPPORTED_PROFILES:
        if p.lower() == cleaned or p.lower().replace("_", "") == compact:
            return p

    logger.warning(
        f"Profile '{name}' is not supported by native engine; falling back to '{DEFAULT_PROFILE}'"
    )
    return DEFAULT_PROFILE


def get_default_headers(profile: str) -> dict[str, str]:
    """Generates canonical browser headers aligned with the profile's cryptographic engine."""
    prof = normalize_profile(profile)

    if prof.startswith("chrome"):
        major_ver = "133"
        full_ver = "133.0.0.0"
        if "131" in prof:
            major_ver = "131"
            full_ver = "131.0.0.0"
        elif "124" in prof:
            major_ver = "124"
            full_ver = "124.0.0.0"
        elif "120" in prof:
            major_ver = "120"
            full_ver = "120.0.0.0"

        return {
            "sec-ch-ua": f'"Chromium";v="{major_ver}", "Not(A:Brand";v="99", "Google Chrome";v="{major_ver}"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "upgrade-insecure-requests": "1",
            "user-agent": f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{full_ver} Safari/537.36",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "sec-fetch-site": "none",
            "sec-fetch-mode": "navigate",
            "sec-fetch-user": "?1",
            "sec-fetch-dest": "document",
            "accept-language": "en-US,en;q=0.9",
            "accept-encoding": "gzip, deflate, br, zstd",
        }

    if prof.startswith("safari"):
        if "15" in prof:
            return {
                "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6.1 Safari/605.1.15",
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "accept-language": "en-US,en;q=0.9",
                "accept-encoding": "gzip, deflate, br",
                "sec-fetch-dest": "document",
                "sec-fetch-mode": "navigate",
                "sec-fetch-site": "none",
            }
        return {
            "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "accept-language": "en-US,en;q=0.9",
            "accept-encoding": "gzip, deflate, br",
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "none",
        }

    if prof.startswith("firefox"):
        ff_ver = "133.0"
        if "132" in prof:
            ff_ver = "132.0"
        elif "120" in prof:
            ff_ver = "120.0"

        return {
            "user-agent": f"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{ff_ver}) Gecko/20100101 Firefox/{ff_ver}",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "accept-language": "en-US,en;q=0.5",
            "accept-encoding": "gzip, deflate, br, zstd",
            "upgrade-insecure-requests": "1",
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "none",
            "sec-fetch-user": "?1",
        }

    if prof.startswith("opera"):
        opr_ver = "90.0.4480.84"
        chr_ver = "104.0.5112.102"
        if "89" in prof:
            opr_ver = "89.0.4447.83"
            chr_ver = "103.0.5060.134"

        return {
            "user-agent": f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chr_ver} Safari/537.36 OPR/{opr_ver}",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "accept-language": "en-US,en;q=0.9",
            "accept-encoding": "gzip, deflate, br",
        }

    return {
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
        "accept": "*/*",
        "accept-language": "en-US,en;q=0.9",
    }
