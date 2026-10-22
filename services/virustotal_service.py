
import os
import base64
import logging
from urllib.parse import urlsplit

import requests

logger = logging.getLogger(__name__)

VT_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
VT_URL = "https://www.virustotal.com/api/v3/urls"


def scan_link(url: str) -> dict:
    if not VT_API_KEY:
        return {
            "Error": "VirusTotal API key is not configured in Render."
        }

    url = str(url or "").strip()

    try:
        parsed = urlsplit(url)
        if (
            parsed.scheme.lower() not in ("http", "https")
            or not parsed.hostname
            or any(char.isspace() for char in url)
        ):
            return {"Error": "Invalid HTTP/HTTPS URL."}
    except (ValueError, TypeError):
        return {"Error": "Invalid URL."}

    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY,
    }

    url_id = base64.urlsafe_b64encode(
        url.encode("utf-8")
    ).decode("ascii").rstrip("=")

    try:
        response = requests.get(
            f"{VT_URL}/{url_id}",
            headers=headers,
            timeout=30,
        )

        if response.status_code == 404:
            return {
                "Status": "No existing VirusTotal analysis was found.",
                "Next step": (
                    "The URL has not been analyzed, or no report is available. "
                    "This is not evidence that it is safe."
                ),
            }

        if response.status_code == 429:
            return {
                "Error": "VirusTotal rate limit exceeded. Try again later."
            }

        if response.status_code != 200:
            logger.warning(
                "VirusTotal returned HTTP %s", response.status_code
            )
            return {
                "Error": f"VirusTotal API returned HTTP {response.status_code}."
            }

        payload = response.json()
        attributes = payload.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        results = attributes.get("last_analysis_results", {})

        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        harmless = int(stats.get("harmless", 0) or 0)
        undetected = int(stats.get("undetected", 0) or 0)
        timeout = int(stats.get("timeout", 0) or 0)
        confirmed_total = malicious + suspicious + harmless + undetected
        total_reported = confirmed_total + timeout

        detections = {}
        for vendor, item in results.items():
            if item.get("category") in ("malicious", "suspicious"):
                detections[vendor] = {
                    "Category": item.get("category", "unknown"),
                    "Result": item.get("result") or "No threat name provided",
                }

        categories = attributes.get("categories", {})
        category_text = (
            ", ".join(sorted(set(str(v) for v in categories.values())))
            if categories else "Not provided"
        )

        if malicious or suspicious:
            assessment = "Detections reported by one or more engines"
        elif total_reported:
            assessment = (
                "No malicious or suspicious detections in the returned results; "
                "this does not guarantee safety"
            )
        else:
            assessment = "Insufficient analysis data to assess this URL"

        return {
            "Target URL": url,
            "Assessment": assessment,
            "Malicious detections": malicious,
            "Suspicious detections": suspicious,
            "Harmless results": harmless,
            "Undetected results": undetected,
            "Timeouts": timeout,
            "Total reported results": total_reported,
            "Categories": category_text,
            "Detection details": detections or "No malicious or suspicious engine results returned.",
            "VirusTotal report": f"https://www.virustotal.com/gui/url/{url_id}",
            "Caution": (
                "Engine results are indicators, not a guarantee. "
                "False positives and false negatives are possible."
            ),
        }

    except requests.RequestException as exc:
        logger.warning("VirusTotal request failed: %s", exc)
        return {"Error": "Could not connect to VirusTotal. Try again later."}
    except (ValueError, TypeError, KeyError) as exc:
        logger.exception("Could not parse VirusTotal response: %s", exc)
        return {"Error": "Could not parse the VirusTotal response."}
