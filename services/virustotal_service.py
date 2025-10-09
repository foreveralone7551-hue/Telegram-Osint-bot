import os
import requests
import html
import re
from urllib.parse import urlparse


def _normalize_url(link: str) -> str:
	"""Fix common OSINT-safe formats and expand shorteners (e.g., vm.tiktok.com)."""
	if not link:
		return link
	# Convert hxxp/hxxps to http/https
	link = re.sub(r"^hxxps://", "https://", link, flags=re.IGNORECASE)
	link = re.sub(r"^hxxp://", "http://", link, flags=re.IGNORECASE)
	# Add scheme if missing
	if not re.match(r"^https?://", link, flags=re.IGNORECASE):
		link = "https://" + link
	# Try to expand shorteners (vm.tiktok.com and others)
	try:
		resp = requests.get(link, allow_redirects=True, timeout=12, headers={"User-Agent": "Mozilla/5.0"})
		final_url = resp.url or link
		return final_url
	except Exception:
		return link


def scan_link(link: str) -> str:
	"""Scan a URL with VirusTotal v3 and return a simple verdict summary."""
	api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
	if not api_key:
		return "VirusTotal API key not configured. Add VIRUSTOTAL_API_KEY to .env."
	# Normalize and expand URL before submitting to VT
	link = _normalize_url(link)
	try:
		resp = requests.post(
			"https://www.virustotal.com/api/v3/urls",
			headers={"x-apikey": api_key},
			data={"url": link},
			timeout=30,
		)
		resp.raise_for_status()
		url_id = resp.json().get("data", {}).get("id")
		if not url_id:
			return "Could not submit URL to VirusTotal."
		analysis = requests.get(
			f"https://www.virustotal.com/api/v3/analyses/{url_id}",
			headers={"x-apikey": api_key},
			timeout=30,
		).json()
		stats = analysis.get("data", {}).get("attributes", {}).get("stats", {})
		mal = int(stats.get("malicious", 0))
		susp = int(stats.get("suspicious", 0))
		und = int(stats.get("undetected", 0))
		harmless = int(stats.get("harmless", 0))
		flagged = mal + susp
		total = max(mal + susp + harmless + und, 1)
		percent = round((flagged / total) * 100)
		# Minimal, user-friendly output
		if mal == 0 and susp == 0:
			return "Link is safe 😊"
		elif mal == 0 and susp > 0:
			return "Link may be risky ⚠️"
		else:
			return "Link is NOT safe ❌"
	except Exception as e:
		return f"VirusTotal error: {e}"


def scan_ip(ip: str) -> str:
	return "IP investigation removed."

