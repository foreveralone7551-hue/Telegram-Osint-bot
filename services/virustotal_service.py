import os
import requests
import base64

VT_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
VT_URL = "https://www.virustotal.com/api/v3/urls"

def scan_link(url: str) -> str:
    if not VT_API_KEY:
        return "❌ Error: VirusTotal API key is not configured."

    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
    }

    try:
        # Encode URL to base64 without padding (VirusTotal API requirement)
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        
        # Request report
        response = requests.get(f"{VT_URL}/{url_id}", headers=headers)
        
        if response.status_code == 404:
            return "⚠️ Link has not been analyzed by VirusTotal yet. Try again later."
            
        if response.status_code != 200:
            return f"❌ VirusTotal API Error: {response.status_code} (Rate limit may be exceeded)."

        data = response.json()
        attributes = data.get("data", {}).get("attributes", {})
        
        stats = attributes.get("last_analysis_stats", {})
        results = attributes.get("last_analysis_results", {})
        
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected

        # Form header
        report = f"🔍 **VirusTotal Analysis for:** `{url}`\n\n"
        
        if malicious > 0 or suspicious > 0:
            report += f"🚨 **Warning! Threats detected:**\n"
            report += f"🔴 Malicious: {malicious}\n"
            report += f"🟡 Suspicious: {suspicious}\n\n"
            report += "**Detection Details:**\n"
            
            # Iterate through results and find those that detected a threat
            found_threats = False
            for vendor, result in results.items():
                category = result.get("category")
                if category in ["malicious", "suspicious"]:
                    threat_name = result.get("result", "Unknown")
                    report += f"• `{vendor}`: {threat_name}\n"
                    found_threats = True
            
            if not found_threats:
                report += "• Antiviruses did not provide threat names.\n"
        else:
            report += f"✅ **Link is safe**\n"
            report += f"🟢 Clean: {harmless + undetected} out of {total} engines.\n"

        # Add site categories (if available)
        categories = attributes.get("categories", {})
        if categories:
            cat_list = list(set(categories.values()))
            report += f"\n📁 **Categories:** {', '.join(cat_list)}\n"

        return report

    except Exception as e:
        return f"❌ Error checking link: {e}"
