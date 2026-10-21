import os
import requests

IPQS_API_KEY = os.environ.get("IPQS_API_KEY")

def lookup_phone(phone_number: str) -> dict:
    if not IPQS_API_KEY:
        return {"error": "IPQS API key is not configured in Render."}

    clean_phone = ''.join(c for c in phone_number if c.isdigit() or c == '+')
    if not clean_phone.startswith('+'):
        clean_phone = '+' + clean_phone

    url = f"https://ipqualityscore.com/api/json/phone/{IPQS_API_KEY}/{clean_phone}"
    
    try:
        response = requests.get(url, timeout=30)
        data = response.json()

        if not data.get("success", False):
            return {"error": data.get("message", "Unknown IPQS error.")}

        return {
            "phone": data.get("formatted", phone_number),
            "valid": "✅ Yes" if data.get("valid") else "❌ No",
            "active": "✅ Yes" if data.get("active") else "❌ No",
            "carrier": data.get("carrier", "Unknown"),
            "line_type": data.get("line_type", "Unknown"),
            "country": data.get("country", "Unknown"),
            "location": f"{data.get('city', 'N/A')}, {data.get('region', 'N/A')}",
            "fraud_score": data.get("fraud_score", 0),
            "risky": "⚠️ Yes" if data.get("risky") else "✅ No"
        }

    except Exception as e:
        return {"error": f"Request failed: {e}"}
