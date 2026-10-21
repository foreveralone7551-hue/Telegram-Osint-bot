import os
import requests
import base64

VT_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
VT_URL = "https://www.virustotal.com/api/v3/urls"

def scan_link(url: str) -> str:
    if not VT_API_KEY:
        return "❌ Ошибка: API-ключ VirusTotal не настроен."

    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
    }

    try:
        # Кодируем URL в base64 без padding (требование VirusTotal API)
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        
        # Запрашиваем отчет
        response = requests.get(f"{VT_URL}/{url_id}", headers=headers)
        
        if response.status_code == 404:
            return "⚠️ Ссылка еще не проверялась VirusTotal. Попробуйте позже (базе нужно время на анализ)."
            
        if response.status_code != 200:
            return f"❌ Ошибка API VirusTotal: {response.status_code} (Возможно, превышен лимит запросов)."

        data = response.json()
        attributes = data.get("data", {}).get("attributes", {})
        
        stats = attributes.get("last_analysis_stats", {})
        results = attributes.get("last_analysis_results", {})
        
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected

        # Формируем заголовок
        report = f"🔍 **Анализ VirusTotal для:** `{url}`\n\n"
        
        if malicious > 0 or suspicious > 0:
            report += f"🚨 **Внимание! Обнаружены угрозы:**\n"
            report += f"🔴 Вредоносных: {malicious}\n"
            report += f"🟡 Подозрительных: {suspicious}\n\n"
            report += "**Детали детектов:**\n"
            
            # Проходимся по результатам и ищем тех, кто нашел угрозу
            found_threats = False
            for vendor, result in results.items():
                category = result.get("category")
                if category in ["malicious", "suspicious"]:
                    threat_name = result.get("result", "Unknown")
                    report += f"• `{vendor}`: {threat_name}\n"
                    found_threats = True
            
            if not found_threats:
                report += "• Антивирусы не предоставили названия угроз.\n"
        else:
            report += f"✅ **Ссылка безопасна**\n"
            report += f"🟢 Чисто: {harmless + undetected} из {total} движков.\n"

        # Добавляем категории сайта (если есть)
        categories = attributes.get("categories", {})
        if categories:
            cat_list = list(set(categories.values()))
            report += f"\n📁 **Категории:** {', '.join(cat_list)}\n"

        return report

    except Exception as e:
        return f"❌ Ошибка при проверке ссылки: {e}"
