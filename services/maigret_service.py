import subprocess
import os
from pathlib import Path

REPORTS_DIR = Path("reports")
REPORTS_DIR.mkdir(exist_ok=True)

def run_maigret(username: str) -> str:
    """Запускает Maigret и возвращает путь к HTML-отчету."""
    report_filename = f"report_{username}.html"
    report_path = REPORTS_DIR / report_filename

    cmd = [
        "maigret", username,
        "--html",
        "--folderoutput", str(REPORTS_DIR),
        "--timeout", "15",
        "--no-color"
    ]

    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if report_path.exists():
            return str(report_path)
        return None
    except Exception as e:
        print(f"Maigret error: {e}")
        return None
