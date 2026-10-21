import subprocess
import os
import sys
import json
import re
import time
from pathlib import Path
from datetime import datetime
import asyncio
from asyncio.subprocess import PIPE

BLACKBIRD_DIR = Path(__file__).resolve().parents[1] / "blackbird-osint"
BLACKBIRD_TIMEOUT = 180
BLACKBIRD_MAX_CONCURRENT = 10

def strip_ansi(text: str) -> str:
    if not text:
        return ""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

def read_json_output(identifier: str) -> str:
    date_raw = datetime.now().strftime("%m_%d_%Y")
    results_dir = BLACKBIRD_DIR / "results"
    if results_dir.exists():
        json_file = results_dir / f"{identifier}_{date_raw}_blackbird.json"
        try:
            if json_file.exists():
                return json_file.read_text(encoding="utf-8")
        except Exception:
            pass
    return ""

def format_results(raw_output: str) -> str:
    """Пытается вытащить красивые ссылки из JSON или текста Blackbird"""
    if not raw_output:
        return ""
    
    # Пытаемся найти JSON внутри текста
    json_match = re.search(r'\[.*\]', raw_output, re.DOTALL)
    if json_match:
        try:
            data = json.loads(json_match.group(0))
            if isinstance(data, list) and len(data) > 0:
                formatted = []
                for item in data:
                    if isinstance(item, dict) and item.get('url'):
                        site = item.get('site', 'Unknown')
                        url = item.get('url')
                        formatted.append(f"🔗 {site}: {url}")
                if formatted:
                    return "\n".join(formatted)
        except json.JSONDecodeError:
            pass
    
    # Если JSON не нашли, очищаем текст от мусора
    clean_text = strip_ansi(raw_output)
    valid_lines = []
    for line in clean_text.split('\n'):
        line = line.strip()
        # Берем строки, где есть хоть что-то похожее на результат
        if "http" in line or "Found" in line or "[+]" in line:
            valid_lines.append(line)
    
    return "\n".join(valid_lines)

async def stream_username(username: str):
    cmd = [sys.executable, str(BLACKBIRD_DIR / "blackbird.py"), "-u", str(username), "--json", "--timeout", str(BLACKBIRD_TIMEOUT), "--no-update"]
    env = os.environ.copy()
    env.update({'PYTHONIOENCODING': 'utf-8', 'TERM': 'dumb', 'NO_COLOR': '1'})
    proc = await asyncio.create_subprocess_exec(*cmd, cwd=str(BLACKBIRD_DIR), stdout=PIPE, stderr=PIPE, env=env)
    if proc.stdout:
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            yield strip_ansi(line.decode("utf-8", errors="ignore").rstrip())
    await proc.wait()

async def stream_email(email: str):
    cmd = [sys.executable, str(BLACKBIRD_DIR / "blackbird.py"), "-e", str(email), "--json", "--timeout", str(BLACKBIRD_TIMEOUT), "--no-update"]
    env = os.environ.copy()
    env.update({'PYTHONIOENCODING': 'utf-8', 'TERM': 'dumb', 'NO_COLOR': '1'})
    proc = await asyncio.create_subprocess_exec(*cmd, cwd=str(BLACKBIRD_DIR), stdout=PIPE, stderr=PIPE, env=env)
    if proc.stdout:
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            yield strip_ansi(line.decode("utf-8", errors="ignore").rstrip())
    await proc.wait()

def search_username(username: str) -> str:
    cmd = [sys.executable, str(BLACKBIRD_DIR / "blackbird.py"), "-u", username, "--json", "--timeout", str(BLACKBIRD_TIMEOUT), "--no-update"]
    try:
        env = os.environ.copy()
        env.update({'PYTHONIOENCODING': 'utf-8', 'TERM': 'dumb', 'NO_COLOR': '1'})
        result = subprocess.run(cmd, cwd=str(BLACKBIRD_DIR), capture_output=True, text=True, timeout=180, env=env)
        
        json_text = read_json_output(username)
        if json_text:
            return format_results(json_text)
        
        clean_stdout = format_results(result.stdout or "")
        if clean_stdout:
            return clean_stdout
            
        return f"Поиск {username} завершен. Аккаунты не найдены (возможно, блокировка IP)."
    except Exception as e:
        return f"Ошибка поиска: {e}"

def scan_email(email: str) -> str:
    cmd = [sys.executable, str(BLACKBIRD_DIR / "blackbird.py"), "-e", email, "--json", "--timeout", str(BLACKBIRD_TIMEOUT), "--no-update"]
    try:
        env = os.environ.copy()
        env.update({'PYTHONIOENCODING': 'utf-8', 'TERM': 'dumb', 'NO_COLOR': '1'})
        result = subprocess.run(cmd, cwd=str(BLACKBIRD_DIR), capture_output=True, text=True, timeout=180, env=env)
        
        json_text = read_json_output(email)
        if json_text:
            return format_results(json_text)
            
        clean_stdout = format_results(result.stdout or "")
        if clean_stdout:
            return clean_stdout
            
        return f"Поиск {email} завершен. Аккаунты не найдены."
    except Exception as e:
        return f"Ошибка поиска: {e}"
