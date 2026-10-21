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
BLACKBIRD_SCRIPT = str(BLACKBIRD_DIR / "blackbird.py")
BLACKBIRD_WRAPPER = str(Path(__file__).resolve().parents[1] / "run_blackbird.py")
BLACKBIRD_TIMEOUT = 180
BLACKBIRD_MAX_CONCURRENT = 10

# Функция для удаления цветовых ANSI-кодов (те самые квадратики)
def strip_ansi(text: str) -> str:
    if not text:
        return ""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

def read_json_output(identifier: str) -> str:
    """Read JSON results for the exact identifier string (may include spaces)."""
    date_raw = datetime.now().strftime("%m_%d_%Y")
    
    variations = [identifier]
    if " " in identifier:
        variations += [
            identifier.replace(" ", ""),
            identifier.replace(" ", "_"),
            identifier.replace(" ", "-"),
            identifier.replace(" ", "."),
        ]
    
    all_variations = []
    for var in variations:
        all_variations.extend([var, var.lower(), var.upper()])
    
    seen = set()
    unique_variations = []
    for var in all_variations:
        if var not in seen:
            seen.add(var)
            unique_variations.append(var)
    
    results_dir = BLACKBIRD_DIR / "results"
    if results_dir.exists():
        for ident in unique_variations:
            json_file = results_dir / f"{ident}_{date_raw}_blackbird.json"
            try:
                if json_file.exists():
                    return json_file.read_text(encoding="utf-8")
            except Exception:
                pass
        
        for json_file in results_dir.glob("*.json"):
            try:
                if json_file.is_file():
                    filename = json_file.stem
                    if (identifier.lower() in filename.lower() or 
                        filename.lower() in identifier.lower() or
                        any(var.lower() in filename.lower() for var in variations)):
                        return json_file.read_text(encoding="utf-8")
            except Exception:
                pass
    
    for ident in unique_variations:
        base = BLACKBIRD_DIR / "results" / f"{ident}_{date_raw}_blackbird" / f"{ident}_{date_raw}_blackbird.json"
        try:
            if base.exists():
                return base.read_text(encoding="utf-8")
        except Exception:
            pass
    
    try:
        if results_dir.exists():
            for subdir in results_dir.iterdir():
                if subdir.is_dir() and "blackbird" in subdir.name:
                    json_file = subdir / f"{subdir.name}.json"
                    if json_file.exists():
                        dir_name = subdir.name.replace(f"_{date_raw}_blackbird", "")
                        if (identifier.lower() in dir_name.lower() or 
                            dir_name.lower() in identifier.lower() or
                            any(var.lower() in dir_name.lower() for var in variations)):
                            return json_file.read_text(encoding="utf-8")
    except Exception:
        pass
    
    return ""

async def stream_username(username: str):
    """Run Blackbird for the provided username string and stream progress lines."""
    cmd = [
        sys.executable,
        str(BLACKBIRD_DIR / "blackbird.py"),
        "-u",
        str(username),
        "--json",
        "--timeout",
        str(BLACKBIRD_TIMEOUT),
        "--max-concurrent-requests",
        str(BLACKBIRD_MAX_CONCURRENT),
        "--no-update",
    ]
    env = os.environ.copy()
    env.update({
        'PYTHONIOENCODING': 'utf-8',
        'TERM': 'dumb',
        'NO_COLOR': '1',
    })
    proc = await asyncio.create_subprocess_exec(
        *cmd, cwd=str(BLACKBIRD_DIR), stdout=PIPE, stderr=PIPE, env=env
    )
    if proc.stdout:
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            yield strip_ansi(line.decode("utf-8", errors="ignore").rstrip())
    await proc.wait()

async def stream_email(email: str):
    """Run Blackbird for the provided email string and stream progress lines."""
    cmd = [
        sys.executable,
        str(BLACKBIRD_DIR / "blackbird.py"),
        "-e",
        str(email),
        "--json",
        "--timeout",
        str(BLACKBIRD_TIMEOUT),
        "--max-concurrent-requests",
        str(BLACKBIRD_MAX_CONCURRENT),
        "--no-update",
    ]
    env = os.environ.copy()
    env.update({
        'PYTHONIOENCODING': 'utf-8',
        'TERM': 'dumb',
        'NO_COLOR': '1',
    })
    proc = await asyncio.create_subprocess_exec(
        *cmd, cwd=str(BLACKBIRD_DIR), stdout=PIPE, stderr=PIPE, env=env
    )
    if proc.stdout:
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            yield strip_ansi(line.decode("utf-8", errors="ignore").rstrip())
    await proc.wait()

def search_username(username: str) -> str:
    original = str(username)
    variants = [original]
    if " " in original:
        variants += [
            original.replace(" ", ""),
            original.replace(" ", "_"),
            original.replace(" ", "-"),
            original.replace(" ", "."),
        ]

    results = []
    for ident in variants:
        print(f"DEBUG: Searching for username variant: '{ident}'")
        
        cmd = [
            sys.executable,
            str(BLACKBIRD_DIR / "blackbird.py"),
            "-u",
            ident,
            "--json",
            "--timeout",
            str(BLACKBIRD_TIMEOUT),
            "--max-concurrent-requests",
            str(BLACKBIRD_MAX_CONCURRENT),
            "--no-update"
        ]
        
        print(f"DEBUG: Running command: {' '.join(cmd)}")
        
        try:
            # ИСПРАВЛЕНИЕ: Используем os.environ.copy(), чтобы не сломать систему
            env = os.environ.copy()
            env.update({
                'PYTHONIOENCODING': 'utf-8',
                'TERM': 'dumb',
                'NO_COLOR': '1'
            })
            
            result = subprocess.run(cmd, cwd=str(BLACKBIRD_DIR), shell=False, capture_output=True, text=True, timeout=180, env=env)
            
            print(f"DEBUG: Return code: {result.returncode}")
            
            time.sleep(5)
            
            json_text = read_json_output(ident)
            
            if json_text:
                results.append(json_text)
            elif result.stdout:
                # Очищаем вывод от цветовых кодов
                clean_stdout = strip_ansi(result.stdout)
                if len(clean_stdout.strip()) > 10:
                    results.append(clean_stdout)
                
        except subprocess.TimeoutExpired:
            print(f"DEBUG: Timeout for '{ident}'")
        except Exception as e:
            print(f"DEBUG: Error for '{ident}': {e}")
    
    if results:
        merged_items = []
        non_json_parts = []
        for part in results:
            try:
                data = json.loads(part)
                if isinstance(data, list):
                    merged_items.extend(data)
                else:
                    non_json_parts.append(part)
            except Exception:
                non_json_parts.append(part)
        if merged_items:
            try:
                return json.dumps(merged_items, ensure_ascii=False)
            except Exception:
                pass
        return "\n\n".join(non_json_parts)
    else:
        return ""

def scan_email(email: str) -> str:
    print(f"DEBUG: Scanning email: '{email}'")
    
    cmd = [
        sys.executable,
        str(BLACKBIRD_DIR / "blackbird.py"),
        "-e",
        str(email),
        "--json",
        "--timeout",
        str(BLACKBIRD_TIMEOUT),
        "--max-concurrent-requests",
        str(BLACKBIRD_MAX_CONCURRENT),
        "--no-update"
    ]
    
    try:
        env = os.environ.copy()
        env.update({
            'PYTHONIOENCODING': 'utf-8',
            'TERM': 'dumb',
            'NO_COLOR': '1',
        })
        
        result = subprocess.run(cmd, cwd=str(BLACKBIRD_DIR), shell=False, capture_output=True, text=True, timeout=180, env=env)
        
        json_text = read_json_output(str(email)) or ""
        
        if json_text:
            return json_text
        
        # Очищаем вывод от цветовых кодов перед отправкой
        output = result.stdout or result.stderr or ""
        output = strip_ansi(output)
        
        if output:
            lines = output.split('\n')
            filtered_lines = []
            for line in lines:
                line = line.strip()
                if (line and 
                    not line.startswith('Using Python:') and 
                    not line.startswith('🔄') and
                    not line.startswith('✔️') and
                    not line.startswith('🛰️') and
                    not line.startswith('🏁') and
                    not line.startswith('💾') and
                    'Enumerating accounts' not in line and
                    'Check completed' not in line and
                    'Saved results' not in line):
                    filtered_lines.append(line)
            
            output = '\n'.join(filtered_lines)
        
        if not output or len(output.strip()) < 10:
            return f"No email accounts found for {email}. This email may not be registered on any of the platforms we check, or the email format might not be valid."
        
        return output
        
    except subprocess.TimeoutExpired:
        return f"Email scan timed out for {email}. Please try again."
    except Exception as e:
        return f"Error scanning email {email}: {e}"
