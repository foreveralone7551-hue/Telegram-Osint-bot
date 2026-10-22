
import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

BLACKBIRD_DIR = Path(__file__).resolve().parents[1] / "blackbird-osint"
BLACKBIRD_SCRIPT = BLACKBIRD_DIR / "blackbird.py"
BLACKBIRD_TIMEOUT = 180


def strip_ansi(text: str) -> str:
    if not text:
        return ""
    ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
    return ansi_escape.sub("", text)


def _environment() -> dict:
    env = os.environ.copy()
    env.update({
        "PYTHONIOENCODING": "utf-8",
        "TERM": "dumb",
        "NO_COLOR": "1",
    })
    return env


def _extract_json(text: str) -> Any:
    """Extract JSON from plain output, including output with surrounding logs."""
    if not text:
        return None

    cleaned = strip_ansi(text).strip()

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    decoder = json.JSONDecoder()

    for index, char in enumerate(cleaned):
        if char not in "[{":
            continue
        try:
            data, _ = decoder.raw_decode(cleaned[index:])
            return data
        except json.JSONDecodeError:
            continue

    return None


def _format_json(data: Any) -> str:
    """Convert common Blackbird JSON result structures into readable text."""
    if isinstance(data, dict):
        # Some versions wrap results in a top-level key.
        for key in ("results", "sites", "data", "accounts", "matches"):
            value = data.get(key)
            if isinstance(value, (list, dict)):
                formatted = _format_json(value)
                if formatted:
                    return formatted

        url = data.get("url") or data.get("link")
        site = (
            data.get("site")
            or data.get("name")
            or data.get("platform")
            or data.get("website")
            or "Unknown site"
        )

        if url and isinstance(url, str):
            return f"🔗 {site}: {url}"

        lines = []
        for key, value in data.items():
            if isinstance(value, (dict, list)):
                nested = _format_json(value)
                if nested:
                    lines.append(nested)
            elif value not in (None, ""):
                lines.append(f"{key}: {value}")
        return "\n".join(lines)

    if isinstance(data, list):
        lines = []
        for item in data:
            formatted = _format_json(item)
            if formatted:
                lines.append(formatted)
        return "\n".join(lines)

    if isinstance(data, str):
        return data.strip()

    return ""


def _read_json_output(identifier: str) -> str:
    """Look for JSON reports created by Blackbird."""
    results_dir = BLACKBIRD_DIR / "results"
    if not results_dir.exists():
        return ""

    safe_identifier = re.sub(r"[^a-zA-Z0-9_.@+-]", "_", identifier)
    today = datetime.now().strftime("%m_%d_%Y")

    candidates = [
        results_dir / f"{safe_identifier}_{today}_blackbird.json",
        results_dir / f"{identifier}_{today}_blackbird.json",
    ]

    for path in candidates:
        try:
            if path.is_file():
                content = path.read_text(encoding="utf-8", errors="replace")
                if content.strip():
                    return content
        except OSError:
            continue

    # Some versions use a slightly different filename.
    try:
        matching = sorted(
            results_dir.glob("*blackbird.json"),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        for path in matching[:10]:
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
                if safe_identifier.lower() in path.name.lower() and content.strip():
                    return content
            except OSError:
                continue
    except OSError:
        pass

    return ""


def format_results(raw_output: str) -> str:
    if not raw_output:
        return ""

    data = _extract_json(raw_output)
    if data is not None:
        formatted = _format_json(data)
        if formatted:
            return formatted

    cleaned = strip_ansi(raw_output)
    useful_lines = []

    for line in cleaned.splitlines():
        line = line.strip()
        if not line:
            continue

        # Avoid presenting raw JSON punctuation as useful output.
        if line in ("[", "]", "{", "}", "},", "],"):
            continue

        if (
            "http://" in line
            or "https://" in line
            or "[+]" in line
            or "found" in line.lower()
            or "error" in line.lower()
            or "failed" in line.lower()
        ):
            useful_lines.append(line)

    return "\n".join(useful_lines)


def _run_blackbird(mode: str, target: str) -> str:
    if not target or not target.strip():
        return "Ошибка: укажи имя пользователя или email."

    if not BLACKBIRD_SCRIPT.is_file():
        return (
            "Ошибка Blackbird: файл blackbird.py не найден.\n"
            f"Ожидаемый путь: {BLACKBIRD_SCRIPT}\n"
            "Проверь, что папка blackbird-osint загружена в GitHub."
        )

    if mode == "username":
        args = ["-u", target]
    elif mode == "email":
        args = ["-e", target]
    else:
        return "Ошибка: неизвестный тип поиска."

    cmd = [
        sys.executable,
        str(BLACKBIRD_SCRIPT),
        *args,
        "--json",
        "--timeout",
        str(BLACKBIRD_TIMEOUT),
        "--no-update",
    ]

    try:
        result = subprocess.run(
            cmd,
            cwd=str(BLACKBIRD_DIR),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=BLACKBIRD_TIMEOUT + 30,
            env=_environment(),
            check=False,
        )

        stdout = strip_ansi(result.stdout or "")
        stderr = strip_ansi(result.stderr or "")

        # Prefer the report generated by this Blackbird run.
        json_text = _read_json_output(target)
        if json_text:
            formatted = format_results(json_text)
            if formatted:
                return formatted

        formatted_stdout = format_results(stdout)
        if formatted_stdout:
            return formatted_stdout

        if result.returncode != 0:
            details = (stderr or stdout).strip()
            if len(details) > 2500:
                details = details[-2500:]
            if not details:
                details = "Blackbird завершился без подробностей об ошибке."

            return (
                f"Ошибка Blackbird (код {result.returncode}).\n"
                f"{details}"
            )

        if stderr.strip():
            # Preserve useful diagnostics when the program emits no results.
            useful_stderr = stderr.strip()
            if len(useful_stderr) > 1500:
                useful_stderr = useful_stderr[-1500:]
            return (
                "Blackbird завершил работу, но не вернул распознанных результатов.\n"
                f"Сообщение программы:\n{useful_stderr}"
            )

        return (
            f"Blackbird завершил поиск {target}, но не вернул распознанных результатов. "
            "Это не подтверждает, что аккаунтов нет. Проверь логи Render и формат "
            "JSON, который создаёт установленная версия Blackbird."
        )

    except subprocess.TimeoutExpired:
        return (
            f"Поиск {target} остановлен: превышено время ожидания "
            f"({BLACKBIRD_TIMEOUT + 30} секунд)."
        )
    except OSError as exc:
        return f"Не удалось запустить Blackbird: {exc}"
    except Exception as exc:
        return f"Непредвиденная ошибка Blackbird: {type(exc).__name__}: {exc}"


def search_username(username: str) -> str:
    return _run_blackbird("username", username)


def scan_email(email: str) -> str:
    return _run_blackbird("email", email)
