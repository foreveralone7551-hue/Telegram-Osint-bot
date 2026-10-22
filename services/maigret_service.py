import html
import logging
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
from bs4 import BeautifulSoup
BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
logger = logging.getLogger("aegis.maigret")
MAIGRET_TIMEOUT = 300
SITE_TIMEOUT = 15
def safe_name(value: str) -> str:
    value = re.sub(r"[^a-zA-Z0-9_.-]", "_", value)
    return value[:80] or "username"
def is_http_url(value: str) -> bool:
    try:
        parsed = urlparse(value)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False
def get_platform(url: str, anchor_text: str = "") -> str:
    """Определяет платформу по адресу, не выдумывая сведения об аккаунте."""
    host = (urlparse(url).hostname or "").lower()
    host = host.removeprefix("www.")
    known = {
        "github.com": "GitHub",
        "gist.github.com": "GitHub Gist",
        "gitlab.com": "GitLab",
        "reddit.com": "Reddit",
        "x.com": "X",
        "twitter.com": "Twitter",
        "instagram.com": "Instagram",
        "facebook.com": "Facebook",
        "tiktok.com": "TikTok",
        "youtube.com": "YouTube",
        "t.me": "Telegram",
        "medium.com": "Medium",
        "pinterest.com": "Pinterest",
        "linkedin.com": "LinkedIn",
        "tumblr.com": "Tumblr",
        "keybase.io": "Keybase",
        "replit.com": "Replit",
        "stackoverflow.com": "Stack Overflow",
        "soundcloud.com": "SoundCloud",
        "itch.io": "itch.io",
        "steamcommunity.com": "Steam",
        "pastebin.com": "Pastebin",
    }
    for domain, name in known.items():
        if host == domain or host.endswith("." + domain):
            return name
    if anchor_text.strip():
        return anchor_text.strip()[:80]
    return host or "Website"
def collect_accounts(source_path: Path):
    """Извлекает ссылки из HTML-отчёта Maigret."""
    soup = BeautifulSoup(
        source_path.read_text(encoding="utf-8", errors="replace"),
        "html.parser",
    )
    accounts = []
    seen = set()
    ignored_hosts = (
        "web.archive.org",
        "archive.is",
        "archive.org",
    )
    for anchor in soup.find_all("a", href=True):
        url = anchor.get("href", "").strip()
        if not is_http_url(url):
            continue
        host = (urlparse(url).hostname or "").lower()
        if any(host == item or host.endswith("." + item) for item in ignored_hosts):
            continue
        if url in seen:
            continue
        seen.add(url)
        label = anchor.get_text(" ", strip=True)
        platform = get_platform(url, label)
        # Берём краткий текст из ближайшего элемента отчёта,
        # если он существует. Полный HTML не вставляем в новый отчёт.
        parent = anchor.find_parent(["tr", "li", "article", "div"])
        details = ""
        if parent:
            details = parent.get_text(" ", strip=True)
            details = re.sub(r"\s+", " ", details).strip()
            details = details[:350]
        if not label:
            label = platform
        accounts.append({
            "platform": platform,
            "url": url,
            "label": label[:120],
            "details": details,
        })
    return accounts
def build_html_report(username: str, source_path: Path, output_path: Path):
    accounts = collect_accounts(source_path)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    cards = []
    for item in accounts:
        platform = html.escape(item["platform"])
        url = html.escape(item["url"], quote=True)
        label = html.escape(item["label"])
        details = html.escape(item["details"])
        cards.append(f"""
        <article class="account">
            <div class="platform">{platform}</div>
            <div class="account-title">{label}</div>
            <p class="details">{details or "Дополнительные сведения отсутствуют в исходном отчёте."}</p>
            <a class="open-link" href="{url}" target="_blank"
               rel="noopener noreferrer">Открыть профиль ↗</a>
            <div class="raw-url">{url}</div>
        </article>
        """)
    if cards:
        cards_html = "\n".join(cards)
    else:
        cards_html = """
        <div class="empty">
            <div class="empty-icon">⌕</div>
            <h2>Профили не извлечены</h2>
            <p>Maigret мог завершить поиск, но автоматическое извлечение
            ссылок из исходного отчёта не нашло подходящих адресов.
            Это не обязательно означает, что аккаунтов нет.</p>
        </div>
        """
    safe_username = html.escape(username)
    total = len(accounts)
    document = f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<title>Aegis Recon — {safe_username}</title>
<style>
:root {{
    --bg: #070b14;
    --panel: #101827;
    --panel2: #0b1220;
    --line: #20324b;
    --blue: #08b9ff;
    --text: #edf5ff;
    --muted: #91a5bf;
}}
* {{ box-sizing: border-box; }}
body {{
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    line-height: 1.55;
}}
.container {{
    width: min(100% - 28px, 920px);
    margin: 0 auto;
    padding: 28px 0 48px;
}}
.header {{
    border: 1px solid var(--line);
    border-radius: 20px;
    padding: 24px;
    background: linear-gradient(135deg, #101e33, #090e18 70%);
    box-shadow: 0 12px 40px #0005;
}}
.brand {{
    color: var(--blue);
    font-size: 12px;
    font-weight: 800;
    letter-spacing: 3px;
}}
h1 {{
    font-size: clamp(25px, 6vw, 40px);
    margin: 12px 0 4px;
    overflow-wrap: anywhere;
}}
.subtitle {{ color: var(--muted); margin: 0; }}
.stats {{
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 12px;
    margin-top: 18px;
}}
.stat {{
    background: #070d18b8;
    border: 1px solid var(--line);
    border-radius: 14px;
    padding: 14px;
    min-width: 0;
}}
.stat-label {{
    color: var(--muted);
    font-size: 12px;
}}
.stat-value {{
    font-size: 22px;
    font-weight: 750;
    overflow-wrap: anywhere;
}}
.section-title {{
    margin: 28px 0 14px;
    font-size: 19px;
}}
.accounts {{
    display: grid;
    gap: 14px;
}}
.account {{
    min-width: 0;
    padding: 19px;
    background: var(--panel);
    border: 1px solid var(--line);
    border-radius: 16px;
    overflow-wrap: anywhere;
}}
.platform {{
    color: var(--blue);
    font-size: 12px;
    font-weight: 800;
    text-transform: uppercase;
    letter-spacing: 1.2px;
}}
.account-title {{
    font-size: 18px;
    font-weight: 700;
    margin-top: 7px;
}}
.details {{
    color: var(--muted);
    font-size: 13px;
    margin: 10px 0 16px;
    overflow-wrap: anywhere;
}}
.open-link {{
    display: inline-block;
    color: #04101a;
    background: var(--blue);
    border-radius: 10px;
    padding: 10px 14px;
    text-decoration: none;
    font-weight: 800;
}}
.raw-url {{
    color: var(--muted);
    font-size: 11px;
    margin-top: 12px;
    overflow-wrap: anywhere;
}}
.empty {{
    padding: 25px;
    border: 1px solid var(--line);
    background: var(--panel);
    border-radius: 16px;
}}
.empty-icon {{
    color: var(--blue);
    font-size: 36px;
}}
.footer {{
    text-align: center;
    color: var(--muted);
    font-size: 12px;
    margin-top: 30px;
}}
.notice {{
    margin-top: 16px;
    padding: 12px 14px;
    border-left: 3px solid var(--blue);
    background: var(--panel2);
    color: var(--muted);
    font-size: 12px;
}}
@media (max-width: 480px) {{
    .container {{ width: min(100% - 20px, 920px); padding-top: 12px; }}
    .header {{ padding: 18px; border-radius: 16px; }}
    .account {{ padding: 16px; }}
    .stats {{ gap: 8px; }}
    .stat {{ padding: 11px; }}
}}
</style>
</head>
<body>
<main class="container">
    <header class="header">
        <div class="brand">AEGIS RECON / OSINT</div>
        <h1>Username Report</h1>
        <p class="subtitle">Результаты поиска по имени пользователя</p>
        <div class="stats">
            <div class="stat">
                <div class="stat-label">USERNAME</div>
                <div class="stat-value">{safe_username}</div>
            </div>
            <div class="stat">
                <div class="stat-label">Извлечено ссылок</div>
                <div class="stat-value">{total}</div>
            </div>
        </div>
        <div class="notice">
            Отчёт сформирован автоматически на основе HTML Maigret.
            Наличие ссылки не гарантирует, что аккаунт принадлежит
            конкретному человеку. Результаты требуют проверки.
        </div>
    </header>
    <h2 class="section-title">Найденные ссылки</h2>
    <section class="accounts">
        {cards_html}
    </section>
    <footer class="footer">
        AEGIS RECON · Создано {html.escape(now)}<br>
        Используйте результаты законно и ответственно.
    </footer>
</main>
</body>
</html>
"""
    output_path.write_text(document, encoding="utf-8")
    return output_path
def run_maigret(username: str):
    """Запускает Maigret и возвращает путь к оформленному HTML-отчёту."""
    username = (username or "").strip()
    if not username or len(username) > 100:
        logger.warning("Invalid username supplied.")
        return None
    safe_username = safe_name(username)
    started_at = time.time()
    # Запоминаем исходные HTML-файлы, чтобы не принять старый отчёт
    # за результат текущего поиска.
    before = {}
    for path in REPORTS_DIR.rglob("*.html"):
        try:
            before[str(path.resolve())] = path.stat().st_mtime
        except OSError:
            pass
    command = [
        "maigret",
        username,
        "--html",
        "--folderoutput",
        str(REPORTS_DIR),
        "--timeout",
        str(SITE_TIMEOUT),
        "--no-color",
    ]
    logger.info("Starting Maigret for username=%s", username)
    try:
        result = subprocess.run(
            command,
            cwd=str(BASE_DIR),
            capture_output=True,
            text=True,
            timeout=MAIGRET_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        logger.error("Maigret timed out for username=%s", username)
        return None
    except FileNotFoundError:
        logger.exception("Maigret executable was not found.")
        return None
    except Exception:
        logger.exception("Could not run Maigret.")
        return None
    if result.returncode != 0:
        logger.warning(
            "Maigret exited with code %s. stderr=%s",
            result.returncode,
            (result.stderr or "")[-1500:],
        )
    candidates = []
    for path in REPORTS_DIR.rglob("*.html"):
        try:
            resolved = str(path.resolve())
            modified = path.stat().st_mtime
            if modified >= started_at - 2:
                candidates.append(path)
            elif resolved not in before:
                candidates.append(path)
            elif modified > before.get(resolved, 0):
                candidates.append(path)
        except OSError:
            continue
    if not candidates:
        logger.error(
            "No new Maigret HTML report found for username=%s. stdout=%s stderr=%s",
            username,
            (result.stdout or "")[-1000:],
            (result.stderr or "")[-1000:],
        )
        return None
    # Самый свежий HTML — вероятнее всего, отчёт текущего запуска.
    source_path = max(candidates, key=lambda path: path.stat().st_mtime)
    output_path = REPORTS_DIR / f"aegis_{safe_username}_{int(time.time())}.html"
    try:
        build_html_report(username, source_path, output_path)
    except Exception:
        logger.exception("Could not build custom Aegis HTML report.")
        return None
    logger.info(
        "Aegis report created: %s",
        output_path.name,
    )
    return str(output_path)
