
import html
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "reports"


def _safe_value(value):
    """Преобразует значение в удобный для HTML текст."""
    if value is None:
        return "N/A"

    if isinstance(value, (dict, list, tuple)):
        try:
            return json.dumps(
                value,
                ensure_ascii=False,
                indent=2,
                default=str,
            )
        except (TypeError, ValueError):
            return str(value)

    return str(value)


def _render_value(value):
    """Экранирует текст и создаёт ссылки только для HTTP(S)."""
    text = _safe_value(value)
    stripped = text.strip()

    try:
        parsed = urlsplit(stripped)
        is_url = (
            parsed.scheme.lower() in ("http", "https")
            and bool(parsed.hostname)
            and not any(char.isspace() for char in stripped)
        )
    except (ValueError, TypeError):
        is_url = False

    if is_url:
        safe_url = html.escape(stripped, quote=True)
        safe_text = html.escape(stripped)

        return (
            f'<a href="{safe_url}" '
            'target="_blank" rel="noopener noreferrer">'
            f"{safe_text}</a>"
        )

    return html.escape(text)


def _safe_filename(filename):
    """Оставляет только безопасное имя файла без пути к каталогам."""
    name = Path(str(filename or "report.html")).name
    name = re.sub(r"[^A-Za-z0-9_.-]", "_", name)

    if not name or name in (".", ".."):
        name = "report.html"

    if not name.lower().endswith(".html"):
        name += ".html"

    return name[:150]


def generate_html_report(
    title: str,
    data_dict: dict,
    filename: str = "report.html",
) -> str:
    """
    Создаёт HTML-отчёт Aegis Recon.
    Возвращает полный путь к созданному файлу.
    """

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    safe_title = html.escape(str(title or "Untitled report"))
    safe_name = _safe_filename(filename)
    report_path = REPORTS_DIR / safe_name

    if not isinstance(data_dict, dict):
        data_dict = {"Result": data_dict}

    if data_dict:
        rows = []

        for key, value in data_dict.items():
            safe_key = html.escape(str(key))
            rendered_value = _render_value(value)

            rows.append(
                f"""
                <tr>
                    <th scope="row" class="key">{safe_key}</th>
                    <td class="value">{rendered_value}</td>
                </tr>
                """
            )

        rows_html = "\n".join(rows)
    else:
        rows_html = """
        <tr>
            <td colspan="2" class="empty">
                No data available for this report.
            </td>
        </tr>
        """

    generated_at = datetime.now(timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )

    document = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="color-scheme" content="dark">
    <title>Aegis Recon | {safe_title}</title>
    <style>
        :root {{
            color-scheme: dark;
            --bg: #0b1020;
            --panel: #121a2b;
            --panel-light: #18243a;
            --text: #e5edf8;
            --muted: #8da2bf;
            --accent: #55b7ff;
            --border: #263750;
        }}

        * {{
            box-sizing: border-box;
        }}

        body {{
            margin: 0;
            padding: 32px 16px;
            background:
                radial-gradient(
                    ellipse at top,
                    #152746 0%,
                    var(--bg) 55%
                );
            color: var(--text);
            font-family:
                -apple-system, BlinkMacSystemFont, "Segoe UI",
                Roboto, Helvetica, Arial, sans-serif;
            line-height: 1.6;
            overflow-wrap: anywhere;
        }}

        .container {{
            width: 100%;
            max-width: 900px;
            margin: 0 auto;
        }}

        .header {{
            text-align: center;
            padding: 28px 16px;
            margin-bottom: 24px;
            border: 1px solid var(--border);
            border-radius: 18px;
            background: rgba(18, 26, 43, 0.92);
        }}

        .logo {{
            font-size: 14px;
            font-weight: 800;
            letter-spacing: 4px;
            color: var(--accent);
            text-transform: uppercase;
        }}

        h1 {{
            margin: 12px 0 4px;
            font-size: clamp(25px, 5vw, 36px);
            line-height: 1.2;
        }}

        .subtitle {{
            color: var(--muted);
            font-size: 13px;
            margin-top: 12px;
        }}

        .status {{
            display: inline-block;
            margin-top: 14px;
            padding: 5px 12px;
            border: 1px solid #245c50;
            border-radius: 999px;
            color: #72e0b3;
            background: #102c29;
            font-size: 12px;
            font-weight: 700;
        }}

        .card {{
            overflow: hidden;
            border: 1px solid var(--border);
            border-radius: 18px;
            background: var(--panel);
            box-shadow: 0 16px 45px rgba(0, 0, 0, 0.22);
        }}

        .card-header {{
            padding: 22px 24px;
            background: var(--panel-light);
            border-bottom: 1px solid var(--border);
        }}

        .card-header h2 {{
            margin: 0;
            color: var(--accent);
            font-size: 19px;
            overflow-wrap: anywhere;
        }}

        .card-header p {{
            margin: 6px 0 0;
            color: var(--muted);
            font-size: 12px;
        }}

        .table-wrap {{
            width: 100%;
            overflow-x: auto;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            table-layout: fixed;
        }}

        th, td {{
            padding: 16px 24px;
            text-align: left;
            vertical-align: top;
            border-bottom: 1px solid var(--border);
            overflow-wrap: anywhere;
            word-break: break-word;
        }}

        tbody tr:last-child th,
        tbody tr:last-child td {{
            border-bottom: 0;
        }}

        tbody tr:nth-child(even) {{
            background: rgba(255, 255, 255, 0.018);
        }}

        th.key {{
            width: 34%;
            color: var(--muted);
            font-size: 13px;
            font-weight: 700;
        }}

        td.value {{
            color: var(--text);
            font-size: 14px;
            white-space: pre-wrap;
        }}

        a {{
            color: var(--accent);
            text-decoration: none;
        }}

        a:hover {{
            text-decoration: underline;
        }}

        .empty {{
            padding: 30px;
            text-align: center;
            color: var(--muted);
        }}

        .footer {{
            margin-top: 24px;
            text-align: center;
            color: var(--muted);
            font-size: 12px;
        }}

        .footer strong {{
            color: var(--accent);
        }}

        @media (max-width: 560px) {{
            body {{
                padding: 16px 10px;
            }}

            .header {{
                padding: 22px 12px;
            }}

            .card-header {{
                padding: 18px 14px;
            }}

            th, td {{
                padding: 12px 10px;
                font-size: 12px;
            }}

            th.key {{
                width: 36%;
                font-size: 12px;
            }}

            td.value {{
                font-size: 12px;
            }}
        }}
    </style>
</head>
<body>
    <main class="container">
        <header class="header">
            <div class="logo">AEGIS RECON</div>
            <h1>Intelligence Report</h1>
            <div class="subtitle">
                Generated: {generated_at}
            </div>
            <div class="status">REPORT GENERATED</div>
        </header>

        <section class="card">
            <div class="card-header">
                <h2>Target: {safe_title}</h2>
                <p>Structured analysis results</p>
            </div>

            <div class="table-wrap">
                <table>
                    <tbody>
                        {rows_html}
                    </tbody>
                </table>
            </div>
        </section>

        <footer class="footer">
            <strong>Aegis Recon</strong><br>
            For lawful and authorized investigations only.
        </footer>
    </main>
</body>
</html>
"""

    try:
        report_path.write_text(document, encoding="utf-8")
        logger.info("HTML report generated: %s", report_path)
        return str(report_path)
    except OSError:
        logger.exception("Could not write HTML report")
        raise
