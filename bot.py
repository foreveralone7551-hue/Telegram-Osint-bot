# -*- coding: utf-8 -*-
import os
import re
import asyncio
import logging
from pathlib import Path
from urllib.parse import urlsplit

import requests
from dotenv import load_dotenv
from telegram import (
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    BotCommand,
    MenuButtonCommands,
    Update,
)
from telegram.constants import ChatAction
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    CallbackQueryHandler,
    MessageHandler,
    ContextTypes,
    filters,
    ChatMemberHandler,
)

from services import blackbird_service, virustotal_service
from phone import lookup_phone
from utils.pdf_generator import generate_html_report
from services.maigret_service import run_maigret


# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
LOG_PATH = BASE_DIR / "bot.log"
BANNER_PATH = BASE_DIR / "assets" / "aegis_banner.png"
REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(exist_ok=True)
MAX_TRACKED_MESSAGES = 100

load_dotenv(BASE_DIR / ".env", override=False)


def normalize(value):
    if not value:
        return ""
    return value.strip().strip('"').strip("'").lstrip("\ufeff")


TOKEN = normalize(os.getenv("TELEGRAM_TOKEN")) or normalize(
    os.getenv("TELEGRAM_BOT_TOKEN")
)

if not TOKEN:
    raise RuntimeError(
        "Telegram token is missing. Set TELEGRAM_TOKEN "
        "or TELEGRAM_BOT_TOKEN in Render Environment."
    )

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(LOG_PATH, encoding="utf-8"),
    ],
)
logger = logging.getLogger("aegis")
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("telegram.request").setLevel(logging.WARNING)


# --------------------------------------------------
# LANGUAGES
# Each user's choice is stored in context.user_data.
# New users default to English.
# --------------------------------------------------

LANGUAGES = {
    "en": {"flag": "🇺🇸", "name": "English"},
    "ru": {"flag": "🇷🇺", "name": "Русский"},
    "pl": {"flag": "🇵🇱", "name": "Polski"},
}

TEXT = {
    "en": {
        "language_button": "🇺🇸 Language",
        "start_button": "🔍 Start Recon",
        "delete_button": "🗑 Delete Chat",
        "welcome": (
            "🛡️ *Aegis Recon*\n\n"
            "OSINT analysis toolkit.\n\n"
            "*Available modules:*\n"
            "• Username Search — Blackbird\n"
            "• Deep Search — Maigret\n"
            "• Email Scan — Blackbird + public MX records\n"
            "• Link Analysis — VirusTotal\n"
            "• Phone Lookup — free local number analysis\n\n"
            "_For lawful and authorized use only._"
        ),
        "main_menu": "Aegis Recon — Main Menu",
        "username": "Username",
        "maigret": "Deep Search",
        "email": "Email Scan",
        "link": "Link Analysis",
        "phone": "Phone Lookup",
        "help": "Help",
        "language_title": "🌐 Choose your language:",
        "back": "⬅️ Back",
        "language_changed": "Language changed to English 🇺🇸",
        "language_current": "Current language: English 🇺🇸",
        "cleanup_no_chat": "Could not identify the chat.",
        "cleanup_done": (
            "Chat cleanup completed.\n"
            "Messages deleted: {deleted}.\n"
            "Messages that could not be deleted: {failed}.\n\n"
            "Telegram does not allow bots to guarantee deletion of the entire "
            "chat history. You can delete older messages manually in Telegram."
        ),
        "help_text": (
            "*Aegis Recon Help*\n\n"
            "/start — Main menu\n"
            "/help — Help\n"
            "/username — Username search\n"
            "/maigret username — Deep username search\n"
            "/email — Email scan\n"
            "/link — URL analysis\n"
            "/phone — Phone lookup\n\n"
            "Choose a tool, send the target, and wait for the HTML report.\n\n"
            "Use only services and data you are authorized to investigate."
        ),
        "ask_username": "Send the username to search with Blackbird.",
        "ask_email": "Send the email address to investigate.",
        "ask_link": "Send the URL to analyze with VirusTotal.",
        "ask_phone": "Send a phone number in international format, e.g. +31612345678.",
        "ask_maigret": "Send a username for a deep Maigret search. This may take several minutes.",
        "welcome_no_tool": "Welcome to Aegis Recon. Use /start to choose a tool.",
        "cancelled": "Operation cancelled.",
        "scanning": "Scanning... Please wait.",
        "unexpected": "Lookup failed: unexpected response.",
        "valid_phone": "Send a phone number in international format, e.g. +31612345678.",
        "phone_checking": "Checking phone information...",
        "phone_error": "Lookup error: {error}",
        "phone_complete": "Phone lookup complete. Preparing HTML report...",
        "phone_failed": "Phone lookup failed. Check the Render logs.",
        "maigret_running": "Running Maigret for {username}. This may take several minutes.",
        "report_sending": "Analysis complete. Sending report...",
        "maigret_no_report": "Maigret did not produce a report. Check Render logs.",
        "maigret_failed": "Maigret failed. Check Render logs.",
        "tool_title_username": "Username",
        "tool_title_email": "Email Scan",
        "tool_title_link": "Link Analysis",
        "tool_title_phone": "Phone Lookup",
        "tool_title_maigret": "Deep Search",
        "valid_username": "Please send a valid username.",
        "valid_email": "That does not look like a valid email format.",
        "valid_url": "Please send a valid HTTP or HTTPS URL.",
        "unknown_tool": "Unknown tool. Use /start to open the menu.",
        "scan_failed": "The scan failed. Check Render logs for the error.",
        "other": "Please send text or use /start to choose a tool.",
        "report_caption": "Aegis Recon | HTML report",
        "report_user": "Aegis Recon report for {username}",
        "prompt_header": "{tool}\n\n{prompt}\n\nUse /start to open the main menu.",
        "help_short": (
            "/username — username search\n"
            "/maigret — deep search\n"
            "/email — email scan\n"
            "/link — URL analysis\n"
            "/phone — phone lookup\n"
            "/start — main menu"
        ),
    },
    "ru": {
        "language_button": "🇷🇺 Язык",
        "start_button": "🔍 Начать разведку",
        "delete_button": "🗑 Очистить чат",
        "welcome": (
            "🛡️ *Aegis Recon*\n\n"
            "Инструменты OSINT-анализа.\n\n"
            "*Доступные модули:*\n"
            "• Поиск имени пользователя — Blackbird\n"
            "• Глубокий поиск — Maigret\n"
            "• Проверка почты — Blackbird + публичные MX-записи\n"
            "• Анализ ссылок — VirusTotal\n"
            "• Проверка номера — локальный бесплатный анализ\n\n"
            "_Используйте сервис только законно и с разрешения._"
        ),
        "main_menu": "Aegis Recon — Главное меню",
        "username": "Поиск имени",
        "maigret": "Глубокий поиск",
        "email": "Проверка почты",
        "link": "Анализ ссылки",
        "phone": "Проверка номера",
        "help": "Помощь",
        "language_title": "🌐 Выберите язык:",
        "back": "⬅️ Назад",
        "language_changed": "Язык изменён на русский 🇷🇺",
        "language_current": "Текущий язык: русский 🇷🇺",
        "cleanup_no_chat": "Не удалось определить чат.",
        "cleanup_done": (
            "Очистка чата завершена.\n"
            "Удалено сообщений: {deleted}.\n"
            "Не удалось удалить: {failed}.\n\n"
            "Telegram не позволяет боту гарантированно удалить всю историю. "
            "Старые сообщения можно удалить вручную в Telegram."
        ),
        "help_text": (
            "*Справка Aegis Recon*\n\n"
            "/start — главное меню\n"
            "/help — помощь\n"
            "/username — поиск имени пользователя\n"
            "/maigret username — глубокий поиск\n"
            "/email — проверка почты\n"
            "/link — анализ ссылки\n"
            "/phone — проверка номера\n\n"
            "Выберите инструмент, отправьте цель и дождитесь HTML-отчёта.\n\n"
            "Используйте только те данные и сервисы, к которым у вас есть законный доступ."
        ),
        "ask_username": "Отправьте имя пользователя для поиска через Blackbird.",
        "ask_email": "Отправьте адрес электронной почты для проверки.",
        "ask_link": "Отправьте ссылку для анализа через VirusTotal.",
        "ask_phone": "Отправьте номер в международном формате, например +79991234567.",
        "ask_maigret": "Отправьте имя пользователя для глубокого поиска Maigret. Это может занять несколько минут.",
        "welcome_no_tool": "Добро пожаловать в Aegis Recon. Используйте /start, чтобы выбрать инструмент.",
        "cancelled": "Операция отменена.",
        "scanning": "Выполняется проверка... Подождите.",
        "unexpected": "Ошибка проверки: получен неожиданный ответ.",
        "valid_phone": "Отправьте номер в международном формате, например +79991234567.",
        "phone_checking": "Проверяю информацию о номере...",
        "phone_error": "Ошибка проверки: {error}",
        "phone_complete": "Проверка номера завершена. Готовлю HTML-отчёт...",
        "phone_failed": "Не удалось проверить номер. Проверьте логи Render.",
        "maigret_running": "Запускаю Maigret для {username}. Это может занять несколько минут.",
        "report_sending": "Анализ завершён. Отправляю отчёт...",
        "maigret_no_report": "Maigret не создал отчёт. Проверьте логи Render.",
        "maigret_failed": "Ошибка Maigret. Проверьте логи Render.",
        "tool_title_username": "Поиск имени",
        "tool_title_email": "Проверка почты",
        "tool_title_link": "Анализ ссылки",
        "tool_title_phone": "Проверка номера",
        "tool_title_maigret": "Глубокий поиск",
        "valid_username": "Отправьте корректное имя пользователя.",
        "valid_email": "Похоже, формат электронной почты неверный.",
        "valid_url": "Отправьте корректную ссылку HTTP или HTTPS.",
        "unknown_tool": "Неизвестный инструмент. Используйте /start, чтобы открыть меню.",
        "scan_failed": "Проверка не удалась. Посмотрите ошибку в логах Render.",
        "other": "Отправьте текст или используйте /start, чтобы выбрать инструмент.",
        "report_caption": "Aegis Recon | HTML-отчёт",
        "report_user": "Отчёт Aegis Recon для {username}",
        "prompt_header": "{tool}\n\n{prompt}\n\nИспользуйте /start, чтобы открыть главное меню.",
        "help_short": (
            "/username — поиск имени\n"
            "/maigret — глубокий поиск\n"
            "/email — проверка почты\n"
            "/link — анализ ссылки\n"
            "/phone — проверка номера\n"
            "/start — главное меню"
        ),
    },
    "pl": {
        "language_button": "🇵🇱 Język",
        "start_button": "🔍 Rozpocznij analizę",
        "delete_button": "🗑 Wyczyść czat",
        "welcome": (
            "🛡️ *Aegis Recon*\n\n"
            "Zestaw narzędzi do analizy OSINT.\n\n"
            "*Dostępne moduły:*\n"
            "• Wyszukiwanie nazwy użytkownika — Blackbird\n"
            "• Wyszukiwanie zaawansowane — Maigret\n"
            "• Analiza e-maila — Blackbird + publiczne rekordy MX\n"
            "• Analiza linków — VirusTotal\n"
            "• Analiza numeru telefonu — bezpłatna analiza lokalna\n\n"
            "_Korzystaj wyłącznie zgodnie z prawem i za zgodą._"
        ),
        "main_menu": "Aegis Recon — Menu główne",
        "username": "Szukaj nazwy",
        "maigret": "Głębokie wyszukiwanie",
        "email": "Analiza e-maila",
        "link": "Analiza linku",
        "phone": "Numer telefonu",
        "help": "Pomoc",
        "language_title": "🌐 Wybierz język:",
        "back": "⬅️ Wróć",
        "language_changed": "Zmieniono język na polski 🇵🇱",
        "language_current": "Aktualny język: polski 🇵🇱",
        "cleanup_no_chat": "Nie można ustalić czatu.",
        "cleanup_done": (
            "Czyszczenie czatu zakończone.\n"
            "Usunięte wiadomości: {deleted}.\n"
            "Nie udało się usunąć: {failed}.\n\n"
            "Telegram nie pozwala botom zagwarantować usunięcia całej historii. "
            "Starsze wiadomości możesz usunąć ręcznie w Telegramie."
        ),
        "help_text": (
            "*Pomoc Aegis Recon*\n\n"
            "/start — menu główne\n"
            "/help — pomoc\n"
            "/username — wyszukiwanie nazwy użytkownika\n"
            "/maigret username — wyszukiwanie zaawansowane\n"
            "/email — analiza e-maila\n"
            "/link — analiza adresu URL\n"
            "/phone — analiza numeru telefonu\n\n"
            "Wybierz narzędzie, wyślij cel i poczekaj na raport HTML.\n\n"
            "Korzystaj tylko z danych i usług, do których masz uprawniony dostęp."
        ),
        "ask_username": "Wyślij nazwę użytkownika do wyszukania przez Blackbird.",
        "ask_email": "Wyślij adres e-mail do analizy.",
        "ask_link": "Wyślij adres URL do analizy przez VirusTotal.",
        "ask_phone": "Wyślij numer telefonu w formacie międzynarodowym, np. +48123456789.",
        "ask_maigret": "Wyślij nazwę użytkownika do głębokiego wyszukiwania Maigret. Może to potrwać kilka minut.",
        "welcome_no_tool": "Witaj w Aegis Recon. Użyj /start, aby wybrać narzędzie.",
        "cancelled": "Operacja anulowana.",
        "scanning": "Skanowanie... Proszę czekać.",
        "unexpected": "Błąd wyszukiwania: nieoczekiwana odpowiedź.",
        "valid_phone": "Wyślij numer telefonu w formacie międzynarodowym, np. +48123456789.",
        "phone_checking": "Sprawdzanie informacji o numerze...",
        "phone_error": "Błąd wyszukiwania: {error}",
        "phone_complete": "Analiza numeru zakończona. Przygotowuję raport HTML...",
        "phone_failed": "Nie udało się przeanalizować numeru. Sprawdź logi Render.",
        "maigret_running": "Uruchamiam Maigret dla {username}. Może to potrwać kilka minut.",
        "report_sending": "Analiza zakończona. Wysyłam raport...",
        "maigret_no_report": "Maigret nie utworzył raportu. Sprawdź logi Render.",
        "maigret_failed": "Maigret nie działa poprawnie. Sprawdź logi Render.",
        "tool_title_username": "Wyszukiwanie nazwy",
        "tool_title_email": "Analiza e-maila",
        "tool_title_link": "Analiza linku",
        "tool_title_phone": "Numer telefonu",
        "tool_title_maigret": "Głębokie wyszukiwanie",
        "valid_username": "Wyślij prawidłową nazwę użytkownika.",
        "valid_email": "Format adresu e-mail wydaje się nieprawidłowy.",
        "valid_url": "Wyślij prawidłowy adres HTTP lub HTTPS.",
        "unknown_tool": "Nieznane narzędzie. Użyj /start, aby otworzyć menu.",
        "scan_failed": "Skanowanie nie powiodło się. Sprawdź logi Render.",
        "other": "Wyślij tekst lub użyj /start, aby wybrać narzędzie.",
        "report_caption": "Aegis Recon | Raport HTML",
        "report_user": "Raport Aegis Recon dla {username}",
        "prompt_header": "{tool}\n\n{prompt}\n\nUżyj /start, aby otworzyć menu główne.",
        "help_short": (
            "/username — wyszukiwanie nazwy\n"
            "/maigret — głębokie wyszukiwanie\n"
            "/email — analiza e-maila\n"
            "/link — analiza URL\n"
            "/phone — analiza numeru\n"
            "/start — menu główne"
        ),
    },
}


def lang(context):
    selected = context.user_data.get("language", "en")
    return selected if selected in LANGUAGES else "en"


def tr(context, key, **kwargs):
    language = lang(context)
    value = TEXT.get(language, TEXT["en"]).get(key, TEXT["en"].get(key, key))
    return value.format(**kwargs) if kwargs else value


def language_keyboard(context):
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("🇺🇸 English", callback_data="lang_en"),
            InlineKeyboardButton("🇷🇺 Русский", callback_data="lang_ru"),
        ],
        [
            InlineKeyboardButton("🇵🇱 Polski", callback_data="lang_pl"),
        ],
        [
            InlineKeyboardButton(tr(context, "back"), callback_data="language_back"),
        ],
    ])


def main_menu_keyboard(context):
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton(tr(context, "username"), callback_data="username"),
            InlineKeyboardButton(tr(context, "maigret"), callback_data="maigret"),
        ],
        [
            InlineKeyboardButton(tr(context, "email"), callback_data="email"),
            InlineKeyboardButton(tr(context, "link"), callback_data="link"),
        ],
        [
            InlineKeyboardButton(tr(context, "phone"), callback_data="phone"),
            InlineKeyboardButton(tr(context, "help"), callback_data="help"),
        ],
    ])


def start_keyboard(context):
    return InlineKeyboardMarkup([
        [InlineKeyboardButton(tr(context, "start_button"), callback_data="start_menu")],
        [InlineKeyboardButton(tr(context, "delete_button"), callback_data="clear_chat")],
        [InlineKeyboardButton(tr(context, "language_button"), callback_data="language_menu")],
    ])


# --------------------------------------------------
# MESSAGE TRACKING
# --------------------------------------------------

def remember_message(context, message_id):
    if not message_id:
        return
    ids = context.user_data.setdefault("tracked_message_ids", [])
    if message_id not in ids:
        ids.append(message_id)
    context.user_data["tracked_message_ids"] = ids[-MAX_TRACKED_MESSAGES:]


async def tracked_reply(message, context, text, **kwargs):
    if not message:
        return None
    remember_message(context, message.message_id)
    sent = await message.reply_text(text, **kwargs)
    remember_message(context, sent.message_id)
    return sent


async def tracked_document(message, context, document, filename, caption=None):
    remember_message(context, message.message_id)
    sent = await message.reply_document(document=document, filename=filename, caption=caption)
    remember_message(context, sent.message_id)
    return sent


async def clear_tracked_chat(query, context):
    chat = query.message.chat if query.message else None
    if not chat:
        await query.answer(tr(context, "cleanup_no_chat"), show_alert=True)
        return

    chat_id = chat.id
    ids = list(context.user_data.get("tracked_message_ids", []))
    if query.message:
        ids.append(query.message.message_id)

    try:
        await query.answer()
    except Exception:
        pass

    deleted = 0
    failed = 0
    for message_id in dict.fromkeys(ids):
        try:
            await context.bot.delete_message(chat_id=chat_id, message_id=message_id)
            deleted += 1
        except Exception as exc:
            failed += 1
            logger.debug("Could not delete message %s: %s", message_id, exc)

    context.user_data.pop("tracked_message_ids", None)
    sent = await context.bot.send_message(
        chat_id=chat_id,
        text=tr(context, "cleanup_done", deleted=deleted, failed=failed),
    )
    remember_message(context, sent.message_id)


# --------------------------------------------------
# REPORT HELPERS
# --------------------------------------------------

def safe_filename(value, prefix="Aegis"):
    value = re.sub(r"[^a-zA-Z0-9_-]", "_", str(value or "report"))
    return f"{prefix}_{value[:70] or 'report'}.html"


def parse_blackbird_results(output):
    output = str(output or "").strip()
    if not output:
        return {"Status": "No results returned by Blackbird."}

    data = {}
    for index, line in enumerate(output.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        match = re.match(r"^(?:🔗\s*)?(.{1,100}?):\s*(https?://\S+)$", line, flags=re.IGNORECASE)
        if match:
            site = match.group(1).strip()
            url = match.group(2).rstrip(".,;)")
            key = site or f"Result {index}"
            if key in data:
                key = f"{key} ({index})"
            data[key] = url
        else:
            data[f"Result {index}"] = line
    return data or {"Status": "No readable results returned."}


def validate_http_url(value):
    value = str(value or "").strip()
    if not re.match(r"^https?://", value, re.IGNORECASE):
        value = "https://" + value
    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme.lower() not in ("http", "https")
            or not parsed.hostname
            or any(char.isspace() for char in value)
        ):
            return None
        _ = parsed.port
    except (ValueError, TypeError):
        return None
    return value


def lookup_mx_records(domain):
    try:
        response = requests.get(
            "https://dns.google/resolve",
            params={"name": domain, "type": "MX"},
            headers={"accept": "application/dns-json"},
            timeout=12,
        )
        response.raise_for_status()
        data = response.json()
        records = [
            answer.get("data", "")
            for answer in data.get("Answer", [])
            if answer.get("type") == 15 and answer.get("data")
        ]
        if records:
            return "\n".join(records)
        if data.get("Status") == 3:
            return "Domain does not appear to exist (NXDOMAIN)."
        return "No MX records returned. This alone does not prove the email address is invalid."
    except Exception as exc:
        logger.warning("MX lookup failed for %s: %s", domain, exc)
        return "MX lookup unavailable."


async def send_html_report(message, context, title, data, filename):
    report_path = await asyncio.to_thread(generate_html_report, title, data, filename)
    if not report_path or not os.path.isfile(report_path):
        raise RuntimeError("HTML report was not created.")
    try:
        with open(report_path, "rb") as report_file:
            await tracked_document(
                message, context, report_file, filename,
                caption=tr(context, "report_caption"),
            )
    finally:
        try:
            os.remove(report_path)
        except OSError:
            logger.warning("Could not remove report: %s", report_path)


# --------------------------------------------------
# COMMAND MENU
# --------------------------------------------------

async def post_init(app):
    try:
        await app.bot.set_my_commands([
            BotCommand("start", "Open the main menu"),
            BotCommand("username", "Username Search"),
            BotCommand("maigret", "Deep Username Search"),
            BotCommand("email", "Email Scan"),
            BotCommand("link", "Link Analysis"),
            BotCommand("phone", "Phone Lookup"),
            BotCommand("help", "Help and instructions"),
        ])
        await app.bot.set_chat_menu_button(menu_button=MenuButtonCommands())
        logger.info("Bot commands menu configured.")
    except Exception:
        logger.exception("Could not configure bot menu.")


# --------------------------------------------------
# COMMANDS
# --------------------------------------------------

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.effective_message
    if not message:
        return

    # Language is English for first-time users, and remains per-user afterwards.
    context.user_data.setdefault("language", "en")
    remember_message(context, message.message_id)

    if BANNER_PATH.is_file():
        try:
            with open(BANNER_PATH, "rb") as banner:
                sent = await message.reply_photo(
                    photo=banner,
                    caption=tr(context, "welcome"),
                    reply_markup=start_keyboard(context),
                    parse_mode="Markdown",
                )
            remember_message(context, sent.message_id)
            return
        except Exception:
            logger.exception("Could not send banner image.")

    sent = await message.reply_text(
        tr(context, "welcome"),
        reply_markup=start_keyboard(context),
        parse_mode="Markdown",
    )
    remember_message(context, sent.message_id)


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await tracked_reply(
        update.effective_message, context, tr(context, "help_text"),
        parse_mode="Markdown",
    )


async def ask_tool(update, context, tool, prompt_key):
    context.user_data["tool"] = tool
    context.user_data["cancel"] = False
    await tracked_reply(update.effective_message, context, tr(context, prompt_key))


async def ask_username(update, context):
    await ask_tool(update, context, "username", "ask_username")


async def ask_email(update, context):
    await ask_tool(update, context, "email", "ask_email")


async def ask_link(update, context):
    await ask_tool(update, context, "link", "ask_link")


async def ask_phone(update, context):
    await ask_tool(update, context, "phone", "ask_phone")


async def ask_maigret(update, context):
    await ask_tool(update, context, "maigret", "ask_maigret")


# --------------------------------------------------
# PHONE LOOKUP COMMAND
# --------------------------------------------------

async def phone_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.effective_message
    if not message:
        return
    phone = context.args[0] if context.args else None
    if not phone:
        context.user_data["tool"] = "phone"
        await tracked_reply(message, context, tr(context, "valid_phone"))
        return

    status = await tracked_reply(message, context, tr(context, "phone_checking"))
    try:
        result = await asyncio.to_thread(lookup_phone, phone)
        if not isinstance(result, dict):
            await status.edit_text(tr(context, "unexpected"))
            return
        if result.get("error"):
            await status.edit_text(tr(context, "phone_error", error=result["error"]))
            return

        await status.edit_text(tr(context, "phone_complete"))
        await send_html_report(
            message, context, f"Phone lookup: {result.get('phone', phone)}",
            {
                "Service": result.get("source", "Free local number analysis"),
                **result,
                "Disclaimer": (
                    "This report does not confirm who owns the number "
                    "or whether a SIM card is active."
                ),
            },
            safe_filename(phone, "Aegis_Phone"),
        )
        try:
            await status.delete()
        except Exception:
            pass
    except Exception:
        logger.exception("Phone lookup failed.")
        try:
            await status.edit_text(tr(context, "phone_failed"))
        except Exception:
            pass


# --------------------------------------------------
# MAIGRET COMMAND
# --------------------------------------------------

async def maigret_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.effective_message
    if not message:
        return
    username = context.args[0] if context.args else None
    if not username:
        context.user_data["tool"] = "maigret"
        await tracked_reply(message, context, tr(context, "ask_maigret"))
        return

    status = await tracked_reply(
        message, context, tr(context, "maigret_running", username=username)
    )
    try:
        report_path = await asyncio.to_thread(run_maigret, username)
        if report_path and os.path.isfile(report_path):
            await status.edit_text(tr(context, "report_sending"))
            with open(report_path, "rb") as report_file:
                await tracked_document(
                    message, context, report_file,
                    safe_filename(username, "Aegis_Maigret"),
                    caption=tr(context, "report_user", username=username),
                )
            try:
                os.remove(report_path)
            except OSError:
                logger.warning("Could not remove Maigret report: %s", report_path)
            try:
                await status.delete()
            except Exception:
                pass
        else:
            await status.edit_text(tr(context, "maigret_no_report"))
    except Exception:
        logger.exception("Maigret search failed.")
        try:
            await status.edit_text(tr(context, "maigret_failed"))
        except Exception:
            pass


# --------------------------------------------------
# CALLBACK BUTTONS
# --------------------------------------------------

async def button(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    if not query:
        return
    data = query.data or ""

    if data == "clear_chat":
        await clear_tracked_chat(query, context)
        return

    await query.answer()

    if data == "language_menu":
        if query.message:
            await query.message.reply_text(
                tr(context, "language_title"),
                reply_markup=language_keyboard(context),
            )
        return

    if data in ("lang_en", "lang_ru", "lang_pl"):
        selected = data.replace("lang_", "")
        context.user_data["language"] = selected
        if query.message:
            # Update the language selection screen immediately.
            try:
                await query.edit_message_text(
                    tr(context, "language_title"),
                    reply_markup=language_keyboard(context),
                )
            except Exception:
                pass
            await query.message.reply_text(tr(context, "language_changed"))
            await query.message.reply_text(
                tr(context, "welcome"),
                reply_markup=start_keyboard(context),
                parse_mode="Markdown",
            )
        return

    if data == "language_back":
        if query.message:
            try:
                await query.edit_message_text(
                    tr(context, "language_current"),
                    reply_markup=InlineKeyboardMarkup([[
                        InlineKeyboardButton(
                            tr(context, "language_button"),
                            callback_data="language_menu",
                        )
                    ]]),
                )
            except Exception:
                pass
            await query.message.reply_text(
                tr(context, "welcome"),
                reply_markup=start_keyboard(context),
                parse_mode="Markdown",
            )
        return

    if data == "start_menu":
        if query.message:
            try:
                await query.edit_message_caption(
                    caption=tr(context, "main_menu"),
                    reply_markup=main_menu_keyboard(context),
                )
            except Exception:
                try:
                    await query.edit_message_text(
                        tr(context, "main_menu"),
                        reply_markup=main_menu_keyboard(context),
                    )
                except Exception:
                    sent = await query.message.reply_text(
                        tr(context, "main_menu"),
                        reply_markup=main_menu_keyboard(context),
                    )
                    remember_message(context, sent.message_id)
        return

    prompt_keys = {
        "username": "ask_username",
        "email": "ask_email",
        "link": "ask_link",
        "phone": "ask_phone",
        "maigret": "ask_maigret",
    }

    if data in prompt_keys:
        context.user_data["tool"] = data
        context.user_data["cancel"] = False
        if query.message:
            title_key = {
                "username": "tool_title_username",
                "email": "tool_title_email",
                "link": "tool_title_link",
                "phone": "tool_title_phone",
                "maigret": "tool_title_maigret",
            }[data]
            sent = await query.message.reply_text(
                tr(
                    context, "prompt_header",
                    tool=tr(context, title_key),
                    prompt=tr(context, prompt_keys[data]),
                )
            )
            remember_message(context, query.message.message_id)
            remember_message(context, sent.message_id)
        return

    if data == "help" and query.message:
        sent = await query.message.reply_text(tr(context, "help_short"))
        remember_message(context, query.message.message_id)
        remember_message(context, sent.message_id)


# --------------------------------------------------
# MAIN MESSAGE HANDLER
# --------------------------------------------------

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.effective_message
    if not message or not message.text:
        return

    text = message.text.strip()
    tool = context.user_data.get("tool")
    if not tool:
        await tracked_reply(message, context, tr(context, "welcome_no_tool"))
        return

    remember_message(context, message.message_id)
    if context.user_data.get("cancel"):
        context.user_data["cancel"] = False
        context.user_data.pop("tool", None)
        await tracked_reply(message, context, tr(context, "cancelled"))
        return

    context.user_data.pop("tool", None)
    status = await tracked_reply(message, context, tr(context, "scanning"))

    try:
        await context.bot.send_chat_action(
            chat_id=update.effective_chat.id,
            action=ChatAction.TYPING,
        )

        if tool == "phone":
            result = await asyncio.to_thread(lookup_phone, text)
            if not isinstance(result, dict):
                await status.edit_text(tr(context, "unexpected"))
                return
            if result.get("error"):
                await status.edit_text(tr(context, "phone_error", error=result["error"]))
                return
            await send_html_report(
                message, context, f"Phone lookup: {result.get('phone', text)}",
                {"Service": result.get("source", "Free local analysis"), **result},
                safe_filename(text, "Aegis_Phone"),
            )

        elif tool == "maigret":
            username = re.sub(r"\s+", "", text)
            if not username or len(username) > 100:
                await status.edit_text(tr(context, "valid_username"))
                return
            report_path = await asyncio.to_thread(run_maigret, username)
            if report_path and os.path.isfile(report_path):
                with open(report_path, "rb") as report_file:
                    await tracked_document(
                        message, context, report_file,
                        safe_filename(username, "Aegis_Maigret"),
                        caption=tr(context, "report_user", username=username),
                    )
                try:
                    os.remove(report_path)
                except OSError:
                    logger.warning("Could not remove Maigret report: %s", report_path)
            else:
                await status.edit_text(tr(context, "maigret_no_report"))
                return

        elif tool == "username":
            username = re.sub(r"\s+", "", text)
            if not username or len(username) > 100:
                await status.edit_text(tr(context, "valid_username"))
                return
            result = await asyncio.to_thread(blackbird_service.search_username, username)
            report_data = {
                "Target username": username,
                "Service": "Blackbird",
                **parse_blackbird_results(result),
            }
            await send_html_report(
                message, context, f"Username Analysis: {username}", report_data,
                safe_filename(username, "Aegis_Username"),
            )

        elif tool == "email":
            if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", text):
                await status.edit_text(tr(context, "valid_email"))
                return
            email = text.strip()
            domain = email.rsplit("@", 1)[1].lower()
            blackbird_result = await asyncio.to_thread(blackbird_service.scan_email, email)
            mx_result = await asyncio.to_thread(lookup_mx_records, domain)
            report_data = {
                "Target email": email,
                "Format check": "Valid-looking syntax",
                "Domain": domain,
                "MX records": mx_result,
                "Blackbird results": parse_blackbird_results(blackbird_result),
                "Mailbox existence": (
                    "Not confirmed. MX records and public search results "
                    "cannot prove that this mailbox exists or is accessible."
                ),
            }
            await send_html_report(
                message, context, f"Email Analysis: {email}", report_data,
                safe_filename(email, "Aegis_Email"),
            )

        elif tool == "link":
            url = validate_http_url(text)
            if not url:
                await status.edit_text(tr(context, "valid_url"))
                return
            result = await asyncio.to_thread(virustotal_service.scan_link, url)
            if isinstance(result, dict):
                report_data = {"Target URL": url, "Service": "VirusTotal", **result}
            else:
                report_data = {
                    "Target URL": url,
                    "Service": "VirusTotal",
                    "Analysis result": str(result or "No results returned."),
                    "Interpretation": (
                        "An absence of detections does not guarantee that a URL is safe."
                    ),
                }
            await send_html_report(
                message, context, f"Link Analysis: {url}", report_data,
                safe_filename("link_analysis", "Aegis_VirusTotal"),
            )
        else:
            await status.edit_text(tr(context, "unknown_tool"))
            return

        try:
            await status.delete()
        except Exception:
            pass

    except Exception:
        logger.exception("Message handling failed for tool=%s", tool)
        try:
            await status.edit_text(tr(context, "scan_failed"))
        except Exception:
            pass


async def handle_other(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.effective_message
    if not message:
        return
    remember_message(context, message.message_id)
    await tracked_reply(message, context, tr(context, "other"))


# --------------------------------------------------
# CHAT MEMBER EVENTS
# --------------------------------------------------

async def chat_member_update(update: Update, context: ContextTypes.DEFAULT_TYPE):
    member_update = update.chat_member or update.my_chat_member
    if member_update:
        logger.info(
            "Chat member status changed in chat_id=%s",
            member_update.chat.id if member_update.chat else None,
        )


# --------------------------------------------------
# ERRORS AND STARTUP
# --------------------------------------------------

async def on_error(update: object, context: ContextTypes.DEFAULT_TYPE):
    logger.error("Unhandled Telegram error", exc_info=context.error)


application = ApplicationBuilder().token(TOKEN).post_init(post_init).build()

application.add_handler(CommandHandler("start", start))
application.add_handler(CommandHandler("help", help_command))
application.add_handler(CommandHandler("username", ask_username))
application.add_handler(CommandHandler("email", ask_email))
application.add_handler(CommandHandler("link", ask_link))
application.add_handler(CommandHandler("phone", phone_command))
application.add_handler(CommandHandler("maigret", maigret_command))
application.add_handler(CallbackQueryHandler(button))
application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
application.add_handler(MessageHandler(~(filters.TEXT | filters.COMMAND), handle_other))
application.add_handler(ChatMemberHandler(chat_member_update, ChatMemberHandler.CHAT_MEMBER))
application.add_handler(ChatMemberHandler(chat_member_update, ChatMemberHandler.MY_CHAT_MEMBER))
application.add_error_handler(on_error)


if __name__ == "__main__":
    logger.info("Aegis Recon starting polling...")
    application.run_polling()
