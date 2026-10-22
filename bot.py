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
    "en": {"flag": "ðºð¸", "name": "English"},
    "ru": {"flag": "ð·ðº", "name": "Ð ÑÑÑÐºÐ¸Ð¹"},
    "pl": {"flag": "ðµð±", "name": "Polski"},
}

TEXT = {
    "en": {
        "language_button": "ðºð¸ Language",
        "start_button": "ð Start Recon",
        "delete_button": "ð Delete Chat",
        "welcome": (
            "ð¡ï¸ *Aegis Recon*\n\n"
            "OSINT analysis toolkit.\n\n"
            "*Available modules:*\n"
            "â¢ Username Search â Blackbird\n"
            "â¢ Deep Search â Maigret\n"
            "â¢ Email Scan â Blackbird + public MX records\n"
            "â¢ Link Analysis â VirusTotal\n"
            "â¢ Phone Lookup â free local number analysis\n\n"
            "_For lawful and authorized use only._"
        ),
        "main_menu": "Aegis Recon â Main Menu",
        "username": "Username",
        "maigret": "Deep Search",
        "email": "Email Scan",
        "link": "Link Analysis",
        "phone": "Phone Lookup",
        "help": "Help",
        "language_title": "ð Choose your language:",
        "back": "â¬ï¸ Back",
        "language_changed": "Language changed to English ðºð¸",
        "language_current": "Current language: English ðºð¸",
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
            "/start â Main menu\n"
            "/help â Help\n"
            "/username â Username search\n"
            "/maigret username â Deep username search\n"
            "/email â Email scan\n"
            "/link â URL analysis\n"
            "/phone â Phone lookup\n\n"
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
            "/username â username search\n"
            "/maigret â deep search\n"
            "/email â email scan\n"
            "/link â URL analysis\n"
            "/phone â phone lookup\n"
            "/start â main menu"
        ),
    },
    "ru": {
        "language_button": "ð·ðº Ð¯Ð·ÑÐº",
        "start_button": "ð ÐÐ°ÑÐ°ÑÑ ÑÐ°Ð·Ð²ÐµÐ´ÐºÑ",
        "delete_button": "ð ÐÑÐ¸ÑÑÐ¸ÑÑ ÑÐ°Ñ",
        "welcome": (
            "ð¡ï¸ *Aegis Recon*\n\n"
            "ÐÐ½ÑÑÑÑÐ¼ÐµÐ½ÑÑ OSINT-Ð°Ð½Ð°Ð»Ð¸Ð·Ð°.\n\n"
            "*ÐÐ¾ÑÑÑÐ¿Ð½ÑÐµ Ð¼Ð¾Ð´ÑÐ»Ð¸:*\n"
            "â¢ ÐÐ¾Ð¸ÑÐº Ð¸Ð¼ÐµÐ½Ð¸ Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»Ñ â Blackbird\n"
            "â¢ ÐÐ»ÑÐ±Ð¾ÐºÐ¸Ð¹ Ð¿Ð¾Ð¸ÑÐº â Maigret\n"
            "â¢ ÐÑÐ¾Ð²ÐµÑÐºÐ° Ð¿Ð¾ÑÑÑ â Blackbird + Ð¿ÑÐ±Ð»Ð¸ÑÐ½ÑÐµ MX-Ð·Ð°Ð¿Ð¸ÑÐ¸\n"
            "â¢ ÐÐ½Ð°Ð»Ð¸Ð· ÑÑÑÐ»Ð¾Ðº â VirusTotal\n"
            "â¢ ÐÑÐ¾Ð²ÐµÑÐºÐ° Ð½Ð¾Ð¼ÐµÑÐ° â Ð»Ð¾ÐºÐ°Ð»ÑÐ½ÑÐ¹ Ð±ÐµÑÐ¿Ð»Ð°ÑÐ½ÑÐ¹ Ð°Ð½Ð°Ð»Ð¸Ð·\n\n"
            "_ÐÑÐ¿Ð¾Ð»ÑÐ·ÑÐ¹ÑÐµ ÑÐµÑÐ²Ð¸Ñ ÑÐ¾Ð»ÑÐºÐ¾ Ð·Ð°ÐºÐ¾Ð½Ð½Ð¾ Ð¸ Ñ ÑÐ°Ð·ÑÐµÑÐµÐ½Ð¸Ñ._"
        ),
        "main_menu": "Aegis Recon â ÐÐ»Ð°Ð²Ð½Ð¾Ðµ Ð¼ÐµÐ½Ñ",
        "username": "ÐÐ¾Ð¸ÑÐº Ð¸Ð¼ÐµÐ½Ð¸",
        "maigret": "ÐÐ»ÑÐ±Ð¾ÐºÐ¸Ð¹ Ð¿Ð¾Ð¸ÑÐº",
        "email": "ÐÑÐ¾Ð²ÐµÑÐºÐ° Ð¿Ð¾ÑÑÑ",
        "link": "ÐÐ½Ð°Ð»Ð¸Ð· ÑÑÑÐ»ÐºÐ¸",
        "phone": "ÐÑÐ¾Ð²ÐµÑÐºÐ° Ð½Ð¾Ð¼ÐµÑÐ°",
        "help": "ÐÐ¾Ð¼Ð¾ÑÑ",
        "language_title": "ð ÐÑÐ±ÐµÑÐ¸ÑÐµ ÑÐ·ÑÐº:",
        "back": "â¬ï¸ ÐÐ°Ð·Ð°Ð´",
        "language_changed": "Ð¯Ð·ÑÐº Ð¸Ð·Ð¼ÐµÐ½ÑÐ½ Ð½Ð° ÑÑÑÑÐºÐ¸Ð¹ ð·ðº",
        "language_current": "Ð¢ÐµÐºÑÑÐ¸Ð¹ ÑÐ·ÑÐº: ÑÑÑÑÐºÐ¸Ð¹ ð·ðº",
        "cleanup_no_chat": "ÐÐµ ÑÐ´Ð°Ð»Ð¾ÑÑ Ð¾Ð¿ÑÐµÐ´ÐµÐ»Ð¸ÑÑ ÑÐ°Ñ.",
        "cleanup_done": (
            "ÐÑÐ¸ÑÑÐºÐ° ÑÐ°ÑÐ° Ð·Ð°Ð²ÐµÑÑÐµÐ½Ð°.\n"
            "Ð£Ð´Ð°Ð»ÐµÐ½Ð¾ ÑÐ¾Ð¾Ð±ÑÐµÐ½Ð¸Ð¹: {deleted}.\n"
            "ÐÐµ ÑÐ´Ð°Ð»Ð¾ÑÑ ÑÐ´Ð°Ð»Ð¸ÑÑ: {failed}.\n\n"
            "Telegram Ð½Ðµ Ð¿Ð¾Ð·Ð²Ð¾Ð»ÑÐµÑ Ð±Ð¾ÑÑ Ð³Ð°ÑÐ°Ð½ÑÐ¸ÑÐ¾Ð²Ð°Ð½Ð½Ð¾ ÑÐ´Ð°Ð»Ð¸ÑÑ Ð²ÑÑ Ð¸ÑÑÐ¾ÑÐ¸Ñ. "
            "Ð¡ÑÐ°ÑÑÐµ ÑÐ¾Ð¾Ð±ÑÐµÐ½Ð¸Ñ Ð¼Ð¾Ð¶Ð½Ð¾ ÑÐ´Ð°Ð»Ð¸ÑÑ Ð²ÑÑÑÐ½ÑÑ Ð² Telegram."
        ),
        "help_text": (
            "*Ð¡Ð¿ÑÐ°Ð²ÐºÐ° Aegis Recon*\n\n"
            "/start â Ð³Ð»Ð°Ð²Ð½Ð¾Ðµ Ð¼ÐµÐ½Ñ\n"
            "/help â Ð¿Ð¾Ð¼Ð¾ÑÑ\n"
            "/username â Ð¿Ð¾Ð¸ÑÐº Ð¸Ð¼ÐµÐ½Ð¸ Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»Ñ\n"
            "/maigret username â Ð³Ð»ÑÐ±Ð¾ÐºÐ¸Ð¹ Ð¿Ð¾Ð¸ÑÐº\n"
            "/email â Ð¿ÑÐ¾Ð²ÐµÑÐºÐ° Ð¿Ð¾ÑÑÑ\n"
            "/link â Ð°Ð½Ð°Ð»Ð¸Ð· ÑÑÑÐ»ÐºÐ¸\n"
            "/phone â Ð¿ÑÐ¾Ð²ÐµÑÐºÐ° Ð½Ð¾Ð¼ÐµÑÐ°\n\n"
            "ÐÑÐ±ÐµÑÐ¸ÑÐµ Ð¸Ð½ÑÑÑÑÐ¼ÐµÐ½Ñ, Ð¾ÑÐ¿ÑÐ°Ð²ÑÑÐµ ÑÐµÐ»Ñ Ð¸ Ð´Ð¾Ð¶Ð´Ð¸ÑÐµÑÑ HTML-Ð¾ÑÑÑÑÐ°.\n\n"
            "ÐÑÐ¿Ð¾Ð»ÑÐ·ÑÐ¹ÑÐµ ÑÐ¾Ð»ÑÐºÐ¾ ÑÐµ Ð´Ð°Ð½Ð½ÑÐµ Ð¸ ÑÐµÑÐ²Ð¸ÑÑ, Ðº ÐºÐ¾ÑÐ¾ÑÑÐ¼ Ñ Ð²Ð°Ñ ÐµÑÑÑ Ð·Ð°ÐºÐ¾Ð½Ð½ÑÐ¹ Ð´Ð¾ÑÑÑÐ¿."
        ),
        "ask_username": "ÐÑÐ¿ÑÐ°Ð²ÑÑÐµ Ð¸Ð¼Ñ Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»Ñ Ð´Ð»Ñ Ð¿Ð¾Ð¸ÑÐºÐ° ÑÐµÑÐµÐ· Blackbird.",
        "ask_email": "ÐÑÐ¿ÑÐ°Ð²ÑÑÐµ Ð°Ð´ÑÐµÑ ÑÐ»ÐµÐºÑÑÐ¾Ð½Ð½Ð¾Ð¹ Ð¿Ð¾ÑÑÑ Ð´Ð»Ñ Ð¿ÑÐ¾Ð²ÐµÑÐºÐ¸.",
        "ask_link": "ÐÑÐ¿ÑÐ°Ð²ÑÑÐµ ÑÑÑÐ»ÐºÑ Ð´Ð»Ñ Ð°Ð½Ð°Ð»Ð¸Ð·Ð° ÑÐµÑÐµÐ· VirusTotal.",
        "ask_phone": "ÐÑÐ¿ÑÐ°Ð²ÑÑÐµ Ð½Ð¾Ð¼ÐµÑ Ð² Ð¼ÐµÐ¶Ð´ÑÐ½Ð°ÑÐ¾Ð´Ð½Ð¾Ð¼ ÑÐ¾ÑÐ¼Ð°ÑÐµ, Ð½Ð°Ð¿ÑÐ¸Ð¼ÐµÑ +79991234567.",
        "ask_maigret": "ÐÑÐ¿ÑÐ°Ð²ÑÑÐµ Ð¸Ð¼Ñ Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»Ñ Ð´Ð»Ñ Ð³Ð»ÑÐ±Ð¾ÐºÐ¾Ð³Ð¾ Ð¿Ð¾Ð¸ÑÐºÐ° Maigret. Ð­ÑÐ¾ Ð¼Ð¾Ð¶ÐµÑ Ð·Ð°Ð½ÑÑÑ Ð½ÐµÑÐºÐ¾Ð»ÑÐºÐ¾ Ð¼Ð¸Ð½ÑÑ.",
        "welcome_no_tool": "ÐÐ¾Ð±ÑÐ¾ Ð¿Ð¾Ð¶Ð°Ð»Ð¾Ð²Ð°ÑÑ Ð² Aegis Recon. ÐÑÐ¿Ð¾Ð»ÑÐ·ÑÐ¹ÑÐµ /start, ÑÑÐ¾Ð±Ñ Ð²ÑÐ±ÑÐ°ÑÑ Ð¸Ð½ÑÑÑÑÐ¼ÐµÐ½Ñ.",
        "cancelled": "ÐÐ¿ÐµÑÐ°ÑÐ¸Ñ Ð¾ÑÐ¼ÐµÐ½ÐµÐ½Ð°.",
        "scanning": "ÐÑÐ¿Ð¾Ð»Ð½ÑÐµÑÑÑ Ð¿ÑÐ¾Ð²ÐµÑÐºÐ°... ÐÐ¾Ð´Ð¾Ð¶Ð´Ð¸ÑÐµ.",
        "unexpected": "ÐÑÐ¸Ð±ÐºÐ° Ð¿ÑÐ¾Ð²ÐµÑÐºÐ¸: Ð¿Ð¾Ð»ÑÑÐµÐ½ Ð½ÐµÐ¾Ð¶Ð¸Ð´Ð°Ð½Ð½ÑÐ¹ Ð¾ÑÐ²ÐµÑ.",
        "valid_phone": "ÐÑÐ¿ÑÐ°Ð²ÑÑÐµ Ð½Ð¾Ð¼ÐµÑ Ð² Ð¼ÐµÐ¶Ð´ÑÐ½Ð°ÑÐ¾Ð´Ð½Ð¾Ð¼ ÑÐ¾ÑÐ¼Ð°ÑÐµ, Ð½Ð°Ð¿ÑÐ¸Ð¼ÐµÑ +79991234567.",
        "phone_checking": "ÐÑÐ¾Ð²ÐµÑÑÑ Ð¸Ð½ÑÐ¾ÑÐ¼Ð°ÑÐ¸Ñ Ð¾ Ð½Ð¾Ð¼ÐµÑÐµ...",
        "phone_error": "ÐÑÐ¸Ð±ÐºÐ° Ð¿ÑÐ¾Ð²ÐµÑÐºÐ¸: {error}",
        "phone_complete": "ÐÑÐ¾Ð²ÐµÑÐºÐ° Ð½Ð¾Ð¼ÐµÑÐ° Ð·Ð°Ð²ÐµÑÑÐµÐ½Ð°. ÐÐ¾ÑÐ¾Ð²Ð»Ñ HTML-Ð¾ÑÑÑÑ...",
        "phone_failed": "ÐÐµ ÑÐ´Ð°Ð»Ð¾ÑÑ Ð¿ÑÐ¾Ð²ÐµÑÐ¸ÑÑ Ð½Ð¾Ð¼ÐµÑ. ÐÑÐ¾Ð²ÐµÑÑÑÐµ Ð»Ð¾Ð³Ð¸ Render.",
        "maigret_running": "ÐÐ°Ð¿ÑÑÐºÐ°Ñ Maigret Ð´Ð»Ñ {username}. Ð­ÑÐ¾ Ð¼Ð¾Ð¶ÐµÑ Ð·Ð°Ð½ÑÑÑ Ð½ÐµÑÐºÐ¾Ð»ÑÐºÐ¾ Ð¼Ð¸Ð½ÑÑ.",
        "report_sending": "ÐÐ½Ð°Ð»Ð¸Ð· Ð·Ð°Ð²ÐµÑÑÑÐ½. ÐÑÐ¿ÑÐ°Ð²Ð»ÑÑ Ð¾ÑÑÑÑ...",
        "maigret_no_report": "Maigret Ð½Ðµ ÑÐ¾Ð·Ð´Ð°Ð» Ð¾ÑÑÑÑ. ÐÑÐ¾Ð²ÐµÑÑÑÐµ Ð»Ð¾Ð³Ð¸ Render.",
        "maigret_failed": "ÐÑÐ¸Ð±ÐºÐ° Maigret. ÐÑÐ¾Ð²ÐµÑÑÑÐµ Ð»Ð¾Ð³Ð¸ Render.",
        "tool_title_username": "ÐÐ¾Ð¸ÑÐº Ð¸Ð¼ÐµÐ½Ð¸",
        "tool_title_email": "ÐÑÐ¾Ð²ÐµÑÐºÐ° Ð¿Ð¾ÑÑÑ",
        "tool_title_link": "ÐÐ½Ð°Ð»Ð¸Ð· ÑÑÑÐ»ÐºÐ¸",
        "tool_title_phone": "ÐÑÐ¾Ð²ÐµÑÐºÐ° Ð½Ð¾Ð¼ÐµÑÐ°",
        "tool_title_maigret": "ÐÐ»ÑÐ±Ð¾ÐºÐ¸Ð¹ Ð¿Ð¾Ð¸ÑÐº",
        "valid_username": "ÐÑÐ¿ÑÐ°Ð²ÑÑÐµ ÐºÐ¾ÑÑÐµÐºÑÐ½Ð¾Ðµ Ð¸Ð¼Ñ Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»Ñ.",
        "valid_email": "ÐÐ¾ÑÐ¾Ð¶Ðµ, ÑÐ¾ÑÐ¼Ð°Ñ ÑÐ»ÐµÐºÑÑÐ¾Ð½Ð½Ð¾Ð¹ Ð¿Ð¾ÑÑÑ Ð½ÐµÐ²ÐµÑÐ½ÑÐ¹.",
        "valid_url": "ÐÑÐ¿ÑÐ°Ð²ÑÑÐµ ÐºÐ¾ÑÑÐµÐºÑÐ½ÑÑ ÑÑÑÐ»ÐºÑ HTTP Ð¸Ð»Ð¸ HTTPS.",
        "unknown_tool": "ÐÐµÐ¸Ð·Ð²ÐµÑÑÐ½ÑÐ¹ Ð¸Ð½ÑÑÑÑÐ¼ÐµÐ½Ñ. ÐÑÐ¿Ð¾Ð»ÑÐ·ÑÐ¹ÑÐµ /start, ÑÑÐ¾Ð±Ñ Ð¾ÑÐºÑÑÑÑ Ð¼ÐµÐ½Ñ.",
        "scan_failed": "ÐÑÐ¾Ð²ÐµÑÐºÐ° Ð½Ðµ ÑÐ´Ð°Ð»Ð°ÑÑ. ÐÐ¾ÑÐ¼Ð¾ÑÑÐ¸ÑÐµ Ð¾ÑÐ¸Ð±ÐºÑ Ð² Ð»Ð¾Ð³Ð°Ñ Render.",
        "other": "ÐÑÐ¿ÑÐ°Ð²ÑÑÐµ ÑÐµÐºÑÑ Ð¸Ð»Ð¸ Ð¸ÑÐ¿Ð¾Ð»ÑÐ·ÑÐ¹ÑÐµ /start, ÑÑÐ¾Ð±Ñ Ð²ÑÐ±ÑÐ°ÑÑ Ð¸Ð½ÑÑÑÑÐ¼ÐµÐ½Ñ.",
        "report_caption": "Aegis Recon | HTML-Ð¾ÑÑÑÑ",
        "report_user": "ÐÑÑÑÑ Aegis Recon Ð´Ð»Ñ {username}",
        "prompt_header": "{tool}\n\n{prompt}\n\nÐÑÐ¿Ð¾Ð»ÑÐ·ÑÐ¹ÑÐµ /start, ÑÑÐ¾Ð±Ñ Ð¾ÑÐºÑÑÑÑ Ð³Ð»Ð°Ð²Ð½Ð¾Ðµ Ð¼ÐµÐ½Ñ.",
        "help_short": (
            "/username â Ð¿Ð¾Ð¸ÑÐº Ð¸Ð¼ÐµÐ½Ð¸\n"
            "/maigret â Ð³Ð»ÑÐ±Ð¾ÐºÐ¸Ð¹ Ð¿Ð¾Ð¸ÑÐº\n"
            "/email â Ð¿ÑÐ¾Ð²ÐµÑÐºÐ° Ð¿Ð¾ÑÑÑ\n"
            "/link â Ð°Ð½Ð°Ð»Ð¸Ð· ÑÑÑÐ»ÐºÐ¸\n"
            "/phone â Ð¿ÑÐ¾Ð²ÐµÑÐºÐ° Ð½Ð¾Ð¼ÐµÑÐ°\n"
            "/start â Ð³Ð»Ð°Ð²Ð½Ð¾Ðµ Ð¼ÐµÐ½Ñ"
        ),
    },
    "pl": {
        "language_button": "ðµð± JÄzyk",
        "start_button": "ð Rozpocznij analizÄ",
        "delete_button": "ð WyczyÅÄ czat",
        "welcome": (
            "ð¡ï¸ *Aegis Recon*\n\n"
            "Zestaw narzÄdzi do analizy OSINT.\n\n"
            "*DostÄpne moduÅy:*\n"
            "â¢ Wyszukiwanie nazwy uÅ¼ytkownika â Blackbird\n"
            "â¢ Wyszukiwanie zaawansowane â Maigret\n"
            "â¢ Analiza e-maila â Blackbird + publiczne rekordy MX\n"
            "â¢ Analiza linkÃ³w â VirusTotal\n"
            "â¢ Analiza numeru telefonu â bezpÅatna analiza lokalna\n\n"
            "_Korzystaj wyÅÄcznie zgodnie z prawem i za zgodÄ._"
        ),
        "main_menu": "Aegis Recon â Menu gÅÃ³wne",
        "username": "Szukaj nazwy",
        "maigret": "GÅÄbokie wyszukiwanie",
        "email": "Analiza e-maila",
        "link": "Analiza linku",
        "phone": "Numer telefonu",
        "help": "Pomoc",
        "language_title": "ð Wybierz jÄzyk:",
        "back": "â¬ï¸ WrÃ³Ä",
        "language_changed": "Zmieniono jÄzyk na polski ðµð±",
        "language_current": "Aktualny jÄzyk: polski ðµð±",
        "cleanup_no_chat": "Nie moÅ¼na ustaliÄ czatu.",
        "cleanup_done": (
            "Czyszczenie czatu zakoÅczone.\n"
            "UsuniÄte wiadomoÅci: {deleted}.\n"
            "Nie udaÅo siÄ usunÄÄ: {failed}.\n\n"
            "Telegram nie pozwala botom zagwarantowaÄ usuniÄcia caÅej historii. "
            "Starsze wiadomoÅci moÅ¼esz usunÄÄ rÄcznie w Telegramie."
        ),
        "help_text": (
            "*Pomoc Aegis Recon*\n\n"
            "/start â menu gÅÃ³wne\n"
            "/help â pomoc\n"
            "/username â wyszukiwanie nazwy uÅ¼ytkownika\n"
            "/maigret username â wyszukiwanie zaawansowane\n"
            "/email â analiza e-maila\n"
            "/link â analiza adresu URL\n"
            "/phone â analiza numeru telefonu\n\n"
            "Wybierz narzÄdzie, wyÅlij cel i poczekaj na raport HTML.\n\n"
            "Korzystaj tylko z danych i usÅug, do ktÃ³rych masz uprawniony dostÄp."
        ),
        "ask_username": "WyÅlij nazwÄ uÅ¼ytkownika do wyszukania przez Blackbird.",
        "ask_email": "WyÅlij adres e-mail do analizy.",
        "ask_link": "WyÅlij adres URL do analizy przez VirusTotal.",
        "ask_phone": "WyÅlij numer telefonu w formacie miÄdzynarodowym, np. +48123456789.",
        "ask_maigret": "WyÅlij nazwÄ uÅ¼ytkownika do gÅÄbokiego wyszukiwania Maigret. MoÅ¼e to potrwaÄ kilka minut.",
        "welcome_no_tool": "Witaj w Aegis Recon. UÅ¼yj /start, aby wybraÄ narzÄdzie.",
        "cancelled": "Operacja anulowana.",
        "scanning": "Skanowanie... ProszÄ czekaÄ.",
        "unexpected": "BÅÄd wyszukiwania: nieoczekiwana odpowiedÅº.",
        "valid_phone": "WyÅlij numer telefonu w formacie miÄdzynarodowym, np. +48123456789.",
        "phone_checking": "Sprawdzanie informacji o numerze...",
        "phone_error": "BÅÄd wyszukiwania: {error}",
        "phone_complete": "Analiza numeru zakoÅczona. PrzygotowujÄ raport HTML...",
        "phone_failed": "Nie udaÅo siÄ przeanalizowaÄ numeru. SprawdÅº logi Render.",
        "maigret_running": "Uruchamiam Maigret dla {username}. MoÅ¼e to potrwaÄ kilka minut.",
        "report_sending": "Analiza zakoÅczona. WysyÅam raport...",
        "maigret_no_report": "Maigret nie utworzyÅ raportu. SprawdÅº logi Render.",
        "maigret_failed": "Maigret nie dziaÅa poprawnie. SprawdÅº logi Render.",
        "tool_title_username": "Wyszukiwanie nazwy",
        "tool_title_email": "Analiza e-maila",
        "tool_title_link": "Analiza linku",
        "tool_title_phone": "Numer telefonu",
        "tool_title_maigret": "GÅÄbokie wyszukiwanie",
        "valid_username": "WyÅlij prawidÅowÄ nazwÄ uÅ¼ytkownika.",
        "valid_email": "Format adresu e-mail wydaje siÄ nieprawidÅowy.",
        "valid_url": "WyÅlij prawidÅowy adres HTTP lub HTTPS.",
        "unknown_tool": "Nieznane narzÄdzie. UÅ¼yj /start, aby otworzyÄ menu.",
        "scan_failed": "Skanowanie nie powiodÅo siÄ. SprawdÅº logi Render.",
        "other": "WyÅlij tekst lub uÅ¼yj /start, aby wybraÄ narzÄdzie.",
        "report_caption": "Aegis Recon | Raport HTML",
        "report_user": "Raport Aegis Recon dla {username}",
        "prompt_header": "{tool}\n\n{prompt}\n\nUÅ¼yj /start, aby otworzyÄ menu gÅÃ³wne.",
        "help_short": (
            "/username â wyszukiwanie nazwy\n"
            "/maigret â gÅÄbokie wyszukiwanie\n"
            "/email â analiza e-maila\n"
            "/link â analiza URL\n"
            "/phone â analiza numeru\n"
            "/start â menu gÅÃ³wne"
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
            InlineKeyboardButton("ðºð¸ English", callback_data="lang_en"),
            InlineKeyboardButton("ð·ðº Ð ÑÑÑÐºÐ¸Ð¹", callback_data="lang_ru"),
        ],
        [
            InlineKeyboardButton("ðµð± Polski", callback_data="lang_pl"),
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
        match = re.match(r"^(?:ð\s*)?(.{1,100}?):\s*(https?://\S+)$", line, flags=re.IGNORECASE)
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
