
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


TOKEN = (
    normalize(os.getenv("TELEGRAM_TOKEN"))
    or normalize(os.getenv("TELEGRAM_BOT_TOKEN"))
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
    remember_message(context, message.message_id)
    sent = await message.reply_text(text, **kwargs)
    remember_message(context, sent.message_id)
    return sent


async def tracked_document(message, context, document, filename, caption=None):
    remember_message(context, message.message_id)

    sent = await message.reply_document(
        document=document,
        filename=filename,
        caption=caption,
    )

    remember_message(context, sent.message_id)
    return sent


async def clear_tracked_chat(query, context):
    chat = query.message.chat if query.message else None

    if not chat:
        await query.answer("Could not identify the chat.", show_alert=True)
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
            await context.bot.delete_message(
                chat_id=chat_id,
                message_id=message_id,
            )
            deleted += 1
        except Exception as exc:
            failed += 1
            logger.debug("Could not delete message %s: %s", message_id, exc)

    context.user_data.pop("tracked_message_ids", None)

    sent = await context.bot.send_message(
        chat_id=chat_id,
        text=(
            "Chat cleanup completed.\n"
            f"Messages deleted: {deleted}.\n"
            f"Messages that could not be deleted: {failed}.\n\n"
            "Telegram does not allow bots to guarantee deletion of the "
            "entire chat history. You can delete older messages manually "
            "in Telegram."
        ),
    )

    remember_message(context, sent.message_id)


# --------------------------------------------------
# HTML REPORT HELPERS
# --------------------------------------------------

def safe_filename(value, prefix="Aegis"):
    value = re.sub(r"[^a-zA-Z0-9_-]", "_", str(value or "report"))
    value = value[:70] or "report"
    return f"{prefix}_{value}.html"


def parse_blackbird_results(output):
    output = str(output or "").strip()

    if not output:
        return {"Status": "No results returned by Blackbird."}

    data = {}

    for index, line in enumerate(output.splitlines(), start=1):
        line = line.strip()

        if not line:
            continue

        match = re.match(
            r"^(?:🔗\s*)?(.{1,100}?):\s*(https?://\S+)$",
            line,
            flags=re.IGNORECASE,
        )

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

        answers = data.get("Answer", [])

        records = [
            answer.get("data", "")
            for answer in answers
            if answer.get("type") == 15 and answer.get("data")
        ]

        if records:
            return "\n".join(records)

        if data.get("Status") == 3:
            return "Domain does not appear to exist (NXDOMAIN)."

        return (
            "No MX records returned. This alone does not prove "
            "the email address is invalid."
        )

    except Exception as exc:
        logger.warning("MX lookup failed for %s: %s", domain, exc)
        return "MX lookup unavailable."


async def send_html_report(message, context, title, data, filename):
    report_path = await asyncio.to_thread(
        generate_html_report,
        title,
        data,
        filename,
    )

    if not report_path or not os.path.isfile(report_path):
        raise RuntimeError("HTML report was not created.")

    try:
        with open(report_path, "rb") as report_file:
            await tracked_document(
                message,
                context,
                report_file,
                filename,
                caption="Aegis Recon | HTML report",
            )
    finally:
        try:
            os.remove(report_path)
        except OSError:
            logger.warning("Could not remove report: %s", report_path)


# --------------------------------------------------
# MENUS
# --------------------------------------------------

def main_menu_keyboard():
    # No Delete Chat button in the tools menu.
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("Username", callback_data="username"),
            InlineKeyboardButton("Deep Search", callback_data="maigret"),
        ],
        [
            InlineKeyboardButton("Email Scan", callback_data="email"),
            InlineKeyboardButton("Link Analysis", callback_data="link"),
        ],
        [
            InlineKeyboardButton("Phone Lookup", callback_data="phone"),
            InlineKeyboardButton("Help", callback_data="help"),
        ],
    ])


def welcome_text():
    return (
        "🛡️ *Aegis Recon*\n\n"
        "OSINT analysis toolkit.\n\n"
        "*Available modules:*\n"
        "• Username Search — Blackbird\n"
        "• Deep Search — Maigret\n"
        "• Email Scan — Blackbird + public MX records\n"
        "• Link Analysis — VirusTotal\n"
        "• Phone Lookup — free local number analysis\n\n"
        "_For lawful and authorized use only._"
    )


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

        await app.bot.set_chat_menu_button(
            menu_button=MenuButtonCommands()
        )

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

    remember_message(context, message.message_id)

    keyboard = InlineKeyboardMarkup([
        [
            InlineKeyboardButton(
                "🔍 Start Recon",
                callback_data="start_menu",
            )
        ],
        [
            InlineKeyboardButton(
                "🗑 Delete Chat",
                callback_data="clear_chat",
            )
        ],
    ])

    if BANNER_PATH.is_file():
        try:
            with open(BANNER_PATH, "rb") as banner:
                sent = await message.reply_photo(
                    photo=banner,
                    caption=welcome_text(),
                    reply_markup=keyboard,
                    parse_mode="Markdown",
                )

            remember_message(context, sent.message_id)
            return

        except Exception:
            logger.exception("Could not send banner image.")

    sent = await message.reply_text(
        welcome_text(),
        reply_markup=keyboard,
        parse_mode="Markdown",
    )
    remember_message(context, sent.message_id)


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (
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
    )

    await tracked_reply(
        update.effective_message,
        context,
        text,
        parse_mode="Markdown",
    )


async def ask_tool(update, context, tool, prompt):
    context.user_data["tool"] = tool
    context.user_data["cancel"] = False
    await tracked_reply(update.effective_message, context, prompt)


async def ask_username(update, context):
    await ask_tool(update, context, "username", "Send the username to search with Blackbird.")


async def ask_email(update, context):
    await ask_tool(update, context, "email", "Send the email address to investigate.")


async def ask_link(update, context):
    await ask_tool(update, context, "link", "Send the URL to analyze with VirusTotal.")


async def ask_phone(update, context):
    await ask_tool(
        update,
        context,
        "phone",
        "Send a phone number in international format, e.g. +31612345678.",
    )


async def ask_maigret(update, context):
    await ask_tool(
        update,
        context,
        "maigret",
        "Send a username for a deep Maigret search. This may take several minutes.",
    )


# --------------------------------------------------
# PHONE LOOKUP
# --------------------------------------------------

async def phone_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.effective_message
    if not message:
        return

    phone = context.args[0] if context.args else None

    if not phone:
        context.user_data["tool"] = "phone"
        await tracked_reply(
            message,
            context,
            "Send a phone number in international format, e.g. +31612345678.",
        )
        return

    status = await tracked_reply(message, context, "Checking phone information...")

    try:
        result = await asyncio.to_thread(lookup_phone, phone)

        if not isinstance(result, dict):
            await status.edit_text("Lookup failed: unexpected response.")
            return

        if result.get("error"):
            await status.edit_text(f"Lookup error: {result['error']}")
            return

        await status.edit_text("Phone lookup complete. Preparing HTML report...")

        await send_html_report(
            message,
            context,
            f"Phone lookup: {result.get('phone', phone)}",
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
            await status.edit_text("Phone lookup failed. Check the Render logs.")
        except Exception:
            pass


# --------------------------------------------------
# MAIGRET
# --------------------------------------------------

async def maigret_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.effective_message
    if not message:
        return

    username = context.args[0] if context.args else None

    if not username:
        context.user_data["tool"] = "maigret"
        await tracked_reply(message, context, "Send a username for the deep search.")
        return

    status = await tracked_reply(
        message,
        context,
        f"Running Maigret for {username}. This may take several minutes.",
    )

    try:
        report_path = await asyncio.to_thread(run_maigret, username)

        if report_path and os.path.isfile(report_path):
            await status.edit_text("Analysis complete. Sending report...")

            with open(report_path, "rb") as report_file:
                await tracked_document(
                    message,
                    context,
                    report_file,
                    safe_filename(username, "Aegis_Maigret"),
                    caption=f"Aegis Recon report for {username}",
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
            await status.edit_text("Maigret did not produce a report. Check Render logs.")

    except Exception:
        logger.exception("Maigret search failed.")
        try:
            await status.edit_text("Maigret failed. Check Render logs.")
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

    if data == "start_menu":
        if query.message:
            try:
                await query.edit_message_caption(
                    caption="Aegis Recon — Main Menu",
                    reply_markup=main_menu_keyboard(),
                )
            except Exception:
                try:
                    await query.edit_message_text(
                        "Aegis Recon — Main Menu",
                        reply_markup=main_menu_keyboard(),
                    )
                except Exception:
                    sent = await query.message.reply_text(
                        "Aegis Recon — Main Menu",
                        reply_markup=main_menu_keyboard(),
                    )
                    remember_message(context, sent.message_id)
        return

    prompts = {
        "username": "Send the username to search with Blackbird.",
        "email": "Send the email address to investigate.",
        "link": "Send the URL to analyze with VirusTotal.",
        "phone": "Send the phone number in international format.",
        "maigret": (
            "Send a username for a deep Maigret search. "
            "This may take several minutes."
        ),
    }

    if data in prompts:
        context.user_data["tool"] = data
        context.user_data["cancel"] = False

        if query.message:
            sent = await query.message.reply_text(
                f"{data.title()}\n\n{prompts[data]}\n\n"
                "Use /start to open the main menu."
            )
            remember_message(context, query.message.message_id)
            remember_message(context, sent.message_id)
        return

    if data == "help" and query.message:
        sent = await query.message.reply_text(
            "/username — username search\n"
            "/maigret — deep search\n"
            "/email — email scan\n"
            "/link — URL analysis\n"
            "/phone — phone lookup\n"
            "/start — main menu"
        )
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
        await tracked_reply(
            message,
            context,
            "Welcome to Aegis Recon. Use /start to choose a tool.",
        )
        return

    remember_message(context, message.message_id)

    if context.user_data.get("cancel"):
        context.user_data["cancel"] = False
        context.user_data.pop("tool", None)
        await tracked_reply(message, context, "Operation cancelled.")
        return

    context.user_data.pop("tool", None)
    status = await tracked_reply(message, context, "Scanning... Please wait.")

    try:
        await context.bot.send_chat_action(
            chat_id=update.effective_chat.id,
            action=ChatAction.TYPING,
        )

        if tool == "phone":
            result = await asyncio.to_thread(lookup_phone, text)

            if not isinstance(result, dict):
                await status.edit_text("Lookup failed: unexpected response.")
                return

            if result.get("error"):
                await status.edit_text(f"Lookup error: {result['error']}")
                return

            await send_html_report(
                message,
                context,
                f"Phone lookup: {result.get('phone', text)}",
                {"Service": result.get("source", "Free local analysis"), **result},
                safe_filename(text, "Aegis_Phone"),
            )

        elif tool == "maigret":
            username = re.sub(r"\s+", "", text)

            if not username or len(username) > 100:
                await status.edit_text("Please send a valid username.")
                return

            report_path = await asyncio.to_thread(run_maigret, username)

            if report_path and os.path.isfile(report_path):
                with open(report_path, "rb") as report_file:
                    await tracked_document(
                        message,
                        context,
                        report_file,
                        safe_filename(username, "Aegis_Maigret"),
                        caption=f"Aegis Recon report for {username}",
                    )

                try:
                    os.remove(report_path)
                except OSError:
                    logger.warning("Could not remove Maigret report: %s", report_path)
            else:
                await status.edit_text("Maigret did not produce a report. Check Render logs.")
                return

        elif tool == "username":
            username = re.sub(r"\s+", "", text)

            if not username or len(username) > 100:
                await status.edit_text("Please send a valid username.")
                return

            result = await asyncio.to_thread(
                blackbird_service.search_username,
                username,
            )

            report_data = {
                "Target username": username,
                "Service": "Blackbird",
                **parse_blackbird_results(result),
            }

            await send_html_report(
                message,
                context,
                f"Username Analysis: {username}",
                report_data,
                safe_filename(username, "Aegis_Username"),
            )

        elif tool == "email":
            if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", text):
                await status.edit_text("That does not look like a valid email format.")
                return

            email = text.strip()
            domain = email.rsplit("@", 1)[1].lower()

            blackbird_result = await asyncio.to_thread(
                blackbird_service.scan_email,
                email,
            )
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
                message,
                context,
                f"Email Analysis: {email}",
                report_data,
                safe_filename(email, "Aegis_Email"),
            )

        elif tool == "link":
            url = validate_http_url(text)

            if not url:
                await status.edit_text("Please send a valid HTTP or HTTPS URL.")
                return

            result = await asyncio.to_thread(virustotal_service.scan_link, url)

            if isinstance(result, dict):
                report_data = {
                    "Target URL": url,
                    "Service": "VirusTotal",
                    **result,
                }
            else:
                report_data = {
                    "Target URL": url,
                    "Service": "VirusTotal",
                    "Analysis result": str(result or "No results returned."),
                    "Interpretation": (
                        "An absence of detections does not guarantee "
                        "that a URL is safe."
                    ),
                }

            await send_html_report(
                message,
                context,
                f"Link Analysis: {url}",
                report_data,
                safe_filename("link_analysis", "Aegis_VirusTotal"),
            )

        else:
            await status.edit_text("Unknown tool. Use /start to open the menu.")
            return

        try:
            await status.delete()
        except Exception:
            pass

    except Exception:
        logger.exception("Message handling failed for tool=%s", tool)
        try:
            await status.edit_text("The scan failed. Check Render logs for the error.")
        except Exception:
            pass


async def handle_other(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.effective_message
    if not message:
        return

    remember_message(context, message.message_id)
    await tracked_reply(message, context, "Please send text or use /start to choose a tool.")


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


application = (
    ApplicationBuilder()
    .token(TOKEN)
    .post_init(post_init)
    .build()
)

application.add_handler(CommandHandler("start", start))
application.add_handler(CommandHandler("help", help_command))
application.add_handler(CommandHandler("username", ask_username))
application.add_handler(CommandHandler("email", ask_email))
application.add_handler(CommandHandler("link", ask_link))
application.add_handler(CommandHandler("phone", ask_phone))
application.add_handler(CommandHandler("maigret", maigret_command))

application.add_handler(CallbackQueryHandler(button))

application.add_handler(
    MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message)
)

application.add_handler(
    MessageHandler(~(filters.TEXT | filters.COMMAND), handle_other)
)

application.add_handler(
    ChatMemberHandler(chat_member_update, ChatMemberHandler.CHAT_MEMBER)
)

application.add_handler(
    ChatMemberHandler(chat_member_update, ChatMemberHandler.MY_CHAT_MEMBER)
)

application.add_error_handler(on_error)


if __name__ == "__main__":
    logger.info("Aegis Recon starting polling...")
    application.run_polling()
