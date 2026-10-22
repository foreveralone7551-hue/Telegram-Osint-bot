
import os
import re
import io
import json
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
from utils.formatting import format_output
from phone import lookup_phone
from utils.pdf_generator import generate_html_report
from services.maigret_service import run_maigret


# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
LOG_PATH = BASE_DIR / "bot.log"

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

application = ApplicationBuilder().token(TOKEN).build()


# --------------------------------------------------
# HTML REPORT HELPERS
# --------------------------------------------------

def safe_filename(value, prefix="Aegis"):
    value = re.sub(r"[^a-zA-Z0-9_-]", "_", str(value or "report"))
    value = value[:70] or "report"
    return f"{prefix}_{value}.html"


def parse_blackbird_results(output):
    """
    Convert Blackbird text output into report rows.
    Keep only data returned by the service; do not invent findings.
    """
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
    except (ValueError, TypeError):
        return None

    return value


def lookup_mx_records(domain):
    """Retrieve public MX records using Google's DNS-over-HTTPS endpoint."""
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

        return "No MX records returned. This alone does not prove the address is invalid."

    except Exception as exc:
        logger.warning("MX lookup failed for %s: %s", domain, exc)
        return "MX lookup unavailable."


async def send_html_report(message, title, data, filename):
    """Create and send an HTML report as a Telegram document."""
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
            await message.reply_document(
                document=report_file,
                filename=filename,
                caption="🛡️ Aegis Recon | HTML report",
            )
    finally:
        try:
            os.remove(report_path)
        except OSError:
            logger.warning("Could not remove report: %s", report_path)


# --------------------------------------------------
# MENU
# --------------------------------------------------

def main_menu_keyboard():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("Username Search", callback_data="username")],
        [InlineKeyboardButton("Deep Search (Maigret)", callback_data="maigret")],
        [InlineKeyboardButton("Email Scan", callback_data="email")],
        [InlineKeyboardButton("Link Analysis", callback_data="link")],
        [InlineKeyboardButton("Phone HLR", callback_data="phone")],
        [InlineKeyboardButton("Help", callback_data="help")],
        [InlineKeyboardButton("🧹 Clear Chat", callback_data="clear_chat")],
    ])


def welcome_text():
    return (
        "**🛡️ Aegis Recon**\n\n"
        "OSINT analysis toolkit.\n\n"
        "**Available modules:**\n"
        "• Username Search — Blackbird\n"
        "• Deep Search — Maigret\n"
        "• Email Scan — Blackbird + public MX records\n"
        "• Link Analysis — VirusTotal\n"
        "• Phone HLR — IPQualityScore\n\n"
        "_For lawful and authorized use only._"
    )


async def setup_menu(update=None, context=None):
    commands = [
        BotCommand("start", "Open the main menu"),
        BotCommand("username", "Username Search"),
        BotCommand("maigret", "Deep Username Search"),
        BotCommand("email", "Email Scan"),
        BotCommand("link", "Link Analysis"),
        BotCommand("phone", "Phone HLR Lookup"),
        BotCommand("help", "Help and instructions"),
    ]

    try:
        await application.bot.set_my_commands(commands)
        await application.bot.set_chat_menu_button(
            menu_button=MenuButtonCommands()
        )
        logger.info("Bot commands menu configured.")
    except Exception:
        logger.exception("Could not configure bot menu.")

    if update and update.effective_message:
        await update.effective_message.reply_text("Bot commands configured.")


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_message:
        await update.effective_message.reply_text(
            welcome_text(),
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("Start Recon", callback_data="start_menu")]
            ]),
            parse_mode="Markdown",
        )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (
        "❓ **Aegis Recon Help**\n\n"
        "/start — Main menu\n"
        "/help — Help\n"
        "/username — Username search\n"
        "/maigret username — Deep username search\n"
        "/email — Email scan\n"
        "/link — URL analysis\n"
        "/phone number — Phone lookup\n\n"
        "Choose a tool, send the target, and wait for the HTML report."
    )
    await update.effective_message.reply_text(text, parse_mode="Markdown")


async def ask_tool(update, context, tool, prompt):
    context.user_data["tool"] = tool
    context.user_data["cancel"] = False
    await update.effective_message.reply_text(prompt)


async def ask_username(update, context):
    await ask_tool(update, context, "username", "Send the username to search.")


async def ask_email(update, context):
    await ask_tool(update, context, "email", "Send the email address to investigate.")


async def ask_link(update, context):
    await ask_tool(update, context, "link", "Send the URL to analyze.")


async def ask_phone(update, context):
    await ask_tool(
        update, context, "phone",
        "Send the phone number in international format, e.g. +79991234567."
    )


application.add_handler(CommandHandler("start", start))
application.add_handler(CommandHandler("help", help_command))
application.add_handler(CommandHandler("setup_menu", setup_menu))
application.add_handler(CommandHandler("username", ask_username))
application.add_handler(CommandHandler("email", ask_email))
application.add_handler(CommandHandler("link", ask_link))
application.add_handler(CommandHandler("phone", ask_phone))


# --------------------------------------------------
# BUTTONS
# --------------------------------------------------

async def button(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data = query.data

    prompts = {
        "username": "Send the username to search with Blackbird.",
        "email": "Send the email address to investigate.",
        "link": "Send the URL to analyze with VirusTotal.",
        "phone": "Send the phone number in international format.",
        "maigret": "Send a username for a deep Maigret search. This may take several minutes.",
    }

    if data in prompts:
        context.user_data["tool"] = data
        context.user_data["cancel"] = False
        await query.edit_message_text(
            f"**{data.title()}**\n\n{prompts[data]}\n\n"
            "Use /start to return to the main menu.",
            parse_mode="Markdown",
        )
        return

    if data == "cancel":
        context.user_data["cancel"] = True
        context.user_data.pop("tool", None)
        await query.edit_message_text("Operation cancelled.")
        return

    if data == "help":
        await query.edit_message_text(
            "/username — username search\n"
            "/maigret username — deep search\n"
            "/email — email scan\n"
            "/link — URL analysis\n"
            "/phone — phone lookup"
        )
        return

    if data == "clear_chat":
        await query.edit_message_text(
            "You can clear the conversation from Telegram. "
            "The bot cannot remove the entire chat history."
        )
        return

    if data in ("start_menu", "back_to_menu"):
        await query.edit_message_text(
            welcome_text(),
            reply_markup=main_menu_keyboard(),
            parse_mode="Markdown",
        )


application.add_handler(CallbackQueryHandler(button))


# --------------------------------------------------
# PHONE HLR
# --------------------------------------------------

async def phone_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    phone = context.args[0] if context.args else None

    if not phone:
        context.user_data["tool"] = "phone"
        await update.effective_message.reply_text(
            "Send a phone number in international format, e.g. +79991234567."
        )
        return

    status = await update.effective_message.reply_text(
        "📡 Checking phone information..."
    )

    try:
        result = await asyncio.to_thread(lookup_phone, phone)

        if not isinstance(result, dict):
            await status.edit_text("Lookup failed: unexpected response.")
            return

        if result.get("error"):
            await status.edit_text(f"Lookup error: {result['error']}")
            return

        await status.edit_text("Phone lookup complete. Preparing HTML report...")

        filename = safe_filename(phone, "Aegis_Phone")
        await send_html_report(
            update.effective_message,
            f"Phone HLR: {result.get('phone', phone)}",
            {
                "Service": "IPQualityScore",
                **result,
                "Disclaimer": (
                    "Fraud score and line status are service estimates, "
                    "not proof of identity or wrongdoing."
                ),
            },
            filename,
        )

    except Exception:
        logger.exception("Phone lookup failed.")
        await status.edit_text(
            "Phone lookup failed. Check the IPQualityScore configuration and Render logs."
        )


# --------------------------------------------------
# MAIGRET
# --------------------------------------------------

async def maigret_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    username = context.args[0] if context.args else None

    if not username:
        context.user_data["tool"] = "maigret"
        await update.effective_message.reply_text(
            "Send a username for the deep search."
        )
        return

    status = await update.effective_message.reply_text(
        f"🕵️ Running Maigret for {username}. This may take several minutes."
    )

    try:
        report_path = await asyncio.to_thread(run_maigret, username)

        if report_path and os.path.isfile(report_path):
            await status.edit_text("Analysis complete. Sending report...")
            with open(report_path, "rb") as report_file:
                await update.effective_message.reply_document(
                    document=report_file,
                    filename=safe_filename(username, "Aegis_Maigret"),
                    caption=f"Aegis Recon report for {username}",
                )

            try:
                os.remove(report_path)
            except OSError:
                logger.warning("Could not remove Maigret report: %s", report_path)
        else:
            await status.edit_text(
                "Maigret did not produce a report. Check Render logs."
            )

    except Exception:
        logger.exception("Maigret search failed.")
        await status.edit_text("Maigret failed. Check Render logs.")


application.add_handler(CommandHandler("maigret", maigret_command))


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
        await message.reply_text(
            "Welcome to Aegis Recon. Use /start to choose a tool."
        )
        return

    if context.user_data.get("cancel"):
        context.user_data["cancel"] = False
        context.user_data.pop("tool", None)
        await message.reply_text("Operation cancelled.")
        return

    context.user_data.pop("tool", None)
    status = await message.reply_text("Scanning... Please wait.")

    try:
        await context.bot.send_chat_action(
            chat_id=update.effective_chat.id,
            action=ChatAction.TYPING,
        )

        # PHONE
        if tool == "phone":
            context.args = [text]
            await phone_command(update, context)
            return

        # MAIGRET
        if tool == "maigret":
            context.args = [text]
            await maigret_command(update, context)
            return

        # USERNAME
        if tool == "username":
            username = re.sub(r"\s+", "", text)
            if not username or len(username) > 100:
                await status.edit_text("Please send a valid username.")
                return

            result = await asyncio.to_thread(
                blackbird_service.search_username, username
            )
            report_data = {
                "Target username": username,
                "Service": "Blackbird",
                **parse_blackbird_results(result),
            }
            title = f"Username Analysis: {username}"
            filename = safe_filename(username, "Aegis_Username")

        # EMAIL
        elif tool == "email":
            if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", text):
                await status.edit_text("That does not look like a valid email format.")
                return

            email = text.strip()
            domain = email.rsplit("@", 1)[1].lower()

            blackbird_result = await asyncio.to_thread(
                blackbird_service.scan_email, email
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
            title = f"Email Analysis: {email}"
            filename = safe_filename(email, "Aegis_Email")

        # VIRUSTOTAL
        elif tool == "link":
            url = validate_http_url(text)
            if not url:
                await status.edit_text("Please send a valid HTTP or HTTPS URL.")
                return

            result = await asyncio.to_thread(
                virustotal_service.scan_link, url
            )

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
                        "An absence of detections does not guarantee that a URL is safe."
                    ),
                }

            title = f"Link Analysis: {url}"
            filename = safe_filename("link_analysis", "Aegis_VirusTotal")

        else:
            await status.edit_text("Unknown tool. Use /start to open the menu.")
            return

        await status.edit_text("Scan complete. Generating HTML report...")

        await send_html_report(
            message,
            title,
            report_data,
            filename,
        )

        try:
            await status.delete()
        except Exception:
            pass

    except Exception:
        logger.exception("Message handling failed for tool=%s", tool)
        try:
            await status.edit_text(
                "The scan failed. Check Render logs for the error."
            )
        except Exception:
            await message.reply_text(
                "The scan failed. Check Render logs for the error."
            )


async def handle_other(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_message:
        await update.effective_message.reply_text(
            "Please send text or use /start to choose a tool."
        )


application.add_handler(
    MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message)
)
application.add_handler(
    MessageHandler(~(filters.TEXT | filters.COMMAND), handle_other)
)


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


application.add_handler(
    ChatMemberHandler(chat_member_update, ChatMemberHandler.CHAT_MEMBER)
)
application.add_handler(
    ChatMemberHandler(chat_member_update, ChatMemberHandler.MY_CHAT_MEMBER)
)


# --------------------------------------------------
# ERRORS AND STARTUP
# --------------------------------------------------

async def on_error(update: object, context: ContextTypes.DEFAULT_TYPE):
    logger.error("Unhandled Telegram error", exc_info=context.error)


application.add_error_handler(on_error)


async def post_init(app):
    await setup_menu()


application.post_init = post_init


if __name__ == "__main__":
    logger.info("Aegis Recon starting polling...")
    application.run_polling()
