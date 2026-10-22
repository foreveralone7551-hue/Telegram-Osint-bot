import os
import re
import io
import asyncio
import logging
from pathlib import Path

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
# LOGGING
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
LOG_PATH = BASE_DIR / "bot.log"
ENV_PATH = BASE_DIR / ".env"

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

load_dotenv(dotenv_path=ENV_PATH, override=False)


def normalize(value):
    if not value:
        return ""

    value = value.strip().strip('"').strip("'")
    return value.lstrip("\ufeff")


TOKEN = (
    normalize(os.getenv("TELEGRAM_TOKEN"))
    or normalize(os.getenv("TELEGRAM_BOT_TOKEN"))
)

if not TOKEN:
    raise RuntimeError(
        "Telegram token is missing. "
        "Set TELEGRAM_TOKEN or TELEGRAM_BOT_TOKEN in Render Environment."
    )

logger.info("Telegram token found.")

application = ApplicationBuilder().token(TOKEN).build()

TOTAL_PLATFORMS = 754


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
        "Advanced OSINT Intelligence Toolkit.\n\n"
        "**Available Modules:**\n"
        "• Username Search — Blackbird\n"
        "• Deep Search — Maigret\n"
        "• Email Scan\n"
        "• Link Analysis — VirusTotal\n"
        "• Phone HLR Lookup\n\n"
        "_For lawful and ethical use only._"
    )


async def setup_menu(update=None, context=None):
    bot = application.bot

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
        await bot.set_my_commands(commands)
        await bot.set_chat_menu_button(menu_button=MenuButtonCommands())
        logger.info("Bot commands menu configured.")
    except Exception:
        logger.exception("Could not configure bot menu.")

    if update and update.effective_message:
        await update.effective_message.reply_text(
            "Bot commands configured."
        )


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    logger.info(
        "/start from user_id=%s",
        getattr(user, "id", None),
    )

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
        "**Commands:**\n"
        "/start — Main menu\n"
        "/help — Help\n"
        "/username — Username search\n"
        "/maigret username — Deep username search\n"
        "/email — Email scan\n"
        "/link — Link analysis\n"
        "/phone number — Phone lookup\n\n"
        "Choose a tool, send the information, and wait for the result."
    )

    if update.effective_message:
        await update.effective_message.reply_text(
            text,
            parse_mode="Markdown",
        )


async def ask_username(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data["tool"] = "username"
    await update.effective_message.reply_text(
        "Send the username you want to search."
    )


async def ask_email(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data["tool"] = "email"
    await update.effective_message.reply_text(
        "Send the email address you want to investigate."
    )


async def ask_link(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data["tool"] = "link"
    await update.effective_message.reply_text(
        "Send the URL you want to analyze."
    )


application.add_handler(CommandHandler("start", start))
application.add_handler(CommandHandler("help", help_command))
application.add_handler(CommandHandler("setup_menu", setup_menu))
application.add_handler(CommandHandler("username", ask_username))
application.add_handler(CommandHandler("email", ask_email))
application.add_handler(CommandHandler("link", ask_link))


# --------------------------------------------------
# BUTTONS
# --------------------------------------------------

async def button(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    data = query.data

    if data in ("username", "email", "link", "phone", "maigret"):
        context.user_data["tool"] = data
        context.user_data["cancel"] = False

        prompts = {
            "username": "Send the username to search with Blackbird.",
            "email": "Send the email address to investigate.",
            "link": "Send the URL to analyze with VirusTotal.",
            "phone": "Send the phone number in international format.",
            "maigret": "Send a username for a deep Maigret search. This may take several minutes.",
        }

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
            "Use /start to open the menu.\n"
            "/username — username search\n"
            "/maigret username — deep search\n"
            "/email — email scan\n"
            "/link — URL analysis\n"
            "/phone number — phone lookup"
        )
        return

    if data == "clear_chat":
        await query.edit_message_text(
            "I can only delete messages the bot is permitted to delete. "
            "You can clear the conversation from Telegram."
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
# PHONE LOOKUP
# --------------------------------------------------

async def phone_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if context.args:
        phone = context.args[0]
    else:
        phone = context.user_data.get("pending_input")

    if not phone:
        context.user_data["tool"] = "phone"
        await update.effective_message.reply_text(
            "Send a phone number in international format, for example +79991234567."
        )
        return

    msg = await update.effective_message.reply_text(
        "📡 Checking phone information..."
    )

    try:
        result = await asyncio.to_thread(lookup_phone, phone)

        if not isinstance(result, dict):
            await msg.edit_text("Lookup failed: unexpected response.")
            return

        if result.get("error"):
            await msg.edit_text(f"Lookup error: {result['error']}")
            return

        report = (
            "🛡️ **Aegis Recon: HLR Report**\n\n"
            f"**Phone:** {result.get('phone', phone)}\n"
            f"**Valid:** {result.get('valid', 'Unknown')}\n"
            f"**Active:** {result.get('active', 'Unknown')}\n"
            f"**Carrier:** {result.get('carrier', 'Unknown')}\n"
            f"**Line Type:** {result.get('line_type', 'Unknown')}\n"
            f"**Country:** {result.get('country', 'Unknown')}\n"
            f"**Location:** {result.get('location', 'Unknown')}\n"
            f"**Fraud Score:** {result.get('fraud_score', 'Unknown')}\n"
            f"**Risky:** {result.get('risky', 'Unknown')}"
        )

        await msg.edit_text(report, parse_mode="Markdown")

        filename = f"Aegis_Report_{re.sub(r'[^a-zA-Z0-9_-]', '_', str(phone))}.html"
        html_path = generate_html_report(
            str(result.get("phone", phone)),
            result,
            filename,
        )

        if html_path and os.path.isfile(html_path):
            with open(html_path, "rb") as file:
                await update.effective_message.reply_document(
                    document=file,
                    filename=filename,
                    caption="Aegis Recon HTML report",
                )

    except Exception:
        logger.exception("Phone lookup failed.")
        await update.effective_message.reply_text(
            "Phone lookup failed. Check the service configuration and logs."
        )


async def phone_from_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    phone = (update.effective_message.text or "").strip()
    context.user_data.pop("tool", None)
    context.args = [phone]
    await phone_command(update, context)


application.add_handler(CommandHandler("phone", phone_command))


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

    msg = await update.effective_message.reply_text(
        f"🕵️ Running Maigret for {username}. This may take several minutes."
    )

    try:
        report_path = await asyncio.to_thread(run_maigret, username)

        if report_path and os.path.isfile(report_path):
            await msg.edit_text("Analysis complete. Sending report...")

            with open(report_path, "rb") as file:
                await update.effective_message.reply_document(
                    document=file,
                    filename=f"maigret_{username}.html",
                    caption=f"Aegis Recon report for {username}",
                )

            try:
                os.remove(report_path)
            except OSError:
                logger.warning("Could not remove report file: %s", report_path)
        else:
            await msg.edit_text(
                "Maigret did not produce a report. Check Render logs."
            )

    except Exception:
        logger.exception("Maigret search failed.")
        await msg.edit_text(
            "Maigret failed. Check Render logs for the error."
        )


application.add_handler(CommandHandler("maigret", maigret_command))


# --------------------------------------------------
# MESSAGE HANDLER
# --------------------------------------------------

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.effective_message

    if not message or not message.text:
        return

    text = message.text.strip()
    tool = context.user_data.get("tool")

    logger.info(
        "Incoming message: user_id=%s tool=%s",
        getattr(update.effective_user, "id", None),
        tool,
    )

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

        if tool == "phone":
            context.user_data["pending_input"] = text
            context.args = [text]
            await phone_command(update, context)
            context.user_data.pop("pending_input", None)
            return

        if tool == "maigret":
            context.args = [text]
            await maigret_command(update, context)
            return

        if tool == "username":
            username = re.sub(r"\s+", "", text)
            result = await asyncio.to_thread(
                blackbird_service.search_username,
                username,
            )

        elif tool == "email":
            if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", text):
                await status.edit_text("That does not look like a valid email address.")
                return

            result = await asyncio.to_thread(
                blackbird_service.scan_email,
                text,
            )

        elif tool == "link":
            if not re.match(r"^(https?://|www\.)", text, re.IGNORECASE):
                text = "https://" + text

            result = await asyncio.to_thread(
                virustotal_service.scan_link,
                text,
            )

        else:
            await status.edit_text("Unknown tool. Use /start to open the menu.")
            return

        output = result if isinstance(result, str) else str(result or "")

        if not output.strip():
            output = "No results were returned by the service."

        try:
            formatted = format_output(tool, output)
            if not isinstance(formatted, str):
                formatted = str(formatted)
        except Exception:
            logger.exception("Output formatting failed.")
            formatted = output

        await status.edit_text("Scan complete. Sending results...")

        if len(formatted) > 3800:
            buffer = io.BytesIO(output.encode("utf-8"))
            buffer.name = "results.txt"

            await message.reply_document(
                document=buffer,
                caption="Full scan results",
            )
        else:
            try:
                await message.reply_text(
                    formatted,
                    parse_mode="HTML",
                    disable_web_page_preview=True,
                )
            except Exception:
                await message.reply_text(output[:4000])

    except Exception:
        logger.exception("Message handling failed.")
        try:
            await status.edit_text(
                "The scan failed. Check Render logs for details."
            )
        except Exception:
            await message.reply_text(
                "The scan failed. Check Render logs for details."
            )


async def handle_other(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_message:
        await update.effective_message.reply_text(
            "Please send text or use /start to choose a tool."
        )


application.add_handler(
    MessageHandler(
        filters.TEXT & ~filters.COMMAND,
        handle_message,
    )
)

application.add_handler(
    MessageHandler(
        ~(filters.TEXT | filters.COMMAND),
        handle_other,
    )
)


# --------------------------------------------------
# CHAT MEMBER EVENTS
# --------------------------------------------------

async def chat_member_update(update: Update, context: ContextTypes.DEFAULT_TYPE):
    member_update = update.chat_member or update.my_chat_member

    if not member_update:
        return

    logger.info(
        "Chat member status changed in chat_id=%s",
        member_update.chat.id if member_update.chat else None,
    )


application.add_handler(
    ChatMemberHandler(
        chat_member_update,
        ChatMemberHandler.CHAT_MEMBER,
    )
)

application.add_handler(
    ChatMemberHandler(
        chat_member_update,
        ChatMemberHandler.MY_CHAT_MEMBER,
    )
)


# --------------------------------------------------
# ERROR HANDLING AND STARTUP
# --------------------------------------------------

async def on_error(update: object, context: ContextTypes.DEFAULT_TYPE):
    logger.error(
        "Unhandled Telegram error",
        exc_info=context.error,
    )


application.add_error_handler(on_error)


async def post_init(app):
    await setup_menu()


application.post_init = post_init


if __name__ == "__main__":
    logger.info("Aegis Recon starting polling...")
    application.run_polling()
