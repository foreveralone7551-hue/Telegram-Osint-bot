import os
import re
import io
import asyncio
from pathlib import Path
from dotenv import load_dotenv
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update, BotCommand, MenuButton, MenuButtonCommands
from telegram.constants import ChatAction
from telegram.ext import ApplicationBuilder, CommandHandler, CallbackQueryHandler, MessageHandler, ContextTypes, filters, ChatMemberHandler
import logging

from services import blackbird_service, virustotal_service
from utils.formatting import format_output
from services.hlr_phone import lookup_phone
from utils.pdf_generator import generate_hlr_pdf

# Logging setup (console + file)
LOG_PATH = Path(__file__).resolve().parent / 'bot.log'
logging.basicConfig(
	level=logging.INFO,
	format='%(asctime)s %(levelname)s %(name)s: %(message)s',
	handlers=[
		logging.StreamHandler(),
		logging.FileHandler(LOG_PATH, encoding='utf-8')
	]
)
logger = logging.getLogger('bot')

# Reduce verbosity of HTTP libraries to avoid leaking sensitive tokens in URLs
logging.getLogger('httpx').setLevel(logging.WARNING)
logging.getLogger('telegram.request').setLevel(logging.WARNING)

# Explicitly load .env from this script's directory
ENV_PATH = Path(__file__).resolve().parent / '.env'
load_dotenv(dotenv_path=ENV_PATH, override=True)

def _normalize(value: str) -> str:
	if value is None:
		return value
	v = value.strip().strip('"').strip("'")
	if v and v[0] == '\ufeff':
		v = v[1:]
	return v

# Fallback: parse .env manually if needed (supports both keys)
if not (_normalize(os.getenv("TELEGRAM_TOKEN")) or _normalize(os.getenv("TELEGRAM_BOT_TOKEN"))) and ENV_PATH.exists():
	try:
		for raw_line in ENV_PATH.read_text(encoding="utf-8").splitlines():
			line = raw_line.strip()
			if not line or line.startswith('#'):
				continue
			if line.startswith('\ufeff'):
				line = line.lstrip('\ufeff')
			if line.startswith('TELEGRAM_TOKEN='):
				val = _normalize(line.split('=', 1)[1])
				if val:
					os.environ['TELEGRAM_TOKEN'] = val
			elif line.startswith('TELEGRAM_BOT_TOKEN='):
				val = _normalize(line.split('=', 1)[1])
				if val:
					os.environ['TELEGRAM_BOT_TOKEN'] = val
	except Exception:
		pass

TOKEN = _normalize(os.getenv("TELEGRAM_TOKEN")) or _normalize(os.getenv("TELEGRAM_BOT_TOKEN"))

if not TOKEN:
	raise RuntimeError(f"Missing bot token. Set TELEGRAM_TOKEN or TELEGRAM_BOT_TOKEN in {ENV_PATH}")

logger.info("Starting application with token present: %s", 'yes')
application = ApplicationBuilder().token(TOKEN).build()

TOTAL_PLATFORMS = 754

async def setup_menu():
	try:
		await application.bot.delete_my_commands()
	except Exception:
		pass

	commands = [
		BotCommand("start", "Start Recon Bot"),
		BotCommand("username", "Username Search"),
		BotCommand("email", "Email Scan"),
		BotCommand("link", "Link Analysis"),
		BotCommand("phone", "Phone HLR Lookup"),
		BotCommand("help", "Get help and instructions")
	]
	await application.bot.set_my_commands(commands)
	
	menu_button = MenuButtonCommands()
	await application.bot.set_chat_menu_button(menu_button=menu_button)
	
	logger.info("Menu and commands set up successfully")

application.add_handler(CommandHandler("setup_menu", setup_menu))

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
	user = update.effective_user
	logger.info("/start from user_id=%s username=%s", getattr(user, 'id', None), getattr(user, 'username', None))
	
	welcome_text = """**What can this bot do?**

Hello! Let's Recon it 🚀

**Available Tools:**
• Username Search - Find profiles across platforms
• Email Scan - Analyze email addresses  
• Link Analysis - Check URLs and domains
• Phone HLR - Check carrier and validity

Note: For LEGAL use only. Do not misuse this tool ⚠️"""
	
	keyboard = [
		[InlineKeyboardButton("Start Recon", callback_data='start_menu')]
	]
	
	if update.message:
		await update.message.reply_text(welcome_text, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode="Markdown")

application.add_handler(CommandHandler("start", start))

application.add_handler(CommandHandler("username", lambda u, c: c.bot.send_message(chat_id=u.effective_chat.id, text="**Username Search**\n\nSend the information you want to investigate:", parse_mode="Markdown")))
application.add_handler(CommandHandler("email", lambda u, c: c.bot.send_message(chat_id=u.effective_chat.id, text="**Email Scan**\n\nSend the information you want to investigate:", parse_mode="Markdown")))
application.add_handler(CommandHandler("link", lambda u, c: c.bot.send_message(chat_id=u.effective_chat.id, text="**Link Analysis**\n\nSend the information you want to investigate:", parse_mode="Markdown")))

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
	user = update.effective_user
	logger.info("/help from user_id=%s username=%s", getattr(user, 'id', None), getattr(user, 'username', None))
	
	help_text = """❓ **Help & Instructions** ❓

**Available Commands:**
• `/start` - Start the bot and show main menu
• `/help` - Show this help message
• `/phone <номер>` - Check phone number info (HLR)

**Available Tools:**
• **👤 Username Search** - Search for usernames
• **📧 Email Scan** - Analyze email addresses
• **🔗 Link Analysis** - Check URLs for safety
• **📞 Phone HLR** - Validate phone numbers

**How to Use:**
1. Choose a tool from the menu
2. Send the information you want to investigate
3. Wait for results (may take up to 1 minute)"""
	
	if update.message:
		await update.message.reply_text(help_text, parse_mode="Markdown")

application.add_handler(CommandHandler("help", help_command))

async def button(update: Update, context: ContextTypes.DEFAULT_TYPE):
	query = update.callback_query
	await query.answer()
	
	user_id = getattr(update.effective_user, 'id', None)
	logger.info("Button pressed: %s by user_id=%s", query.data, user_id)
	
	if query.data in ['username', 'email', 'link']:
		context.user_data['tool'] = query.data
		tool_names = {
			'username': 'Username Search',
			'email': 'Email Scan', 
			'link': 'Link Analysis',
		}
		keyboard = [[InlineKeyboardButton("✖ Cancel", callback_data='cancel')]]
		await query.edit_message_text(
			f"**{tool_names[query.data]}**\n\nSend the information you want to investigate:",
			reply_markup=InlineKeyboardMarkup(keyboard)
		)
	
	elif query.data == 'cancel':
		context.user_data['cancel'] = True
		try:
			await query.edit_message_text("Scan cancelled.")
		except Exception:
			pass
		return
	
	elif query.data == 'help':
		await help_command(update, context)
	
	elif query.data == 'clear_chat':
		chat = update.effective_chat
		if chat:
			deleted = 0
			try:
				for msg_id in range(query.message.message_id - 1, max(query.message.message_id - 50, 1), -1):
					try:
						await context.bot.delete_message(chat_id=chat.id, message_id=msg_id)
						deleted += 1
					except Exception:
						pass
				await query.edit_message_text("Chat cleared.")
			except Exception:
				try:
					await query.edit_message_text("Couldn't clear messages here.")
				except Exception:
					pass
	
	elif query.data in ['back_to_menu', 'start_menu']:
		menu_text = """**What can this bot do?**

Hello! Let's Recon it 🚀

**Available Tools:**
• Username Search - Find profiles across platforms
• Email Scan - Analyze email addresses  
• Link Analysis - Check URLs and domains
• Phone HLR - Check carrier and validity

Note: For LEGAL use only. Do not misuse this tool ⚠️"""
		
		keyboard = [
			[InlineKeyboardButton("Username Search", callback_data='username')],
			[InlineKeyboardButton("Email Scan", callback_data='email')],
			[InlineKeyboardButton("Link Analysis", callback_data='link')],
			[InlineKeyboardButton("Help", callback_data='help')],
			[InlineKeyboardButton("🧹 Clear Chat", callback_data='clear_chat')]
		]
		await query.edit_message_text(menu_text, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode="Markdown")

application.add_handler(CallbackQueryHandler(button))

# --- НОВАЯ ФУНКЦИЯ ДЛЯ HLR ---
async def phone_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
	if not context.args:
		await update.message.reply_text("Usage: `/phone <номер>`\nExample: `/phone +79991234567`", parse_mode='Markdown')
		return

	phone = context.args[0]
	msg = await update.message.reply_text(f"📡 Checking `{phone}` via HLR...")

	result = lookup_phone(phone)

	if "error" in result:
		await msg.edit_text(f"❌ Error: {result['error']}")
		return

	text_report = (
		f"📞 **HLR Report for {result['phone']}**\n\n"
		f"**Valid:** {result['valid']}\n"
		f"**Active:** {result['active']}\n"
		f"**Carrier:** {result['carrier']}\n"
		f"**Line Type:** {result['line_type']}\n"
		f"**Country:** {result['country']}\n"
		f"**Location:** {result['location']}\n"
		f"**Fraud Score:** {result['fraud_score']}/100\n"
		f"**Risky:** {result['risky']}"
	)
	await msg.edit_text(text_report, parse_mode='Markdown')

	try:
		pdf_path = generate_hlr_pdf(result, f"hlr_{phone}.pdf")
		with open(pdf_path, 'rb') as pdf_file:
			await update.message.reply_document(
				document=pdf_file,
				filename=f"HLR_{result['phone']}.pdf",
				caption="📄 Detailed PDF Report"
			)
		os.remove(pdf_path)
	except Exception as e:
		await update.message.reply_text(f"⚠️ Could not generate PDF: {e}")

# Регистрируем команду /phone
application.add_handler(CommandHandler("phone", phone_command))


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
	tool = context.user_data.get('tool')
	user = update.effective_user
	text = (update.message.text if update.message else None) or (update.message.caption if update.message else None)
	logger.info("Message from user_id=%s tool=%s text=%s", getattr(user, 'id', None), tool, text)
	if not tool:
		if update.message:
			welcome_text = """Hello, welcome! 👋

Tap /start or use the button below to open the menu and begin.
"""
			keyboard = [[InlineKeyboardButton("Start Recon", callback_data='start_menu')]]
			await update.message.reply_text(
				welcome_text,
				reply_markup=InlineKeyboardMarkup(keyboard)
			)
		return
	msg = text
	if not msg:
		return
	if re.search(r"https?://|www\\.", msg, re.IGNORECASE):
		context.user_data['tool'] = 'link'
		tool = 'link'
	elif re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", msg, re.IGNORECASE):
		context.user_data['tool'] = 'email'
		tool = 'email'
	context.user_data['cancel'] = False
	try:
		status_text = f"Scanning {tool}… This may take up to 3 minutes."
		status_msg = None
		if update.message:
			status_msg = await update.message.reply_text(status_text)
			await context.bot.send_chat_action(chat_id=update.effective_chat.id, action=ChatAction.TYPING)

		if tool == 'username':
			search_name = re.sub(r"\s+", "", msg)
			processed = 0
			try:
				async for _ in blackbird_service.stream_username(search_name):
					if context.user_data.get('cancel'):
						break
					processed += 1
					if processed % 10 == 0 and status_msg:
						percent = 100 if processed >= TOTAL_PLATFORMS else int(processed * 100 / TOTAL_PLATFORMS)
						try:
							await status_msg.edit_text(f"🔍 **Username Search Progress**\n\n{percent}% ({min(processed, TOTAL_PLATFORMS)}/{TOTAL_PLATFORMS})")
						except Exception:
							pass
			except Exception as e:
				logger.warning("Error in streaming: %s", e)
			result = "Cancelled." if context.user_data.get('cancel') else await asyncio.to_thread(blackbird_service.search_username, search_name)
		elif tool == 'email':
			processed = 0
			try:
				async for _ in blackbird_service.stream_email(msg):
					if context.user_data.get('cancel'):
						break
					processed += 1
					if processed % 10 == 0 and status_msg:
						percent = 100 if processed >= TOTAL_PLATFORMS else int(processed * 100 / TOTAL_PLATFORMS)
						try:
							await status_msg.edit_text(f"📧 **Email Scan Progress**\n\n{percent}% ({min(processed, TOTAL_PLATFORMS)}/{TOTAL_PLATFORMS})")
						except Exception:
							pass
			except Exception as e:
				logger.warning("Error in streaming: %s", e)
			result = "Cancelled." if context.user_data.get('cancel') else await asyncio.to_thread(blackbird_service.scan_email, msg)
		elif tool == 'link':
			result = await asyncio.to_thread(virustotal_service.scan_link, msg)
		else:
			result = "Unknown tool"
		logger.info("Result for tool=%s length=%s", tool, len(result) if isinstance(result, str) else 'n/a')
		if update.message:
			if status_msg:
				try:
					await status_msg.edit_text("Scan complete. Sending results…")
				except Exception:
					pass
		text_out = result if isinstance(result, str) else (str(result) if result is not None else "")
		if not text_out or not text_out.strip():
			if tool == 'username':
				text_out = f"🔍 **Username Search Complete**\n\n❌ No accounts found for '{msg}'\n\nThis username may not be registered on any of the 724 platforms we checked, or it might be using a different variation of the name."
			elif tool == 'email':
				text_out = f"📧 **Email Scan Complete**\n\n❌ No accounts found for '{msg}'\n\nThis email may not be registered on any of the platforms we checked, or the email format might not be valid."
			else:
				text_out = "No results found or the tool produced no output."
		
		formatted_output = format_output(tool, text_out)
		
		try:
			if len(formatted_output) > 3800:
				try:
					await update.message.reply_text("Results are large. Sending full output as a file…")
				except Exception:
					pass
				buf = io.BytesIO(text_out.encode('utf-8'))
				buf.name = "results.txt"
				await update.message.reply_document(document=buf, caption="Full results")
			else:
				await update.message.reply_text(formatted_output, parse_mode="HTML", disable_web_page_preview=False)
		except Exception as e:
			logger.warning("Sending as HTML failed, falling back to plain text: %s", e)
			try:
				await update.message.reply_text(text_out)
			except Exception:
				await update.message.reply_text("Could not send results due to Telegram limits.")
	except Exception as exc:
		logger.exception("Error while handling message: %s", exc)
		if update.message:
			await update.message.reply_text(f"Error: {exc}")

async def handle_other(update: Update, context: ContextTypes.DEFAULT_TYPE):
	user = update.effective_user
	msg = update.message
	type_name = None
	if msg.photo:
		type_name = 'photo'
	elif msg.document:
		type_name = 'document'
	logger.info("Non-text message from user_id=%s type=%s", getattr(user, 'id', None), type_name)
	if update.message:
		await update.message.reply_text("Received your message. Use /start to pick a tool.")

application.add_handler(MessageHandler(~(filters.TEXT | filters.CAPTION), handle_other))
application.add_handler(MessageHandler(filters.TEXT | filters.CAPTION, handle_message))

async def chat_member_update(update: Update, context: ContextTypes.DEFAULT_TYPE):
	cm = update.chat_member or update.my_chat_member
	if not cm:
		return
	user = cm.from_user
	old = getattr(cm, 'old_chat_member', cm.old_chat_member)
	new = getattr(cm, 'new_chat_member', cm.new_chat_member)
	logger.info(
		"ChatMember change user_id=%s username=%s old_status=%s new_status=%s chat_id=%s",
		getattr(user, 'id', None), getattr(user, 'username', None), getattr(old, 'status', None), getattr(new, 'status', None), getattr(cm, 'chat', None).id if getattr(cm, 'chat', None) else None
	)

application.add_handler(ChatMemberHandler(chat_member_update, ChatMemberHandler.CHAT_MEMBER))
application.add_handler(ChatMemberHandler(chat_member_update, ChatMemberHandler.MY_CHAT_MEMBER))

async def on_error(update: object, context: ContextTypes.DEFAULT_TYPE):
	logger.exception("Unhandled error: %s", context.error)

application.add_error_handler(on_error)

async def post_init(application):
	await setup_menu()

if __name__ == "__main__":
	logger.info("Bot starting polling...")
	application.post_init = post_init
	application.run_polling()
