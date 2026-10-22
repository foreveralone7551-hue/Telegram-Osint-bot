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

# Импорты сервисов
from services import blackbird_service, virustotal_service
from utils.formatting import format_output
from phone import lookup_phone
from utils.pdf_generator import generate_html_report
from services.maigret_service import run_maigret  # <--- ДОБАВЛЕН ИМПОРТ МАЙГРЕТА

# Logging setup
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

logging.getLogger('httpx').setLevel(logging.WARNING)
logging.getLogger('telegram.request').setLevel(logging.WARNING)

ENV_PATH = Path(__file__).resolve().parent / '.env'
load_dotenv(dotenv_path=ENV_PATH, override=True)

def _normalize(value: str) -> str:
	if value is None:
		return value
	v = value.strip().strip('"').strip("'")
	if v and v[0] == '\ufeff':
		v = v[1:]
	return v

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

logger.info("Starting Aegis Recon with token present: %s", 'yes')
application = ApplicationBuilder().token(TOKEN).build()

TOTAL_PLATFORMS = 754

async def setup_menu():
	try:
		await application.bot.delete_my_commands()
	except Exception:
		pass

	commands = [
		BotCommand("start", "Aegis Recon Bot"),
		BotCommand("username", "Username Search (Blackbird)"),
		BotCommand("maigret", "Deep Username Search (Maigret)"),
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
	
	welcome_text = """**🛡️ Aegis Recon**

Advanced OSINT Intelligence Toolkit. 🚀

**Available Modules:**
• **Username Search** - Fast scan (Blackbird)
• **Deep Search** - Deep scan (Maigret, 3000+ sites)
• **Email Scan** - Breach & data analysis
• **Link Analysis** - Threat intelligence (VirusTotal)
• **Phone HLR** - Telecom metadata & carrier info

_Note: For legal and ethical use only. Do not misuse._ ⚠️"""
	
	keyboard = [
		[InlineKeyboardButton("Start Recon", callback_data='start_menu')]
	]
	
	if update.message:
		await update.message.reply_text(welcome_text, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode="Markdown")

application.add_handler(CommandHandler("start", start))

application.add_handler(CommandHandler("username", lambda u, c: c.bot.send_message(chat_id=u.effective_chat.id, text="**Username Search**\n\nSend the username you want to investigate:", parse_mode="Markdown")))
application.add_handler(CommandHandler("email", lambda u, c: c.bot.send_message(chat_id=u.effective_chat.id, text="**Email Scan**\n\nSend the email you want to investigate:", parse_mode="Markdown")))
application.add_handler(CommandHandler("link", lambda u, c: c.bot.send_message(chat_id=u.effective_chat.id, text="**Link Analysis**\n\nSend the URL you want to investigate:", parse_mode="Markdown")))

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
	user = update.effective_user
	logger.info("/help from user_id=%s username=%s", getattr(user, 'id', None), getattr(user, 'username', None))
	
	help_text = """❓ **Aegis Recon Help** ❓

**Available Commands:**
• `/start` - Start the bot and show main menu
• `/help` - Show this help message
• `/maigret <username>` - Deep username search (slow)
• `/phone <number>` - Check phone number info (HLR)

**Available Tools:**
• **👤 Username Search** - Search for usernames (Blackbird)
• **🔎 Deep Search** - Search across 3000+ sites (Maigret)
• **📧 Email Scan** - Analyze email addresses
• **🔗 Link Analysis** - Check URLs for safety
• **📞 Phone HLR** - Validate phone numbers

**How to Use:**
1. Choose a tool from the menu
2. Send the information you want to investigate
3. Wait for results (Maigret can take up to 10 minutes)"""
	
	if update.message:
		await update.message.reply_text(help_text, parse_mode="Markdown")

application.add_handler(CommandHandler("help", help_command))

async def button(update: Update, context: ContextTypes.DEFAULT_TYPE):
	query = update.callback_query
	await query.answer()
	
	user_id = getattr(update.effective_user, 'id', None)
	logger.info("Button pressed: %s by user_id=%s", query.data, user_id)
	
	if query.data in ['username', 'email', 'link', 'phone', 'maigret']:
		context.user_data['tool'] = query.data
		tool_names = {
			'username': 'Username Search (Blackbird)',
			'maigret': 'Deep Search (Maigret)',
			'email': 'Email Scan', 
			'link': 'Link Analysis',
			'phone': 'Phone HLR Lookup',
		}
		
		prompt_text = "Send the information you want to investigate:"
		if query.data == 'phone':
			prompt_text = "Send the phone number in international format (e.g., +79991234567):"
		elif query.data == 'maigret':
			prompt_text = "Send the username. ⚠️ This may take 5-10 minutes on free tier."
			
		keyboard = [[InlineKeyboardButton("✖ Cancel", callback_data='cancel')]]
		await query.edit_message_text(
			f"**{tool_names[query.data]}**\n\n{prompt_text}",
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
		menu_text = """**🛡️ Aegis Recon**

Advanced OSINT Intelligence Toolkit. 🚀

**Available Modules:**
• **Username Search** - Fast scan (Blackbird)
• **Deep Search** - Deep scan (Maigret, 3000+ sites)
• **Email Scan** - Breach & data analysis
• **Link Analysis** - Threat intelligence (VirusTotal)
• **Phone HLR** - Telecom metadata & carrier info

_Note: For legal and ethical use only. Do not misuse._ ⚠️"""
		
		keyboard = [
			[InlineKeyboardButton("Username Search", callback_data='username')],
			[InlineKeyboardButton("Deep Search (Maigret)", callback_data='maigret')],
			[InlineKeyboardButton("Email Scan", callback_data='email')],
			[InlineKeyboardButton("Link Analysis", callback_data='link')],
			[InlineKeyboardButton("Phone HLR", callback_data='phone')],
			[InlineKeyboardButton("Help", callback_data='help')],
			[InlineKeyboardButton("🧹 Clear Chat", callback_data='clear_chat')]
		]
		await query.edit_message_text(menu_text, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode="Markdown")

application.add_handler(CallbackQueryHandler(button))

async def phone_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
	if not context.args:
		await update.message.reply_text("Usage: `/phone <number>`\nExample: `/phone +79991234567`", parse_mode='Markdown')
		return

	phone = context.args[0]
	msg = await update.message.reply_text(f"📡 Checking `{phone}` via HLR (Aegis Recon)...")

	result = lookup_phone(phone)

	if "error" in result:
		await msg.edit_text(f"❌ Error: {result['error']}")
		return

	text_report = (
		f"🛡️ **Aegis Recon: HLR Report**\n\n"
		f"**Phone:** {result['phone']}\n"
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
		filename = f"Aegis_Report_{result['phone']}.html"
		html_path = generate_html_report(result['phone'], result, filename)
		
		with open(html_path, 'rb') as html_file:
			await update.message.reply_document(
				document=html_file,
				filename=filename,
				caption="🛡️ Detailed Aegis Recon HTML Report"
			)
		os.remove(html_path)
	except Exception as e:
		await update.message.reply_text(f"⚠️ Could not generate HTML: {e}")

application.add_handler(CommandHandler("phone", phone_command))

async def maigret_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
	if not context.args:
		await update.message.reply_text("Usage: `/maigret <username>`", parse_mode='Markdown')
		return

	username = context.args[0]
	msg = await update.message.reply_text(f"🕵️ Running Deep Search (Maigret) for `{username}`... This may take 5-10 minutes.")

	report_path = await asyncio.to_thread(run_maigret, username)

	if report_path and os.path.exists(report_path):
		await msg.edit_text("✅ Analysis complete. Sending HTML report...")
		with open(report_path, 'rb') as f:
			await update.message.reply_document(
				document=f,
				filename=f"maigret_{username}.html",
				caption=f"🛡️ Aegis Recon: Maigret Report for {username}"
			)
		os.remove(report_path)
	else:
		await msg.edit_text(f"❌ No results or error for `{username}`.")

application.add_handler(CommandHandler("maigret", maigret_command))

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
	tool = context.user_data.get('tool')
	user = update.effective_user
	text = (update.message.text if update.message else None) or (update.message.caption if update.message else None)
	logger.info("Message from user_id=%s tool=%s text=%s", getattr(user, 'id', None), tool, text)
	
	if not tool:
		if update.message:
			welcome_text = """Hello, welcome to Aegis Recon! 👋

Tap /start or use the button below to open the menu and begin."""
			keyboard = [[InlineKeyboardButton("Start Recon", callback_data='start_menu')]]
			await update.message.reply_text(welcome_text, reply_markup=InlineKeyboardMarkup(keyboard))
		return
		
	msg = text
	if not msg:
		return
		
	if tool == 'phone':
		await context.bot.send_chat_action(chat_id=update.effective_chat.id, action=ChatAction.TYPING)
		context.args = [msg]
		await phone_command(update, context)
		return
	elif tool == 'maigret':
		await context.bot.send_chat_action(chat_id=update.effective_chat.id, action=ChatAction.TYPING)
		context.args = [msg]
		await maigret_command(update, context)
		return

	if re.search(r"https?://|www\\.", msg, re.IGNORECASE):
		context.user_data['tool'] = 'link'
		tool = 'link'
	elif re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", msg, re.IGN ==ORECASE):
		context.user_data['tool'] = 'email'
		tool = ' 'email'
	context.user_data['cancelemail'] = False
	try:
		status_text = f':
"Scanning {tool}… This may take up		 to 3 minutes."
		status_msg = None
		if update.message:
			status_msg = await	 update.message.reply_text(status_text)
			await context.bot.sendprocessed_chat_action(chat_id=update.effective_chat =.id, action=ChatAction.TYPING)

		if  tool == 'username':
			search0_name = re.sub(r"\s+", "", msg
)
			processed = 0
			try:
						async for _ in blackbird_service.stream_username(search_name):
					if context.user_data.get('cancel'):
						break
					processed += 1
					if processed % 10 == 0 and status_msg:
						percent = 100 if processed >= TOTAL	try_PLATFORMS else int(processed * 100 /:
 TOTAL_PLATFORMS)
						try:
										await status_msg.edit_text(f"🔍 **Username Search Progress**\	n\n{percent}% ({min(processed,async TOTAL_PLATFORMS)}/{T forOTAL_PLATFORMS})")
						except _ Exception:
							pass
			except Exception as in e:
				logger.warning("Error in streaming: black %s", ebird_service)
			result = ".streamCancelled." if context.user_data.get('cancel')_email else await asyncio.to_thread(blackbird_service.search_(msgusername, search_name)
		elif tool):
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
	logger.info("Aegis Recon starting polling...")
	application.post_init = post_init
	application.run_polling()
