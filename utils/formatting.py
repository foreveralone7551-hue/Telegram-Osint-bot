import json
import html
import re

def format_output(title, data):
	"""Return HTML-formatted output with clickable links. Falls back to escaped text."""
	if not data or not data.strip():
		return f"🔹 {html.escape(str(title))}\n\nNo results found or the tool produced no output."

	# Try to parse as JSON first
	try:
		json_data = json.loads(data)
		if isinstance(json_data, list) and len(json_data) > 0:
			# Format JSON results as HTML
			safe_title = html.escape(str(title))
			formatted = f"<b>🔹 {safe_title}</b>\n\n"
			found_count = len([item for item in json_data if item.get('status') == 'FOUND'])
			formatted += f"📊 Found {found_count} results out of {len(json_data)} platforms checked\n\n"

			# Group by category
			categories = {}
			for item in json_data:
				if item.get('status') == 'FOUND':
					category = item.get('category', 'misc')
					categories.setdefault(category, []).append(item)

			# Display results by category (show all without "...more")
			for category, items in categories.items():
				safe_cat = html.escape(str(category).title())
				formatted += f"📂 <b>{safe_cat}</b> ({len(items)} found)\n"
				for item in items:  # show all
					name = html.escape(str(item.get('name', 'Unknown')))
					url = str(item.get('url', '')).strip()
					if url and (url.startswith('http://') or url.startswith('https://')):
						formatted += f"  • <a href=\"{html.escape(url)}\">{name}</a>\n"
					else:
						# Fallback: show as text
						formatted += f"  • {name}: {html.escape(url)}\n"
				formatted += "\n"

			return formatted
	except (json.JSONDecodeError, TypeError):
		pass

	# If not JSON or parsing failed, return escaped plain text
	safe_title = html.escape(str(title))
	# For link analysis, make URLs clickable while escaping any other HTML-like text
	if str(title).lower() in {"link", "link analysis"}:
		urls = re.findall(r"https?://[^\s]+", str(data))
		body_escaped = html.escape(str(data))
		for u in urls:
			escaped_u = html.escape(u)
			body_escaped = body_escaped.replace(escaped_u, f"<a href=\"{escaped_u}\">{escaped_u}</a>")
		return f"<b>🔹 {safe_title}</b>\n\n{body_escaped}"
	# Default: show as code block
	safe_text = html.escape(str(data))
	return f"<b>🔹 {safe_title}</b>\n\n<pre>{safe_text}</pre>\n"
