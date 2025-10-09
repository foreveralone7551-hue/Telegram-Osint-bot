# Telegram Recon Bot

A focused OSINT (Open Source Intelligence) Telegram bot for quick recon on usernames, emails and links.

## Features

- **Username Search (Blackbird)**: Searches up to 700+ platforms. Handles spaced names by trying variants (e.g., "herz dj", `herzdj`, `herz_dj`, `herz-dj`, `herz.dj`). Live progress and merged results with clickable links.
- **Email Scan (Blackbird)**: Scans for accounts/signals tied to an email. Live progress and formatted output.
- **Link Analysis (VirusTotal)**: Checks URLs using VirusTotal API; summarizes verdict (Malicious/Suspicious/Clean) with safe clickable links.

## Commands

- `/start` – Open the welcome page and tap “Start Recon” to see the tool menu
- `/username` – Jump directly to Username Search
- `/email` – Jump directly to Email Scan
- `/link` – Jump directly to Link Analysis
- `/help` – Short instructions

## Setup

### 1) Install dependencies
```bash
pip install -r requirements.txt
```

### 2) Clone required repositories (if not present)
```bash
git clone https://github.com/phend0/blackbird-osint.git
```

### 3) Configure environment variables
Create a `.env` file in the project root:
```bash
TELEGRAM_TOKEN=YOUR_TELEGRAM_BOT_TOKEN
# Optional
VIRUSTOTAL_API_KEY=YOUR_VIRUSTOTAL_KEY
```
Get tokens/keys:
- Telegram: create a bot with [@BotFather](https://t.me/botfather)
- VirusTotal: get a key at `https://www.virustotal.com/gui/my-apikey`

### 4) Run the bot
```bash
python bot.py
```

## Usage

1. Open your bot in Telegram
2. Send `/start` and tap “Start Recon”
3. Choose a tool (Username, Email, Link)
4. Send the value to investigate
5. Watch progress updates; receive results with clickable links. Large results are sent as a `.txt` file



## Requirements

- Python 3.10+
- Internet connection
- Optional API keys for external services (e.g., VirusTotal)

## Disclaimer

This bot is for educational and legitimate OSINT purposes only. Users are responsible for complying with all applicable laws and terms of service when using this tool.
