#!/bin/bash

echo "Setting up Telegram OSINT Bot..."

# Install Python dependencies
echo "Installing Python dependencies..."
pip install -r requirements.txt

# Clone required repositories
echo "Cloning Blackbird OSINT repository..."
git clone https://github.com/phend0/blackbird-osint.git

echo "Setup complete!"
echo ""
echo "Next steps:"
echo "1. Edit the .env file and add your API keys"
echo "2. Get a Telegram bot token from @BotFather"
echo "3. Get a VirusTotal API key from https://www.virustotal.com/gui/my-apikey"
echo "4. Run the bot with: python bot.py"
