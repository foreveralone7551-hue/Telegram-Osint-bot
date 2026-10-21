import os
import threading
from flask import Flask

app = Flask(__name__)

@app.route('/')
def health_check():
    return "Bot is running", 200

def run_bot():
    # Запускаем твой основной файл бота
    os.system("python bot.py")

if __name__ == '__main__':
    # Запускаем бота в фоне
    threading.Thread(target=run_bot, daemon=True).start()
    # Запускаем веб-сервер на порту, который даст Render
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)
