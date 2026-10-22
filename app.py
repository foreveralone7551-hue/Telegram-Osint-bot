
import logging
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

from flask import Flask, jsonify

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
BOT_PATH = BASE_DIR / "bot.py"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("aegis-web")

bot_process = None
bot_lock = threading.Lock()
shutting_down = threading.Event()


def start_bot():
    """Запускает Telegram-бота отдельным процессом."""
    global bot_process

    with bot_lock:
        if bot_process is not None and bot_process.poll() is None:
            logger.info("Telegram bot is already running")
            return

        if not BOT_PATH.is_file():
            logger.error("bot.py not found: %s", BOT_PATH)
            return

        logger.info("Starting Telegram bot")

        try:
            bot_process = subprocess.Popen(
                [sys.executable, str(BOT_PATH)],
                cwd=str(BASE_DIR),
                env=os.environ.copy(),
                stdin=subprocess.DEVNULL,
            )
            logger.info("Telegram bot process started: pid=%s", bot_process.pid)

        except OSError:
            logger.exception("Could not start Telegram bot")
            bot_process = None


def stop_bot():
    """Корректно останавливает Telegram-бота при завершении сервиса."""
    global bot_process

    shutting_down.set()

    with bot_lock:
        process = bot_process

        if process is None or process.poll() is not None:
            return

        logger.info("Stopping Telegram bot: pid=%s", process.pid)
        process.terminate()

    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        logger.warning("Bot did not stop in time; killing process")
        process.kill()
        process.wait(timeout=5)

    with bot_lock:
        if bot_process is process:
            bot_process = None


@app.route("/", methods=["GET"])
def health_check():
    """Проверяет состояние веб-сервера и процесса бота."""
    with bot_lock:
        process = bot_process

        if process is None:
            return jsonify({
                "service": "Aegis Recon",
                "web": "running",
                "bot": "not_started",
            }), 503

        return_code = process.poll()

        if return_code is not None:
            return jsonify({
                "service": "Aegis Recon",
                "web": "running",
                "bot": "stopped",
                "exit_code": return_code,
            }), 503

        return jsonify({
            "service": "Aegis Recon",
            "web": "running",
            "bot": "running",
        }), 200


@app.route("/health", methods=["GET"])
def health():
    """Простой health-check веб-сервера."""
    return "OK", 200


def main():
    if not BOT_PATH.is_file():
        raise FileNotFoundError(f"Missing bot.py: {BOT_PATH}")

    start_bot()

    if bot_process is None or bot_process.poll() is not None:
        raise RuntimeError("Telegram bot failed to start")

    port = int(os.environ.get("PORT", "10000"))

    logger.info("Starting Aegis Recon web server on port %s", port)

    try:
        # Один экземпляр Flask и один экземпляр Telegram-бота.
        app.run(
            host="0.0.0.0",
            port=port,
            debug=False,
            use_reloader=False,
            threaded=True,
        )
    finally:
        stop_bot()


if __name__ == "__main__":
    main()
