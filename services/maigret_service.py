
import logging
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# Ограничения для слабого хостинга
SITE_TIMEOUT = 8
PROCESS_TIMEOUT = 180
MAX_USERNAME_LENGTH = 64


def run_maigret(username: str) -> Optional[str]:
    """Запускает ограниченный поиск Maigret и возвращает HTML-отчёт."""

    if not isinstance(username, str):
        return None

    username = username.strip()

    # Не допускаем пути, аргументы CLI и неожиданные символы.
    if (
        not username
        or len(username) > MAX_USERNAME_LENGTH
        or not re.fullmatch(r"[A-Za-z0-9_.-]+", username)
    ):
        logger.warning("Maigret: invalid username")
        return None

    # Отдельная папка для каждого запуска.
    # Это исключает отправку старого или чужого отчёта.
    with tempfile.TemporaryDirectory(
        prefix="maigret_",
        dir=str(REPORTS_DIR),
    ) as temp_dir:
        output_dir = Path(temp_dir)

        cmd = [
            sys.executable,
            "-m",
            "maigret",
            username,
            "--html",
            "--folderoutput",
            str(output_dir),
            "--timeout",
            str(SITE_TIMEOUT),
        ]

        try:
            result = subprocess.run(
                cmd,
                cwd=str(BASE_DIR),
                capture_output=True,
                text=True,
                timeout=PROCESS_TIMEOUT,
                check=False,
            )

            if result.returncode != 0:
                logger.error(
                    "Maigret failed (exit=%s): %s",
                    result.returncode,
                    (result.stderr or result.stdout or "")[-3000:],
                )
                return None

            # Не полагаемся на заранее угаданное имя файла.
            reports = sorted(output_dir.glob("*.html"))

            if not reports:
                logger.warning(
                    "Maigret exited successfully but HTML is missing. "
                    "stdout=%s stderr=%s",
                    (result.stdout or "")[-1500:],
                    (result.stderr or "")[-1500:],
                )
                return None

            # Сохраняем отчёт за пределами временной папки,
            # прежде чем TemporaryDirectory удалит её.
            source = reports[0]
            destination = REPORTS_DIR / (
                f"maigret_{username}_{next(tempfile._get_candidate_names())}.html"
            )
            destination.write_bytes(source.read_bytes())

            if destination.stat().st_size == 0:
                destination.unlink(missing_ok=True)
                logger.warning("Maigret generated an empty HTML report")
                return None

            logger.info(
                "Maigret report created: %s (%s bytes)",
                destination.name,
                destination.stat().st_size,
            )
            return str(destination)

        except subprocess.TimeoutExpired:
            logger.warning(
                "Maigret timed out after %s seconds",
                PROCESS_TIMEOUT,
            )
            return None

        except OSError:
            logger.exception("Could not start Maigret")
            return None

        except Exception:
            logger.exception("Unexpected Maigret error")
            return None
