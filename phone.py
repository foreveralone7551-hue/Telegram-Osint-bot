
import re

try:
    import phonenumbers
    from phonenumbers import carrier, geocoder, number_type
    from phonenumbers import PhoneNumberFormat, PhoneNumberType
except ImportError:
    phonenumbers = None


def lookup_phone(phone_number: str) -> dict:
    """Free local phone-number analysis. No paid API calls."""

    original = str(phone_number or "").strip()

    if not original:
        return {"error": "Введите номер телефона."}

    # Keep only digits and an optional leading plus.
    clean = re.sub(r"[^\d+]", "", original)

    if clean.count("+") > 1 or ("+" in clean and not clean.startswith("+")):
        return {"error": "Неверный формат номера телефона."}

    digits = clean.lstrip("+")

    if not digits.isdigit() or not (7 <= len(digits) <= 15):
        return {
            "error": "Номер должен содержать от 7 до 15 цифр. "
                     "Для точного определения страны используйте формат +код страны."
        }

    if phonenumbers is None:
        return {
            "error": "Бесплатная библиотека phonenumbers не установлена. "
                     "Добавьте phonenumbers в requirements.txt и перезапустите Render."
        }

    if not clean.startswith("+"):
        return {
            "error": "Укажите международный формат номера, например +31612345678."
        }

    try:
        parsed = phonenumbers.parse(clean, None)
        possible = phonenumbers.is_possible_number(parsed)
        valid = phonenumbers.is_valid_number(parsed)

        region = geocoder.description_for_number(parsed, "ru") or "Не определена"
        provider = carrier.name_for_number(parsed, "ru") or "Не определён"

        kind = number_type(parsed)
        if kind == PhoneNumberType.MOBILE:
            line_type = "Мобильный"
        elif kind == PhoneNumberType.FIXED_LINE:
            line_type = "Стационарный"
        elif kind == PhoneNumberType.FIXED_LINE_OR_MOBILE:
            line_type = "Стационарный или мобильный"
        elif kind == PhoneNumberType.TOLL_FREE:
            line_type = "Бесплатный номер"
        elif kind == PhoneNumberType.VOIP:
            line_type = "VoIP"
        else:
            line_type = "Не определён"

        return {
            "phone": phonenumbers.format_number(
                parsed, PhoneNumberFormat.INTERNATIONAL
            ),
            "valid": "Да" if valid else "Нет или номер не распознан",
            "possible": "Да" if possible else "Нет",
            "country": phonenumbers.region_code_for_number(parsed) or "Не определена",
            "location": region,
            "carrier": provider,
            "line_type": line_type,
            "active": "Не проверяется бесплатно",
            "fraud_score": "Недоступен без соответствующего сервиса",
            "risky": "Не проверяется",
            "source": "Локальная библиотека phonenumbers",
            "note": (
                "Это справочная проверка формата и нумерации. "
                "Она не подтверждает, что SIM активна или номер принадлежит конкретному человеку."
            ),
        }

    except phonenumbers.NumberParseException:
        return {"error": "Не удалось распознать номер. Проверьте код страны."}
    except Exception:
        return {"error": "Не удалось обработать номер. Проверьте формат и попробуйте снова."}
