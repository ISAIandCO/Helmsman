"""Small shared RU/EN catalogue; state and protocol identifiers are never translated."""
import copy
import json
import re
from pathlib import Path

EN = json.loads(Path(__file__).with_name('locales').joinpath('en.json').read_text())
_language = 'ru'
# The service historically persisted plain Russian error strings. Match known
# message fragments in one pass to render those errors in either UI as well.
_fragments = re.compile('|'.join(re.escape(key) for key in sorted(EN, key=len, reverse=True)))


def set_language(value):
    global _language
    _language = value if value in {'ru', 'en'} else 'ru'


def language():
    return _language


def translate_message(text, lang):
    if lang != 'en' or not isinstance(text, str):
        return text
    return EN.get(text) or _fragments.sub(lambda match: EN[match.group()], text)


def tr(text):
    return translate_message(text, _language)


def localize_response(value, lang, method=''):
    """Only own presentation fields: never walk into profile/config/name values."""
    if method in {'configuration', 'list_content'}:
        return value
    result = copy.deepcopy(value)
    def messages(obj):
        if isinstance(obj, dict):
            for key in ('message', 'error'):
                if key in obj:
                    obj[key] = translate_message(obj[key], lang)
            if isinstance(obj.get('last_probe'), dict):
                messages(obj['last_probe'])
    messages(result)
    if isinstance(result, dict):
        status = result.get('status', result)
        messages(status)
        for key in ('presets', 'preset_descriptions', 'countries'):
            if key in status:
                status[key] = {k: translate_message(v, lang) for k, v in status[key].items()}
        for key in ('active_preset_name', 'active_preset_description'):
            if key in status:
                status[key] = translate_message(status[key], lang)
        for sub in status.get('subscriptions', []):
            messages(sub)
        for event in result.get('events', []):
            messages(event)
    return result
