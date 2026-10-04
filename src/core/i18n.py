#!/usr/bin/env python
# coding=utf-8
#############################################
#
# Translation layer for SET's user-facing text.
#
# English is, and stays, the default: nothing here changes behavior unless
# SET_LANG is explicitly set. Flip it to pick up the French strings:
#
#   export SET_LANG=fr
#   setoolkit
#
# Every other value (including an unset/unknown one) falls back to English,
# so a typo never breaks the tool - it just stays in English.
#
#############################################
import os

_SUPPORTED_LANGS = ("en", "fr")


def _detect_lang():
    lang = os.environ.get("SET_LANG", "en").strip().lower()
    return lang if lang in _SUPPORTED_LANGS else "en"


LANG = _detect_lang()

_catalog = None


def _load_catalog():
    """Lazily import the active language's string catalog.

    Lazy on purpose: most runs are English and never need to pay for the
    import, and it keeps a bad catalog file from breaking anything that
    doesn't actually need a translation.
    """
    global _catalog
    if _catalog is None:
        if LANG == "fr":
            from src.core.i18n_fr import CATALOG
            _catalog = CATALOG
        else:
            _catalog = {}
    return _catalog


def translate(text):
    """Return the translated string for the active language, or `text`
    unchanged if there is no entry (untranslated strings degrade gracefully
    to English instead of ever showing a missing-key error).
    """
    return _load_catalog().get(text, text)


# Short alias, the usual gettext convention: `from src.core.i18n import translate as _`
_ = translate


def set_lang(lang):
    """Override the active language at runtime (e.g. from a config value
    read after this module has already loaded). Falls back to English for
    anything unrecognized.
    """
    global LANG, _catalog
    lang = (lang or "en").strip().lower()
    LANG = lang if lang in _SUPPORTED_LANGS else "en"
    _catalog = None
