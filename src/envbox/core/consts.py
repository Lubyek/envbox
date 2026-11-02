"""Общие константы ядра: регулярные выражения, режимы сети, подписи, пути установки."""

import os
import re

from ..resources import resource_text


ENVBOX_SH_TEXT = resource_text("envbox.sh")


SHELLS = ("bash", "fish", "zsh")


NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,47}$")


VAR_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


DOMAIN_RE = re.compile(
    r"^(\*\.)?[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$")


RESERVED_VARS = {"HOME", "USER", "LOGNAME", "SHELL", "PATH", "PWD", "OLDPWD"}


KINDS = ("app", "browser")


KIND_LABELS = {"app": "Приложение (терминал)", "browser": "Браузер (Chromium)"}


CDP_PORT = 9222


BROWSER_NAMES = ("google-chrome-stable", "google-chrome", "chromium", "chromium-browser", "chrome")


UPSTREAM_AUTH_VAR = "ENVBOX_UPSTREAM_AUTH"


LANG_RE = re.compile(r"^([A-Za-z]{2,3}(_[A-Za-z]{2,3})?(\.[A-Za-z0-9-]+)?(@[A-Za-z0-9]+)?|C|POSIX|C\.[A-Za-z0-9-]+)$")


TZ_RE = re.compile(r"^[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+){0,2}$")


ATTACH_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]{0,47})(?::([0-9]{1,5})?)?(?::([0-9]{1,5}))?$")


NET_MODES = ("off", "log", "allowlist", "host")


# Что нужно Claude Code в сети (code.claude.com/docs/en/network-config): API, вход через claude.ai и
# обновление OAuth-токена на platform.claude.com. Без *.claude.com токен через несколько часов не обновляется,
# и Claude внутри среды «теряет сеть» (просит войти заново).
CLAUDE_DOMAINS = ("*.anthropic.com", "*.claude.ai", "*.claude.com")


# Claude Desktop дополнительно держит соединение с bridge.claudeusercontent.com. Если его закрыть, приложение
# повторяет попытку каждые несколько секунд и показывает «Connection problem». Вход проверяется через hCaptcha
# (js.hcaptcha.com и соседи): без него страница входа пишет «Couldn't verify your browser». Телеметрия
# (Sentry, Datadog) и GitHub не нужны для работы и остаются закрытыми.
CLAUDE_DESKTOP_DOMAINS = CLAUDE_DOMAINS + ("bridge.claudeusercontent.com", "*.hcaptcha.com")


# Прежний список пресета Claude Desktop (без hCaptcha): профили с ровно таким списком обновляются при загрузке.
OLD_CLAUDE_DESKTOP_DOMAINS = list(CLAUDE_DOMAINS) + ["bridge.claudeusercontent.com"]


# Прежний список пресета «Claude CLI»: профили с ровно таким списком обновляются при загрузке.
OLD_CLAUDE_DOMAINS = ["*.anthropic.com", "claude.ai"]


NET_LABELS = {
    "off": "Нет сети (офлайн)",
    "log": "Через прокси с журналом (любые сайты)",
    "allowlist": "Через прокси: только выбранные сайты",
    "host": "Общая с компьютером (небезопасно)",
}


NET_SHORT = {"off": "офлайн", "log": "сеть с журналом", "allowlist": "сеть: выбранные сайты",
             "host": "сеть компьютера"}


INSTALL_DIR = os.path.join(os.environ.get("XDG_DATA_HOME") or
                           os.path.join(os.path.expanduser("~"), ".local", "share"), "envbox")


INSTALLED_PY = os.path.join(INSTALL_DIR, "envbox.py")


INSTALLED_PYC = os.path.join(INSTALL_DIR, "envbox.pyc")   # предкомпилированная копия для быстрых служебных вызовов


INSTALLED_PYC_TAG = INSTALLED_PYC + ".python"        # каким Python собран .pyc (после его обновления .pyc негоден)


ENVBOX_SH = os.path.join(INSTALL_DIR, "envbox.sh")   # извлекается из envbox.py при установке


ENVBOX_NET = INSTALLED_PY                            # сетевой шлюз — этот же файл


SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]{0,30}$")
