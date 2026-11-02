"""Среды-браузеры: поиск Chrome/Chromium, монтирование, команда запуска, CDP-сокет."""

import os
import re
import shutil

from .consts import ATTACH_RE, BROWSER_NAMES, CDP_PORT
from .root import box_dir, envbox_root


def find_browser():
    for n in BROWSER_NAMES:
        p = shutil.which(n)
        if p:
            return p
    return ""


def browser_mounts(binpath):
    """Каталоги вне /usr, которые нужно смонтировать на чтение, чтобы браузер запустился.

    Версии из AUR (google-chrome) запускаются скриптом-обёрткой, а сам Chrome лежит в /opt:
    ищем такие каталоги и в тексте обёртки."""
    if not binpath:
        return []
    real = os.path.realpath(binpath)
    dirs = []
    if not real.startswith(("/usr/", "/bin/", "/lib/", "/lib64/")):
        dirs.append(os.path.dirname(real))
    try:
        if os.path.getsize(real) < 65536:
            with open(real, "rb") as f:
                head = f.read(65536)
            if head.startswith(b"#!"):
                for m in re.finditer(rb"/opt/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)?", head):
                    path = m.group(0).decode()
                    cand = path if os.path.isdir(path) else os.path.dirname(path)
                    if cand.count("/") >= 2 and os.path.isdir(cand) and cand not in dirs:
                        dirs.append(cand)
    except OSError:
        pass
    # вложенные каталоги не нужны, если родитель уже есть
    return [d for d in dirs if not any(d != o and d.startswith(o + "/") for o in dirs)]


def host_program_in_home(argv0):
    """Если программа установлена в домашний каталог (~/.local, ~/.npm-global…), вернуть
    (настоящий путь, каталог для монтирования на чтение), иначе None."""
    if not argv0:
        return None
    found = os.path.expanduser(argv0) if argv0.startswith("~") else argv0
    if "/" not in found:
        found = shutil.which(found) or ""
    if not found or not os.path.isabs(found):
        return None
    real = os.path.realpath(found)
    home = os.path.realpath(os.path.expanduser("~"))
    root = os.path.realpath(envbox_root())
    if not (real.startswith(home + os.sep)) or real.startswith(root + os.sep):
        return None
    parts = os.path.relpath(real, home).split(os.sep)
    # ~/.local/share/<программа>/… монтируем целиком (рядом лежат библиотеки и версии)
    if len(parts) >= 4 and parts[0] == ".local" and parts[1] == "share":
        mount = os.path.join(home, *parts[:3])
    elif len(parts) >= 3 and parts[0] in (".cargo", ".npm-global", ".nvm", ".bun", ".deno"):
        mount = os.path.join(home, parts[0])
    else:
        mount = os.path.dirname(real)
    return real, mount


def browser_display_flag(p):
    """Режим показа браузера.

    Режим --headless=new — это отдельная урезанная сборка: Chrome в нём называет себя «HeadlessChrome»,
    и Google (вход в Gmail), GitHub, Cloudflare и многие другие сайты такому браузеру отказывают. Поэтому
    без окна запускается обычный полноценный Chrome на платформе ozone «headless»: у него обычный
    User-Agent, окна и Wayland не нужны, а кадры для просмотра в envbox идут по CDP как раньше.
    Если установленная версия Chrome такую платформу не поддерживает и сразу завершается, запустите
    envbox с ENVBOX_BROWSER_HEADLESS=new — вернётся прежний режим."""
    if p.browser_visible:
        return "--ozone-platform=wayland"
    if os.environ.get("ENVBOX_BROWSER_HEADLESS", "").strip().lower() == "new":
        return "--headless=new"
    return "--ozone-platform=headless"


def browser_command(p):
    """argv браузера внутри среды."""
    exe = p.browser_bin or find_browser() or "chromium"
    profile_dir = os.path.join(os.path.realpath(os.path.expanduser("~")), "chrome-profile")
    argv = [exe, f"--user-data-dir={profile_dir}", f"--remote-debugging-port={CDP_PORT}",
            "--no-first-run", "--no-default-browser-check", "--disable-gpu",
            "--disable-background-networking", "--disable-component-update", "--disable-sync",
            "--disable-breakpad", "--password-store=basic"]
    if p.net != "off":
        argv.append("--proxy-server=http://127.0.0.1:3128")
    argv.append(browser_display_flag(p))
    if not p.browser_chrome_sandbox:
        argv.append("--no-sandbox")
    argv.append(p.browser_start_url.strip() or "about:blank")
    return argv


def cdp_socket_path(name):
    return os.path.join(box_dir(name), "run", "expose", f"{CDP_PORT}.sock")


def attach_snippets(spec):
    """Готовые строки подключения ИИ к браузеру (выполняются внутри ИИ-среды)."""
    m = ATTACH_RE.match(spec)
    local = (m.group(3) or m.group(2) or str(CDP_PORT)) if m else str(CDP_PORT)
    url = f"http://127.0.0.1:{local}"
    return [
        ("Адрес CDP внутри среды", url),
        ("Playwright MCP для Claude Code",
         f"claude mcp add playwright -- npx -y @playwright/mcp@latest --cdp-endpoint {url}"),
        ("Chrome DevTools MCP для Claude Code",
         f"claude mcp add chrome-devtools -- npx -y chrome-devtools-mcp@latest --browser-url={url}"),
        ("Playwright (Node.js)", f"const browser = await chromium.connectOverCDP('{url}');"),
    ]
