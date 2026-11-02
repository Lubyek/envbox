"""Обработчик ссылок envbox в системе (xdg desktop) и команда open-link."""

import os
import shutil
import subprocess
import sys

from .consts import INSTALLED_PY, SCHEME_RE
from .desktop import _desktop_quote
from .links import log_link_event, notify_desktop, open_link_in_env, safe_link_label


def link_handler_desktop(scheme):
    data = os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share")
    return os.path.join(data, "applications", f"envbox-link-{scheme}.desktop")


def install_link_handler(scheme):
    """Связывает схему (например claude) с envbox: ссылки claude://… из браузера пойдут в среду.

    Меняет ассоциации вашего рабочего стола (файл ~/.local/share/applications/envbox-link-<схема>.desktop и xdg-mime)."""
    scheme = scheme.lower().strip()
    if not SCHEME_RE.match(scheme) or scheme in ("http", "https", "file", "ftp", "mailto"):
        raise ValueError(f"схема «{scheme}» не подходит (нельзя http, https, file, ftp, mailto)")
    path = link_handler_desktop(scheme)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    text = ("[Desktop Entry]\nType=Application\n"
            f"Name=envbox: открыть {scheme}:// в песочнице\n"
            f"Comment=Передаёт ссылки {scheme}:// приложению в среде envbox\n"
            f"Exec=/usr/bin/python3 -I {_desktop_quote(INSTALLED_PY)} open-link %u\n"
            f"Terminal=false\nNoDisplay=true\nMimeType=x-scheme-handler/{scheme};\n")
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    note = ""
    if shutil.which("xdg-mime"):
        r = subprocess.run(["xdg-mime", "default", os.path.basename(path), f"x-scheme-handler/{scheme}"],
                           capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            note = " xdg-mime не сработал: " + (r.stderr.strip() or "ошибка")
    else:
        note = " Не найден xdg-mime (пакет xdg-utils): назначьте обработчик вручную в настройках браузера."
    if shutil.which("update-desktop-database"):
        subprocess.run(["update-desktop-database", "-q", os.path.dirname(path)], capture_output=True, timeout=30)
    return path, note.strip()


def link_handler_installed(scheme):
    if not os.path.exists(link_handler_desktop(scheme)):
        return False
    if shutil.which("xdg-mime"):
        r = subprocess.run(["xdg-mime", "query", "default", f"x-scheme-handler/{scheme}"],
                           capture_output=True, text=True, timeout=30)
        return r.stdout.strip() == os.path.basename(link_handler_desktop(scheme))
    return True


def remove_link_handler(scheme):
    try:
        os.unlink(link_handler_desktop(scheme))
    except OSError:
        pass


def cmd_open_link(argv):
    """envbox.py open-link [--env ИМЯ] [--no-start] ССЫЛКА: передать ссылку приложению в среде."""
    env, start, url = None, True, None
    it = iter(argv)
    for arg in it:
        if arg == "--env":
            env = next(it, None)
        elif arg == "--no-start":
            start = False
        elif arg in ("-h", "--help"):
            print(cmd_open_link.__doc__)
            return 0
        elif url is None:
            url = arg
        else:
            print("envbox open-link: лишний аргумент: " + arg, file=sys.stderr)
            return 2
    if not url or env == "":
        print("envbox open-link: нужна ссылка. Пример: envbox.py open-link claude://...", file=sys.stderr)
        return 2
    label = safe_link_label(url)
    from_desktop = not sys.stderr.isatty()   # запущено браузером: окна и терминала нет, ошибки нужно показать иначе
    try:
        name, msg = open_link_in_env(url, env, start)
    except (ValueError, OSError, subprocess.SubprocessError) as e:
        log_link_event(label, f"ошибка: {e}")
        if from_desktop:
            notify_desktop("envbox: ссылка не передана", str(e))
        print(f"envbox open-link: {e}", file=sys.stderr)
        return 1
    log_link_event(label, f"среда «{name}»: {msg}")
    if from_desktop:
        notify_desktop("envbox: ссылка передана", f"Среда «{name}»: {msg}")
    print(f"envbox: «{name}»: {msg}")
    return 0
