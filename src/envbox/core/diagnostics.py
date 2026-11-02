"""Диагностика: что есть на компьютере для работы envbox."""

import os
import shlex
import shutil
import subprocess

from .browser import find_browser
from .consts import ENVBOX_NET, ENVBOX_SH
from .keyring import secret_tool_available
from .system import pkg_hint
from .terminal import detect_terminal


def diagnostics(settings=None):
    """Список (статус, заголовок, подробности); статус: ok | warn | fail."""
    res = []

    def add(st, title, detail=""):
        res.append((st, title, detail))

    for path, label in ((ENVBOX_SH, "envbox.sh"), (ENVBOX_NET, "envbox.py")):
        if os.path.isfile(path):
            add("ok" if os.access(path, os.X_OK) or path == ENVBOX_NET else "fail",
                f"{label} найден", path)
        else:
            add("fail", f"{label} не найден", "запустите: python3 envbox.py install")

    bwrap = shutil.which("bwrap")
    if not bwrap:
        add("fail", "bwrap не установлен", pkg_hint("bubblewrap"))
    else:
        real = os.path.realpath(bwrap)
        ver = subprocess.run([real, "--version"], capture_output=True, text=True).stdout.strip()
        ver = ver.splitlines()[0] if ver else ""
        add("ok", f"bwrap: {ver or 'версия неизвестна'}", real)
        if os.stat(real).st_mode & 0o4000:
            add("fail", "bwrap установлен с setuid-битом", "envbox работает только с bwrap без setuid")
        helptext = subprocess.run([real, "--help"], capture_output=True, text=True)
        helptext = helptext.stdout + helptext.stderr
        if "--disable-userns" in helptext:
            add("ok", "поддерживается --disable-userns")
        else:
            add("warn", "нет --disable-userns", "нужен bwrap >= 0.8: вложенные userns не запрещаются")
        probe = subprocess.run([real, "--unshare-user", "--ro-bind", "/", "/", "--", "/usr/bin/true"],
                               capture_output=True, text=True)
        if probe.returncode == 0:
            add("ok", "user namespaces работают")
        else:
            detail = probe.stderr.strip()
            try:
                with open("/proc/sys/kernel/apparmor_restrict_unprivileged_userns") as f:
                    if f.read().strip() == "1":
                        detail += ("\nAppArmor ограничивает userns. Запустите envbox.sh из терминала: "
                                   "он напечатает профиль AppArmor только для bwrap.")
            except OSError:
                pass
            add("fail", "bwrap не может создать user namespace", detail)

    try:
        with open("/proc/sys/dev/tty/legacy_tiocsti") as f:
            v = f.read().strip()
        add("ok", f"dev.tty.legacy_tiocsti = {v}",
            "TIOCSTI запрещён ядром" if v == "0" else "защита от TIOCSTI — через --new-session")
    except OSError:
        add("ok", "legacy_tiocsti недоступен", "защита от TIOCSTI — через --new-session")

    browser = find_browser()
    if browser:
        real = os.path.realpath(browser)
        try:
            ver = subprocess.run([browser, "--version"], capture_output=True, text=True,
                                 stdin=subprocess.DEVNULL, timeout=15).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            ver = ""
        if real.startswith(("/snap/", "/var/lib/flatpak/")):
            add("fail", f"браузер: {browser}", "snap/flatpak-версия не подходит для изолированной среды")
        else:
            add("ok", f"браузер: {ver or browser}", real)
    else:
        add("warn", "Chrome/Chromium не найден", "нужен только для сред-браузеров: "
            + pkg_hint("chromium"))
    add("ok" if os.access("/usr/bin/python3", os.X_OK) else "fail",
        "/usr/bin/python3" + ("" if os.access("/usr/bin/python3", os.X_OK) else " не найден"),
        "нужен для сетевого журнала")
    if secret_tool_available():
        add("ok", "secret-tool найден", "секреты хранятся в системном keyring")
    else:
        add("warn", "secret-tool не найден", "для секретов: " + pkg_hint("secret-tool"))
    term = detect_terminal(settings)
    if term:
        add("ok", "терминал: " + shlex.join(term))
    else:
        add("fail", "терминал не найден", "укажите команду терминала в настройках, например 'xterm -e'")
    return res
