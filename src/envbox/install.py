"""Установка: самокопирование в ~/.local/share/envbox, извлечение envbox.sh, команда envbox."""

import os
import re
import shlex
import subprocess
import sys

from .core.consts import ENVBOX_SH, ENVBOX_SH_TEXT, INSTALLED_PY, INSTALLED_PYC, INSTALLED_PYC_TAG, INSTALL_DIR
from .core.fsutil import _atomic_write
from .selfpath import bundle_path


def file_version_text(path):
    """Версия envbox в файле строкой (как в version.py, например 2026.11.01.2) или None."""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            m = re.search(r'^ENVBOX_VERSION = "([0-9.]+)"', f.read(), re.M)
    except OSError:
        return None
    return m.group(1) if m else None


def file_version(path):
    """Версия envbox в файле (кортеж чисел) или None."""
    text = file_version_text(path)
    return tuple(int(x) for x in text.split(".")) if text else None


def _system_python():
    """Настоящий путь к /usr/bin/python3 (например /usr/bin/python3.14): .pyc годится только для этой версии."""
    return os.path.realpath("/usr/bin/python3")


def _tag_matches():
    try:
        with open(INSTALLED_PYC_TAG, encoding="utf-8") as f:
            return f.read() == _system_python()
    except OSError:
        return False


def compile_installed():
    """Кладёт рядом с установленным envbox.py скомпилированную копию (служебные вызовы ~20 мс вместо ~150 мс).

    Копия проверяется запуском; при любой неудаче удаляется, и envbox.sh пользуется обычным файлом.
    После обновления Python (на Arch это бывает часто) .pyc становится нечитаемым: рядом хранится метка версии,
    и по её несовпадению копия собирается заново, а до тех пор envbox.sh пользуется обычным файлом."""
    try:
        if (os.path.exists(INSTALLED_PYC) and os.path.exists(INSTALLED_PY)
                and os.path.getmtime(INSTALLED_PYC) >= os.path.getmtime(INSTALLED_PY) and _tag_matches()):
            return False
        want = file_version(INSTALLED_PY)
        tmp = INSTALLED_PYC + ".new"
        r = subprocess.run(["/usr/bin/python3", "-I", "-c",
                            "import py_compile,sys; py_compile.compile(sys.argv[1], cfile=sys.argv[2], doraise=True)",
                            INSTALLED_PY, tmp], capture_output=True, timeout=120)
        if r.returncode == 0 and want:
            v = subprocess.run(["/usr/bin/python3", "-I", tmp, "version"], capture_output=True, text=True, timeout=60)
            # сравнение по числам: в строке версии бывают ведущие нули (2026.11.01.1), в кортеже их нет
            if v.returncode == 0 and tuple(int(x) for x in v.stdout.strip().split(".")) == want:
                os.chmod(tmp, 0o644)
                _atomic_write(INSTALLED_PYC_TAG, _system_python().encode("utf-8"), 0o644)
                os.replace(tmp, INSTALLED_PYC)
                return True
        if os.path.exists(tmp):
            os.unlink(tmp)
    except (OSError, subprocess.SubprocessError):
        pass
    for stale in (INSTALLED_PYC, INSTALLED_PYC_TAG):   # устаревшая копия опаснее её отсутствия
        try:
            os.unlink(stale)
        except OSError:
            pass
    return False


def ensure_installed(force=False):
    """Копирует envbox.py в ~/.local/share/envbox, извлекает envbox.sh и создаёт команду envbox.

    Запущенные среды используют установленные копии, поэтому не зависят от того,
    откуда запущен GUI (папка загрузок, смонтированный AppImage). Возвращает список изменений.
    Установленная более новая версия по умолчанию не затирается (force=True — затирается).
    """
    changed = []
    SELF = bundle_path()
    os.makedirs(INSTALL_DIR, mode=0o755, exist_ok=True)
    if not force and SELF != os.path.realpath(INSTALLED_PY) and os.path.exists(INSTALLED_PY):
        mine, theirs = file_version(SELF), file_version(INSTALLED_PY)
        if mine and theirs and mine < theirs:
            # установлена более новая версия: старый запуск (например, из AppImage) её не затирает
            if not os.environ.get("ENVBOX_NO_REEXEC"):
                os.environ["ENVBOX_NO_REEXEC"] = "1"
                os.execv("/usr/bin/python3", ["/usr/bin/python3", "-I", INSTALLED_PY, *sys.argv[1:]])
            return changed
    if SELF != os.path.realpath(INSTALLED_PY):
        with open(SELF, "rb") as f:
            data = f.read()
        try:
            with open(INSTALLED_PY, "rb") as f:
                same = f.read() == data
        except OSError:
            same = False
        if not same:
            _atomic_write(INSTALLED_PY, data, 0o755)
            changed.append(INSTALLED_PY)
    sh_data = ENVBOX_SH_TEXT.replace("__ENVBOX_PY__", shlex.quote(INSTALLED_PY)).encode("utf-8")
    try:
        with open(ENVBOX_SH, "rb") as f:
            same = f.read() == sh_data
    except OSError:
        same = False
    if not same:
        _atomic_write(ENVBOX_SH, sh_data, 0o755)
        changed.append(ENVBOX_SH)
    link = os.path.join(os.path.expanduser("~"), ".local", "bin", "envbox")
    if not os.path.lexists(link) or os.path.islink(link):
        os.makedirs(os.path.dirname(link), exist_ok=True)
        if os.path.realpath(link) != os.path.realpath(ENVBOX_SH):
            tmp = link + ".new"
            if os.path.lexists(tmp):
                os.unlink(tmp)
            os.symlink(ENVBOX_SH, tmp)
            os.replace(tmp, link)
            changed.append(link)
    if compile_installed():
        changed.append(INSTALLED_PYC)
    return changed
