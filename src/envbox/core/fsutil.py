"""Файловые помощники: приватная запись, надёжное удаление, проверка вложенности путей."""

import os
import shutil


def _is_under(path, base):
    return path == base or path.startswith(base.rstrip(os.sep) + os.sep)


def _write_private(path, text):
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)


def tilde(path):
    """Путь с «~» вместо домашнего каталога (для показа)."""
    home = os.path.expanduser("~")
    if path == home:
        return "~"
    return "~" + path[len(home):] if path.startswith(home + os.sep) else path


def _force_rmtree(path):
    """Удаляет каталог, даже если внутри есть недоступные для записи каталоги (node_modules, go mod)."""
    for root, dirs, _files in os.walk(path):
        for d in dirs:
            full = os.path.join(root, d)
            if not os.path.islink(full):
                try:
                    os.chmod(full, 0o700)
                except OSError:
                    pass
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass
    shutil.rmtree(path)


def _atomic_write(path, data, mode):
    tmp = path + ".new"
    with open(tmp, "wb") as f:
        f.write(data)
    os.chmod(tmp, mode)
    os.replace(tmp, path)
