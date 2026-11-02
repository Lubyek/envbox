"""Каталог данных envbox и глобальные папки (_global): выбор, создание, перенос."""

import os
import re

from .consts import NAME_RE
from .fsutil import _is_under, _write_private


GLOBAL_DIR = "_global"   # каталог глобальных папок внутри корня; с «_» в начале он не совпадёт с именем среды


GLOBAL_ENTRY_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]{0,47}):(ro|rw)$")


ROOT_SYSTEM_DIRS = ("/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/proc", "/sys", "/dev", "/run", "/boot", "/var")


_ROOT_CACHE = [None]


def default_root():
    return os.path.join(os.path.expanduser("~"), ".envbox")


def root_pointer_path():
    """Файл с выбранным каталогом данных. Лежит вне самого каталога данных (он ведь и меняется)."""
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "envbox", "root")


def configured_root():
    """Каталог данных, заданный пользователем: ENVBOX_ROOT, затем файл-указатель. Пусто — стандартный."""
    value = os.environ.get("ENVBOX_ROOT", "").strip()
    if not value:
        try:
            with open(root_pointer_path(), encoding="utf-8") as f:
                value = f.readline().strip()
        except OSError:
            value = ""
    return value


def root_error(path):
    """Почему путь не годится как каталог данных (текст) или пустая строка."""
    if not path or not os.path.isabs(path):
        return "нужен абсолютный путь"
    real = os.path.realpath(path)
    home = os.path.realpath(os.path.expanduser("~"))
    if real == os.sep:
        return "каталог данных не может быть «/»"
    if _is_under(home, real):
        return "каталог данных не может совпадать с домашним каталогом или содержать его"
    if not _is_under(real, home) and any(_is_under(real, d) for d in ROOT_SYSTEM_DIRS):
        return "каталог данных не может лежать в системном каталоге"
    if os.path.lexists(real) and not os.path.isdir(real):
        return "это не каталог"
    return ""


def envbox_root():
    """Каталог данных envbox: ENVBOX_ROOT, затем выбранный в GUI, иначе ~/.envbox."""
    if _ROOT_CACHE[0] is None:
        value = configured_root()
        root = default_root()
        if value and not root_error(value):
            root = os.path.realpath(value)
        _ROOT_CACHE[0] = root
    return _ROOT_CACHE[0]


def reset_root_cache():
    _ROOT_CACHE[0] = None


def set_root(path):
    """Запомнить каталог данных (пустая строка — вернуть стандартный ~/.envbox). Бросает ValueError."""
    path = (path or "").strip()
    if path:
        path = os.path.expanduser(path)
        if not os.path.isabs(path):
            raise ValueError("нужен абсолютный путь")
        path = os.path.realpath(path)
        err = root_error(path)
        if err:
            raise ValueError(err)
    ptr = root_pointer_path()
    if not path or path == os.path.realpath(default_root()):
        try:
            os.unlink(ptr)
        except FileNotFoundError:
            pass
    else:
        _write_private(ptr, path + "\n")
    reset_root_cache()


def box_dir(name):
    return os.path.join(envbox_root(), name)


def global_root():
    return os.path.join(envbox_root(), GLOBAL_DIR)


def global_path(name):
    return os.path.join(global_root(), name)


def list_global_folders():
    """Имена глобальных папок (настоящие каталоги прямо внутри <корень>/_global)."""
    d = global_root()
    try:
        names = os.listdir(d)
    except OSError:
        return []
    return sorted(n for n in names if NAME_RE.match(n) and os.path.isdir(os.path.join(d, n))
                  and not os.path.islink(os.path.join(d, n)))


def create_global_folder(name):
    name = name.strip()
    if not NAME_RE.match(name):
        raise ValueError("имя папки: латиница, цифры, «.», «_», «-», первый символ — буква или цифра, до 48 знаков")
    path = global_path(name)
    if os.path.lexists(path):
        raise ValueError(f"глобальная папка «{name}» уже существует")
    for d in (envbox_root(), global_root()):
        if os.path.islink(d):
            raise ValueError(f"{d} — символическая ссылка: так нельзя")
        os.makedirs(d, mode=0o700, exist_ok=True)
    os.mkdir(path, 0o700)
    return path


# Независимые параметры изоляции. «Включено» = защита работает.
#   store: "iso" — хранится в профиле (isolation), иначе имя поля профиля; invert — поле хранит обратное
#   warn_off — показывать предупреждение, когда защита выключена; presets — участвует в наборах
ISO_GROUPS = ("Файлы", "Процессы и система", "Сеть", "Окружение")
