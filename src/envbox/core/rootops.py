"""Операции над каталогом данных и глобальными папками, затрагивающие профили и сеансы: перенос, удаление, список пользователей."""

import json
import os
import shutil
import stat

from .consts import NAME_RE
from .fsutil import _force_rmtree, _is_under, _write_private
from .root import global_path, root_error
from .sessions import list_sessions
from .store import list_profiles, load_profile


def global_folder_users(name):
    """Имена сред, которые используют глобальную папку (подключена, проект или пути внутри неё)."""
    base = global_path(name)
    out = []
    for n in list_profiles():
        try:
            p = load_profile(n)
        except (OSError, ValueError):
            continue
        used = p.global_on and any(g.split(":", 1)[0] == name for g in p.global_folders)
        for v in ([] if (p.is_browser or p.no_workdir) else [p.workdir]) + p.ro + p.rw:
            if v and _is_under(os.path.normpath(os.path.expanduser(v)), base):
                used = True
        if used:
            out.append(n)
    return out


def delete_global_folder(name):
    """Удалить глобальную папку вместе с содержимым. Среды, которые её используют, должны быть остановлены."""
    if not NAME_RE.match(name):
        raise ValueError(f"недопустимое имя папки: '{name}'")
    path = global_path(name)
    if not os.path.isdir(path) or os.path.islink(path):
        raise ValueError(f"глобальная папка «{name}» не найдена")
    running = {s.name for s in list_sessions()}
    busy = [n for n in global_folder_users(name) if n in running]
    if busy:
        raise ValueError("папку использует запущенная среда: " + ", ".join(busy) + ". Сначала остановите её")
    _force_rmtree(path)


def _ignore_special(directory, names):
    """Сокеты, каналы и устройства не копируются при переносе (это следы запущенных сред)."""
    skip = []
    for n in names:
        try:
            m = os.lstat(os.path.join(directory, n)).st_mode
        except OSError:
            continue
        if not (stat.S_ISREG(m) or stat.S_ISDIR(m) or stat.S_ISLNK(m)):
            skip.append(n)
    return skip


def _remap_path(value, old_forms, new_root):
    """Если путь лежит внутри старого каталога данных — тот же путь в новом, иначе None."""
    expanded = os.path.normpath(os.path.expanduser(value))
    for old in old_forms:
        if _is_under(expanded, old):
            return os.path.normpath(os.path.join(new_root, os.path.relpath(expanded, old)))
    return None


def move_root(old, new):
    """Перенести каталог данных из `old` в `new` и поправить в профилях пути, которые вели внутрь него
    (например, проект в глобальной папке). `new` должен не существовать или быть пустым каталогом.
    Запущенных сред быть не должно. Бросает ValueError."""
    old_raw = os.path.normpath(old)
    old, new = os.path.realpath(old), os.path.realpath(new)
    if old == new:
        return
    if any(True for _ in list_sessions()):
        raise ValueError("сначала остановите все запущенные среды")
    if _is_under(new, old) or _is_under(old, new):
        raise ValueError("старый и новый каталоги не должны лежать один внутри другого")
    err = root_error(new)
    if err:
        raise ValueError(err)
    if os.path.isdir(new):
        if os.listdir(new):
            raise ValueError("новый каталог не пуст: выберите пустой или несуществующий")
        os.rmdir(new)
    parent = os.path.dirname(new)
    os.makedirs(parent, exist_ok=True)
    if os.path.isdir(old):
        try:
            os.rename(old, new)
        except OSError:   # другой раздел диска: копируем, потом удаляем старое
            try:
                shutil.copytree(old, new, symlinks=True, ignore=_ignore_special)
            except (OSError, shutil.Error) as e:
                if os.path.isdir(new):
                    _force_rmtree(new)
                raise ValueError(f"не удалось скопировать данные: {e}") from e
            _force_rmtree(old)
    else:
        os.makedirs(new, mode=0o700)
    os.chmod(new, 0o700)
    forms = [f for f in dict.fromkeys([old, old_raw]) if f]
    for n in sorted(os.listdir(new)):
        pp = os.path.join(new, n, "profile.json")
        if not (NAME_RE.match(n) and os.path.isfile(pp)):
            continue
        try:
            with open(pp, encoding="utf-8") as f:
                d = json.load(f)
        except (OSError, ValueError):
            continue
        changed = False
        for key in ("workdir", "ro", "rw", "path"):
            v = d.get(key)
            if isinstance(v, str) and v:
                r = _remap_path(v, forms, new)
                if r:
                    d[key], changed = r, True
            elif isinstance(v, list):
                items = []
                for x in v:
                    r = _remap_path(str(x), forms, new) if x else None
                    changed = changed or bool(r)
                    items.append(r or x)
                d[key] = items
        if changed:
            _write_private(pp, json.dumps(d, ensure_ascii=False, indent=2) + "\n")
