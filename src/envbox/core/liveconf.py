"""Настройки запущенной среды, которые применяются сразу, без перезапуска: списки сайтов.

GUI при сохранении профиля пишет <каталог среды>/live.json, а шлюз среды следит за этим файлом (net/proxy.py live_loop).
Каталог среды на хосте закрыт для песочницы, поэтому сама среда этот файл изменить не может."""

import json
import os

from .root import box_dir


def live_path(name):
    return os.path.join(box_dir(name), "live.json")


def live_data(p):
    """Что применяется на лету: разрешённые сайты (пусто — все), сайты «напрямую», пускать ли на частные адреса."""
    return {"allow": [d.lower() for d in p.allow_domains] if p.net == "allowlist" else [],
            "direct": [d.lower() for d in p.direct_domains] if p.has_remote else [],
            "allow_private": bool(p.net_allow_private)}


def write_live(p):
    """Записать настройки для работающего шлюза среды (атомарно: шлюз никогда не увидит половину файла).

    Возвращает True, если файл записан; False — шлюзу среды (режим без сети или нет каталога среды) нечего обновлять
    либо данные не изменились с прошлой записи (тогда шлюз зря не перечитывает файл)."""
    if p.net not in ("log", "allowlist") or not os.path.isdir(box_dir(p.name)):
        return False
    path = live_path(p.name)
    data = live_data(p)
    try:
        with open(path, encoding="utf-8") as f:
            if json.load(f) == data:
                return False
    except (OSError, ValueError):
        pass
    fd = os.open(path + ".new", os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)
    os.replace(path + ".new", path)
    return True


def live_supported(name):
    """Следит ли запущенный шлюз за файлом настроек: по последнему proxy-start в журнале (старый шлюз поля live не пишет)."""
    path = os.path.join(box_dir(name), "net.log")
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            f.seek(max(0, f.tell() - 262144))
            tail = f.read().decode("utf-8", "replace")
    except OSError:
        return False
    for line in reversed(tail.splitlines()):
        if '"proxy-start"' in line:
            try:
                return json.loads(line).get("live") is True
            except ValueError:
                return False
    return False
