"""Хранилище VPN-конфигураций: импорт, список, удаление и проверка наличия клиента.

Файлы лежат в <корень>/_vpn/<имя>.<расширение> с правами 0600 (в них ключи). Вид VPN определяет расширение:
.conf — WireGuard, .xray — VLESS-ссылка или JSON Xray, .singbox — JSON sing-box. Шлюз сам запускает клиент при
старте среды и останавливает при её остановке (см. net/vpn.py)."""

import os

from ..net.vpn import (VPN_BINARIES, VPN_HINTS, VPN_KINDS, VPN_LABELS, VpnClient, detect_kind, find_binary,
                       vpn_validate)
from .consts import NAME_RE
from .root import envbox_root


VPN_DIR = "_vpn"


VPN_EXT = {"wireguard": ".conf", "xray": ".xray", "singbox": ".singbox"}


VPN_MAX_BYTES = 256 * 1024


def vpn_dir():
    return os.path.join(envbox_root(), VPN_DIR)


def vpn_path(name, kind):
    return os.path.join(vpn_dir(), name + VPN_EXT[kind])


def vpn_name_from_file(filename):
    """Подходящее имя VPN из имени файла (wg0.conf -> wg0)."""
    stem = os.path.splitext(os.path.basename(filename))[0]
    stem = "".join(c if c.isalnum() and c.isascii() or c in "._-" else "-" for c in stem).strip("-._")
    return stem[:48] or "vpn"


def list_vpns():
    """Сохранённые VPN: [{name, kind, label, path, server, error, binary}] по имени."""
    out = []
    try:
        names = sorted(os.listdir(vpn_dir()))
    except OSError:
        return out
    by_ext = {ext: kind for kind, ext in VPN_EXT.items()}
    for fname in names:
        stem, ext = os.path.splitext(fname)
        kind = by_ext.get(ext)
        path = os.path.join(vpn_dir(), fname)
        if kind is None or not NAME_RE.match(stem) or not os.path.isfile(path) or os.path.islink(path):
            continue
        server, error = "", ""
        try:
            with open(path, encoding="utf-8") as f:
                server = vpn_validate(kind, f.read(VPN_MAX_BYTES + 1))
        except (OSError, ValueError) as e:
            error = str(e)
        out.append({"name": stem, "kind": kind, "label": VPN_LABELS[kind], "path": path, "server": server,
                    "error": error, "binary": find_binary(kind) or ""})
    return out


def vpn_source(name):
    """(вид, путь) сохранённого VPN или ValueError."""
    for v in list_vpns():
        if v["name"] == name:
            return v["kind"], v["path"]
    raise ValueError(f"VPN «{name}» не найден: добавьте его на вкладке «VPN»")


def import_vpn(name, text, replace=False):
    """Проверить и сохранить конфигурацию. Возвращает (имя, вид, описание сервера). ValueError — понятный текст."""
    name = (name or "").strip()
    if not NAME_RE.match(name):
        raise ValueError("имя VPN: латинские буквы, цифры, точка, дефис и подчёркивание, до 48 знаков")
    text = (text or "").replace("\r\n", "\n").strip()
    if len(text.encode("utf-8")) > VPN_MAX_BYTES:
        raise ValueError("конфигурация слишком большая (больше 256 КБ)")
    kind = detect_kind(text)
    server = vpn_validate(kind, text)
    existing = [v for v in list_vpns() if v["name"] == name]
    if existing and not replace:
        raise ValueError(f"VPN «{name}» уже есть: выберите другое имя или замените")
    os.makedirs(vpn_dir(), mode=0o700, exist_ok=True)
    path = vpn_path(name, kind)
    tmp = path + ".new"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)   # ключи: сразу только владельцу
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text + "\n")
    os.replace(tmp, path)
    for v in existing:
        if v["path"] != path:
            os.unlink(v["path"])    # заменили конфигурацию другого вида под тем же именем
    return name, kind, server


def delete_vpn(name):
    for v in list_vpns():
        if v["name"] == name:
            os.unlink(v["path"])
            return True
    return False


def vpn_binary_problem(kind):
    """Пустая строка, если программа клиента есть; иначе подсказка, что установить."""
    if kind not in VPN_KINDS:
        return f"неизвестный вид VPN: {kind}"
    if find_binary(kind):
        return ""
    return f"не найдена программа {VPN_BINARIES[kind]}: {VPN_HINTS[kind]}"


def test_vpn(name, target=("example.com", 443)):
    """Запустить клиент VPN, открыть через него туннель до target и остановить клиент -> (получилось, текст)."""
    import asyncio
    import time
    try:
        kind, path = vpn_source(name)
    except ValueError as e:
        return False, str(e)
    problem = vpn_binary_problem(kind)
    if problem:
        return False, problem
    log = os.path.join(vpn_dir(), name + ".test.log")

    async def run():
        client = VpnClient(kind, path, log)
        try:
            t0 = time.monotonic()
            await client.start()
            started = time.monotonic() - t0
            t1 = time.monotonic()
            _r, w = await asyncio.wait_for(client.upstream.tunnel(*target), 15)
            w.close()
            return True, (f"VPN «{name}» работает: клиент запущен за {started:.1f} с, туннель до {target[0]} "
                          f"открыт за {int((time.monotonic() - t1) * 1000)} мс")
        except (OSError, asyncio.TimeoutError) as e:
            return False, f"VPN «{name}» не работает: {e or type(e).__name__}. Журнал клиента: {log}"
        finally:
            client.stop()

    return asyncio.run(run())
