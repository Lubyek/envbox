"""Хранилище VPN-конфигураций: импорт, список, удаление и проверка наличия клиента.

Файлы лежат в <корень>/_vpn/<имя>.<расширение> с правами 0600 (в них ключи). Вид VPN определяет расширение:
.conf — WireGuard, .xray — VLESS-ссылка или JSON Xray, .singbox — JSON sing-box. Шлюз сам запускает клиент при
старте среды и останавливает при её остановке (см. net/vpn.py)."""

import os
import re

from ..net.vpn import (VPN_BINARIES, VPN_HINTS, VPN_KINDS, VPN_LABELS, VpnClient, detect_kind, find_binary,
                       split_links, vpn_validate)
from ..net.upstream import Upstream
from .consts import NAME_RE
from .root import envbox_root


VPN_DIR = "_vpn"


VPN_EXT = {"wireguard": ".conf", "xray": ".xray", "singbox": ".singbox"}


VPN_MAX_BYTES = 256 * 1024


# Подписка: ответ сервера не больше этого размера, серверов берём не больше SUB_MAX_LINKS
SUB_MAX_BYTES = 2 * 1024 * 1024


SUB_MAX_LINKS = 40


def vpn_dir():
    return os.path.join(envbox_root(), VPN_DIR)


def vpn_path(name, kind):
    return os.path.join(vpn_dir(), name + VPN_EXT[kind])


def vpn_name_from_file(filename):
    """Подходящее имя VPN из имени файла (wg0.conf -> wg0)."""
    stem = os.path.splitext(os.path.basename(filename))[0]
    stem = "".join(c if c.isalnum() and c.isascii() or c in "._-" else "-" for c in stem).strip("-._")
    return stem[:48] or "vpn"


SOURCE_RE = re.compile(r"^(https?://|vless://|vmess://|trojan://|ss://|\[interface\]|\{)", re.I)


def normalize_name(name, fallback="vpn"):
    """Допустимое имя VPN из чего угодно: лишние знаки заменяются дефисом, пустое — запасное имя."""
    out = "".join(c if (c.isalnum() and c.isascii()) or c in "._-" else "-" for c in (name or "").strip())
    out = re.sub(r"-{2,}", "-", out).strip("-._")[:40]
    return out or fallback


def free_name(base):
    """Имя, которого ещё нет среди сохранённых: vpn, vpn-2, vpn-3…"""
    taken = {v["name"] for v in list_vpns()}
    name, i = base, 2
    while name in taken:
        name, i = f"{base}-{i}", i + 1
    return name


def looks_like_source(text):
    """Похоже ли на саму конфигурацию или ссылку (а не на имя): так понимаем, что её вставили не в то поле."""
    return bool(SOURCE_RE.match((text or "").strip()))


def is_subscription_url(text):
    """Одна ссылка http(s):// — это подписка, которую нужно скачать, а не конфигурация."""
    t = (text or "").strip().strip("\"'<>")
    return bool(re.match(r"^https?://\S+$", t))


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


def base_name_from_url(url):
    """Имя VPN из адреса подписки: https://www.example.com/x -> example-com."""
    import urllib.parse
    host = (urllib.parse.urlsplit(url).hostname or "vpn").lower()
    host = host[4:] if host.startswith("www.") else host
    return "".join(c if c.isalnum() and c.isascii() else "-" for c in host).strip("-")[:40] or "vpn"


def open_via_proxy(proxy, auth, host, port, timeout):
    """Подключённый сокет до host:port через прокси (http или socks5); имя сайта разрешает сам прокси."""
    import asyncio
    import socket

    async def go():
        up = Upstream(proxy, auth or None)
        _r, w = await asyncio.wait_for(up.tunnel(host, port), timeout)
        try:
            return os.dup(w.get_extra_info("socket").fileno())     # соединение переживёт закрытие транспорта
        finally:
            w.close()
            await asyncio.sleep(0)

    sock = socket.socket(fileno=asyncio.run(go()))
    sock.settimeout(timeout)
    return sock


def fetch_subscription(url, timeout=20, proxy="", auth=""):
    """Скачать подписку по ссылке: напрямую с вашего компьютера (сервер подписки увидит ваш настоящий адрес) или
    через прокси `proxy` (тогда имя сайта разрешает он: помогает, когда сайт блокируется или не находится по DNS).

    Многие панели отдают разные форматы разным программам, поэтому представляемся клиентом v2rayN: он получает
    список ссылок. ValueError с понятным текстом при любой неудаче."""
    import http.client
    import socket
    import ssl
    import urllib.parse
    url = (url or "").strip()
    if urllib.parse.urlsplit(url).scheme not in ("http", "https") or any(c.isspace() for c in url):
        raise ValueError("нужна ссылка http:// или https:// без пробелов")
    via = " через прокси" if proxy else ""
    for _hop in range(5):                                           # переходы по перенаправлениям
        u = urllib.parse.urlsplit(url)
        https = u.scheme == "https"
        host = u.hostname or ""
        try:
            port = u.port or (443 if https else 80)
        except ValueError:
            raise ValueError("в ссылке неверный порт") from None
        path = (u.path or "/") + (("?" + u.query) if u.query else "")
        conn = (http.client.HTTPSConnection if https else http.client.HTTPConnection)(host, port, timeout=timeout)
        try:
            if proxy:
                raw = open_via_proxy(proxy, auth, host, port, timeout)
                conn.sock = ssl.create_default_context().wrap_socket(raw, server_hostname=host) if https else raw
            conn.request("GET", path, headers={"User-Agent": "v2rayN/6.42", "Accept": "*/*",
                                               "Accept-Encoding": "identity", "Connection": "close"})
            r = conn.getresponse()
            if r.status in (301, 302, 303, 307, 308) and r.getheader("Location"):
                url = urllib.parse.urljoin(url, r.getheader("Location"))
                continue
            if r.status >= 400:
                raise ValueError(f"сервер подписки ответил: HTTP {r.status}")
            data = r.read(SUB_MAX_BYTES + 1)
        except socket.gaierror:
            raise ValueError(f"не удалось найти сайт «{host}»: DNS вашего компьютера не отвечает или сайт "
                             "заблокирован. Выберите «Через прокси среды…» в окне добавления") from None
        except (OSError, http.client.HTTPException, UnicodeError) as e:
            raise ValueError(f"не удалось скачать подписку{via}: {e or type(e).__name__}") from None
        finally:
            conn.close()
        if len(data) > SUB_MAX_BYTES:
            raise ValueError("ответ сервера слишком большой (больше 2 МБ): это не подписка")
        return data.decode("utf-8", "replace")
    raise ValueError("слишком много перенаправлений")


def import_many(base, text, replace=False):
    """Добавить VPN из текста: одна конфигурация, ссылка или подписка (список ссылок, в том числе в base64).

    Возвращает ([(имя, вид, описание)], [причины пропуска]). Из подписки каждый сервер сохраняется отдельным VPN
    с именем <основа>-1, <основа>-2…; повторный импорт заменяет одноимённые. Ссылки других видов
    (hysteria2, tuic…) пропускаются с пояснением."""
    base = normalize_name(base, "")
    if not base:
        base = free_name("vpn")     # имя не задано или целиком из недопустимых знаков: не затираем то, что уже есть
    links, other = split_links(text)
    if not links:
        if other:
            raise ValueError("в подписке только неподдерживаемые ссылки: " + ", ".join(sorted(set(other)))
                             + ". Поддерживаются vless, vmess, trojan, ss, WireGuard и JSON Xray / sing-box")
        return [import_vpn(base, text, replace=replace)], []
    done, skipped = [], []
    base = base[:40]
    for i, link in enumerate(links[:SUB_MAX_LINKS], 1):
        name = base if len(links) == 1 else f"{base}-{i}"
        try:
            done.append(import_vpn(name, link, replace=replace or len(links) > 1))
        except ValueError as e:
            skipped.append(f"сервер {i}: {e}")
    if len(links) > SUB_MAX_LINKS:
        skipped.append(f"взяты первые {SUB_MAX_LINKS} серверов из {len(links)}")
    if other:
        skipped.append("неподдерживаемые ссылки пропущены: " + ", ".join(sorted(set(other))))
    if not done:
        raise ValueError("ни один сервер не удалось добавить: " + "; ".join(skipped[:3]))
    return done, skipped


def import_subscription(base, url, proxy="", auth=""):
    """Скачать подписку (напрямую или через прокси) и добавить серверы из неё (см. import_many)."""
    url = (url or "").strip().strip("\"'<>")
    return import_many(base or base_name_from_url(url), fetch_subscription(url, proxy=proxy, auth=auth), replace=True)
