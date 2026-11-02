"""Хранилище VPN-конфигураций: импорт, список, удаление и проверка наличия клиента.

Файлы лежат в <корень>/_vpn/<имя>.<расширение> с правами 0600 (в них ключи). Вид VPN определяет расширение:
.conf — WireGuard, .xray — VLESS-ссылка или JSON Xray, .singbox — JSON sing-box. Шлюз сам запускает клиент при
старте среды и останавливает при её остановке (см. net/vpn.py)."""

import json
import os
import re
import time

from ..net.vpn import (VPN_BINARIES, VPN_HINTS, VPN_KINDS, VPN_LABELS, VpnClient, detect_kind, find_binary,
                       describe_response, is_stub_link, json_server, split_json_configs, split_links, stub_remark,
                       vpn_info, vpn_validate, STUB_HOSTS)
from ..net.upstream import Upstream
from .consts import NAME_RE
from .root import envbox_root


VPN_DIR = "_vpn"


VPN_EXT = {"wireguard": ".conf", "xray": ".xray", "singbox": ".singbox"}


VPN_MAX_BYTES = 256 * 1024


# Подписка: ответ сервера не больше этого размера, серверов берём не больше SUB_MAX_LINKS
SUB_MAX_BYTES = 2 * 1024 * 1024


SUB_MAX_LINKS = 300


# Под какими приложениями пробуем скачать подписку: многие провайдеры отдают настоящие серверы только «своему»
# клиенту (Happ), остальным — заглушки «Приложение не поддерживается». Берётся первый ответ с настоящими серверами.
SUB_AGENTS = ("Happ/2.5.0", "v2rayN/6.42", "sing-box/1.9.0")


META_FILE = "meta.json"


HWID_FILE = ".hwid"


def vpn_dir():
    return os.path.join(envbox_root(), VPN_DIR)


def vpn_path(name, kind):
    return os.path.join(vpn_dir(), name + VPN_EXT[kind])


def vpn_name_from_file(filename):
    """Подходящее имя VPN из имени файла (wg0.conf -> wg0)."""
    stem = os.path.splitext(os.path.basename(filename))[0]
    stem = "".join(c if c.isalnum() and c.isascii() or c in "._-" else "-" for c in stem).strip("-._")
    return stem[:48] or "vpn"


# Режимы выхода в интернет: каждый — готовый порядок каналов (Profile.upstream_chain)
EXIT_MODES = ("proxy", "vpn_only", "vpn_then_proxy", "proxy_then_vpn", "custom")


EXIT_LABELS = {
    "proxy": "Напрямую или только через свой прокси (как раньше)",
    "vpn_only": "Только через VPN (без прокси и без прямого выхода)",
    "vpn_then_proxy": "Сначала VPN, запасной — свой прокси",
    "proxy_then_vpn": "Сначала свой прокси, запасной — VPN",
    "custom": "Свой порядок каналов (список ниже)",
}


def exit_chain(mode, vpn):
    """Порядок каналов для режима выхода и выбранного VPN (режим custom список не меняет: возвращает None)."""
    if mode == "proxy":
        return []
    if mode == "custom":
        return None
    v = f"vpn:{vpn}"
    return {"vpn_only": [v], "vpn_then_proxy": [v, "proxy"], "proxy_then_vpn": ["proxy", v]}[mode]


def exit_mode(chain):
    """(режим, имя VPN) по порядку каналов; нестандартный порядок — режим custom."""
    chain = list(chain or [])
    if not chain:
        return "proxy", ""
    vpn = lambda c: c[4:] if c.startswith("vpn:") else ""    # noqa: E731
    if len(chain) == 1 and vpn(chain[0]):
        return "vpn_only", vpn(chain[0])
    if chain[1:] == ["proxy"] and vpn(chain[0]):
        return "vpn_then_proxy", vpn(chain[0])
    if chain[:1] == ["proxy"] and len(chain) == 2 and vpn(chain[1]):
        return "proxy_then_vpn", vpn(chain[1])
    return "custom", ""


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


def clean_folder(name):
    """Название папки (сервиса) для показа: без управляющих знаков, до 40 знаков; пусто — «без папки»."""
    return "".join(c for c in (name or "") if c.isprintable()).strip()[:40]


def load_meta():
    """Папки и принадлежность VPN к ним: {"folders": {папка: сведения подписки}, "vpns": {имя: {"folder": …}}}."""
    try:
        with open(os.path.join(vpn_dir(), META_FILE), encoding="utf-8") as f:
            d = json.load(f)
    except (OSError, ValueError):
        d = {}
    if not isinstance(d, dict):
        d = {}
    d.setdefault("folders", {})
    d.setdefault("vpns", {})
    return d


def save_meta(meta):
    """В метаданных адрес подписки с токеном, поэтому права только владельцу."""
    os.makedirs(vpn_dir(), mode=0o700, exist_ok=True)
    path = os.path.join(vpn_dir(), META_FILE)
    fd = os.open(path + ".new", os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=1)
    os.replace(path + ".new", path)


def set_folder(name, folder):
    """Положить VPN в папку (пустое название — вынуть из папки)."""
    meta = load_meta()
    folder = clean_folder(folder)
    if folder:
        meta["vpns"].setdefault(name, {})["folder"] = folder
        meta["folders"].setdefault(folder, {})
    else:
        meta["vpns"].pop(name, None)
    save_meta(meta)


def human_bytes(n):
    n = float(n)
    for unit in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if n < 1024 or unit == "ТБ":
            return f"{n:.0f} {unit}" if unit == "Б" else f"{n:.1f} {unit}"
        n /= 1024
    return ""


def folder_summary(info):
    """Строка про подписку папки: трафик, срок, когда обновлялась, поддержка."""
    parts = []
    if info.get("total"):
        parts.append(f"трафик: {human_bytes(info.get('used', 0))} из {human_bytes(info['total'])}")
    elif info.get("used"):
        parts.append(f"трафик: {human_bytes(info['used'])}")
    if info.get("expire"):
        parts.append("действует до " + time.strftime("%d.%m.%Y", time.localtime(info["expire"])))
    if info.get("updated"):
        parts.append("обновлено " + time.strftime("%d.%m %H:%M", time.localtime(info["updated"])))
    if info.get("support"):
        parts.append("поддержка: " + info["support"])
    return " · ".join(parts)


def natural_key(name):
    """Ключ сортировки, при котором vpn-2 идёт раньше vpn-10."""
    return [int(t) if t.isdigit() else t for t in re.split(r"(\d+)", name.lower())]


def list_folders():
    """Папки (сервисы): {название: сведения подписки}; пустые папки без серверов не показываются."""
    meta = load_meta()
    used = {m.get("folder") for m in meta["vpns"].values()}
    return {f: info for f, info in sorted(meta["folders"].items()) if f in used}


def delete_folder(folder):
    """Удалить папку вместе со всеми её VPN. Возвращает, сколько VPN удалено."""
    meta = load_meta()
    names = [n for n, m in meta["vpns"].items() if m.get("folder") == folder]
    for n in names:
        delete_vpn(n)
    meta = load_meta()
    meta["folders"].pop(folder, None)
    save_meta(meta)
    return len(names)


def search_vpns(vpns, query):
    """Поиск по названию, серверу (адрес и порт), папке и виду; все слова запроса должны встретиться."""
    tokens = (query or "").lower().split()
    if not tokens:
        return list(vpns)

    def hay(v):
        return " ".join([v["name"], v.get("title", ""), v.get("host", ""), str(v.get("port") or ""),
                         v.get("folder", ""), v.get("label", ""), v["kind"]]).lower()
    return [v for v in vpns if all(t in hay(v) for t in tokens)]


def tcp_ping(host, port, timeout=3.0):
    """Время подключения к серверу в мс (TCP) или None, если не ответил. С вашего компьютера напрямую."""
    import socket
    t0 = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return max(1, int((time.monotonic() - t0) * 1000))
    except OSError:
        return None


def ping_vpns(vpns, timeout=3.0, workers=16):
    """Пинг серверов: {имя: мс или None}. WireGuard (UDP) и конфигурации без адреса сервера не измеряются."""
    from concurrent.futures import ThreadPoolExecutor
    todo = [v for v in vpns if v.get("host") and v.get("port") and not v.get("udp")]
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(todo) or 1))) as pool:
        times = list(pool.map(lambda v: tcp_ping(v["host"], v["port"], timeout), todo))
    return {v["name"]: ms for v, ms in zip(todo, times)}


def list_vpns():
    """Сохранённые VPN: [{name, kind, label, path, server, error, binary, folder, title, host, port, udp}] по имени."""
    out = []
    try:
        names = sorted(os.listdir(vpn_dir()))
    except OSError:
        return out
    by_ext = {ext: kind for kind, ext in VPN_EXT.items()}
    folders = {n: m.get("folder", "") for n, m in load_meta()["vpns"].items()}
    for fname in names:
        stem, ext = os.path.splitext(fname)
        kind = by_ext.get(ext)
        path = os.path.join(vpn_dir(), fname)
        if kind is None or not NAME_RE.match(stem) or not os.path.isfile(path) or os.path.islink(path):
            continue
        server, error, info = "", "", {"title": "", "host": "", "port": 0, "udp": False}
        try:
            with open(path, encoding="utf-8") as f:
                text = f.read(VPN_MAX_BYTES + 1)
            server = vpn_validate(kind, text)
            info = vpn_info(kind, text)
        except (OSError, ValueError) as e:
            error = str(e)
        out.append({"name": stem, "kind": kind, "label": VPN_LABELS[kind], "path": path, "server": server,
                    "error": error, "binary": find_binary(kind) or "", "folder": folders.get(stem, ""), **info})
    return out


def vpn_source(name):
    """(вид, путь) сохранённого VPN или ValueError."""
    for v in list_vpns():
        if v["name"] == name:
            return v["kind"], v["path"]
    raise ValueError(f"VPN «{name}» не найден: добавьте его на вкладке «VPN»")


def import_vpn(name, text, replace=False, folder=None):
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
    if folder is not None:
        set_folder(name, folder)
    return name, kind, server


def delete_vpn(name):
    for v in list_vpns():
        if v["name"] == name:
            os.unlink(v["path"])
            meta = load_meta()
            if meta["vpns"].pop(name, None) is not None:
                save_meta(meta)
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


def device_headers():
    """Заголовки устройства, как у приложений-клиентов (Happ и др.): провайдеры с лимитом устройств (HWID) считают по
    ним. Идентификатор случайный, создаётся один раз и хранится рядом с VPN; настоящих данных о компьютере нет."""
    import platform
    import uuid
    path = os.path.join(vpn_dir(), HWID_FILE)
    try:
        with open(path, encoding="utf-8") as f:
            hwid = f.read().strip()
    except OSError:
        hwid = ""
    if not re.match(r"^[0-9a-f]{16,64}$", hwid):
        hwid = uuid.uuid4().hex
        os.makedirs(vpn_dir(), mode=0o700, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(hwid + "\n")
    return {"x-hwid": hwid, "x-device-os": "Linux", "x-ver-os": platform.release()[:40] or "linux",
            "x-device-model": "envbox"}


def http_errors():
    """Какие исключения означают сбой сети в http_request (http.client подключается лениво: он тяжёлый)."""
    import http.client
    return (OSError, http.client.HTTPException, UnicodeError, ValueError)


def http_request(url, proxy="", auth="", timeout=15, headers=None, max_bytes=256 * 1024):
    """Один GET напрямую или через прокси (имя сайта разрешает прокси): (статус, заголовки в нижнем регистре, тело,
    миллисекунды до ответа). Перенаправления не выполняются: нужен сам ответ. Сбой сети — исключение из http_errors()."""
    import http.client
    import ssl
    import urllib.parse
    u = urllib.parse.urlsplit(url)
    https, host = u.scheme == "https", u.hostname or ""
    port = u.port or (443 if https else 80)
    conn = (http.client.HTTPSConnection if https else http.client.HTTPConnection)(host, port, timeout=timeout)
    t0 = time.monotonic()
    try:
        if proxy:
            raw = open_via_proxy(proxy, auth, host, port, timeout)
            conn.sock = ssl.create_default_context().wrap_socket(raw, server_hostname=host) if https else raw
        conn.request("GET", (u.path or "/") + (("?" + u.query) if u.query else ""),
                     headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) envbox-check", "Accept": "*/*",
                              "Accept-Encoding": "identity", "Connection": "close", **(headers or {})})
        r = conn.getresponse()
        ms = int((time.monotonic() - t0) * 1000)
        return r.status, {k.lower(): v for k, v in r.getheaders()}, r.read(max_bytes), ms
    finally:
        conn.close()


def fetch_subscription(url, timeout=20, proxy="", auth="", agent=SUB_AGENTS[0]):
    """Текст подписки (см. fetch_subscription_full)."""
    return fetch_subscription_full(url, timeout, proxy, auth, agent)[0]


def fetch_subscription_full(url, timeout=20, proxy="", auth="", agent=SUB_AGENTS[0]):
    """Скачать подписку по ссылке: напрямую с вашего компьютера (сервер подписки увидит ваш настоящий адрес) или
    через прокси `proxy` (тогда имя сайта разрешает он: помогает, когда сайт блокируется или не находится по DNS).

    Многие панели отдают разные форматы и разные наборы серверов разным программам, поэтому представляемся клиентом
    `agent` и отправляем заголовки устройства. Возвращает (текст, заголовки ответа в нижнем регистре).
    ValueError с понятным текстом при любой неудаче."""
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
            conn.request("GET", path, headers={"User-Agent": agent, "Accept": "*/*", "Accept-Encoding": "identity",
                                               "Connection": "close", **device_headers()})
            r = conn.getresponse()
            if r.status in (301, 302, 303, 307, 308) and r.getheader("Location"):
                url = urllib.parse.urljoin(url, r.getheader("Location"))
                continue
            if r.status >= 400:
                raise ValueError(f"сервер подписки ответил: HTTP {r.status}")
            data = r.read(SUB_MAX_BYTES + 1)
            headers = {k.lower(): v for k, v in r.getheaders()}
        except socket.gaierror:
            raise ValueError(f"не удалось найти сайт «{host}»: DNS вашего компьютера не отвечает или сайт "
                             "заблокирован. Выберите «Через прокси среды…» в окне добавления") from None
        except (OSError, http.client.HTTPException, UnicodeError) as e:
            raise ValueError(f"не удалось скачать подписку{via}: {e or type(e).__name__}") from None
        finally:
            conn.close()
        if len(data) > SUB_MAX_BYTES:
            raise ValueError("ответ сервера слишком большой (больше 2 МБ): это не подписка")
        return data.decode("utf-8", "replace"), headers
    raise ValueError("слишком много перенаправлений")


def header_text(value):
    """Значение заголовка подписки: бывает `base64:…` или в процентной записи."""
    import base64
    import urllib.parse
    v = (value or "").strip()
    if v.lower().startswith("base64:"):
        try:
            return base64.b64decode(v[7:] + "=" * (-len(v[7:]) % 4)).decode("utf-8", "replace").strip()
        except ValueError:
            return ""
    return urllib.parse.unquote(v)


def subscription_info(headers):
    """Сведения о подписке из заголовков: {title, used, total, expire, interval, support}; нужные есть не всегда."""
    info = {"title": clean_folder(header_text(headers.get("profile-title", ""))),
            "support": header_text(headers.get("support-url", ""))[:200]}
    for part in (headers.get("subscription-userinfo") or "").split(";"):
        key, _, val = part.strip().partition("=")
        if key in ("upload", "download", "total", "expire") and val.strip().isdigit():
            info[key] = int(val)
    if "upload" in info or "download" in info:
        info["used"] = info.pop("upload", 0) + info.pop("download", 0)
    interval = (headers.get("profile-update-interval") or "").strip()
    if interval.isdigit():
        info["interval"] = int(interval)
    return info


def parse_subscription(text):
    """Что в ответе подписки -> (серверы, заглушки, другие схемы).

    серверы — тексты, которые можно сохранить как VPN (ссылка на сервер, конфигурация из массива JSON или весь текст,
    если это одна конфигурация); заглушки — имена фальшивых серверов провайдера; другие схемы — hysteria2, tuic…"""
    configs = split_json_configs(text)
    if configs:
        items, stubs = [], []
        for remark, body in configs:
            host, port = json_server(json.loads(body))
            if host and (host.lower() in STUB_HOSTS or port <= 1):
                stubs.append(remark or host)
            else:
                items.append(body)
        return items, stubs, []
    links, other = split_links(text)
    if links:
        stubs = [stub_remark(x) or x[:30] for x in links if is_stub_link(x)]
        return [x for x in links if not is_stub_link(x)], stubs, other
    if other:
        return [], [], other
    return ([text] if (text or "").strip() else []), [], []


def import_many(base, text, replace=False, folder=None):
    """Добавить VPN из текста: одна конфигурация, ссылка или подписка (список ссылок или массив конфигураций JSON,
    в том числе в base64).

    Возвращает ([(имя, вид, описание)], [причины пропуска]). Из подписки каждый сервер сохраняется отдельным VPN
    с именем <основа>-1, <основа>-2…; повторный импорт заменяет одноимённые. Заглушки провайдера (адрес 0.0.0.0,
    «Используйте Happ») и ссылки других видов (hysteria2, tuic…) пропускаются с пояснением. `folder` — в какую
    папку (сервис) положить (None — не менять)."""
    base = normalize_name(base, "")
    if not base:
        base = free_name("vpn")     # имя не задано или целиком из недопустимых знаков: не затираем то, что уже есть
    items, stubs, other = parse_subscription(text)
    done, skipped = [], []
    if stubs:
        skipped.append("заглушки провайдера пропущены: " + ", ".join("«" + t + "»" for t in dict.fromkeys(stubs)))
    if not items:
        if stubs:
            raise ValueError("провайдер вернул вместо серверов только заглушки (" + ", ".join(dict.fromkeys(stubs))
                             + "): подписка привязана к приложению провайдера или лимиту устройств")
        if other:
            raise ValueError("в подписке только неподдерживаемые ссылки: " + ", ".join(sorted(set(other)))
                             + ". Поддерживаются vless, vmess, trojan, ss, WireGuard и JSON Xray / sing-box")
        raise ValueError("ответ не похож на подписку: " + describe_response(text))
    if len(items) == 1 and items[0] is text:       # весь ответ — одна конфигурация (WireGuard, JSON-объект), не список
        try:
            detect_kind(text)
        except ValueError:
            raise ValueError("ответ не похож на подписку: " + describe_response(text)) from None
        return [import_vpn(base, text, replace=replace, folder=folder)], skipped
    base = base[:40]
    for i, item in enumerate(items[:SUB_MAX_LINKS], 1):
        name = base if len(items) == 1 else f"{base}-{i}"
        try:
            done.append(import_vpn(name, item, replace=replace or len(items) > 1, folder=folder))
        except ValueError as e:
            skipped.append(f"сервер {i}: {e}")
    if len(items) > SUB_MAX_LINKS:
        skipped.append(f"взяты первые {SUB_MAX_LINKS} серверов из {len(items)}")
    if other:
        skipped.append("неподдерживаемые ссылки пропущены: " + ", ".join(sorted(set(other))))
    if not done:
        raise ValueError("ни один сервер не удалось добавить: " + "; ".join(skipped[:3]))
    return done, skipped


def import_subscription(base, url, proxy="", auth="", via="", folder=None):
    """Скачать подписку (напрямую или через прокси) и добавить серверы в папку-сервис (см. import_many).

    Пробуем приложения из SUB_AGENTS по очереди и берём первый ответ с настоящими серверами. Папка — название из
    заголовка подписки (profile-title) или имя сайта; рядом запоминаются адрес подписки (для «Обновить»), трафик,
    срок и ссылка на поддержку. `via` — среда, через чей прокси скачивали (чтобы обновлять так же)."""
    url = (url or "").strip().strip("\"'<>")
    stubs, text, headers = [], "", {}
    for agent in SUB_AGENTS:
        text, headers = fetch_subscription_full(url, proxy=proxy, auth=auth, agent=agent)
        items, found, _other = parse_subscription(text)
        stubs += found
        if items or not found:       # настоящие серверы (или вообще не заглушки): дальше не перебираем
            break
    info = subscription_info(headers)
    base = base or base_name_from_url(url)
    folder = clean_folder(folder if folder is not None else (info["title"] or base))
    try:
        done, skipped = import_many(base, text, replace=True, folder=folder)
    except ValueError as e:
        if stubs:
            raise ValueError(f"{e}. Пробовал как {', '.join(SUB_AGENTS)}; откройте подписку в приложении провайдера "
                             "или попросите у поддержки ссылку для других клиентов") from None
        raise
    meta = load_meta()
    meta["folders"][folder] = {**info, "url": url, "via": via, "base": base, "updated": int(time.time()),
                               "count": len(done)}
    meta["folders"][folder].pop("title", None)
    save_meta(meta)
    return done, skipped


def refresh_folder(folder, proxy="", auth=""):
    """Обновить папку по сохранённой подписке: новые серверы добавляются, пропавшие у провайдера удаляются.
    Возвращает (импортировано, пропущено, удалено)."""
    meta = load_meta()
    sub = meta["folders"].get(folder) or {}
    if not sub.get("url"):
        raise ValueError(f"у папки «{folder}» нет подписки: серверы добавлены вручную")
    before = {n for n, m in meta["vpns"].items() if m.get("folder") == folder}
    done, skipped = import_subscription(sub.get("base") or "", sub["url"], proxy=proxy, auth=auth,
                                        via=sub.get("via", ""), folder=folder)
    gone = sorted(before - {n for n, _k, _s in done})
    for n in gone:
        delete_vpn(n)
    return done, skipped, gone
