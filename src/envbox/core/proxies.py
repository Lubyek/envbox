"""Хранилище прокси: список, папки (сервисы), поиск, пинг, проверка и проверка «для Claude».

Файл <корень>/_proxy/proxies.json с правами 0600 (в нём логины и пароли). Прокси в списке не привязаны к средам:
«Применить к среде» копирует адрес в профиль среды, а пароль кладёт в keyring этой среды, как при ручном вводе."""

import json
import os
import re
import time

from ..net.upstream import Upstream
from .root import envbox_root
from .upstream import split_proxy_url
from .vpn import (SUB_MAX_BYTES, base_name_from_url, clean_folder, http_errors, http_request, natural_key,
                  normalize_name)
from .vpncheck import check_exit, verdict


PX_DIR = "_proxy"


PX_FILE = "proxies.json"


PX_MAX_LINES = 1000


PX_SCHEMES = ("http", "socks5", "socks5h")


PX_LABELS = {"http": "HTTP", "socks5": "SOCKS5", "socks5h": "SOCKS5"}


def px_path():
    return os.path.join(envbox_root(), PX_DIR, PX_FILE)


def load_px():
    """{"proxies": {имя: {url, auth, folder, title, added}}, "folders": {папка: сведения списка}}."""
    try:
        with open(px_path(), encoding="utf-8") as f:
            d = json.load(f)
    except (OSError, ValueError):
        d = {}
    if not isinstance(d, dict):
        d = {}
    d["proxies"] = d["proxies"] if isinstance(d.get("proxies"), dict) else {}
    d["folders"] = d["folders"] if isinstance(d.get("folders"), dict) else {}
    return d


def save_px(d):
    path = px_path()
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    fd = os.open(path + ".new", os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(d, f, ensure_ascii=False, indent=1)
    os.replace(path + ".new", path)


def parse_proxy_line(line, default="http"):
    """Одна строка -> (адрес без пароля, 'логин:пароль' или '', пометка из #…).

    Понимает схема://[логин:пароль@]хост:порт, [логин:пароль@]хост:порт, хост:порт:логин:пароль и хост:порт;
    без схемы берётся `default`. ValueError с понятным текстом."""
    import urllib.parse
    text, _, remark = line.strip().partition("#")
    text, remark = text.strip(), urllib.parse.unquote(remark.strip())
    if not text:
        raise ValueError("пустая строка")
    if "://" not in text:
        parts = text.split(":")
        if len(parts) == 4 and parts[1].isdigit():             # хост:порт:логин:пароль (в пароле может быть @)
            host, port, user, password = parts
            text = f"{default}://{urllib.parse.quote(user, safe='')}:{urllib.parse.quote(password, safe='')}@{host}:{port}"
        elif "@" in text or len(parts) == 2:
            text = f"{default}://{text}"
        else:
            raise ValueError(f"не понял формат «{text[:40]}»: нужен хост:порт, хост:порт:логин:пароль или схема://…")
    url, auth = split_proxy_url(text)
    return url, auth, remark


def proxy_lines(text):
    """Строки с прокси из текста: пустые и комментарии (# в начале) пропускаются."""
    return [ln.strip() for ln in (text or "").splitlines() if ln.strip() and not ln.strip().startswith("#")]


def is_proxy_list_url(text):
    """Ссылка на список прокси (её нужно скачать), а не сам прокси: http://хост:порт — это прокси."""
    import urllib.parse
    t = (text or "").strip().strip("\"'<>")
    if not re.match(r"^https?://\S+$", t):
        return False
    u = urllib.parse.urlsplit(t)
    return not (u.port and u.path in ("", "/") and not u.query)


def px_name_free(base, taken, single):
    """Свободное имя: base (один прокси) или base-1, base-2…"""
    if single and base not in taken:
        return base
    i = 1
    while f"{base}-{i}" in taken:
        i += 1
    return f"{base}-{i}"


def import_proxies(base, text, default_scheme="http", folder=None, replace=False):
    """Добавить прокси из текста (по одному в строке). -> ([(имя, адрес, «хост:порт»)], [причины пропуска]).

    Уже имеющийся такой же прокси (адрес и логин совпали) не дублируется. replace=True (обновление списка)
    пишет в имена base-1, base-2… по номеру строки, затирая прежние."""
    lines = proxy_lines(text)
    if not lines:
        raise ValueError("в тексте нет ни одного прокси")
    base = normalize_name(base, "") or "proxy"
    base = base[:40]
    folder = clean_folder(folder) if folder is not None else None
    data = load_px()
    existing = {(v.get("url"), v.get("auth", "")): n for n, v in data["proxies"].items()}
    done, skipped = [], []
    for i, line in enumerate(lines[:PX_MAX_LINES], 1):
        try:
            url, auth, remark = parse_proxy_line(line, default_scheme)
        except ValueError as e:
            skipped.append(f"строка {i}: {e}")
            continue
        hostport = url.split("://", 1)[1]
        if not replace and (url, auth) in existing:
            skipped.append(f"{hostport} уже есть как «{existing[(url, auth)]}»")
            continue
        if replace:
            name = base if len(lines) == 1 else f"{base}-{i}"
        else:
            name = px_name_free(base, set(data["proxies"]), len(lines) == 1)
        old = data["proxies"].get(name, {})
        data["proxies"][name] = {"url": url, "auth": auth, "title": remark,
                                 "folder": old.get("folder", "") if folder is None else folder,
                                 "added": int(time.time())}
        existing[(url, auth)] = name
        done.append((name, url, hostport))
    if len(lines) > PX_MAX_LINES:
        skipped.append(f"взяты первые {PX_MAX_LINES} строк из {len(lines)}")
    if not done:
        raise ValueError("ни один прокси не добавлен: " + "; ".join(skipped[:3]))
    if folder:
        data["folders"].setdefault(folder, {})
    save_px(data)
    return done, skipped


def list_proxies():
    """Сохранённые прокси: [{name, url, kind, label, host, port, udp, has_auth, folder, title, error}] по имени.

    Пароль в список не попадает: он нужен только запуску (proxy_credentials)."""
    import urllib.parse
    out = []
    for name, v in sorted(load_px()["proxies"].items(), key=lambda kv: natural_key(kv[0])):
        try:
            u = urllib.parse.urlsplit(v.get("url", ""))
            host, port, scheme = u.hostname or "", u.port or 0, u.scheme
            error = "" if scheme in PX_SCHEMES and host and port else "адрес повреждён"
        except ValueError:
            host, port, scheme, error = "", 0, "", "адрес повреждён"
        out.append({"name": name, "url": v.get("url", ""), "kind": scheme, "label": PX_LABELS.get(scheme, "?"),
                    "host": host, "port": port, "udp": False, "has_auth": bool(v.get("auth")),
                    "folder": v.get("folder", ""), "title": v.get("title", ""), "error": error})
    return out


def proxy_credentials(name):
    """(адрес, 'логин:пароль' или '') сохранённого прокси; ValueError, если такого нет."""
    v = load_px()["proxies"].get(name)
    if not v:
        raise ValueError(f"прокси «{name}» не найден: добавьте его на вкладке «Прокси»")
    return v["url"], v.get("auth", "")


def proxy_url_with_auth(name):
    """Адрес прокси с логином и паролем внутри (схема://логин:пароль@хост:порт) — для поля прокси среды: профиль сам
    перенесёт пароль в keyring и оставит в профиле чистый адрес. Только для передачи в окно: нигде не сохранять."""
    import urllib.parse
    url, auth = proxy_credentials(name)
    if not auth:
        return url
    user, _, password = auth.partition(":")
    scheme, _, rest = url.partition("://")
    return f"{scheme}://{urllib.parse.quote(user, safe='')}:{urllib.parse.quote(password, safe='')}@{rest}"


def delete_proxies(names):
    """Удалить выделенные прокси одним действием. Возвращает, сколько удалено."""
    data = load_px()
    done = sum(1 for n in set(names) if data["proxies"].pop(n, None) is not None)
    used = {v.get("folder") for v in data["proxies"].values()}
    data["folders"] = {f: i for f, i in data["folders"].items() if f in used}
    save_px(data)
    return done


def clear_proxies():
    """Удалить все прокси и папки. Возвращает, сколько прокси удалено."""
    n = len(load_px()["proxies"])
    save_px({"proxies": {}, "folders": {}})
    return n


def set_px_folder(name, folder):
    data = load_px()
    if name not in data["proxies"]:
        raise ValueError(f"прокси «{name}» не найден")
    folder = clean_folder(folder)
    data["proxies"][name]["folder"] = folder
    if folder:
        data["folders"].setdefault(folder, {})
    used = {v.get("folder") for v in data["proxies"].values()}
    data["folders"] = {f: i for f, i in data["folders"].items() if f in used}
    save_px(data)


def list_px_folders():
    """Папки с прокси: {название: сведения списка}; пустые не показываются."""
    data = load_px()
    used = {v.get("folder") for v in data["proxies"].values()}
    return {f: i for f, i in sorted(data["folders"].items()) if f in used}


def delete_px_folder(folder):
    """Удалить папку вместе с прокси в ней. Возвращает, сколько прокси удалено."""
    names = [n for n, v in load_px()["proxies"].items() if v.get("folder") == folder]
    return delete_proxies(names)


def fetch_proxy_list(url, proxy="", auth="", timeout=20):
    """Скачать список прокси по ссылке (напрямую или через прокси `proxy`). ValueError с понятным текстом."""
    import socket
    import urllib.parse
    url = (url or "").strip().strip("\"'<>")
    for _hop in range(5):
        host = urllib.parse.urlsplit(url).hostname or ""
        try:
            status, headers, body, _ms = http_request(url, proxy, auth, timeout, max_bytes=SUB_MAX_BYTES + 1)
        except socket.gaierror:
            raise ValueError(f"не удалось найти сайт «{host}»: DNS компьютера не отвечает или сайт заблокирован") from None
        except http_errors() as e:
            raise ValueError(f"не удалось скачать список: {e or type(e).__name__}") from None
        if status in (301, 302, 303, 307, 308) and headers.get("location"):
            url = urllib.parse.urljoin(url, headers["location"])
            continue
        if status >= 400:
            raise ValueError(f"сервер ответил: HTTP {status}")
        if len(body) > SUB_MAX_BYTES:
            raise ValueError("ответ слишком большой (больше 2 МБ): это не список прокси")
        return body.decode("utf-8", "replace")
    raise ValueError("слишком много перенаправлений")


def import_proxy_url(base, url, default_scheme="http", folder=None, proxy="", auth="", via=""):
    """Скачать список прокси по ссылке и добавить в папку (запоминается адрес для «Обновить»)."""
    url = (url or "").strip().strip("\"'<>")
    text = fetch_proxy_list(url, proxy, auth)
    base = base or base_name_from_url(url)
    folder = clean_folder(folder if folder is not None else base)
    done, skipped = import_proxies(base, text, default_scheme, folder=folder, replace=True)
    data = load_px()
    data["folders"][folder] = {"url": url, "scheme": default_scheme, "via": via, "base": base,
                               "updated": int(time.time()), "count": len(done)}
    save_px(data)
    return done, skipped


def refresh_px_folder(folder, proxy="", auth=""):
    """Обновить папку по сохранённому адресу списка: пропавшие прокси удаляются. -> (добавлено, пропущено, удалено)."""
    sub = load_px()["folders"].get(folder) or {}
    if not sub.get("url"):
        raise ValueError(f"у папки «{folder}» нет адреса списка: прокси добавлены вручную")
    before = {n for n, v in load_px()["proxies"].items() if v.get("folder") == folder}
    done, skipped = import_proxy_url(sub.get("base") or "", sub["url"], sub.get("scheme", "http"), folder=folder,
                                     proxy=proxy, auth=auth, via=sub.get("via", ""))
    gone = sorted(before - {n for n, _u, _h in done})
    delete_proxies(gone)
    return done, skipped, gone


def test_proxy(name, target=("example.com", 443)):
    """Открыть через прокси туннель до target -> (получилось, текст)."""
    import asyncio
    try:
        url, auth = proxy_credentials(name)
    except ValueError as e:
        return False, str(e)

    async def run():
        t0 = time.monotonic()
        _r, w = await asyncio.wait_for(Upstream(url, auth or None).tunnel(*target), 20)
        w.close()
        return int((time.monotonic() - t0) * 1000)

    try:
        ms = asyncio.run(run())
    except (OSError, ValueError, asyncio.TimeoutError) as e:
        return False, f"прокси «{name}» не работает: {e or type(e).__name__}"
    return True, f"прокси «{name}» работает: туннель до {target[0]} открыт за {ms} мс"


def proxy_transport_report(url, has_auth):
    """Безопасность самого канала до прокси: [(уровень, текст)]."""
    kind = "HTTP-прокси" if url.startswith("http:") else "SOCKS5-прокси"
    out = [("ok", f"{kind}: HTTPS шифруется до самого сайта, прокси видит только адреса сайтов и объёмы")]
    out.append(("warn", f"канал до {kind} не шифруется: ваш провайдер видит, что вы пользуетесь этим прокси"
                        + (", а логин и пароль передаются открытым текстом" if has_auth else "")))
    if not has_auth:
        out.append(("warn", "прокси без логина и пароля: им может воспользоваться любой, кто знает адрес "
                            "(платные обычно привязаны к вашему IP)"))
    return out


def check_proxy(name, env_tz="", compare_real=True, timeout=15):
    """Проверка выхода сохранённого прокси «для Claude» (см. vpncheck.check_exit) + безопасность канала."""
    url, auth = proxy_credentials(name)
    report = check_exit(url, auth, timeout, compare_real=compare_real, env_tz=env_tz)
    report["transport"] = proxy_transport_report(url, bool(auth))
    report["verdict"] = verdict(report["findings"] + report["transport"])
    return report
