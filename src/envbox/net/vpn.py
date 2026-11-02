"""Сетевой шлюз: VPN-клиенты как локальные SOCKS-прокси.

WireGuard запускается через wireproxy (WireGuard в пространстве пользователя), VLESS и JSON-конфигурации — через
Xray или sing-box. Все они работают без root: клиент слушает 127.0.0.1:<порт> с одноразовым логином и паролем
(чужие программы на компьютере не смогут пользоваться вашим VPN), а шлюз подключается к нему как к обычному
вышестоящему SOCKS5-прокси. Среда по-прежнему выходит только через прокси envbox."""

import os
import time

from ..lazy import asyncio, base64, json, re, signal, socket, urllib_parse
from .upstream import Upstream


VPN_KINDS = ("wireguard", "xray", "singbox")


VPN_LABELS = {"wireguard": "WireGuard", "xray": "VLESS / Xray", "singbox": "sing-box"}


# Какая программа нужна для каждого вида (искать в PATH; путь можно задать переменной окружения)
VPN_BINARIES = {"wireguard": "wireproxy", "xray": "xray", "singbox": "sing-box"}


VPN_ENV = {"wireguard": "ENVBOX_VPN_WIREPROXY", "xray": "ENVBOX_VPN_XRAY", "singbox": "ENVBOX_VPN_SINGBOX"}


VPN_HINTS = {
    "wireguard": "wireproxy: https://github.com/pufferffish/wireproxy (AUR: wireproxy)",
    "xray": "Xray-core: https://github.com/XTLS/Xray-core (AUR: xray)",
    "singbox": "sing-box: https://github.com/SagerNet/sing-box (AUR: sing-box)",
}


# Сколько ждать, пока клиент начнёт слушать порт
START_TIMEOUT = 20.0


# Разделы и ключи WireGuard, которые не нужны клиенту в пространстве пользователя или опасны: сценарии wg-quick
# (PostUp и др. исполняют команды) и туннели wireproxy, открывающие порты компьютера
WG_DROP_KEYS = ("preup", "postup", "predown", "postdown", "saveconfig", "table", "fwmark")
WG_KEEP_SECTIONS = ("interface", "peer")


# Ссылки на серверы, которые превращаются в конфигурацию Xray (клиент xray)
LINK_SCHEMES = ("vless://", "vmess://", "trojan://", "ss://")


UUID_RE = r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$"


def detect_kind(text):
    """Вид VPN-конфигурации по тексту: wireguard, xray или singbox. Непонятный формат — ValueError."""
    t = (text or "").strip()
    if not t:
        raise ValueError("конфигурация пуста")
    if t.lower().startswith(LINK_SCHEMES):
        return "xray"
    if t.startswith("{"):
        try:
            data = json.loads(t)
        except ValueError:
            raise ValueError("JSON повреждён") from None
        outs = data.get("outbounds") if isinstance(data, dict) else None
        if isinstance(outs, list):
            if any(isinstance(o, dict) and "protocol" in o for o in outs):
                return "xray"
            if any(isinstance(o, dict) and "type" in o for o in outs):
                return "singbox"
        raise ValueError("JSON не похож на конфигурацию Xray или sing-box (нет outbounds)")
    if re.search(r"^\s*\[interface\]", t, re.I | re.M) and re.search(r"^\s*\[peer\]", t, re.I | re.M):
        return "wireguard"
    raise ValueError("не удалось определить формат: ожидается WireGuard (.conf с [Interface] и [Peer]), ссылка "
                     "vless://, vmess://, trojan:// или ss://, список таких ссылок (подписка) или JSON Xray / sing-box")


def wg_sections(text):
    """Разбор WireGuard-конфигурации: [(раздел в нижнем регистре, {ключ в нижнем регистре: значение})]."""
    out = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            out.append((line[1:-1].strip().lower(), {}))
        elif "=" in line and out:
            k, _, v = line.partition("=")
            out[-1][1][k.strip().lower()] = v.strip()
    return out


def wg_validate(text):
    """Проверка WireGuard-конфигурации: нужные поля есть. Возвращает краткое описание сервера."""
    secs = wg_sections(text)
    iface = next((d for n, d in secs if n == "interface"), None)
    peers = [d for n, d in secs if n == "peer"]
    if iface is None or not peers:
        raise ValueError("нужны разделы [Interface] и [Peer]")
    for key in ("privatekey", "address"):
        if not iface.get(key):
            raise ValueError(f"в [Interface] нет {'PrivateKey' if key == 'privatekey' else 'Address'}")
    peer = peers[0]
    for key, title in (("publickey", "PublicKey"), ("endpoint", "Endpoint"), ("allowedips", "AllowedIPs")):
        if not peer.get(key):
            raise ValueError(f"в [Peer] нет {title}")
    return peer["endpoint"]


def wg_runtime(text, port, user, password):
    """Конфигурация wireproxy: исходная без сценариев wg-quick и чужих туннелей + наш SOCKS5 на loopback."""
    keep, section = [], ""
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            if section in WG_KEEP_SECTIONS:
                keep.append(line)
            continue
        if section not in WG_KEEP_SECTIONS or not line or line.startswith("#"):
            continue
        key = line.split("=", 1)[0].strip().lower()
        if key in WG_DROP_KEYS:
            continue
        keep.append(line)
    if not any(re.match(r"^dns\s*=", ln, re.I) for ln in keep):
        # без DNS внутри туннеля имена пришлось бы разрешать у себя (утечка): берём публичный сервер через VPN
        for i, ln in enumerate(keep):
            if ln.lower() == "[interface]":
                keep.insert(i + 1, "DNS = 1.1.1.1")
                break
    body = "\n".join(keep)
    return f"{body}\n\n[Socks5]\nBindAddress = 127.0.0.1:{port}\nUsername = {user}\nPassword = {password}\n"


def share_scheme(text):
    """Схема ссылки на сервер (vless, vmess, trojan, ss) или пустая строка."""
    t = (text or "").strip().lower()
    return next((x[:-3] for x in LINK_SCHEMES if t.startswith(x)), "")


def b64decode(text):
    """base64 в обычном и url-безопасном виде, с отсутствующими знаками «=». ValueError, если не base64."""
    t = re.sub(r"\s+", "", text).replace("-", "+").replace("_", "/")
    return base64.b64decode(t + "=" * (-len(t) % 4))


def stream_settings(q, host, security="none"):
    """Параметры транспорта Xray из параметров ссылки (type, security, sni, fp, path, host, serviceName, pbk, sid…)."""
    net = (q.get("type") or q.get("net") or "tcp").lower()
    sec = (q.get("security") or security or "none").lower()
    net = {"splithttp": "xhttp", "h2": "http"}.get(net, net)
    stream = {"network": net, "security": sec}
    if sec == "tls":
        tls = {"serverName": q.get("sni") or q.get("host") or host, "fingerprint": q.get("fp") or "chrome"}
        if q.get("alpn"):
            tls["alpn"] = q["alpn"].split(",")
        stream["tlsSettings"] = tls
    elif sec == "reality":
        if not q.get("pbk"):
            raise ValueError("для reality в ссылке нужен параметр pbk (публичный ключ)")
        stream["realitySettings"] = {"serverName": q.get("sni") or host, "fingerprint": q.get("fp") or "chrome",
                                     "publicKey": q["pbk"], "shortId": q.get("sid", ""), "spiderX": q.get("spx", "")}
    elif sec != "none":
        raise ValueError(f"неподдерживаемая защита транспорта security={sec}")
    path = q.get("path") or "/"
    if net == "ws":
        stream["wsSettings"] = {"path": path, "headers": {"Host": q.get("host") or q.get("sni") or host}}
    elif net == "grpc":
        stream["grpcSettings"] = {"serviceName": q.get("serviceName") or q.get("path") or ""}
    elif net == "xhttp":
        stream["xhttpSettings"] = {"path": path, "host": q.get("host") or "", "mode": q.get("mode") or "auto"}
    elif net == "httpupgrade":
        stream["httpupgradeSettings"] = {"path": path, "host": q.get("host") or ""}
    elif net == "http":
        stream["httpSettings"] = {"path": path, "host": [h for h in (q.get("host") or "").split(",") if h]}
    elif net == "kcp":
        stream["kcpSettings"] = {"header": {"type": q.get("headerType") or "none"}, "seed": q.get("seed", "")}
    elif net != "tcp":
        raise ValueError(f"неподдерживаемый транспорт type={net}")
    return stream


def check_server(host, port):
    if not host or not port or not 0 < port < 65536:
        raise ValueError("в ссылке нет адреса сервера или порта")


def parse_vmess_json(t):
    """vmess://<base64 от JSON>: самый распространённый вид ссылки vmess."""
    try:
        d = json.loads(b64decode(t[len("vmess://"):].split("#", 1)[0]).decode("utf-8", "replace"))
        host, port, uid = str(d.get("add") or ""), int(d.get("port") or 0), str(d.get("id") or "")
    except (ValueError, TypeError, AttributeError):
        raise ValueError("в ссылке vmess:// повреждены данные") from None
    check_server(host, port)
    if not re.match(UUID_RE, uid):
        raise ValueError("в ссылке vmess:// неверный UUID")
    tls = str(d.get("tls") or "").lower()
    q = {"type": d.get("net") or "tcp", "security": "tls" if tls == "tls" else "none", "sni": d.get("sni") or "",
         "host": d.get("host") or "", "path": d.get("path") or "", "fp": d.get("fp") or "", "alpn": d.get("alpn") or "",
         "serviceName": d.get("path") or "", "headerType": d.get("type") if d.get("type") != "none" else ""}
    try:
        alter = int(d.get("aid") or 0)
    except ValueError:
        alter = 0
    user = {"id": uid, "alterId": alter, "security": d.get("scy") or "auto"}
    out = {"protocol": "vmess", "tag": "proxy", "streamSettings": stream_settings(q, host, q["security"]),
           "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]}}
    return out, str(d.get("ps") or "")


def parse_shadowsocks(t):
    """ss://: SIP002 (метод:пароль в base64 или открытым текстом @хост:порт) и старый вид «всё в base64»."""
    body, _, frag = t[len("ss://"):].partition("#")
    body, _, query = body.partition("?")
    if "plugin=" in query:
        raise ValueError("ss:// с плагином (obfs, v2ray-plugin) не поддерживается")
    body = body.rstrip("/")
    try:
        if "@" in body:
            userinfo, _, hostport = body.rpartition("@")
            userinfo = urllib_parse.unquote(userinfo)
            if ":" not in userinfo:
                userinfo = b64decode(userinfo).decode("utf-8")
        else:
            userinfo, _, hostport = b64decode(urllib_parse.unquote(body)).decode("utf-8").rpartition("@")
        method, _, password = userinfo.partition(":")
        u = urllib_parse.urlsplit("//" + hostport)
        host, port = u.hostname, u.port
    except (ValueError, UnicodeDecodeError):
        raise ValueError("в ссылке ss:// повреждены данные") from None
    check_server(host, port)
    if not method or not password:
        raise ValueError("в ссылке ss:// нет метода шифрования или пароля")
    out = {"protocol": "shadowsocks", "tag": "proxy",
           "settings": {"servers": [{"address": host, "port": port, "method": method, "password": password}]}}
    return out, urllib_parse.unquote(frag)


def parse_share_link(url):
    """Ссылка vless://, vmess://, trojan://, ss:// -> (исходящее подключение Xray, имя из ссылки)."""
    t = url.strip()
    scheme = share_scheme(t)
    if not scheme:
        raise ValueError("ожидается ссылка vless://, vmess://, trojan:// или ss://")
    if scheme == "ss":
        return parse_shadowsocks(t)
    if scheme == "vmess" and "@" not in t.split("#", 1)[0]:
        return parse_vmess_json(t)
    u = urllib_parse.urlsplit(t)
    host = u.hostname
    try:
        port = u.port
    except ValueError:
        port = None
    check_server(host, port)
    q = dict(urllib_parse.parse_qsl(u.query))
    remark = urllib_parse.unquote(u.fragment)
    cred = urllib_parse.unquote(u.netloc.rpartition("@")[0])
    if scheme == "trojan":
        if not cred:
            raise ValueError("в ссылке trojan:// нет пароля")
        out = {"protocol": "trojan", "tag": "proxy", "streamSettings": stream_settings(q, host, "tls"),
               "settings": {"servers": [{"address": host, "port": port, "password": cred}]}}
        return out, remark
    if not re.match(UUID_RE, cred):
        raise ValueError(f"в ссылке {scheme}:// неверный UUID")
    if scheme == "vless":
        user = {"id": cred, "encryption": q.get("encryption") or "none"}
        if q.get("flow"):
            user["flow"] = q["flow"]
    else:   # vmess в виде vmess://uuid@хост:порт?параметры
        user = {"id": cred, "alterId": 0, "security": q.get("encryption") or q.get("scy") or "auto"}
    out = {"protocol": scheme, "tag": "proxy", "streamSettings": stream_settings(q, host),
           "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]}}
    return out, remark


def link_server(out):
    """«хост:порт» исходящего подключения Xray."""
    s = out["settings"]
    node = (s.get("vnext") or s.get("servers"))[0]
    return f"{node['address']}:{node['port']}"


# Какие исходящие подключения считаются «через сервер» (а не прямым выходом, блокировкой и т. п.)
PROXY_PROTOCOLS = ("vless", "vmess", "trojan", "shadowsocks", "socks", "http", "wireguard", "hysteria", "hysteria2",
                   "tuic", "shadowtls", "ssh")


# Адреса, которые подписки подставляют вместо серверов, когда приложение им «не подходит»
STUB_HOSTS = ("0.0.0.0", "127.0.0.1", "::", "::1", "localhost")


def is_stub_link(link):
    """Заглушка провайдера вместо сервера: адрес 0.0.0.0/localhost или порт 0–1 («Используйте Happ»…)."""
    try:
        out, _remark = parse_share_link(link)
        node = (out["settings"].get("vnext") or out["settings"].get("servers"))[0]
    except (ValueError, KeyError, IndexError, TypeError):
        return False
    return str(node["address"]).lower() in STUB_HOSTS or int(node["port"]) <= 1


def stub_remark(link):
    """Что провайдер написал в имени заглушки (например «Приложение не поддерживается»)."""
    try:
        return parse_share_link(link)[1]
    except ValueError:
        return ""


def json_server(cfg):
    """(хост, порт) первого исходящего подключения конфигурации Xray или sing-box; ('', 0), если не нашли."""
    for o in cfg.get("outbounds") or []:
        if not isinstance(o, dict):
            continue
        s = o.get("settings") or {}
        node = ((s.get("vnext") or s.get("servers") or [None])[0]) or {}
        host, port = node.get("address") or o.get("server"), node.get("port") or o.get("server_port")
        if host and port:
            try:
                return str(host), int(port)
            except (TypeError, ValueError):
                continue
    return "", 0


def split_json_configs(text):
    """Подписка-массив готовых конфигураций Xray/sing-box ([{"remarks": …, "outbounds": […]}, …]) -> [(имя, JSON)]."""
    t = (text or "").strip()
    if not t.startswith("["):
        return []
    try:
        data = json.loads(t)
    except ValueError:
        return []
    out = []
    for item in data if isinstance(data, list) else []:
        if isinstance(item, dict) and isinstance(item.get("outbounds"), list):
            out.append((str(item.get("remarks") or item.get("remark") or item.get("name") or ""),
                        json.dumps(item, ensure_ascii=False)))
    return out


def describe_response(text):
    """Что за ответ пришёл вместо подписки (без самих данных: в них могут быть секреты)."""
    t = (text or "").strip()
    if not t:
        return "пустой ответ"
    if t.lstrip().lower().startswith(("<!doctype", "<html", "<head", "<body")):
        return "веб-страница (HTML): адрес ведёт на страницу, а не на подписку"
    if t.startswith(("{", "[")):
        try:
            data = json.loads(t)
            return f"JSON ({'массив из ' + str(len(data)) + ' элементов' if isinstance(data, list) else 'объект'}), "\
                   "но без конфигураций Xray или sing-box (outbounds)"
        except ValueError:
            return "повреждённый JSON"
    if re.search(r"^\s*(proxies|proxy-groups|port|mixed-port)\s*:", t, re.M):
        return "Clash-подписка (YAML): такой формат не поддерживается"
    return f"текст из {len(t)} знаков без ссылок vless://, vmess://, trojan://, ss://"


def vpn_info(kind, text):
    """Сведения для списка: {title, host, port, udp}. ValueError при плохой конфигурации (как vpn_validate)."""
    if kind == "wireguard":
        host, _, port = wg_validate(text).rpartition(":")
        return {"title": "", "host": host.strip("[]"), "port": int(port) if port.isdigit() else 0, "udp": True}
    if share_scheme(text):
        out, remark = parse_share_link(text)
        node = (out["settings"].get("vnext") or out["settings"].get("servers"))[0]
        return {"title": remark, "host": str(node["address"]), "port": int(node["port"]), "udp": False}
    vpn_validate(kind, text)
    cfg = json.loads(text)
    host, port = json_server(cfg)
    return {"title": str(cfg.get("remarks") or cfg.get("remark") or "") if isinstance(cfg, dict) else "",
            "host": host, "port": port, "udp": False}


def first_proxy_outbound(cfg):
    """Первый прокси-выход конфигурации Xray или sing-box (словарь) или None."""
    for o in cfg.get("outbounds") or []:
        if isinstance(o, dict) and (o.get("protocol") or o.get("type")) in PROXY_PROTOCOLS:
            return o
    return None


def transport_report(kind, text):
    """Безопасность и «отпечаток» самого VPN-транспорта по конфигурации (без сети): [(уровень, текст)].

    Уровни: ok, warn, bad. Это не то, что видит Anthropic (он видит выходной адрес), а то, что видит ваш провайдер и
    тот, кто просматривает трафик до VPN-сервера."""
    out = []
    if kind == "wireguard":
        out.append(("ok", "WireGuard: шифрование ChaCha20-Poly1305, ключи из вашей конфигурации"))
        out.append(("warn", "WireGuard работает по UDP и легко опознаётся по рукопожатию: многие провайдеры и "
                            "сети его блокируют или замедляют; для таких сетей надёжнее VLESS с Reality"))
        return out
    try:
        if share_scheme(text):
            cfg = {"outbounds": [parse_share_link(text)[0]]}
        else:
            cfg = json.loads(text)
    except ValueError:
        return [("bad", "конфигурация не читается")]
    o = first_proxy_outbound(cfg)
    if o is None:
        return [("bad", "нет прокси-выхода: трафик пошёл бы напрямую")]
    def d(x):      # поле, которое должно быть словарём (в чужих конфигурациях бывает строкой, списком, null)
        return x if isinstance(x, dict) else {}

    def t(x):
        return x if isinstance(x, str) else ""
    proto = t(o.get("protocol") or o.get("type"))
    st, tls = d(o.get("streamSettings")), d(o.get("tls"))
    net = t(st.get("network")) or t(d(o.get("transport")).get("type")) or "tcp"
    sec = (t(st.get("security")) or ("reality" if d(tls.get("reality")).get("enabled") else
                                     "tls" if tls.get("enabled") else "none")).lower()
    sec_cfg = d(st.get("realitySettings")) or d(st.get("tlsSettings"))
    fp = t(sec_cfg.get("fingerprint")) or t(d(tls.get("utls")).get("fingerprint"))
    insecure = bool(d(st.get("tlsSettings")).get("allowInsecure") or tls.get("insecure"))
    sni = t(sec_cfg.get("serverName")) or t(tls.get("server_name"))
    out.append(("ok", f"протокол {proto}, транспорт {net}, защита канала: {sec}" + (f", SNI {sni}" if sni else "")))
    if sec == "none" and proto in ("vless", "trojan"):
        out.append(("bad", f"{proto} без TLS/Reality: трафик до VPN-сервера идёт открыто, его видно провайдеру и "
                           "каждому узлу по пути"))
    elif sec == "none" and proto in ("vmess", "shadowsocks"):
        out.append(("warn", f"{proto} без TLS: содержимое шифруется самим протоколом, но по виду трафика VPN легко "
                            "опознать и заблокировать"))
    elif sec == "reality":
        out.append(("ok", "Reality: рукопожатие выглядит как обычный HTTPS к чужому сайту, сертификаты подделывать "
                          "не нужно"))
    if insecure:
        out.append(("bad", "allowInsecure: сертификат сервера не проверяется, VPN-сервер можно подменить"))
    if sec in ("tls", "reality"):
        if not fp:
            out.append(("warn", "не задан отпечаток TLS (fp): рукопожатие клиента отличается от браузера и легче "
                                "опознаётся; задайте fp=chrome"))
        elif fp.lower() in ("random", "randomized", "randomizednoalpn"):
            out.append(("warn", f"отпечаток TLS {fp}: меняется от соединения к соединению; стабильный chrome "
                                "обычно незаметнее"))
        else:
            out.append(("ok", f"отпечаток TLS (uTLS): {fp}"))
    return out


def split_links(text):
    """Ссылки на серверы из текста подписки -> (поддерживаемые ссылки, схемы остальных ссылок).

    Подписка — это список ссылок по одной в строке; провайдеры часто отдают его целиком в base64."""
    def lines(t):
        return [ln.strip() for ln in t.splitlines() if ln.strip()]
    found = lines(text)
    if not any(re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", ln) for ln in found):
        try:
            found = lines(b64decode(text).decode("utf-8", "replace"))
        except ValueError:
            found = []
    ours, other = [], []
    for ln in found:
        if share_scheme(ln):
            ours.append(ln)
        else:
            m = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*)://", ln)
            if m:
                other.append(m.group(1).lower())
    return ours, other


def xray_runtime(text, port, user, password):
    """Конфигурация Xray: исходные исходящие подключения + наш SOCKS5 на loopback вместо всех входящих."""
    t = text.strip()
    if share_scheme(t):
        cfg = {"outbounds": [parse_share_link(t)[0]]}
    else:
        cfg = json.loads(t)
        for k in ("api", "stats", "metrics", "observatory", "burstObservatory"):   # чужие управляющие порты не нужны
            cfg.pop(k, None)
        # Маршрутизация подписки («российские сайты напрямую», блокировка рекламы) вывела бы часть трафика мимо VPN:
        # убираем её, и всё идёт через первый прокси-выход (его ставим первым: по умолчанию берётся первый)
        cfg.pop("routing", None)
        outs = [o for o in cfg.get("outbounds") or [] if isinstance(o, dict)]
        first = next((o for o in outs if o.get("protocol") in PROXY_PROTOCOLS), None)
        if first is None:
            raise ValueError("в конфигурации нет прокси-выхода (vless, vmess, trojan, shadowsocks…): только прямой выход")
        cfg["outbounds"] = [first] + [o for o in outs if o is not first]
    cfg["log"] = {"loglevel": "warning"}
    cfg["inbounds"] = [{"tag": "envbox-in", "listen": "127.0.0.1", "port": port, "protocol": "socks",
                        "settings": {"auth": "password", "udp": False, "accounts": [{"user": user, "pass": password}]}}]
    return json.dumps(cfg, ensure_ascii=False, indent=1)


def singbox_runtime(text, port, user, password):
    """Конфигурация sing-box: исходные исходящие подключения + наш SOCKS5 на loopback вместо всех входящих."""
    cfg = json.loads(text)
    for k in ("experimental", "ntp"):   # clash_api и подобное открывают порты
        cfg.pop(k, None)
    # правила маршрутизации подписки вывели бы часть трафика мимо VPN: всё идёт через первый прокси-выход
    first = next((o for o in cfg.get("outbounds") or [] if isinstance(o, dict) and o.get("type") in PROXY_PROTOCOLS),
                 None)
    if first is None:
        raise ValueError("в конфигурации нет прокси-выхода (vless, vmess, trojan, shadowsocks…): только прямой выход")
    cfg["route"] = {"final": first.setdefault("tag", "envbox-out")}
    cfg["log"] = {"level": "warn"}
    cfg["inbounds"] = [{"type": "socks", "tag": "envbox-in", "listen": "127.0.0.1", "listen_port": port,
                        "users": [{"username": user, "password": password}]}]
    return json.dumps(cfg, ensure_ascii=False, indent=1)


def vpn_validate(kind, text):
    """Проверка конфигурации при импорте; возвращает короткое описание (сервер). ValueError с понятным текстом."""
    if kind == "wireguard":
        return wg_validate(text)
    if kind == "xray" and share_scheme(text):
        out, remark = parse_share_link(text)
        return f"{remark} ({link_server(out)})" if remark else link_server(out)
    try:
        cfg = json.loads(text)
    except ValueError:
        raise ValueError("JSON повреждён") from None
    outs = cfg.get("outbounds") if isinstance(cfg, dict) else None
    if not isinstance(outs, list) or not outs:
        raise ValueError("в конфигурации нет outbounds")
    return f"исходящих подключений: {len(outs)}"


def build_runtime(kind, text, port, user, password):
    """(имя файла, текст конфигурации, аргументы запуска до пути конфигурации) для клиента вида kind."""
    if kind == "wireguard":
        return "wireproxy.conf", wg_runtime(text, port, user, password), ["-c"]
    if kind == "xray":
        return "config.json", xray_runtime(text, port, user, password), ["run", "-c"]
    if kind == "singbox":
        return "config.json", singbox_runtime(text, port, user, password), ["run", "-c"]
    raise ValueError(f"неизвестный вид VPN: {kind}")


def find_binary(kind):
    """Путь к программе клиента или None (сначала переменная окружения, потом PATH)."""
    import shutil
    own = os.environ.get(VPN_ENV[kind], "")
    if own:
        return own if os.access(own, os.X_OK) else None
    return shutil.which(VPN_BINARIES[kind])


def die_with_parent():
    """Для preexec_fn: клиент получает SIGTERM, если шлюз погиб (иначе VPN остался бы подключённым навсегда)."""
    try:
        import ctypes
        ctypes.CDLL(None).prctl(1, 15)     # PR_SET_PDEATHSIG, SIGTERM
    except (OSError, AttributeError):
        pass


def free_port():
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


class VpnClient:
    """Один запущенный VPN-клиент: процесс, временная конфигурация (0700) и вышестоящий SOCKS5 к нему."""

    def __init__(self, kind, source_path, log_path):
        self.kind, self.source_path, self.log_path = kind, source_path, log_path
        self.proc = None
        self.dir = None
        self.upstream = None

    async def start(self):
        """Запустить клиент и дождаться порта. Ошибки — OSError с текстом для журнала."""
        import secrets
        import subprocess
        import tempfile
        binary = find_binary(self.kind)
        if binary is None:
            raise OSError(f"не найдена программа {VPN_BINARIES[self.kind]} ({VPN_HINTS[self.kind]})")
        try:
            with open(self.source_path, encoding="utf-8") as f:
                text = f.read()
            port, user, password = free_port(), secrets.token_hex(8), secrets.token_hex(16)
            fname, cfg, args = build_runtime(self.kind, text, port, user, password)
        except (OSError, ValueError) as e:
            raise OSError(f"конфигурация VPN не читается: {e}") from None
        self.dir = tempfile.mkdtemp(prefix="envbox-vpn-")
        path = os.path.join(self.dir, fname)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(cfg)
        log = open(self.log_path, "ab")
        try:
            self.proc = subprocess.Popen([binary, *args, path], stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                         start_new_session=True, cwd=self.dir,
                                         preexec_fn=die_with_parent)
        finally:
            log.close()
        deadline = time.monotonic() + START_TIMEOUT
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise OSError(f"VPN-клиент завершился с кодом {self.proc.returncode} (см. {self.log_path})")
            try:
                _r, w = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", port), 1.0)
                w.close()
                break
            except (OSError, asyncio.TimeoutError):
                await asyncio.sleep(0.2)
        else:
            raise OSError(f"VPN-клиент не открыл порт за {int(START_TIMEOUT)} с (см. {self.log_path})")
        self.upstream = Upstream(f"socks5://127.0.0.1:{port}", f"{user}:{password}")

    def stop(self):
        """Остановить клиент и стереть временную конфигурацию (в ней ключи)."""
        import shutil
        if self.proc is not None and self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGTERM)
            except OSError:
                pass
            try:
                self.proc.wait(timeout=3)
            except Exception:  # noqa: BLE001
                try:
                    os.killpg(self.proc.pid, signal.SIGKILL)
                except OSError:
                    pass
        if self.dir:
            shutil.rmtree(self.dir, ignore_errors=True)
            self.dir = None
