"""Сетевой шлюз: VPN-клиенты как локальные SOCKS-прокси.

WireGuard запускается через wireproxy (WireGuard в пространстве пользователя), VLESS и JSON-конфигурации — через
Xray или sing-box. Все они работают без root: клиент слушает 127.0.0.1:<порт> с одноразовым логином и паролем
(чужие программы на компьютере не смогут пользоваться вашим VPN), а шлюз подключается к нему как к обычному
вышестоящему SOCKS5-прокси. Среда по-прежнему выходит только через прокси envbox."""

import os
import time

from ..lazy import asyncio, json, re, signal, socket, urllib_parse
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


UUID_RE = r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$"


def detect_kind(text):
    """Вид VPN-конфигурации по тексту: wireguard, xray или singbox. Непонятный формат — ValueError."""
    t = (text or "").strip()
    if not t:
        raise ValueError("конфигурация пуста")
    if t.lower().startswith("vless://"):
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
                     "vless://… или JSON Xray / sing-box")


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


def parse_vless(url):
    """Ссылка vless://uuid@хост:порт?параметры#имя -> исходящее подключение Xray."""
    u = urllib_parse.urlsplit(url.strip())
    if u.scheme.lower() != "vless":
        raise ValueError("ожидается ссылка vless://")
    uid, host = urllib_parse.unquote(u.username or ""), u.hostname
    try:
        port = u.port
    except ValueError:
        port = None
    if not re.match(UUID_RE, uid):
        raise ValueError("в ссылке vless:// неверный UUID")
    if not host or not port or not 0 < port < 65536:
        raise ValueError("в ссылке vless:// нет адреса сервера или порта")
    q = {k: v for k, v in urllib_parse.parse_qsl(u.query)}
    net = (q.get("type") or "tcp").lower()
    sec = (q.get("security") or "none").lower()
    stream = {"network": "xhttp" if net == "splithttp" else net, "security": sec}
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
    elif net in ("xhttp", "splithttp"):
        stream["xhttpSettings"] = {"path": path, "host": q.get("host") or "", "mode": q.get("mode") or "auto"}
    elif net == "httpupgrade":
        stream["httpupgradeSettings"] = {"path": path, "host": q.get("host") or ""}
    elif net == "tcp":
        pass
    else:
        raise ValueError(f"неподдерживаемый транспорт type={net}")
    user = {"id": uid, "encryption": q.get("encryption") or "none"}
    if q.get("flow"):
        user["flow"] = q["flow"]
    return {"protocol": "vless", "tag": "proxy", "streamSettings": stream,
            "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]}}


def xray_runtime(text, port, user, password):
    """Конфигурация Xray: исходные исходящие подключения + наш SOCKS5 на loopback вместо всех входящих."""
    t = text.strip()
    if t.lower().startswith("vless://"):
        cfg = {"outbounds": [parse_vless(t)]}
    else:
        cfg = json.loads(t)
        for k in ("api", "stats", "metrics"):   # управляющие порты чужого конфига нам не нужны
            cfg.pop(k, None)
    cfg["log"] = {"loglevel": "warning"}
    cfg["inbounds"] = [{"tag": "envbox-in", "listen": "127.0.0.1", "port": port, "protocol": "socks",
                        "settings": {"auth": "password", "udp": False, "accounts": [{"user": user, "pass": password}]}}]
    return json.dumps(cfg, ensure_ascii=False, indent=1)


def singbox_runtime(text, port, user, password):
    """Конфигурация sing-box: исходные исходящие подключения + наш SOCKS5 на loopback вместо всех входящих."""
    cfg = json.loads(text)
    for k in ("experimental", "ntp"):   # clash_api и подобное открывают порты
        cfg.pop(k, None)
    cfg["log"] = {"level": "warn"}
    cfg["inbounds"] = [{"type": "socks", "tag": "envbox-in", "listen": "127.0.0.1", "listen_port": port,
                        "users": [{"username": user, "password": password}]}]
    return json.dumps(cfg, ensure_ascii=False, indent=1)


def vpn_validate(kind, text):
    """Проверка конфигурации при импорте; возвращает короткое описание (сервер). ValueError с понятным текстом."""
    if kind == "wireguard":
        return wg_validate(text)
    if kind == "xray" and text.strip().lower().startswith("vless://"):
        out = parse_vless(text)
        v = out["settings"]["vnext"][0]
        return f"{v['address']}:{v['port']}"
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
