#!/usr/bin/env python3
# ВНИМАНИЕ: файл собран build.py из src/envbox/. Правьте исходники, а не его.
"""envbox — изолированные среды на bubblewrap: всё в одном файле.

  python3 envbox.py                  графический интерфейс (при первом запуске установка)
  python3 envbox.py install [--force]  установить: ~/.local/share/envbox, команда ~/.local/bin/envbox
                                     (--force: заменить и более новую установленную версию)
  python3 envbox.py run ARGS...      консольный запуск: envbox -n имя -w проект -- команда
  python3 envbox.py build-appimage   собрать envbox-<архитектура>.AppImage
  python3 envbox.py root [ПУТЬ|--reset] [--move]   показать или сменить каталог данных (по умолчанию ~/.envbox)
  python3 envbox.py global [list|create ИМЯ|delete ИМЯ]   глобальные папки в <каталог данных>/_global
  python3 envbox.py --version        версия этого файла (то же показывает заголовок окна GUI)
  python3 envbox.py --install-desktop  ярлык и значок в меню приложений
  python3 envbox.py proxy|wrap|probe|report  внутренние команды сетевого шлюза

Что внутри этого файла:
  1. консольная утилита envbox (bash, извлекается в ~/.local/share/envbox/envbox.sh);
  2. сетевой шлюз: журналирующий прокси, мосты unix-сокет <-> localhost, проверка прокси;
  3. ядро: профили, запуск терминала, секреты в keyring, сеансы, описание среды;
  4. графический интерфейс GTK 4 (нужен системный python-gobject и gtk4);
  5. сборка AppImage.

Нужны: bubblewrap, системный /usr/bin/python3; для GUI — GTK 4 (Arch: sudo pacman -S
python-gobject gtk4 vte4; vte4 — встроенный терминал, без него терминал открывается во внешнем окне),
для секретов — libsecret (secret-tool), для сред-браузеров — Chrome/Chromium.

Горячие клавиши GUI: Ctrl+S сохранить, Ctrl+N новая среда, Ctrl+T терминал в среде,
Ctrl+R запустить команду/браузер, F5 обновить.
"""
import itertools
import os
import shlex
import stat
import struct
import sys
import time


# ---- version.py: Версия envbox (строка читается регулярным выражением при установке — не менять формат).

ENVBOX_VERSION = "2026.11.02.2"


# ---- lazy.py: Ленивые модули стандартной библиотеки: настоящий import происходит при первом обращении к атрибуту.

class _LazyModule:
    def __init__(self, name):
        self._name = name
        self._real = None

    def __getattr__(self, attr):
        real = self.__dict__["_real"]
        if real is None:
            import importlib
            real = self.__dict__["_real"] = importlib.import_module(self.__dict__["_name"])
        return getattr(real, attr)


asyncio = _LazyModule("asyncio")
base64 = _LazyModule("base64")
datetime = _LazyModule("datetime")
ipaddress = _LazyModule("ipaddress")
json = _LazyModule("json")
re = _LazyModule("re")
signal = _LazyModule("signal")
socket = _LazyModule("socket")
threading = _LazyModule("threading")
urllib_parse = _LazyModule("urllib.parse")


# ---- net/common.py: Сетевой шлюз: общие константы и мелкие помощники (время, host:port, публичные адреса, имена хостов).

HEAD_LIMIT = 64 * 1024


HEAD_TIMEOUT = 30


CONNECT_TIMEOUT = 15


# Соединение, по которому нет ни байта в обе стороны дольше этого, прокси закрывает сам: клиент увидит обрыв и повторит
# запрос, а не будет ждать мёртвый туннель до своего большого тайм-аута (после сна, смены сети, падения VPN).
# Живые потоки (SSE, WebSocket с пингами) байты передают, поэтому их это не затрагивает.
IDLE_TIMEOUT = 180


# Если туннель через вышестоящий прокси не готов за это время, рядом запускается второй такой же: побеждает первый
# готовый. Потерянный пакет в начале соединения иначе стоит 1, 3, 7 секунд ожидания.
HEDGE_DELAY = 2.0


# Сколько вторых туннелей может строиться одновременно. Когда вышестоящий прокси перегружен или отвечает медленно
# для всех, повтор каждого соединения удвоил бы нагрузку на него и сделал бы хуже.
MAX_HEDGES = 4


# Сколько туннелей к вышестоящему прокси может устанавливаться одновременно. Приложения (Claude Desktop) открывают
# десятки соединений за секунду; платные прокси такой всплеск часто принимают, но не обслуживают (соединения висят
# до тайм-аута клиента). Лишние ждут своей очереди: установка занимает около полусекунды, всплеск рассасывается за секунды.
MAX_SETUPS = 8


BUF = 64 * 1024


# Диапазон 198.18.0.0/15 зарезервирован для стендов и в обычных сетях не маршрутизируется. Его отдают
# DNS-серверы VPN и прокси-клиентов в режиме fake-ip (Clash, sing-box, Hiddify…): сам клиент подменяет
# такой адрес настоящим. Если считать его «частным», при таком VPN не откроется ни один сайт.
FAKE_IP_PREFIX = 0xC6120000 >> 17   # 198.18.0.0/15: старшие 15 бит адреса


def now():
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


def split_hostport(s, default_port):
    if s.startswith("["):
        end = s.find("]")
        if end < 0:
            raise ValueError(s)
        host, rest = s[1:end], s[end + 1:]
        if rest.startswith(":"):
            port = int(rest[1:])
        elif rest == "":
            port = default_port
        else:
            raise ValueError(s)
    elif s.count(":") == 1:
        host, p = s.split(":")
        port = int(p)
    elif ":" in s:
        raise ValueError(s)
    else:
        host, port = s, default_port
    if not host or not 0 < port < 65536:
        raise ValueError(s)
    return host, port


def is_public(ip_str):
    ip = ipaddress.ip_address(ip_str.split("%", 1)[0])
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.version == 4 and int(ip) >> 17 == FAKE_IP_PREFIX:
        return True
    return ip.is_global and not ip.is_multicast


_HOST_BAD = frozenset(" \t/\\@?#<>\"'`|^{}%;,*")


def canon_host(host):
    """Каноничное ASCII-имя хоста или ValueError.

    Имя приводится к той форме, в которой оно уйдёт дальше (IDNA, нижний регистр), и только потом проверяется:
    иначе «1²7.0.0.1» не распознаётся как IP, но после IDNA-кодирования превращается в 127.0.0.1.
    Управляющие символы и разделители запрещены (из имени нельзя собрать лишние строки запроса)."""
    if not host or len(host) > 253:
        raise ValueError("недопустимое имя хоста")
    if any(ord(c) < 33 or ord(c) == 127 or c in _HOST_BAD for c in host):
        raise ValueError("недопустимые символы в имени хоста")
    if ":" in host:    # IPv6-литерал
        try:
            return str(ipaddress.ip_address(host))
        except ValueError:
            raise ValueError("недопустимый IPv6-адрес") from None
    try:
        name = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ValueError("недопустимое имя хоста") from None
    if not name or len(name) > 253 or any(not 0 < len(label) < 64 for label in name.rstrip(".").split(".")):
        raise ValueError("недопустимое имя хоста")
    return name


def tune_socket(sock):
    """Живые соединения не должны зависать насовсем: после сна компьютера, смены сети или перезапуска VPN
    мёртвый сокет обнаруживается за пару минут, а не остаётся «открытым» навсегда. Мелкие записи не ждут."""
    if sock is None or sock.family not in (socket.AF_INET, socket.AF_INET6):
        return
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 15)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 4)
    except (OSError, AttributeError):
        pass


# ---- net/upstream.py: Сетевой шлюз: вышестоящий прокси (http / socks5 / socks5h).

class UpstreamError(OSError):
    pass


SOCKS_ERRORS = {1: "общий сбой", 2: "запрещено правилами прокси", 3: "сеть недоступна",
                4: "хост недоступен", 5: "соединение отклонено", 6: "TTL истёк",
                7: "команда не поддерживается", 8: "тип адреса не поддерживается"}


class Upstream:
    """Один вышестоящий прокси: http://host:port, socks5://host:port или socks5h://host:port."""

    def __init__(self, url, auth=None):
        u = urllib_parse.urlsplit(url)
        scheme = u.scheme.lower()
        if scheme not in ("http", "socks5", "socks5h") or not u.hostname:
            raise ValueError("поддерживаются http://хост:порт, socks5://хост:порт, socks5h://хост:порт")
        if u.username or u.password:
            raise ValueError("логин и пароль нельзя указывать в URL (он виден в списке процессов); "
                             "используйте переменную окружения ENVBOX_UPSTREAM_AUTH=логин:пароль")
        if u.path not in ("", "/") or u.query or u.fragment:
            raise ValueError("URL прокси не должен содержать путь")
        try:
            port = u.port
        except ValueError:
            raise ValueError("неверный порт прокси") from None
        self.kind = "http" if scheme == "http" else "socks5"
        self.host = u.hostname
        self.port = port or (8080 if self.kind == "http" else 1080)
        if auth and ":" not in auth:
            raise ValueError("ENVBOX_UPSTREAM_AUTH должен иметь вид логин:пароль")
        self.auth = auth or None
        shown = f"[{self.host}]" if ":" in self.host else self.host
        self.label = f"{scheme}://{shown}:{self.port}"

    def basic(self):
        return "Basic " + base64.b64encode(self.auth.encode()).decode()

    async def open(self):
        r, w = await asyncio.wait_for(asyncio.open_connection(self.host, self.port), CONNECT_TIMEOUT)
        tune_socket(w.get_extra_info("socket"))
        return r, w

    async def tunnel(self, host, port):
        """TCP-туннель до host:port через прокси; имя разрешает сам прокси."""
        r, w = await self.open()
        try:
            await asyncio.wait_for(self._handshake(r, w, host, port), CONNECT_TIMEOUT)
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            w.close()
            raise UpstreamError("прокси закрыл соединение во время подключения") from None
        except BaseException:
            w.close()
            raise
        return r, w

    async def _handshake(self, r, w, host, port):
        if self.kind == "http":
            hp = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
            req = f"CONNECT {hp} HTTP/1.1\r\nHost: {hp}\r\n"
            if self.auth:
                req += f"Proxy-Authorization: {self.basic()}\r\n"
            w.write((req + "\r\n").encode("latin-1"))
            await w.drain()
            head = await r.readuntil(b"\r\n\r\n")
            status = head.split(b"\r\n", 1)[0].decode("latin-1")
            bits = status.split(" ", 2)
            if len(bits) < 2 or not bits[1].startswith("2"):
                raise UpstreamError(f"прокси ответил: {status[:80]}")
            return
        w.write(b"\x05\x02\x00\x02" if self.auth else b"\x05\x01\x00")
        await w.drain()
        resp = await r.readexactly(2)
        if resp[0] != 5:
            raise UpstreamError("это не SOCKS5-прокси")
        if resp[1] == 2:
            if not self.auth:
                raise UpstreamError("прокси требует логин и пароль")
            user, _, pw = self.auth.partition(":")
            ub, pb = user.encode(), pw.encode()
            if len(ub) > 255 or len(pb) > 255:
                raise UpstreamError("логин или пароль длиннее 255 байт")
            w.write(b"\x01" + bytes([len(ub)]) + ub + bytes([len(pb)]) + pb)
            await w.drain()
            if (await r.readexactly(2))[1] != 0:
                raise UpstreamError("прокси отклонил логин или пароль")
        elif resp[1] != 0:
            raise UpstreamError("прокси не поддерживает нужный способ входа")
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ip = None
        if ip is None:
            try:
                hb = host.encode("idna")
            except UnicodeError:
                raise UpstreamError("недопустимое имя хоста") from None
            if not 0 < len(hb) < 256:
                raise UpstreamError("недопустимое имя хоста")
            addr = b"\x03" + bytes([len(hb)]) + hb
        else:
            addr = (b"\x01" if ip.version == 4 else b"\x04") + ip.packed
        w.write(b"\x05\x01\x00" + addr + struct.pack(">H", port))
        await w.drain()
        head = await r.readexactly(4)
        if head[1] != 0:
            raise UpstreamError("SOCKS5: " + SOCKS_ERRORS.get(head[1], f"код {head[1]}"))
        extra = {1: 4, 4: 16}.get(head[3])
        if head[3] == 3:
            extra = (await r.readexactly(1))[0]
        if extra is None:
            raise UpstreamError("SOCKS5: неизвестный тип адреса в ответе")
        await r.readexactly(extra + 2)


# ---- net/bridge.py: Сетевой шлюз: мосты unix-сокет <-> localhost, канал ссылок (команды wrap, probe).

def pump(client, dial):
    """Двунаправленная пересылка между client и сокетом, созданным dial()."""
    try:
        peer = dial()
    except OSError:
        client.close()
        return
    tune_socket(client)
    tune_socket(peer)

    def one(src, dst):
        try:
            while True:
                d = src.recv(BUF)
                if not d:
                    break
                dst.sendall(d)
        except OSError:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    t = threading.Thread(target=one, args=(peer, client), daemon=True)
    t.start()
    one(client, peer)
    t.join()
    client.close()
    peer.close()


def dial_unix(path):
    def dial():
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.connect(path)
        except OSError:
            s.close()
            raise
        return s
    return dial


def dial_tcp(port):
    def dial():
        sock = socket.create_connection(("127.0.0.1", port), timeout=10)
        sock.settimeout(None)  # таймаут только на подключение: пауза в разговоре не должна рвать соединение
        return sock
    return dial


def parse_port(text, what):
    try:
        port = int(text)
    except ValueError:
        port = 0
    if not 0 < port < 65536:
        sys.exit(f"envbox-net wrap: неверный порт в {what}: {text!r}")
    return port


_LOOPBACK_HOSTS = ("localhost", "127.0.0.1", "::1")


def inbox_handle(data, handler, schemes, callback, recent):
    """Одна ссылка из inbox (выполняется ВНУТРИ песочницы). Возвращает текст ответа для envbox."""
    try:
        text = data.decode("utf-8", "replace").strip().splitlines()[0]
    except IndexError:
        return "пустой запрос"
    if not text or len(text) > 2048 or any(ord(c) < 32 or ord(c) == 127 or c.isspace() for c in text):
        return "ссылка отклонена: пробелы, управляющие символы или слишком длинный адрес"
    m = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*):", text)
    scheme = m.group(1).lower() if m else ""
    if scheme not in ("http", "https") and scheme not in [x.lower() for x in schemes]:
        return f"ссылка отклонена: схема «{scheme or '?'}» не разрешена для этой среды"
    now_t = time.monotonic()
    recent[:] = [t for t in recent if now_t - t < 10]
    if len(recent) >= 8:
        return "слишком много ссылок подряд: подождите несколько секунд"
    recent.append(now_t)
    import urllib.parse
    u = urllib.parse.urlsplit(text)
    if callback and scheme == "http" and (u.hostname or "").lower() in _LOOPBACK_HOSTS:
        import http.client
        try:
            conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=20)  # без прокси и без переходов
            conn.request("GET", (u.path or "/") + (("?" + u.query) if u.query else ""),
                         headers={"User-Agent": "envbox-inbox", "Host": u.netloc})
            resp = conn.getresponse()
            resp.read(65536)
            conn.close()
            return f"запрос выполнен внутри среды: HTTP {resp.status}"
        except (OSError, http.client.HTTPException) as e:
            return f"запрос внутри среды не удался: {e}"
    if not handler:
        return "ссылка не принята: в этой среде нет приложения для её открытия"
    import subprocess
    try:
        subprocess.Popen(shlex.split(handler) + [text], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True)
    except (OSError, ValueError) as e:
        return f"не удалось запустить «{handler}»: {e}"
    return "ссылка передана приложению"


def inbox_loop(directory, handler, schemes, callback):
    """Внутри песочницы: забирает ссылки, которые пользователь отправил из envbox, и отвечает файлом .result."""
    recent = []
    while True:
        try:
            names = sorted(os.listdir(directory))
        except OSError:
            time.sleep(1)
            continue
        for fname in names:
            if fname.endswith((".tmp", ".result")):
                continue
            path = os.path.join(directory, fname)
            try:
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                try:
                    if not stat.S_ISREG(os.fstat(fd).st_mode):
                        raise OSError("не обычный файл")
                    data = os.read(fd, 4096)
                finally:
                    os.close(fd)
            except OSError:
                try:
                    os.unlink(path)
                except OSError:
                    pass
                continue
            try:
                os.unlink(path)
            except OSError:
                pass
            answer = inbox_handle(data, handler, schemes, callback, recent)
            try:
                with open(path + ".result", "w", encoding="utf-8") as f:
                    f.write(answer[:300])
            except OSError:
                pass
        time.sleep(0.4)


def cmd_wrap(a):
    cmd = a.cmd[1:] if a.cmd and a.cmd[0] == "--" else a.cmd
    if not cmd:
        sys.exit("envbox-net wrap: не указана команда")
    listeners = []  # (слушающий сокет, функция соединения)
    for spec in a.map:
        port_s, _, path = spec.partition(":")
        port = parse_port(port_s, "--map")
        ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            ls.bind(("127.0.0.1", port))
        except OSError as e:
            sys.exit(f"envbox-net wrap: порт {port} внутри среды занят: {e}")
        ls.listen(512)  # слушаем до запуска команды: гонки при первом соединении нет
        listeners.append((ls, dial_unix(path)))
    for spec in a.serve:
        path, _, port_s = spec.rpartition(":")
        port = parse_port(port_s, "--serve")
        if os.path.lexists(path):
            os.unlink(path)
        ls = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old = os.umask(0o177)
        try:
            ls.bind(path)
        finally:
            os.umask(old)
        ls.listen(512)
        listeners.append((ls, dial_tcp(port)))

    if listeners or a.inbox:
        parent = os.getpid()
        if os.fork() == 0:
            try:
                # завершиться вместе с командой, даже если pid namespace не используется
                try:
                    import ctypes
                    ctypes.CDLL(None, use_errno=True).prctl(1, signal.SIGTERM)  # PR_SET_PDEATHSIG
                except (OSError, AttributeError):
                    pass
                if os.getppid() != parent:
                    os._exit(0)
                devnull = os.open(os.devnull, os.O_RDWR)
                os.dup2(devnull, 0)
                os.dup2(devnull, 1)

                def accept_loop(ls, dial):
                    while True:
                        try:
                            c, _ = ls.accept()
                        except OSError:
                            return
                        threading.Thread(target=pump, args=(c, dial), daemon=True).start()

                if a.inbox:
                    threading.Thread(target=inbox_loop, args=(a.inbox, a.inbox_cmd, list(a.inbox_scheme),
                                                              a.inbox_callback), daemon=True).start()
                for ls, dial in listeners[1:]:
                    threading.Thread(target=accept_loop, args=(ls, dial), daemon=True).start()
                if listeners:
                    accept_loop(*listeners[0])
                else:
                    threading.Event().wait()
            finally:
                os._exit(0)
        for ls, _ in listeners:
            ls.close()
    try:
        os.execvp(cmd[0], cmd)
    except OSError as e:
        print(f"envbox: не удалось запустить {cmd[0]}: {e}", file=sys.stderr)
        os._exit(127)


def cmd_probe(a):
    try:
        up = Upstream(a.upstream, os.environ.get("ENVBOX_UPSTREAM_AUTH"))
        host, port = split_hostport(a.target, 443)
    except ValueError as e:
        print(f"ошибка: {e}")
        sys.exit(2)

    async def run():
        t0 = time.monotonic()
        r, w = await up.tunnel(host, port)
        w.close()
        return int((time.monotonic() - t0) * 1000)

    try:
        ms = asyncio.run(run())
    except (OSError, asyncio.TimeoutError) as e:
        print(f"не удалось: {e or type(e).__name__}")
        sys.exit(1)
    print(f"прокси {up.label} работает: туннель до {host}:{port} открыт за {ms} мс")


# ---- net/connect.py: Сетевой шлюз: подключение к одному из адресов хоста (Happy Eyeballs).

STAGGER = 0.25   # через сколько начинать следующий адрес, если предыдущий ещё не ответил


def interleave(ips):
    """Адреса вперемешку по семействам (v6, v4, v6, v4…), начиная с семейства первого адреса:
    если IPv6 «чёрная дыра», IPv4 попробуется почти сразу, а не через весь тайм-аут."""
    groups, order = {}, []
    for ip in ips:
        try:
            fam = ipaddress.ip_address(ip.split("%", 1)[0]).version
        except ValueError:
            fam = 4
        if fam not in groups:
            groups[fam] = []
            order.append(fam)
        groups[fam].append(ip)
    out = []
    while any(groups.values()):
        for fam in order:
            if groups[fam]:
                out.append(groups[fam].pop(0))
    return out


async def connect_race(ips, port, timeout=CONNECT_TIMEOUT, stagger=STAGGER):
    """(адрес, reader, writer) первого успешного подключения. Остальные попытки отменяются.
    OSError (последняя ошибка) или TimeoutError, если не удалось ни одно."""
    loop = asyncio.get_running_loop()
    queue = interleave(ips)
    tasks = {}
    last = None
    end = loop.time() + timeout
    try:
        while True:
            if queue:
                ip = queue.pop(0)
                tasks[asyncio.ensure_future(asyncio.open_connection(ip, port))] = ip
            if not tasks:
                break
            remaining = end - loop.time()
            if remaining <= 0:
                break
            done, _ = await asyncio.wait(set(tasks), timeout=min(stagger, remaining) if queue else remaining,
                                         return_when=asyncio.FIRST_COMPLETED)
            for t in done:
                ip = tasks.pop(t)
                try:
                    r, w = t.result()
                except OSError as e:
                    last = e
                    continue
                tune_socket(w.get_extra_info("socket"))
                return ip, r, w
            if not queue and not tasks:
                break
    finally:
        for t in tasks:
            t.cancel()
        for t, _ip in list(tasks.items()):
            try:
                _r, w = await t
                w.close()    # подключение успело завершиться в момент отмены
            except BaseException:   # noqa: BLE001 — отменённые и неудавшиеся попытки не важны
                pass
    if last is not None:
        raise last
    raise asyncio.TimeoutError()


# ---- net/dns.py: Сетевой шлюз: свой DNS-клиент и проверки имён/адресов.

DNS_TIMEOUT = 3


def _dns_skip_name(data, i):
    while True:
        if i >= len(data):
            raise OSError("обрезанный ответ DNS")
        n = data[i]
        if n == 0:
            return i + 1
        if n & 0xC0 == 0xC0:
            return i + 2
        i += 1 + n


def _dns_parse(data, qid):
    """Адреса A/AAAA из ответа DNS; (флаги, список IP) или None, если это не наш ответ."""
    if len(data) < 12 or struct.unpack(">H", data[:2])[0] != qid:
        return None
    flags, qd, an = struct.unpack(">HHH", data[2:8])
    pos = 12
    for _ in range(qd):
        pos = _dns_skip_name(data, pos) + 4
    ips = []
    for _ in range(an):
        pos = _dns_skip_name(data, pos)
        if pos + 10 > len(data):
            raise OSError("обрезанный ответ DNS")
        rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[pos:pos + 10])
        pos += 10
        rdata = data[pos:pos + rdlen]
        pos += rdlen
        if len(rdata) != rdlen:
            raise OSError("обрезанный ответ DNS")
        if rtype == 1 and rdlen == 4:
            ips.append(socket.inet_ntoa(rdata))
        elif rtype == 28 and rdlen == 16:
            ips.append(socket.inet_ntop(socket.AF_INET6, rdata))
    return flags, ips


def _dns_query(name, qtype, server):
    """Один запрос (A=1, AAAA=28) к серверу по UDP; при усечённом ответе повтор по TCP."""
    try:
        labels = name.rstrip(".").encode("idna").split(b".")
    except UnicodeError:
        raise OSError("недопустимое имя хоста") from None
    if not labels or any(not 0 < len(l) < 64 for l in labels):
        raise OSError("недопустимое имя хоста")
    qid = struct.unpack(">H", os.urandom(2))[0]
    query = (struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
             + b"".join(bytes([len(l)]) + l for l in labels) + b"\0" + struct.pack(">HH", qtype, 1))
    fam = socket.AF_INET6 if ":" in server else socket.AF_INET
    parsed = None
    with socket.socket(fam, socket.SOCK_DGRAM) as s:
        s.settimeout(DNS_TIMEOUT)
        s.connect((server, 53))
        s.send(query)
        while parsed is None:
            parsed = _dns_parse(s.recv(4096), qid)
    flags, ips = parsed
    if flags & 0x0200:  # ответ усечён: повторяем по TCP
        with socket.socket(fam, socket.SOCK_STREAM) as t:
            t.settimeout(DNS_TIMEOUT)
            t.connect((server, 53))
            t.sendall(struct.pack(">H", len(query)) + query)
            head = b""
            while len(head) < 2:
                chunk = t.recv(2 - len(head))
                if not chunk:
                    raise OSError("DNS-сервер закрыл соединение")
                head += chunk
            need, body = struct.unpack(">H", head)[0], b""
            while len(body) < need:
                chunk = t.recv(need - len(body))
                if not chunk:
                    raise OSError("DNS-сервер закрыл соединение")
                body += chunk
        parsed = _dns_parse(body, qid)
        if parsed is None:
            raise OSError("некорректный ответ DNS")
        flags, ips = parsed
    rcode = flags & 0xF
    if rcode not in (0, 3):
        raise OSError(f"DNS-сервер ответил с кодом {rcode}")
    return ips


def dns_lookup(host, servers, qtype):
    """Адреса одного типа записи (A=1, AAAA=28): серверы пробуются по очереди.
    Пустой список — имя существует, но записей нет; OSError — ни один сервер не ответил."""
    last, answered = None, False
    for server in servers:
        try:
            ips = _dns_query(host, qtype, server)
        except OSError as e:
            last = e
            continue
        if ips:
            return ips
        answered = True
    if answered or last is None:
        return []
    raise last


def dns_resolve_blocking(host, servers):
    """Адреса хоста через заданные DNS-серверы (A и AAAA); серверы пробуются по очереди."""
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass
    ips, last = [], None
    for qtype in (1, 28):
        try:
            ips += dns_lookup(host, servers, qtype)
        except OSError as e:
            last = e
    if ips:
        return list(dict.fromkeys(ips))
    raise last or OSError("имя не найдено")


class Resolver:
    """Разрешение имён для прокси: свои DNS-серверы профиля или системный резолвер.

    Ответы кэшируются (иначе каждое соединение браузера или npm ждёт DNS заново), одинаковые запросы
    объединяются, A и AAAA спрашиваются одновременно, а медленный DNS не занимает общий пул потоков asyncio:
    у резолвера свой пул, и один зависший сервер не останавливает все остальные соединения."""

    MAX_ENTRIES = 2048

    def __init__(self, servers=None, timeout=CONNECT_TIMEOUT, ttl=60.0, neg_ttl=2.0, workers=32):
        self.servers = list(servers or [])
        self.timeout = timeout
        self.ttl = ttl
        self.neg_ttl = neg_ttl
        self.workers = workers
        self.cache = {}       # имя -> (до какого момента, адреса или None, текст ошибки)
        self.inflight = {}    # имя -> задача
        self._pool = None

    def pool(self):
        if self._pool is None:
            from concurrent.futures import ThreadPoolExecutor
            self._pool = ThreadPoolExecutor(max_workers=self.workers, thread_name_prefix="envbox-dns")
        return self._pool

    def remember(self, host, ips, error):
        now = time.monotonic()
        if len(self.cache) >= self.MAX_ENTRIES:
            self.cache = {k: v for k, v in self.cache.items() if v[0] > now}
            if len(self.cache) >= self.MAX_ENTRIES:
                self.cache.clear()
        self.cache[host] = (now + (self.ttl if ips is not None else self.neg_ttl), ips, error)

    async def lookup(self, host):
        loop = asyncio.get_running_loop()
        try:
            ipaddress.ip_address(host)
            return [host]
        except ValueError:
            pass
        try:
            if self.servers:
                res = await asyncio.gather(
                    loop.run_in_executor(self.pool(), dns_lookup, host, self.servers, 1),
                    loop.run_in_executor(self.pool(), dns_lookup, host, self.servers, 28),
                    return_exceptions=True)
                ips = []
                for r in res:
                    if isinstance(r, list):
                        ips += r
                if not ips:
                    err = next((r for r in res if isinstance(r, BaseException)), None)
                    raise err if isinstance(err, OSError) else OSError(str(err) if err else "имя не найдено")
            else:
                infos = await loop.run_in_executor(
                    self.pool(), socket.getaddrinfo, host, None, 0, socket.SOCK_STREAM)
                ips = [i[4][0] for i in infos]
            ips = list(dict.fromkeys(ips))
            if not ips:
                raise OSError("имя не найдено")
        except OSError as e:
            self.remember(host, None, str(e) or type(e).__name__)
            raise
        self.remember(host, ips, "")
        return ips

    async def resolve(self, host):
        """Список адресов хоста (в порядке предпочтения системы); OSError или TimeoutError при сбое."""
        hit = self.cache.get(host)
        if hit is not None and hit[0] > time.monotonic():
            if hit[1] is None:
                raise OSError(hit[2])
            return list(hit[1])
        task = self.inflight.get(host)
        if task is None:
            task = asyncio.ensure_future(self.lookup(host))
            self.inflight[host] = task

            def done(t, key=host):
                self.inflight.pop(key, None)
                if not t.cancelled():
                    t.exception()   # ошибка уже запомнена в кэше; без этого asyncio ругался бы в stderr

            task.add_done_callback(done)
        return list(await asyncio.wait_for(asyncio.shield(task), self.timeout))


def is_private_name(host):
    """Литеральные частные IP (в том числе 127.1, 2130706433, 0x7f000001) и localhost.
    Имена остальных разрешает вышестоящий прокси."""
    h = host.lower().rstrip(".")
    if h == "localhost" or h.endswith(".localhost"):
        return True
    try:
        return not is_public(h)
    except ValueError:
        pass
    if re.fullmatch(r"[0-9a-fx.]+", h):  # старые формы IPv4: сокращённая, десятичная, 16-ричная, 8-ричная
        try:
            return not is_public(socket.inet_ntoa(socket.inet_aton(h)))
        except (OSError, ValueError):
            return False
    return False


def is_ip_literal(host):
    """True, если host — IP-адрес (в том числе в старых формах), а не имя сайта."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    if re.fullmatch(r"[0-9a-fx.]+", host.lower()):
        try:
            socket.inet_aton(host)
            return True
        except OSError:
            return False
    return False


# ---- net/gitcheck.py: Проверка Git после работы среды: хуки и config проекта не должны меняться незаметно.

# ---- проверка Git после работы среды: хуки и config в проекте не должны меняться незаметно

def _sha256(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _walk_files(root, base, out, depth=6):
    if depth < 0 or not os.path.isdir(root) or os.path.islink(root):
        return
    for name in sorted(os.listdir(root)):
        path = os.path.join(root, name)
        rel = os.path.relpath(path, base)
        if os.path.islink(path):
            out[rel] = "link:" + os.readlink(path)
        elif os.path.isdir(path):
            _walk_files(path, base, out, depth - 1)
        elif os.path.isfile(path) and not name.endswith(".sample"):   # *.sample git не запускает
            out[rel] = _sha256(path)


def git_state(workdir):
    """Состояние того, что запускается при командах git: сам .git, config, хуки, hooksPath, подмодули."""
    gp = os.path.join(workdir, ".git")
    try:
        st = os.lstat(gp)
    except OSError:
        return {"kind": "none", "ino": [0, 0], "files": {}}
    kind = "link" if stat.S_ISLNK(st.st_mode) else "dir" if stat.S_ISDIR(st.st_mode) else "file"
    files = {}
    if kind == "file":
        files[".git"] = _sha256(gp)
    elif kind == "dir":
        cfg = os.path.join(gp, "config")
        if os.path.isfile(cfg):
            files[".git/config"] = _sha256(cfg)
        # commondir подменяет каталог, откуда git берёт config и хуки; config.worktree читается при extensions.worktreeConfig
        for extra in ("commondir", "config.worktree"):
            path = os.path.join(gp, extra)
            if os.path.islink(path):
                files[".git/" + extra] = "link:" + os.readlink(path)
            elif os.path.isfile(path):
                files[".git/" + extra] = _sha256(path)
        _walk_files(os.path.join(gp, "hooks"), workdir, files)
        files[".git/hooks/"] = "каталог" if os.path.isdir(os.path.join(gp, "hooks")) else "нет"
        mods = os.path.join(gp, "modules")
        for root, dirs, names in os.walk(mods):
            if root.count(os.sep) - mods.count(os.sep) > 5:
                dirs[:] = []
                continue
            for d in list(dirs):
                if d == "hooks":
                    _walk_files(os.path.join(root, d), workdir, files)
            if "config" in names:
                path = os.path.join(root, "config")
                files[os.path.relpath(path, workdir)] = _sha256(path)
        hp = ""
        if os.path.isfile(cfg):
            import subprocess
            try:
                hp = subprocess.run(["git", "config", "--file", cfg, "--get", "core.hooksPath"],
                                    capture_output=True, text=True, timeout=10).stdout.strip()
            except (OSError, subprocess.SubprocessError):
                hp = ""
        if hp:
            hp = os.path.realpath(hp if os.path.isabs(hp) else os.path.join(workdir, hp))
            if hp.startswith(os.path.realpath(workdir) + os.sep):
                _walk_files(hp, workdir, files)
    return {"kind": kind, "ino": [st.st_dev, st.st_ino], "files": files}


def cmd_gitcheck(a):
    if a.action == "snapshot":
        json.dump(git_state(a.workdir), sys.stdout)
        return
    try:
        with open(a.snapshot, encoding="utf-8") as f:
            before = json.load(f)
    except (OSError, ValueError):
        return
    after = git_state(a.workdir)
    notes = []
    if before["kind"] == "none" and after["kind"] != "none":
        notes.append("«.git» создан внутри среды (раньше в проекте репозитория не было)")
    elif before["kind"] != after["kind"] or before["ino"] != after["ino"]:
        notes.append("«.git» заменён или пересоздан (другой объект на диске)")
    for key in sorted(set(before["files"]) | set(after["files"])):
        old, new = before["files"].get(key), after["files"].get(key)
        if old == new:
            continue
        what = "добавлен" if old is None else "удалён" if new is None else "изменён"
        notes.append(f"{what}: {key}")
    if notes:
        print("\n⚠ envbox: после работы среды изменилось то, что запускается при командах git "
              "в проекте — проверьте, прежде чем использовать git на компьютере:", file=sys.stderr)
        for n in notes:
            print("   · " + n, file=sys.stderr)
        print("   Проверка: ls -la .git/hooks; git config --local --list", file=sys.stderr)
        sys.exit(4)


# ---- net/proxy.py: Сетевой шлюз: журналирующий прокси (команда proxy).

LOG_LIMIT = 20 * 1024 * 1024        # больше этого размера журнал уходит в .1
LOG_CHECK_EVERY = 500               # как часто (в записях) проверять размер во время работы


def host_matches(rules, host):
    """Подходит ли имя хоста под одно из правил: «example.com» — только он, «*.example.com» — он и поддомены."""
    h = host.lower().rstrip(".")
    for rule in rules:
        if rule.startswith("*."):
            base = rule[2:]
            if h == base or h.endswith("." + base):
                return True
        elif h == rule:
            return True
    return False


def err_text(e):
    """Текст ошибки для журнала и ответа клиенту: у TimeoutError и подобных он пустой, тогда — имя ошибки
    (само исключение всегда «истинно», поэтому `e or имя` не годится)."""
    return str(e) or type(e).__name__


class Proxy:
    def __init__(self, log_path, allow, allow_private, upstream=None, dns=None, direct=None,
                 idle=IDLE_TIMEOUT, hedge=HEDGE_DELAY, max_hedges=MAX_HEDGES, max_setups=MAX_SETUPS):
        self.log_path = log_path
        self.setups = asyncio.Semaphore(max_setups)   # одновременные установки туннеля к вышестоящему прокси
        self.max_hedges = max_hedges
        self.hedging = 0          # сколько вторых туннелей строится прямо сейчас
        self.idle = idle          # секунд без единого байта до закрытия соединения (0 — не закрывать)
        self.hedge = hedge        # через сколько секунд начинать второй туннель к вышестоящему прокси
        self.rotate()
        self.allow = [a.lower().rstrip(".") for a in allow]
        self.allow_private = allow_private
        self.upstream = upstream
        # сайты, к которым прокси подключается сам, минуя вышестоящий прокси (некоторые сайты не пускают его адрес)
        self.direct = [a.lower().rstrip(".") for a in (direct or [])]
        self.dns = list(dns or [])
        self.ids = itertools.count(1)
        self.run_id = os.urandom(3).hex()   # у каждого запуска свои номера соединений
        # прокси на этом же компьютере или в локальной сети разрешает имена у себя: проверяем и здесь
        self.check_local = bool(upstream is not None and is_private_name(upstream.host))
        self.resolver = Resolver(self.dns)
        # проверка «имя не ведёт на частный адрес» не должна задерживать соединения, если локальный DNS
        # не отвечает (сам вышестоящий прокси разрешит имя по-своему): короткий тайм-аут и долгая память об отказе
        self.local_resolver = Resolver(self.dns, timeout=2.5, neg_ttl=30.0)

    def rotate(self):
        """Журнал не растёт бесконечно: больше 20 МБ — прежний уходит в .1 (при старте и по ходу работы)."""
        try:
            if os.path.getsize(self.log_path) > LOG_LIMIT:
                os.replace(self.log_path, self.log_path + ".1")
        except OSError:
            pass
        old = getattr(self, "log", None)
        fd = os.open(self.log_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        self.log = os.fdopen(fd, "a", buffering=1, encoding="utf-8")
        self.written = 0
        if old is not None:
            try:
                old.close()
            except OSError:
                pass

    def write(self, rec):
        self.log.write(json.dumps({"ts": now(), "run": self.run_id, **rec}, ensure_ascii=False) + "\n")
        self.written += 1
        if self.written >= LOG_CHECK_EVERY:
            self.written = 0
            try:
                if os.fstat(self.log.fileno()).st_size > LOG_LIMIT:
                    self.rotate()
            except OSError:
                pass

    def allowed(self, host):
        # сайт из списка «напрямую» пользователь назвал явно, поэтому он разрешён и в режиме allowlist
        return not self.allow or host_matches(self.allow, host) or host_matches(self.direct, host)

    def via_upstream(self, host):
        """Идёт ли соединение с хостом через вышестоящий прокси (сайты из списка «напрямую» идут мимо него)."""
        return self.upstream is not None and not host_matches(self.direct, host)

    @staticmethod
    async def reply(writer, code, text):
        body = (text + "\n").encode("ascii", "replace")
        head = (f"HTTP/1.1 {code} {text}\r\nContent-Type: text/plain\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n")
        try:
            writer.write(head.encode("ascii", "replace") + body)
            await writer.drain()
        except (ConnectionError, OSError):
            pass

    async def hedged_tunnel(self, host, port):
        """Туннель через вышестоящий прокси. Если первая попытка не готова за `hedge` секунд, стартует вторая;
        берётся первая удавшаяся, остальные закрываются. Ошибка — только если не удалась ни одна."""
        first = asyncio.ensure_future(self.upstream.tunnel(host, port))
        done, _ = await asyncio.wait({first}, timeout=self.hedge)
        if done:
            return first.result()
        if self.hedging >= self.max_hedges:
            return await first          # прокси и так перегружен: вторую попытку не добавляем
        self.hedging += 1
        self.write({"event": "hedge", "host": host, "port": port, "reason": "upstream-slow"})
        pending = {first, asyncio.ensure_future(self.upstream.tunnel(host, port))}
        winner, error = None, None
        try:
            while pending and winner is None:
                done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
                for t in done:
                    if t.exception() is not None:
                        error = t.exception()
                    elif winner is None:
                        winner = t.result()
                    else:
                        t.result()[1].close()      # обе попытки закончились одновременно: вторая не нужна
        finally:
            self.hedging -= 1
            for t in pending:
                t.cancel()
            for res in await asyncio.gather(*pending, return_exceptions=True):
                if isinstance(res, tuple):
                    res[1].close()                 # успела завершиться в момент отмены
        if winner is None:
            raise error
        return winner

    async def pipe(self, cr, cw, ur, uw, first):
        """Пересылка в обе стороны. Возвращает (отправлено, получено, кто_закончил): «client», «upstream» или «idle»."""
        counts = {"up": len(first), "down": 0}
        last = [time.monotonic()]
        stalled = [False]
        ended = []        # какая сторона закончила первой: по этому видно, кто рвёт соединения (клиент или прокси)
        if first:
            uw.write(first)
            await uw.drain()

        async def copy(src, dst, key):
            try:
                while True:
                    data = await src.read(BUF)
                    if not data:
                        break
                    last[0] = time.monotonic()
                    counts[key] += len(data)
                    dst.write(data)
                    await dst.drain()
            except (ConnectionError, OSError):
                pass
            finally:
                ended.append(key)
                try:
                    if dst.can_write_eof():
                        dst.write_eof()
                except (ConnectionError, OSError, RuntimeError):
                    pass

        async def watch():
            step = max(0.05, min(5.0, self.idle / 4))
            while True:
                await asyncio.sleep(step)
                if time.monotonic() - last[0] > self.idle:
                    stalled[0] = True
                    for w in (cw, uw):
                        w.close()      # оба копировщика получат конец потока и завершатся
                    return

        watcher = asyncio.ensure_future(watch()) if self.idle else None
        try:
            # одна сторона упала неожиданной ошибкой — вторая всё равно доводится до конца, а не остаётся висеть
            await asyncio.gather(copy(cr, uw, "up"), copy(ur, cw, "down"), return_exceptions=True)
        finally:
            if watcher is not None:
                watcher.cancel()
        end = "idle" if stalled[0] else "client" if ended[:1] == ["up"] else "upstream"
        return counts["up"], counts["down"], end

    async def deny(self, writer, rec, code, reason, text, **extra):
        """Отказ: запись в журнал и быстрый ответ клиенту (с названием хоста: понятно, что именно закрыто)."""
        self.write({**rec, "event": "deny" if code == 403 else "error", "reason": reason, **extra})
        await self.reply(writer, code, f"{text}: {rec.get('host', '?')}")

    async def handle(self, reader, writer):
        cid = next(self.ids)
        t0 = time.monotonic()
        rec = {"id": cid}
        upstream = None
        try:
            try:
                head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), HEAD_TIMEOUT)
            except (asyncio.IncompleteReadError, asyncio.LimitOverrunError,
                    asyncio.TimeoutError, ConnectionError):
                return
            lines = head[:-4].decode("latin-1").split("\r\n")
            parts = lines[0].split(" ")
            if len(parts) != 3:
                await self.reply(writer, 400, "Bad Request")
                return
            method, target = parts[0].upper(), parts[1]

            if method == "CONNECT":
                try:
                    host, port = split_hostport(target, 443)
                    host = canon_host(host)
                except ValueError:
                    await self.reply(writer, 400, "Bad Request")
                    return
                rec.update(kind="CONNECT", host=host, port=port)
                path = None
            else:
                u = urllib_parse.urlsplit(target)
                try:
                    port = u.port or 80
                except ValueError:
                    port = None
                try:
                    host = canon_host(u.hostname or "")
                except ValueError:
                    host = None
                if u.scheme.lower() != "http" or host is None or port is None:
                    self.write({**rec, "event": "error", "kind": "HTTP", "method": method,
                                "host": u.hostname or "?", "reason": "unsupported-request"})
                    await self.reply(writer, 400, "Bad Request")
                    return
                hp = f"[{host}]" if ":" in host else host   # у IPv6 в адресе нужны скобки
                path = urllib_parse.urlunsplit(("", "", u.path or "/", u.query, ""))
                # userinfo из URL не логируем
                rec.update(kind="HTTP", host=host, port=port, method=method,
                           url=f"http://{hp}:{port}{path}")

            if not self.allowed(host):
                await self.deny(writer, rec, 403, "not-in-allowlist", "Forbidden by envbox allowlist")
                return

            tunnel = True
            if self.via_upstream(host):
                if not self.allow_private and is_private_name(host):
                    await self.deny(writer, rec, 403, "private-address", "Private address forbidden by envbox")
                    return
                if self.check_local and not self.allow_private and not is_ip_literal(host):
                    # вышестоящий прокси рядом с вами: имя вроде localtest.me могло бы указывать на 127.0.0.1
                    try:
                        local = await self.local_resolver.resolve(host)
                    except (OSError, asyncio.TimeoutError):
                        local = []
                    if any(not is_public(a) for a in local):
                        await self.deny(writer, rec, 403, "private-address",
                                        "Private address forbidden by envbox", resolved=local)
                        return
                try:
                    if method == "CONNECT" or self.upstream.kind == "socks5":
                        queued = time.monotonic()
                        async with self.setups:
                            waited = time.monotonic() - queued
                            ur, upstream = await self.hedged_tunnel(host, port)
                        if waited > 0.2:
                            rec["wait_ms"] = int(waited * 1000)   # всплеск соединений: ждали своей очереди
                    else:
                        tunnel = False  # обычный HTTP: запрос в абсолютной форме самому прокси
                        ur, upstream = await self.upstream.open()
                except (OSError, asyncio.TimeoutError) as e:
                    await self.deny(writer, rec, 502, f"upstream: {err_text(e)}",
                                    "Upstream proxy failed", via=self.upstream.label)
                    return
                rec["via"] = self.upstream.label
            else:
                try:
                    addrs = await self.resolver.resolve(host)
                except (OSError, asyncio.TimeoutError) as e:
                    await self.deny(writer, rec, 502, f"dns: {err_text(e)}", "DNS resolution failed")
                    return
                candidates = addrs if self.allow_private else [a for a in addrs if is_public(a)]
                if not candidates:
                    await self.deny(writer, rec, 403, "private-address",
                                    "Private address forbidden by envbox", resolved=addrs)
                    return
                try:  # подключаемся к уже проверенному IP (без повторного DNS), адреса пробуются «наперегонки»
                    ip, ur, upstream = await connect_race(candidates, port)
                except (OSError, asyncio.TimeoutError) as e:
                    await self.deny(writer, rec, 502, f"connect: {err_text(e)}",
                                    "Upstream connection failed")
                    return
                rec["ip"] = ip
                if self.upstream is not None:
                    rec["direct"] = True   # из списка «напрямую»: мимо вышестоящего прокси

            self.write({**rec, "event": "open"})
            if method == "CONNECT":
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await writer.drain()
                first = b""
            else:
                websocket = any(h.lower().startswith("upgrade:") for h in lines[1:])
                # обычно соединение закрывается после ответа; при Upgrade (WebSocket) его нужно сохранить
                skip = ("proxy-", "keep-alive:") if websocket else ("proxy-", "connection:", "keep-alive:")
                headers = [h for h in lines[1:] if h and not h.lower().startswith(skip)]
                if not any(h.lower().startswith("host:") for h in headers):
                    headers.append("Host: " + (f"[{host}]" if ":" in host else host))
                target_line = path
                if not tunnel:
                    target_line = rec["url"]
                    if self.upstream.auth:
                        headers.append(f"Proxy-Authorization: {self.upstream.basic()}")
                req = f"{method} {target_line} HTTP/1.1\r\n" + "".join(h + "\r\n" for h in headers)
                first = (req + ("" if websocket else "Connection: close\r\n") + "\r\n").encode("latin-1")
            up, down, end = await self.pipe(reader, writer, ur, upstream, first)
            self.write({"id": cid, "event": "close", "host": host, "port": port,
                        "up": up, "down": down, "ms": int((time.monotonic() - t0) * 1000), "end": end,
                        **({"idle": True} if end == "idle" else {})})
        except Exception as e:  # журнал не должен ронять прокси
            self.write({**rec, "event": "error", "reason": f"internal: {e!r}"})
        finally:
            for w in (writer, upstream):
                if w is not None:
                    try:
                        w.close()
                    except Exception:
                        pass


def cmd_proxy(a):
    signal.signal(signal.SIGINT, signal.SIG_IGN)  # Ctrl+C в терминале не должен терять журнал
    auth = os.environ.pop("ENVBOX_UPSTREAM_AUTH", None)
    upstream = None
    if a.upstream:
        try:
            upstream = Upstream(a.upstream, auth)
        except ValueError as e:
            sys.exit(f"envbox-net: ошибка прокси: {e}")
    for d in a.dns:
        try:
            ipaddress.ip_address(d)
        except ValueError:
            sys.exit(f"envbox-net: недопустимый DNS-сервер: {d}")
    proxy = Proxy(a.log, a.allow, a.allow_private, upstream, a.dns, a.direct)

    async def main():
        if os.path.lexists(a.socket):
            os.unlink(a.socket)
        old = os.umask(0o177)
        try:
            server = await asyncio.start_unix_server(proxy.handle, path=a.socket, limit=HEAD_LIMIT, backlog=512)
        finally:
            os.umask(old)
        proxy.write({"event": "proxy-start", "allow": proxy.allow or ["*"],
                     "allow_private": proxy.allow_private,
                     "upstream": upstream.label if upstream else None,
                     "dns": proxy.dns or None, "direct": proxy.direct or None})
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        loop.add_signal_handler(signal.SIGTERM, stop.set)

        async def watch_parent():
            while not stop.is_set():
                if a.parent_pid and os.getppid() != a.parent_pid:
                    stop.set()
                    return
                await asyncio.sleep(1)

        watcher = asyncio.ensure_future(watch_parent())
        await stop.wait()
        watcher.cancel()
        server.close()
        proxy.write({"event": "proxy-stop"})

    asyncio.run(main())
    # потоки DNS-запросов могли зависнуть на ответе сервера: ждать их при выходе незачем (журнал построчный)
    os._exit(0)


# ---- net/report.py: Сетевой шлюз: чтение и вывод журнала соединений (команда report).

def human(n):
    for unit in ("Б", "КБ", "МБ", "ГБ"):
        if n < 1024 or unit == "ГБ":
            return f"{n:.0f} {unit}" if unit == "Б" else f"{n:.1f} {unit}"
        n /= 1024


def clean(value):
    """Строка для вывода в терминал: управляющие символы (в том числе ESC) заменяются на «?».
    Имена хостов и адреса приходят из среды, и последовательность вроде \\e]0;… не должна управлять терминалом."""
    return "".join("?" if ord(c) < 32 or 0x7F <= ord(c) < 0xA0 else c for c in str(value))


def events(path):
    with open(path, encoding="utf-8") as f:
        for line in f:
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def fmt_event(e):
    return clean(_fmt_event(e))


def _fmt_event(e):
    ev = e.get("event", "?")
    if ev in ("proxy-start", "proxy-stop"):
        extra = f" разрешено: {', '.join(map(str, e.get('allow', [])))}" if ev == "proxy-start" else ""
        return f"{e.get('ts', '')}  --- {ev}{extra}"
    target = f"{e.get('host', '?')}:{e.get('port', '?')}"
    label = {"open": "ОТКРЫТО", "close": "ЗАКРЫТО", "deny": "ЗАПРЕТ", "error": "ОШИБКА"}.get(ev, ev)
    tail = ""
    if ev == "open":
        tail = f" ({e.get('ip') or 'через ' + str(e.get('via', '?'))}{', напрямую' if e.get('direct') else ''})"
        if e.get("url"):
            tail += f" {e.get('method', '')} {e['url']}"
    elif ev == "close":
        tail = f" ↑{human(e.get('up', 0))} ↓{human(e.get('down', 0))} {e.get('ms', 0)} мс"
        if e.get("idle"):
            tail += " (закрыто: не было данных)"
        elif e.get("end"):
            tail += " (закрыл " + {"client": "клиент", "upstream": "сервер или прокси"}.get(e["end"], e["end"]) + ")"
    elif ev in ("deny", "error"):
        tail = f" {e.get('reason', '')}"
    return f"{e.get('ts', '')}  {label:<8} {target}{tail}"


def cmd_report(a):
    if a.follow:
        with open(a.log, encoding="utf-8") as f:
            try:
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(0.5)
                        continue
                    try:
                        print(fmt_event(json.loads(line)), flush=True)
                    except json.JSONDecodeError:
                        pass
            except KeyboardInterrupt:
                return
    if a.raw:
        for e in events(a.log):
            print(fmt_event(e))
        return
    agg = {}
    for e in events(a.log):
        if "host" not in e:
            continue
        key = (e["host"], e.get("port"))
        s = agg.setdefault(key, {"n": 0, "deny": 0, "err": 0, "up": 0, "down": 0,
                                 "first": e["ts"], "last": e["ts"], "ips": set()})
        s["last"] = e["ts"]
        ev = e.get("event")
        if ev == "open":
            s["n"] += 1
            if e.get("ip"):
                s["ips"].add(e["ip"])
        elif ev == "deny":
            s["deny"] += 1
        elif ev == "error":
            s["err"] += 1
        elif ev == "close":
            s["up"] += e.get("up", 0)
            s["down"] += e.get("down", 0)
    if not agg:
        print("В журнале нет сетевых обращений.")
        return
    rows = sorted(agg.items(), key=lambda kv: kv[1]["last"])
    hdr = f"{'последнее':<25} {'хост:порт':<40} {'соед':>5} {'запр':>5} {'ошиб':>5} {'отпр':>10} {'получ':>10}  IP"
    print(hdr)
    print("-" * len(hdr))
    for (host, port), s in rows:
        print(clean(f"{s['last']:<25} {f'{host}:{port}':<40} {s['n']:>5} {s['deny']:>5} {s['err']:>5} "
                    f"{human(s['up']):>10} {human(s['down']):>10}  {', '.join(sorted(s['ips']))}"))


# ---- net/seccomp.py: seccomp-фильтр для bwrap (команда seccomp).

# Запрещённые системные вызовы (x86_64): отладка чужих процессов, ядро и модули, eBPF/perf,
# io_uring, новый API монтирования, ключи ядра, часы и т. п. Остальное разрешено.
SECCOMP_DENY_X86_64 = {
    "ptrace": 101, "process_vm_readv": 310, "process_vm_writev": 311,
    "kexec_load": 246, "kexec_file_load": 320, "bpf": 321, "perf_event_open": 298,
    "userfaultfd": 323, "io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427,
    "keyctl": 250, "add_key": 248, "request_key": 249,
    "mount": 165, "umount2": 166, "pivot_root": 155, "chroot": 161,
    "swapon": 167, "swapoff": 168, "reboot": 169,
    "init_module": 175, "finit_module": 313, "delete_module": 176,
    "acct": 163, "settimeofday": 164, "adjtimex": 159, "clock_settime": 227, "clock_adjtime": 305,
    "iopl": 172, "ioperm": 173, "open_by_handle_at": 304, "lookup_dcookie": 212, "quotactl": 179,
    "open_tree": 428, "move_mount": 429, "fsopen": 430, "fsconfig": 431, "fsmount": 432,
    "fspick": 433, "mount_setattr": 442,
    "syslog": 103, "pidfd_getfd": 438, "kcmp": 312, "process_madvise": 440,
}


def seccomp_program_x86_64(deny=None):
    """Классический BPF-фильтр для bwrap --seccomp: запрещённые вызовы возвращают EPERM,
    чужая архитектура и x32-вызовы убивают процесс."""
    nums = sorted((deny or SECCOMP_DENY_X86_64).values())
    kill, allow, eperm = 0x80000000, 0x7FFF0000, 0x00050001
    ins = [(0x20, 0, 0, 4),                     # A = архитектура
           (0x15, 1, 0, 0xC000003E),            # x86_64? пропускаем «убить»
           (0x06, 0, 0, kill),
           (0x20, 0, 0, 0),                     # A = номер вызова
           (0x35, 0, 1, 0x40000000),            # номер >= x32? иначе пропускаем «убить»
           (0x06, 0, 0, kill)]
    n = len(nums)
    ins += [(0x15, n - j, 0, nr) for j, nr in enumerate(nums)]
    ins += [(0x06, 0, 0, allow), (0x06, 0, 0, eperm)]
    return b"".join(struct.pack("=HBBI", *i) for i in ins)


def cmd_seccomp(a):
    if os.uname().machine != "x86_64":
        print("seccomp-фильтр поддерживается только на x86_64", file=sys.stderr)
        sys.exit(3)
    unknown = [n for n in a.allow if n not in SECCOMP_DENY_X86_64]
    if unknown:
        print("неизвестные системные вызовы для --allow: " + ", ".join(unknown), file=sys.stderr)
        sys.exit(2)
    deny = {k: v for k, v in SECCOMP_DENY_X86_64.items() if k not in a.allow}
    sys.stdout.buffer.write(seccomp_program_x86_64(deny))


# ---- net/entry.py: Диспетчер служебных команд envbox.py, вызываемых из envbox.sh и из песочницы.

# Разбор аргументов написан вручную: argparse в Python 3.14 тянет за собой ~18 мс импортов, а эти команды
# запускаются при каждом старте среды и каждой команде внутри неё.
# Вид: команда -> {параметр: вид}, где вид: str, int, list (повторяемый) или flag.
NET_OPTIONS = {
    "proxy": {"--socket": "str", "--log": "str", "--allow": "list", "--allow-private": "flag",
              "--parent-pid": "int", "--upstream": "str", "--dns": "list", "--direct": "list"},
    "wrap": {"--map": "list", "--serve": "list", "--inbox": "str", "--inbox-cmd": "str",
             "--inbox-scheme": "list", "--inbox-callback": "flag"},
    "seccomp": {"--allow": "list"},
    "version": {},
    "gitcheck": {},
    "probe": {"--upstream": "str", "--target": "str"},
    "report": {"--follow": "flag", "--raw": "flag"},
}


NET_REQUIRED = {"proxy": ("socket", "log"), "probe": ("upstream",)}


NET_POSITIONAL = {"gitcheck": ("action", "workdir", "snapshot"), "report": ("log",)}


NET_OPTIONAL_POSITIONAL = {"gitcheck": 1}   # сколько последних позиционных необязательны


NET_DEFAULTS = {"target": "example.com:443"}


class NetArgs:
    """Результат разбора: атрибуты по именам параметров (как у argparse.Namespace)."""

    def __init__(self, mode):
        self.mode = mode


def net_usage(msg):
    print(f"envbox-net: ошибка: {msg}", file=sys.stderr)
    sys.exit(2)


def net_parse(mode, argv):
    spec = NET_OPTIONS[mode]
    a = NetArgs(mode)
    for opt, kind in spec.items():
        dest = opt[2:].replace("-", "_")
        setattr(a, dest, [] if kind == "list" else False if kind == "flag" else 0 if kind == "int"
                else NET_DEFAULTS.get(dest, ""))
    names = NET_POSITIONAL.get(mode, ())
    for n in names:
        setattr(a, n, None)
    if mode == "wrap":
        a.cmd = []
    positional = []
    i = 0
    while i < len(argv):
        arg = argv[i]
        i += 1
        if mode == "wrap" and (arg == "--" or not arg.startswith("-")):
            a.cmd = argv[i:] if arg == "--" else argv[i - 1:]   # всё остальное — команда
            break
        if arg == "--" or not arg.startswith("-") or arg == "-":
            positional.append(arg)
            continue
        opt, eq, value = arg.partition("=")
        kind = spec.get(opt)
        if kind is None:
            net_usage(f"неизвестный параметр {opt} (команда {mode})")
        dest = opt[2:].replace("-", "_")
        if kind == "flag":
            if eq:
                net_usage(f"параметр {opt} не принимает значение")
            setattr(a, dest, True)
            continue
        if not eq:
            if i >= len(argv):
                net_usage(f"параметру {opt} нужно значение")
            value = argv[i]
            i += 1
        if kind == "list":
            getattr(a, dest).append(value)
        elif kind == "int":
            try:
                setattr(a, dest, int(value))
            except ValueError:
                net_usage(f"параметр {opt}: ожидается число, получено {value!r}")
        else:
            setattr(a, dest, value)
    required = len(names) - NET_OPTIONAL_POSITIONAL.get(mode, 0)
    if len(positional) < required or len(positional) > len(names):
        net_usage(f"команда {mode}: ожидаются аргументы: {' '.join(names)}")
    for n, v in zip(names, positional):
        setattr(a, n, v)
    for n in NET_REQUIRED.get(mode, ()):
        if not getattr(a, n):
            net_usage(f"команда {mode}: не указан параметр --{n.replace('_', '-')}")
    if mode == "gitcheck" and a.action not in ("snapshot", "verify"):
        net_usage("gitcheck: действие должно быть snapshot или verify")
    return a


def net_main():
    argv = sys.argv[1:]
    mode = argv[0] if argv else ""
    if mode not in NET_OPTIONS:
        net_usage("ожидается одна из команд: " + ", ".join(NET_OPTIONS))
    a = net_parse(mode, argv[1:])
    {"proxy": cmd_proxy, "wrap": cmd_wrap, "probe": cmd_probe, "report": cmd_report,
     "seccomp": cmd_seccomp, "gitcheck": cmd_gitcheck,
     "version": lambda _a: print(ENVBOX_VERSION)}[a.mode](a)


NET_COMMANDS = tuple(NET_OPTIONS)


# ---- быстрый вход: служебные команды шлюза не загружают остальной код

if __name__ == "__main__" and sys.argv[1:2] and sys.argv[1] in NET_COMMANDS:
    sys.exit(net_main())


import base64
import datetime as dt
import hashlib
import ipaddress
import json
import re
import shutil
import signal
import socket
import subprocess
import threading
import urllib.parse
from dataclasses import asdict
from dataclasses import dataclass
from dataclasses import dataclass, field, fields


# ---- resources.py: Встроенные ресурсы (envbox.sh, значки, CSS…): файлы из resources/; в собранном envbox.py они вшиты строками.

_RESOURCES = {
    'AppRun.sh': '''#!/usr/bin/env bash
here=$(dirname "$(readlink -f "$0")")
unset PYTHONHOME PYTHONPATH
exec /usr/bin/python3 -I "$here/usr/share/envbox/envbox.py" "$@"
''',
    'envbox.desktop': '''[Desktop Entry]
Type=Application
Name=envbox
Comment=Изолированные среды на bubblewrap
Exec=envbox
Icon=envbox
Terminal=false
Categories=System;Security;
''',
    'envbox.sh': r'''#!/usr/bin/env bash
# envbox — запуск одной команды в изолированной среде на базе bubblewrap.
#
#   envbox -n <имя> -w <каталог> [опции] -- <команда> [аргументы...]
#
# (Этот файл извлекается из envbox.py автоматически: правьте envbox.py.)
# Требования: Linux, bash >= 4.4, bubblewrap (>= 0.8 для --disable-userns),
# GNU coreutils (realpath). Запуск только от обычного пользователя.

set -euo pipefail

readonly PROG="envbox"

die()  { printf '%s: ошибка: %s\n' "$PROG" "$*" >&2; exit 1; }
warn() { printf '%s: предупреждение: %s\n' "$PROG" "$*" >&2; }
info() { printf '%s: %s\n' "$PROG" "$*" >&2; }

usage() {
  cat <<'EOF'
Использование:
  envbox -n <имя> -w <каталог> [опции] -- <команда> [аргументы...]

Обязательные:
  -n, --name <имя>        имя среды: [A-Za-z0-9][A-Za-z0-9._-]*, до 48 символов;
                          домашний каталог среды: <корень>/<имя>/home
                          (корень по умолчанию ~/.envbox, см. --root)
  -w, --workdir <каталог> рабочий каталог проекта (единственный путь хоста,
                          доступный на запись; не нужен с --no-workdir)

Опции:
  --root <каталог>        каталог данных envbox (по умолчанию ~/.envbox). Если не задан,
                          берётся переменная ENVBOX_ROOT, затем первая строка файла
                          ~/.config/envbox/root (его пишет GUI)
  --no-net                отключить сеть (остаётся только loopback внутри среды)
  --net-log               своей сети у среды нет; выход наружу только через
                          HTTP(S)-прокси на хосте, который журналирует каждое
                          соединение в <корень>/<имя>/net.log
  --allow-domain <домен>  разрешить только эти домены (включает --net-log);
                          'example.com' — точное совпадение, '*.example.com' —
                          домен и все поддомены; повторяемый
  --upstream <URL>        пускать весь трафик через вышестоящий прокси (включает --net-log):
                          http://хост:порт, socks5://хост:порт, socks5h://хост:порт.
                          Логин:пароль — только через переменную окружения
                          ENVBOX_UPSTREAM_AUTH=логин:пароль (в argv они были бы видны в ps).
                          Имена хостов тогда разрешает вышестоящий прокси, а не этот компьютер
  --direct-domain <домен> с --upstream: подключаться к этому сайту напрямую, мимо вышестоящего
                          прокси (сайт видит ваш настоящий адрес, а не адрес прокси). Среда по-прежнему
                          выходит только через прокси envbox. Формат как у --allow-domain; в режиме
                          --allow-domain такой сайт разрешён автоматически; повторяемый
  --expose-port <порт>    сделать порт 127.0.0.1:<порт> внутри среды доступным другим средам
                          через unix-сокет <корень>/<имя>/run/expose (нужен --net-log
                          или --no-net); повторяемый
  --attach <среда[:порт[:локальный]]>
                          внутри этой среды слушать 127.0.0.1:<локальный> (по умолчанию
                          <порт>, по умолчанию 9222) и пересылать на порт, открытый
                          средой <среда> через --expose-port (нужен --net-log или --no-net)
  --lang <локаль>         язык системы внутри среды (LANG), например ru_RU.UTF-8; локаль должна
                          быть сгенерирована на компьютере (locale -a)
  --timezone <пояс>       часовой пояс внутри среды, например Europe/Moscow (файл из
                          /usr/share/zoneinfo). Это пояс, а не подмена часов: время то же,
                          что у компьютера
  --dns <ip>              DNS-сервер для разрешения имён (повторяемый). С --net-log имена
                          разрешает прокси на компьютере через эти серверы; в режиме общей сети
                          они записываются в /etc/resolv.conf среды. Несовместим с --no-net
                          и --upstream (там имена разрешает вышестоящий прокси)
  --iso КЛЮЧ=on|off       включить или выключить одну защиту (повторяемый). По умолчанию включены все:
                          seccomp — фильтр системных вызовов (ptrace, bpf, io_uring, mount…)
                          pid — скрывать процессы компьютера   ipc — своя общая память (IPC)
                          uts — своё имя компьютера            cgroup — скрывать cgroup
                          session — без управляющего терминала (защита от TIOCSTI)
                          die_parent — завершать среду вместе с envbox
                          caps — сбросить capabilities         ro_root — корень среды только для чтения
                          clean_env — передавать только перечисленные переменные
                          neutral_dns — скрывать адреса ваших DNS в /etc/resolv.conf
                          host_net_forbidden — запретить сеть компьютера (сеть — только через прокси)
                          home_real=on — настоящий домашний каталог (нужен --confirm-host-access)
  --relaxed               старый «мягкий» набор: --iso seccomp=off --iso neutral_dns=off
                          --iso host_net_forbidden=off
  --host-files ro|rw      ВЫХОД ЗА ПЕСОЧНИЦУ: среда видит весь компьютер (ro — писать только в
                          проект, rw — писать везде) и работает с настоящим домашним каталогом.
                          Сеть, язык, часовой пояс и DNS остаются заданными. Требует
                          --confirm-host-access
  --confirm-host-access   подтверждение для --host-files: «я понимаю, что среда получает доступ
                          к моим файлам»
  --no-workdir            не монтировать рабочий каталог проекта (без -w); начальный
                          каталог — домашний каталог среды
  --wayland               пробросить сокет Wayland хоста (для окна браузера; ослабляет
                          изоляцию: композитор может отдавать снимки экрана любому клиенту)
  --net-allow-private     разрешить прокси соединяться с частными и loopback-
                          адресами (по умолчанию запрещено: это путь к сервисам хоста)
  --env VAR              передать переменную VAR со значением из окружения хоста
  --env VAR=значение      задать переменную явно (значение попадёт в argv envbox!)
  --ro <путь>             дополнительно смонтировать путь хоста только на чтение
                          (по тому же пути); повторяемый
  --rw <путь>             дополнительно смонтировать путь хоста на чтение и запись
                          (по тому же пути; как и проект, с защитой .git); повторяемый
  --global <имя>[:ro|:rw] подключить глобальную папку <корень>/_global/<имя> (по умолчанию
                          :rw) по её настоящему пути. Такие папки лежат отдельно от каталогов
                          сред: удаление среды их не затрагивает; повторяемый
  --path <каталог>        добавить каталог в начало PATH внутри среды; повторяемый
  --inbox-cmd <команда>   принимать ссылки от envbox: внутри среды запускается «команда ссылка»
                          (например claude-desktop: приложение откроет claude://… у себя)
  --inbox-scheme <схема>  разрешить ссылки такой схемы (например claude); http и https разрешены всегда; повторяемый
  --inbox-callback        принимать адреса http://localhost:порт/… и выполнять запрос внутри среды
                          (вход в Claude CLI: браузер на компьютере не может достучаться до порта среды)
  --shell <имя>           оболочка для интерактивной работы: bash (по умолчанию), fish или zsh.
                          Должна быть установлена на компьютере (в среде виден только /usr, на чтение).
                          Для удобства в пустой домашний каталог среды кладётся стартовый конфиг
  --ephemeral             домашний каталог среды в tmpfs (ничего не сохраняется)
  --no-protect-git        не защищать .git/hooks и .git/config от записи
  --allow-userns          разрешить вложенные user namespaces внутри среды
                          (нужно, если приложение само запускает bwrap/podman)
  --keep-session          то же, что --iso session=off; допустимо только если ядро запрещает
                          TIOCSTI (dev.tty.legacy_tiocsti = 0)
  --dry-run               показать команду bwrap и выйти (значения переменных
                          не печатаются)
  -h, --help              эта справка

Просмотр сетевого журнала среды:
  envbox --net-report -n <имя> [--follow | --raw]
    без флагов — сводка по хостам; --raw — все события; --follow — в реальном времени

Всегда передаются: HOME, USER, LOGNAME, SHELL, PATH, TERM (если задана на хосте),
LANG (C.UTF-8, если не передана через --env). Всё остальное окружение удаляется.
EOF
}

# --- проверки окружения запуска ---------------------------------------------

if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 4) )); then
  die "нужен bash >= 4.4, текущий: $BASH_VERSION"
fi
[[ "$(uname -s)" == Linux ]] || die "envbox работает только в Linux (bubblewrap использует namespaces ядра Linux)"
(( EUID != 0 )) || die "не запускайте envbox от root: изоляция рассчитана на непривилегированный user namespace"
[[ -n "${HOME:-}" && "$HOME" == /* && -d "$HOME" ]] || die "переменная HOME не задана или указывает на несуществующий каталог"

# --- разбор аргументов --------------------------------------------------------

name=""
workdir=""
net=1
ephemeral=0
protect_git=1
shell_name=bash
inbox_cmd=""
inbox_schemes=()
inbox_callback=0
allow_userns=0
dry_run=0
net_log=0
net_allow_private=0
net_report=0
report_mode=""
upstream=""
iso_seccomp=1 iso_pid=1 iso_ipc=1 iso_uts=1 iso_cgroup=1 iso_session=1 iso_die_parent=1
iso_caps=1 iso_ro_root=1 iso_clean_env=1 iso_neutral_dns=1 iso_net_forced=1 iso_home_real=0
host_files=""
host_confirm=0
lang=""
timezone=""
dns_servers=()
expose_ports=()
attach_specs=()
wayland=0
no_workdir=0
allow_domains=()
direct_domains=()
env_specs=()
ro_specs=()
rw_specs=()
global_specs=()
root_opt=""
path_specs=()

set_iso() {
  local key=${1%%=*} val=${1#*=} v
  [[ "$1" == *=* ]] || die "--iso: ожидается КЛЮЧ=on|off, получено '$1'"
  case "$val" in
    on|1|true|yes) v=1 ;;
    off|0|false|no) v=0 ;;
    *) die "--iso $key: значение должно быть on или off, получено '$val'" ;;
  esac
  case "$key" in
    seccomp) iso_seccomp=$v ;;
    pid) iso_pid=$v ;;
    ipc) iso_ipc=$v ;;
    uts) iso_uts=$v ;;
    cgroup) iso_cgroup=$v ;;
    session) iso_session=$v ;;
    die_parent) iso_die_parent=$v ;;
    caps) iso_caps=$v ;;
    ro_root) iso_ro_root=$v ;;
    clean_env) iso_clean_env=$v ;;
    neutral_dns) iso_neutral_dns=$v ;;
    host_net_forbidden) iso_net_forced=$v ;;
    home_real) iso_home_real=$v ;;
    *) die "--iso: неизвестная защита '$key' (см. --help)" ;;
  esac
}

need_arg() { (( $2 >= 2 )) || die "параметру $1 нужно значение (см. --help)"; }

while (( $# )); do
  case "$1" in
    -n|--name)        need_arg "$1" $#; name=$2; shift 2 ;;
    -w|--workdir)     need_arg "$1" $#; workdir=$2; shift 2 ;;
    --no-net)         net=0; shift ;;
    --net-log)        net_log=1; shift ;;
    --allow-domain)   need_arg "$1" $#; allow_domains+=("$2"); net_log=1; shift 2 ;;
    --net-allow-private) net_allow_private=1; shift ;;
    --direct-domain)  need_arg "$1" $#; direct_domains+=("$2"); shift 2 ;;
    --upstream)      need_arg "$1" $#; upstream=$2; net_log=1; shift 2 ;;
    --iso)            need_arg "$1" $#; set_iso "$2"; shift 2 ;;
    --relaxed)        iso_seccomp=0; iso_neutral_dns=0; iso_net_forced=0; shift ;;
    --host-files)     need_arg "$1" $#; host_files=$2; shift 2 ;;
    --confirm-host-access) host_confirm=1; shift ;;
    --lang)           need_arg "$1" $#; lang=$2; shift 2 ;;
    --timezone)       need_arg "$1" $#; timezone=$2; shift 2 ;;
    --dns)            need_arg "$1" $#; dns_servers+=("$2"); shift 2 ;;
    --expose-port)    need_arg "$1" $#; expose_ports+=("$2"); shift 2 ;;
    --attach)         need_arg "$1" $#; attach_specs+=("$2"); shift 2 ;;
    --wayland)        wayland=1; shift ;;
    --no-workdir)     no_workdir=1; shift ;;
    --net-report)     net_report=1; shift ;;
    --follow)         report_mode=--follow; shift ;;
    --raw)            report_mode=--raw; shift ;;
    --env)            need_arg "$1" $#; env_specs+=("$2"); shift 2 ;;
    --ro)             need_arg "$1" $#; ro_specs+=("$2"); shift 2 ;;
    --rw)             need_arg "$1" $#; rw_specs+=("$2"); shift 2 ;;
    --global)         need_arg "$1" $#; global_specs+=("$2"); shift 2 ;;
    --root)           need_arg "$1" $#; root_opt=$2; shift 2 ;;
    --path)           need_arg "$1" $#; path_specs+=("$2"); shift 2 ;;
    --shell)          need_arg "$1" $#; shell_name=$2; shift 2 ;;
    --inbox-cmd)      need_arg "$1" $#; inbox_cmd=$2; shift 2 ;;
    --inbox-scheme)   need_arg "$1" $#; inbox_schemes+=("$2"); shift 2 ;;
    --inbox-callback) inbox_callback=1; shift ;;
    --ephemeral)      ephemeral=1; shift ;;
    --no-protect-git) protect_git=0; shift ;;
    --allow-userns)   allow_userns=1; shift ;;
    --keep-session)   iso_session=0; shift ;;
    --dry-run)        dry_run=1; shift ;;
    -h|--help)        usage; exit 0 ;;
    --)               shift; break ;;
    -*)               die "неизвестный параметр: $1 (см. --help)" ;;
    *)                die "команда должна идти после '--' (встречено: $1)" ;;
  esac
done

cmd=("$@")

# --- валидация ------------------------------------------------------------------

[[ -n "$name" ]] || die "не задано имя среды (-n)"
[[ "$name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,47}$ ]] \
  || die "недопустимое имя среды '$name': разрешены латиница, цифры, '.', '_', '-', первый символ — буква или цифра, длина до 48"

# true, если путь $1 совпадает с $2 или лежит внутри него (оба — абсолютные, без '/' в конце)
is_under() { [[ "$1" == "$2" || "$1" == "$2"/* ]]; }

# Оболочка: берётся с компьютера (/usr виден в среде только на чтение)
login_shell=/bin/bash
case "$shell_name" in
  bash) ;;
  fish|zsh)
    shell_host=$(command -v "$shell_name" 2>/dev/null || true)
    [[ -n "$shell_host" ]] || die "оболочка $shell_name не установлена на компьютере (sudo pacman -S $shell_name)"
    shell_real=$(realpath -e -- "$shell_host") || die "не удалось разрешить путь $shell_host"
    is_under "$shell_real" /usr || die "оболочка $shell_name лежит вне /usr ($shell_real): в среде её не будет видно"
    login_shell=$shell_real ;;
  *) die "--shell: допустимы bash, fish, zsh (получено '$shell_name')" ;;
esac
# Приём ссылок
for sc in "${inbox_schemes[@]}"; do
  [[ "$sc" =~ ^[a-z][a-z0-9+.-]{0,30}$ ]] || die "--inbox-scheme: недопустимая схема '$sc' (строчные латинские буквы, цифры, '+', '.', '-')"
done
if (( ${#inbox_schemes[@]} )) && [[ -z "$inbox_cmd" ]]; then
  die "--inbox-scheme нужна вместе с --inbox-cmd: без команды ссылку некому открыть"
fi
inbox_on=0
if [[ -n "$inbox_cmd" ]] || (( inbox_callback )); then inbox_on=1; fi
# стартовые конфиги нужны только когда запускается сама оболочка
want_rc=0
case "$(basename -- "${cmd[0]:-}")" in bash|fish|zsh) want_rc=1 ;; esac

real_home=$(realpath -e -- "$HOME") || die "не удалось разрешить путь HOME: $HOME"
[[ "$real_home" != / ]] || die "HOME указывает на '/', так нельзя"

# Каталог данных: --root, затем ENVBOX_ROOT, затем файл ~/.config/envbox/root, иначе ~/.envbox
if [[ -z "$root_opt" ]]; then root_opt=${ENVBOX_ROOT:-}; fi
if [[ -z "$root_opt" ]]; then
  root_ptr="${XDG_CONFIG_HOME:-$real_home/.config}/envbox/root"
  if [[ -f "$root_ptr" && -r "$root_ptr" ]]; then IFS= read -r root_opt < "$root_ptr" || true; fi
fi
if [[ -z "$root_opt" ]]; then
  envbox_root="$real_home/.envbox"
else
  [[ "$root_opt" == /* ]] || die "каталог данных (--root) должен быть абсолютным путём: $root_opt"
  envbox_root=$(realpath -m -- "$root_opt") || die "не удалось разрешить каталог данных: $root_opt"
  [[ "$envbox_root" != / ]] || die "каталог данных не может быть '/'"
  if is_under "$real_home" "$envbox_root"; then
    die "каталог данных $envbox_root совпадает с HOME или содержит его — туда нельзя класть данные сред"
  fi
  if ! is_under "$envbox_root" "$real_home"; then   # HOME сам может лежать в /var/home
    case "$envbox_root" in
      /usr|/usr/*|/bin|/bin/*|/sbin|/sbin/*|/lib|/lib/*|/lib64|/lib64/*|/etc|/etc/*|/proc|/proc/*|/sys|/sys/*|/dev|/dev/*|/run|/run/*|/boot|/boot/*|/var|/var/*)
        die "каталог данных не может лежать в системном каталоге: $envbox_root" ;;
    esac
  fi
fi
# Глобальные папки: отдельные каталоги внутри корня, которые не принадлежат ни одной среде
global_root="$envbox_root/_global"
# true, если путь лежит строго внутри <корень>/_global (в глобальной папке, а не сам _global)
in_global_area() { [[ "$1" == "$global_root"/?* ]]; }
# true, если путь пересекается с данными envbox (корнем и каталогами сред), кроме глобальных папок
overlaps_envbox_data() {
  if in_global_area "$1"; then return 1; fi
  is_under "$1" "$envbox_root" || is_under "$envbox_root" "$1"
}

net_py=__ENVBOX_PY__
# Предкомпилированная копия запускается в разы быстрее: не нужно разбирать 10 000 строк при каждом вызове
# (seccomp, проверка git, мост, прокси). Если она устарела, собрана другой версией Python (после обновления
# системы файл .pyc перестаёт читаться) или отсутствует — используется обычный файл.
net_pyc="${net_py%.py}.pyc"
if [[ "$net_py" == *.py && -f "$net_pyc" && ! "$net_py" -nt "$net_pyc" && -r "$net_pyc.python" ]] \
   && [[ "$(< "$net_pyc.python")" == "$(readlink -f /usr/bin/python3 2>/dev/null)" ]]; then
  net_py=$net_pyc
fi
need_net_py() {
  [[ -f "$net_py" ]] || die "не найден $net_py — запустите: python3 envbox.py install"
  [[ -x /usr/bin/python3 ]] || die "для сетевого журнала нужен /usr/bin/python3"
}

# Режим просмотра журнала: команда не нужна
if (( net_report )); then
  (( ${#cmd[@]} == 0 )) || die "--net-report не принимает команду"
  need_net_py
  log_file="$envbox_root/$name/net.log"
  [[ -f "$log_file" ]] || die "журнал не найден: $log_file (среда запускалась с --net-log?)"
  exec /usr/bin/python3 -I "$net_py" report "$log_file" ${report_mode:+"$report_mode"}
fi
[[ -z "$report_mode" ]] || die "--follow и --raw используются только с --net-report"

(( ${#cmd[@]} )) || die "не указана команда после '--'"

# Жёсткий режим: сети компьютера нет, если явно не выбран другой режим сети
if (( iso_net_forced && net && ! net_log )); then
  net_log=1
  info "сеть компьютера запрещена: выход только через прокси с журналом (разрешить: --iso host_net_forbidden=off)"
fi

if (( net_log )); then
  (( net )) || die "--no-net и --net-log/--allow-domain взаимоисключающие"
  need_net_py
  for d in "${allow_domains[@]}"; do
    [[ "$d" =~ ^(\*\.)?[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$ ]] \
      || die "недопустимый домен для --allow-domain: '$d'"
  done
elif (( net_allow_private )); then
  die "--net-allow-private имеет смысл только вместе с --net-log"
fi

if [[ -n "$upstream" ]]; then
  upstream_re='^(http|socks5|socks5h)://[][A-Za-z0-9._:-]+$'
  [[ "$upstream" != *@* ]] \
    || die "логин и пароль нельзя указывать в --upstream (они видны в ps). Задайте переменную окружения ENVBOX_UPSTREAM_AUTH=логин:пароль"
  [[ "$upstream" =~ $upstream_re ]] \
    || die "недопустимый --upstream '$upstream': нужен http://хост:порт, socks5://хост:порт или socks5h://хост:порт"
fi
if (( ${#direct_domains[@]} )); then
  for d in "${direct_domains[@]}"; do
    [[ "$d" =~ ^(\*\.)?[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$ ]] \
      || die "недопустимый домен для --direct-domain: '$d'"
  done
  if [[ -z "$upstream" ]]; then
    warn "--direct-domain имеет смысл только вместе с --upstream (без него все соединения и так идут напрямую) — игнорирую"
    direct_domains=()
  fi
fi
if [[ -n "${ENVBOX_UPSTREAM_AUTH:-}" && -z "$upstream" ]]; then
  warn "ENVBOX_UPSTREAM_AUTH задана, но --upstream не указан — игнорирую"
fi

if (( iso_home_real )); then
  (( host_confirm )) || die "настоящий домашний каталог (--iso home_real=on) открывает среде ваши личные файлы. Если вы это понимаете, добавьте --confirm-host-access"
  warn "ВНИМАНИЕ: среда работает с настоящим домашним каталогом"
fi
if [[ -n "$host_files" ]]; then
  [[ "$host_files" == ro || "$host_files" == rw ]] || die "--host-files принимает ro или rw"
  (( host_confirm )) || die "--host-files даёт среде доступ к вашему компьютеру. Если вы это понимаете, добавьте --confirm-host-access"
  (( ! net || net_log )) || die "--host-files несовместим с сетью компьютера: используйте --net-log или --no-net"
  warn "ВНИМАНИЕ: включён доступ к файлам компьютера (--host-files $host_files). Среда видит настоящий домашний каталог"
fi

valid_ip() {
  local ip=$1 o
  if [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
    for o in "${BASH_REMATCH[@]:1}"; do (( 10#$o <= 255 )) || return 1; done
    return 0
  fi
  [[ "$ip" == *:* && "$ip" =~ ^[0-9A-Fa-f:.]+$ && ${#ip} -le 45 ]]
}
if [[ -n "$lang" ]]; then
  lang_re='^([A-Za-z]{2,3}(_[A-Za-z]{2,3})?(\.[A-Za-z0-9-]+)?(@[A-Za-z0-9]+)?|C|POSIX|C\.[A-Za-z0-9-]+)$'
  [[ "$lang" =~ $lang_re ]] || die "недопустимая локаль '$lang': ожидается вид ru_RU.UTF-8"
  case "$lang" in
    C|POSIX|C.*) ;;
    *)
      if command -v locale >/dev/null 2>&1; then
        want=${lang,,}; want=${want//utf-8/utf8}
        avail=$(locale -a 2>/dev/null | tr 'A-Z' 'a-z' | sed 's/utf-8/utf8/' || true)
        if ! grep -qxF -- "$want" <<<"$avail"; then
          warn "локаль '$lang' не найдена на этом компьютере (locale -a): программы вернутся к английскому. Сгенерируйте её (Arch: раскомментируйте строку в /etc/locale.gen и выполните sudo locale-gen)"
        fi
      fi ;;
  esac
fi
if [[ -n "$timezone" ]]; then
  tz_re='^[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+){0,2}$'
  [[ "$timezone" =~ $tz_re ]] || die "недопустимый часовой пояс '$timezone': ожидается вид Europe/Moscow"
  [[ -f "/usr/share/zoneinfo/$timezone" ]] \
    || die "часовой пояс '$timezone' не найден в /usr/share/zoneinfo (нужен пакет tzdata)"
fi
if (( ${#dns_servers[@]} )); then
  for d in "${dns_servers[@]}"; do
    valid_ip "$d" || die "недопустимый DNS-сервер '$d': нужен IP-адрес"
  done
  (( net )) || die "--dns не имеет смысла с --no-net: сети нет"
  [[ -z "$upstream" ]] || die "--dns несовместим с --upstream: имена разрешает вышестоящий прокси"
fi

box_dir="$envbox_root/$name"

if (( no_workdir )); then
  [[ -z "$workdir" ]] || die "--no-workdir несовместим с -w"
else
  [[ -n "$workdir" ]] || die "не задан рабочий каталог (-w); для среды без проекта используйте --no-workdir"
  [[ -e "$workdir" ]] || die "рабочий каталог не существует: $workdir"
  [[ -d "$workdir" ]] || die "рабочий путь не является каталогом: $workdir"
  workdir=$(realpath -e -- "$workdir") || die "не удалось разрешить путь рабочего каталога"
  [[ -w "$workdir" ]] || die "нет прав на запись в рабочий каталог: $workdir"
  [[ "$workdir" != / ]] || die "рабочий каталог не может быть '/'"
  if is_under "$real_home" "$workdir"; then
    die "рабочий каталог $workdir совпадает с HOME или содержит его — это открыло бы весь домашний каталог на запись"
  fi
  if overlaps_envbox_data "$workdir"; then
    die "рабочий каталог не может пересекаться с $envbox_root (кроме глобальных папок в $global_root)"
  fi
fi
# true, если путь лежит внутри смонтированного рабочего каталога
in_workdir() { (( ! no_workdir )) && is_under "$1" "$workdir"; }

# --expose-port и --attach
valid_port() { [[ "$1" =~ ^[0-9]{1,5}$ ]] && (( 10#$1 > 0 && 10#$1 < 65536 )); }
if (( ${#expose_ports[@]} || ${#attach_specs[@]} )); then
  (( ! net || net_log )) \
    || die "--expose-port и --attach требуют --net-log или --no-net: иначе порты открылись бы на сети хоста"
fi
for pt in "${expose_ports[@]}"; do
  valid_port "$pt" || die "недопустимый порт для --expose-port: '$pt'"
done
attach_names=(); attach_remote=(); attach_local=()
used_local=()
(( ! net_log )) || used_local+=(3128)
for pt in "${expose_ports[@]}"; do used_local+=("$((10#$pt))"); done
for spec in "${attach_specs[@]}"; do
  IFS=: read -r a_name a_port a_local extra <<<"$spec"
  [[ -z "${extra:-}" ]] || die "недопустимый формат --attach '$spec': нужно среда[:порт[:локальный_порт]]"
  a_port=${a_port:-9222}
  a_local=${a_local:-$a_port}
  [[ "$a_name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,47}$ ]] || die "недопустимое имя среды в --attach: '$a_name'"
  [[ "$a_name" != "$name" ]] || die "среда не может подключаться сама к себе (--attach $a_name)"
  valid_port "$a_port" || die "недопустимый порт в --attach: '$a_port'"
  valid_port "$a_local" || die "недопустимый локальный порт в --attach: '$a_local'"
  a_port=$((10#$a_port)); a_local=$((10#$a_local))
  for u in "${used_local[@]}"; do
    [[ "$u" != "$a_local" ]] || die "порт $a_local внутри среды уже занят (прокси, --expose-port или другой --attach)"
  done
  [[ -d "$envbox_root/$a_name" && ! -L "$envbox_root/$a_name" ]] \
    || die "среда '$a_name' не найдена в $envbox_root (создайте и запустите её сначала)"
  attach_names+=("$a_name"); attach_remote+=("$a_port"); attach_local+=("$a_local")
  used_local+=("$a_local")
done

if (( wayland )); then
  [[ -n "${WAYLAND_DISPLAY:-}" && -n "${XDG_RUNTIME_DIR:-}" ]] \
    || die "--wayland: на хосте не заданы WAYLAND_DISPLAY и XDG_RUNTIME_DIR (сеанс Wayland не запущен?)"
  [[ "$WAYLAND_DISPLAY" != */* && "$WAYLAND_DISPLAY" =~ ^[A-Za-z0-9._-]+$ ]] \
    || die "--wayland: значение WAYLAND_DISPLAY='$WAYLAND_DISPLAY' не поддерживается (нужно простое имя сокета)"
  wl_sock="$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY"
  [[ -S "$wl_sock" ]] || die "--wayland: нет сокета $wl_sock"
fi

# Разбор путей хоста для --ro и --rw: <ключ> <путь> -> результат в $resolved_path
resolve_host_path() {
  local opt=$1 p=$2 rp
  [[ -e "$p" ]] || die "путь для $opt не существует: $p"
  rp=$(realpath -e -- "$p") || die "не удалось разрешить путь $opt: $p"
  [[ "$rp" != / ]] || die "$opt / откроет всю файловую систему; укажите конкретные каталоги"
  if is_under "$real_home" "$rp"; then
    die "$opt $p совпадает с HOME или содержит его — реальный домашний каталог стал бы виден"
  fi
  if overlaps_envbox_data "$rp"; then
    die "$opt $p пересекается с $envbox_root (каталогами сред). Для общих данных используйте глобальные папки: --global"
  fi
  resolved_path=$rp
}

ro_paths=()
for p in "${ro_specs[@]}"; do
  resolve_host_path --ro "$p"
  ro_paths+=("$resolved_path")
done

rw_paths=()
for p in "${rw_specs[@]}"; do
  resolve_host_path --rw "$p"
  [[ -d "$resolved_path" ]] || die "--rw принимает только каталог: $p"
  [[ -w "$resolved_path" ]] || die "нет прав на запись в каталог для --rw: $p"
  rw_paths+=("$resolved_path")
done

# Глобальные папки: <корень>/_global/<имя>[:ro|:rw]. Только настоящие каталоги прямо внутри _global:
# ссылки запрещены, иначе папка вывела бы за пределы данных envbox.
global_paths=(); global_modes=()
for spec in "${global_specs[@]}"; do
  g_name=${spec%%:*}
  g_mode=rw
  if [[ "$spec" == *:* ]]; then g_mode=${spec#*:}; fi
  [[ "$g_name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,47}$ ]] \
    || die "--global: недопустимое имя папки '$g_name' (латиница, цифры, '.', '_', '-')"
  [[ "$g_mode" == ro || "$g_mode" == rw ]] || die "--global $g_name: режим должен быть ro или rw, получено '$g_mode'"
  g_path="$global_root/$g_name"
  [[ -d "$g_path" ]] || die "глобальная папка '$g_name' не найдена: $g_path (создайте её в GUI или командой mkdir)"
  for d in "$envbox_root" "$global_root" "$g_path"; do
    [[ ! -L "$d" ]] || die "$d — символическая ссылка; из соображений безопасности это запрещено"
  done
  [[ "$(realpath -e -- "$g_path")" == "$g_path" ]] || die "глобальная папка $g_path лежит не там, где указано (ссылки в пути)"
  if [[ "$g_mode" == rw ]]; then [[ -w "$g_path" ]] || die "нет прав на запись в глобальную папку $g_path"; fi
  for known in "${global_paths[@]}"; do
    [[ "$known" != "$g_path" ]] || die "глобальная папка '$g_name' указана дважды"
  done
  global_paths+=("$g_path"); global_modes+=("$g_mode")
done

for d in "${path_specs[@]}"; do
  [[ "$d" == /* ]] || die "--path требует абсолютный путь: $d"
  [[ "$d" != *:* ]] || die "--path не может содержать ':': $d"
done

# Переменные окружения: ключи в порядке появления, значения отдельно.
reserved_re='^(HOME|USER|LOGNAME|SHELL|PATH|PWD|OLDPWD)$'
loader_re='^(LD_.*|GCONV_PATH|GLIBC_TUNABLES|LOCPATH|NLSPATH|MALLOC_.*|HOSTALIASES|RES_OPTIONS|LOCALDOMAIN|BASH_ENV|BASH_FUNC_.*|ENV|PROMPT_COMMAND|SHELLOPTS|BASHOPTS|IFS|CDPATH|GLOBIGNORE|PS4)$'
env_keys=()
declare -A env_vals=()
for spec in "${env_specs[@]}"; do
  if [[ "$spec" == *=* ]]; then
    key=${spec%%=*}
    val=${spec#*=}
  else
    key=$spec
    if [[ ! "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
      die "недопустимое имя переменной: '$key'"
    fi
    if [[ -z "${!key+x}" ]]; then
      warn "переменная $key не задана на хосте — не передаю"
      continue
    fi
    val=${!key}
  fi
  [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || die "недопустимое имя переменной: '$key'"
  [[ ! "$key" =~ $reserved_re ]] || die "переменную $key задаёт сам envbox; используйте --path для PATH"
  [[ -n "${env_vals[$key]+x}" ]] || env_keys+=("$key")
  env_vals[$key]=$val
done

# --- bubblewrap ---------------------------------------------------------------

bwrap_bin=$(command -v bwrap) \
  || die "bwrap не найден. Установите: sudo pacman -S bubblewrap (Arch), sudo apt install bubblewrap (Debian/Ubuntu), sudo dnf install bubblewrap (Fedora)"
bwrap_bin=$(realpath -e -- "$bwrap_bin")
if [[ -u "$bwrap_bin" ]]; then
  die "$bwrap_bin установлен с setuid-битом. envbox рассчитан на непривилегированный режим; используйте bwrap без setuid (ядро должно разрешать user namespaces)"
fi

bwrap_help=$("$bwrap_bin" --help 2>&1 || true)
bwrap_has() { [[ "$bwrap_help" == *"$1"* ]]; }
has_unsetenv=0
bwrap_has --unsetenv && has_unsetenv=1

diagnose_userns() {
  local err=$1 v
  printf '%s: ошибка: bwrap не смог создать user namespace:\n  %s\n' "$PROG" "$err" >&2
  if [[ -r /proc/sys/kernel/apparmor_restrict_unprivileged_userns ]]; then
    v=$(< /proc/sys/kernel/apparmor_restrict_unprivileged_userns)
    if [[ "$v" == 1 ]]; then
      cat >&2 <<EOF

Причина, скорее всего: AppArmor ограничивает непривилегированные user namespaces
(kernel.apparmor_restrict_unprivileged_userns = 1, по умолчанию в Ubuntu 23.10+).
Не отключайте ограничение глобально. Разрешите userns только бинарнику bwrap:

  sudo tee /etc/apparmor.d/envbox-bwrap >/dev/null <<'PROFILE'
abi <abi/4.0>,
include <tunables/global>

profile envbox-bwrap $bwrap_bin flags=(unconfined) {
  userns,
  include if exists <local/envbox-bwrap>
}
PROFILE
  sudo apparmor_parser -r /etc/apparmor.d/envbox-bwrap

Сначала проверьте, нет ли уже профиля для bwrap: grep -rl bwrap /etc/apparmor.d/
EOF
      exit 1
    fi
  fi
  if [[ -r /proc/sys/kernel/unprivileged_userns_clone ]] && [[ "$(< /proc/sys/kernel/unprivileged_userns_clone)" == 0 ]]; then
    printf '\nkernel.unprivileged_userns_clone = 0: ядро запрещает непривилегированные user namespaces.\n' >&2
  fi
  if [[ -r /proc/sys/user/max_user_namespaces ]] && [[ "$(< /proc/sys/user/max_user_namespaces)" == 0 ]]; then
    printf '\nuser.max_user_namespaces = 0: user namespaces отключены.\n' >&2
  fi
  exit 1
}

if ! probe_err=$("$bwrap_bin" --unshare-user --ro-bind / / -- /usr/bin/true 2>&1); then
  diagnose_userns "$probe_err"
fi

if (( ! iso_session )); then
  tiocsti=""
  [[ -r /proc/sys/dev/tty/legacy_tiocsti ]] && tiocsti=$(< /proc/sys/dev/tty/legacy_tiocsti)
  [[ "$tiocsti" == 0 ]] \
    || die "отключать управляющий терминал нельзя (--iso session=off / --keep-session): ядро разрешает TIOCSTI (dev.tty.legacy_tiocsti != 0 или параметр отсутствует)"
fi

# --- каталог среды ----------------------------------------------------------

for d in "$envbox_root" "$box_dir" "$box_dir/home" "$box_dir/etc" "$box_dir/empty"; do
  [[ ! -L "$d" ]] || die "$d — символическая ссылка; из соображений безопасности это запрещено"
  if [[ ! -d "$d" ]]; then
    mkdir -m 700 -- "$d" || die "не удалось создать каталог $d"
  fi
done
chmod 700 -- "$envbox_root" "$box_dir"

if true; then   # каталог run нужен всегда: в нём каналы ссылок
  run_dir="$box_dir/run"
  [[ ! -L "$run_dir" ]] || die "$run_dir — символическая ссылка; это запрещено"
  [[ -d "$run_dir" ]] || mkdir -m 700 -- "$run_dir"
fi
if (( ${#expose_ports[@]} )); then
  [[ ! -L "$run_dir/expose" ]] || die "$run_dir/expose — символическая ссылка; это запрещено"
  [[ -d "$run_dir/expose" ]] || mkdir -m 700 -- "$run_dir/expose"
fi
if (( inbox_on )); then
  [[ ! -L "$run_dir/inbox" ]] || die "$run_dir/inbox — символическая ссылка; это запрещено"
  [[ -d "$run_dir/inbox" ]] || mkdir -m 700 -- "$run_dir/inbox"
fi
# Канал links: программа в среде (xdg-open, $BROWSER, Electron, CLI) просит открыть ссылку; envbox на компьютере
# читает этот каталог, проверяет адреса и открывает их в изолированном браузере. Среда сама ничего не открывает.
for d in links bin; do
  [[ ! -L "$run_dir/$d" ]] || die "$run_dir/$d — символическая ссылка; это запрещено"
  [[ -d "$run_dir/$d" ]] || mkdir -m 700 -- "$run_dir/$d"
done


for a_name in "${attach_names[@]}"; do
  for d in "$envbox_root/$a_name/run" "$envbox_root/$a_name/run/expose"; do
    [[ ! -L "$d" ]] || die "$d — символическая ссылка; это запрещено"
    [[ -d "$d" ]] || mkdir -m 700 -- "$d"
  done
done
proxy_pid=""
cleanup() {
  if [[ -n "$proxy_pid" ]]; then
    kill "$proxy_pid" 2>/dev/null || true
    wait "$proxy_pid" 2>/dev/null || true
  fi
  [[ -z "${sock:-}" ]] || rm -f -- "$sock"
}
if (( net_log )); then
  sock="$run_dir/proxy.sock"
  (( ${#sock} < 100 )) || die "слишком длинный путь к сокету прокси ($sock); укоротите имя среды"
  net_log_file="$box_dir/net.log"
  readonly bridge_port=3128
  trap cleanup EXIT
  if (( ! dry_run )); then
    # С --net-log прокси на хосте живёт, пока работает среда. Запускаем его сразу: старт (~0,1 с) идёт параллельно
    # остальной подготовке, а к запуску bwrap сокет уже готов.
    proxy_args=()
    for d in "${allow_domains[@]}"; do proxy_args+=(--allow "$d"); done
    (( net_allow_private )) && proxy_args+=(--allow-private)
    [[ -z "$upstream" ]] || proxy_args+=(--upstream "$upstream")
    for d in "${direct_domains[@]}"; do proxy_args+=(--direct "$d"); done
    for d in "${dns_servers[@]}"; do proxy_args+=(--dns "$d"); done
    rm -f -- "$sock"
    /usr/bin/python3 -I "$net_py" proxy --socket "$sock" --log "$net_log_file" \
      --parent-pid $$ "${proxy_args[@]}" </dev/null &
    proxy_pid=$!
  fi
fi

uid=$(id -u); gid=$(id -g)
user=$(id -un); group=$(id -gn)
hostname="envbox-$name"

write_file() {  # атомарная запись: write_file <путь> <содержимое>
  local tmp
  tmp=$(mktemp -- "$1.XXXXXX")
  printf '%s' "$2" > "$tmp"
  chmod 644 -- "$tmp"
  mv -f -- "$tmp" "$1"
}
# Шимы канала ссылок (каталоги links и bin созданы выше)
IFS= read -r -d '' open_url_shim <<'SHIM_EOF' || true
#!/bin/sh
# envbox: передаёт ссылку приложению envbox на компьютере; она откроется в изолированном браузере
url=$1
case "$url" in
  http://*|https://*) ;;
  *) echo "envbox: открываются только ссылки http и https" >&2; exit 1 ;;
esac
d=${ENVBOX_LINK_DIR:-/run/envbox/links}
[ -d "$d" ] || { echo "envbox: канал ссылок недоступен" >&2; exit 1; }
f="$d/$(date +%s%N 2>/dev/null || date +%s).$$"
printf '%s\n' "$url" > "$f.tmp" && mv "$f.tmp" "$f" || exit 1
echo "envbox: ссылка передана приложению envbox; если оно запущено, оно откроет её в изолированном браузере: $url" >&2
SHIM_EOF
write_file "$run_dir/bin/open-url" "$open_url_shim"
chmod 755 -- "$run_dir/bin/open-url"
ln -sf open-url "$run_dir/bin/xdg-open"

write_file "$box_dir/etc/passwd" \
"$user:x:$uid:$gid:envbox:$real_home:$login_shell
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
"
write_file "$box_dir/etc/group" \
"$group:x:$gid:
nogroup:x:65534:
"
write_file "$box_dir/etc/hosts" \
"127.0.0.1 localhost
::1 localhost ip6-localhost ip6-loopback
127.0.1.1 $hostname
"
write_file "$box_dir/etc/hostname" "$hostname
"

# --- PATH внутри среды -------------------------------------------------------

# каталоги, куда ставятся Node, Go, Rust, Bun, Deno из рецептов установки (если их нет — не мешают)
sandbox_path_parts=("${path_specs[@]}" "$real_home/.local/bin" "$real_home/.local/go/bin"
  "$real_home/go/bin" "$real_home/.cargo/bin" "$real_home/.bun/bin" "$real_home/.deno/bin"
  /usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin)
sandbox_path=$(IFS=:; printf '%s' "${sandbox_path_parts[*]}")
sandbox_path="/run/envbox/bin:$sandbox_path"   # xdg-open и open-url из канала ссылок идут первыми

# Где на хосте реально лежит каталог $1 так, как его увидит среда.
host_view_of() {
  local d=$1 rp
  if in_workdir "$d"; then printf '%s' "$d"; return; fi
  for rp in "${ro_paths[@]}"; do
    if is_under "$d" "$rp"; then printf '%s' "$d"; return; fi
  done
  if is_under "$d" "$real_home"; then
    (( ephemeral )) && return 1
    printf '%s' "$box_dir/home${d#"$real_home"}"; return
  fi
  case "$d" in
    /usr|/usr/*|/bin|/sbin) printf '%s' "$d" ;;
    *) return 1 ;;
  esac
}

# Предупредить, если команда не будет найдена внутри среды.
if [[ "${cmd[0]}" != */* ]]; then
  found=0
  for d in "${sandbox_path_parts[@]}"; do
    hv=$(host_view_of "$d") || continue
    if [[ -x "$hv/${cmd[0]}" ]]; then found=1; break; fi
  done
  if (( ! found )); then
    host_loc=$(command -v -- "${cmd[0]}" 2>/dev/null || true)
    if [[ -n "$host_loc" ]]; then
      warn "'${cmd[0]}' не будет найден внутри среды. На хосте он лежит в $host_loc ($(realpath -- "$host_loc" 2>/dev/null || echo '?')). Добавьте нужные каталоги через --ro и --path или установите программу внутри среды"
    else
      warn "'${cmd[0]}' не найден ни в PATH среды, ни на хосте"
    fi
  fi
fi

# --- аргументы bwrap ------------------------------------------------------------

args=()

# true, если путь лежит в месте, доступном среде на запись: проект, --rw или глобальная папка в режиме rw.
# Поверх таких мест путь «только чтение» монтируется отдельно, после них.
in_writable() {
  local x i
  in_workdir "$1" && return 0
  for x in "${rw_paths[@]}"; do is_under "$1" "$x" && return 0; done
  for i in "${!global_paths[@]}"; do
    [[ "${global_modes[i]}" == rw ]] && is_under "$1" "${global_paths[i]}" && return 0
  done
  return 1
}

# Каталоги, где защищаются .git/hooks и .git/config: проект, --rw и глобальные папки с записью
git_dirs=()
add_git_dir() {
  local x
  for x in "${git_dirs[@]}"; do [[ "$x" != "$1" ]] || return 0; done
  git_dirs+=("$1")
}
if (( protect_git )); then
  (( no_workdir )) || add_git_dir "$workdir"
  for rp in "${rw_paths[@]}"; do add_git_dir "$rp"; done
  for i in "${!global_paths[@]}"; do
    [[ "${global_modes[i]}" != rw ]] || add_git_dir "${global_paths[i]}"
  done
fi
# Снимки состояния Git запускаются сразу и работают параллельно подготовке; результат ждём перед запуском среды
git_snap_pids=()
if (( ! dry_run )); then
  for gi in "${!git_dirs[@]}"; do
    /usr/bin/python3 -I "$net_py" gitcheck snapshot "${git_dirs[gi]}" >"$box_dir/git.snapshot.$gi" 2>/dev/null &
    git_snap_pids[gi]=$!
  done
fi

# Защита Git для каталога $1: хуки и config недоступны на запись, сам .git нельзя переименовать или заменить
# (иначе программа подложила бы хук, который выполнится у вас при команде git)
protect_git_dir() {
  local dir=$1 gitp gp hp
  gitp="$dir/.git"
  if [[ -L "$gitp" ]]; then
    warn ".git в $dir — символическая ссылка: защита Git не применяется"
  elif [[ -d "$gitp" ]]; then
    args+=(--bind "$gitp" "$gitp")
    if [[ -d "$gitp/hooks" ]]; then
      args+=(--ro-bind "$gitp/hooks" "$gitp/hooks")
    else
      args+=(--ro-bind "$box_dir/empty" "$gitp/hooks")
    fi
    [[ ! -e "$gitp/config" ]] || args+=(--ro-bind "$gitp/config" "$gitp/config")
    if [[ -d "$gitp/modules" ]]; then
      while IFS= read -r gp; do
        args+=(--ro-bind "$gp" "$gp")
      done < <(find "$gitp/modules" -maxdepth 5 \( -type d -name hooks -o -type f -name config \) 2>/dev/null)
    fi
    hp=$(git config --file "$gitp/config" --get core.hooksPath 2>/dev/null || true)
    if [[ -n "$hp" ]]; then
      [[ "$hp" == /* ]] || hp="$dir/$hp"
      hp=$(realpath -m -- "$hp")
      if [[ -d "$hp" ]] && is_under "$hp" "$dir" && ! is_under "$hp" "$gitp"; then
        args+=(--ro-bind "$hp" "$hp")
      fi
    fi
  elif [[ -f "$gitp" ]]; then
    args+=(--ro-bind "$gitp" "$gitp")
  fi
}

# Данные envbox: при доступе к файлам компьютера скрываем другие среды (там токены) и защищаем код envbox
hide_envbox_data() {
  local inst
  inst=$(dirname "$net_py")
  args+=(--tmpfs "$envbox_root")
  if [[ -d "$inst" ]]; then args+=(--ro-bind "$inst" "$inst"); fi
}

# Пространства имён
args+=(--unshare-user)
(( ! iso_ipc )) || args+=(--unshare-ipc)
(( ! iso_pid )) || args+=(--unshare-pid)
(( ! iso_uts )) || args+=(--unshare-uts --hostname "$hostname")
(( ! iso_cgroup )) || args+=(--unshare-cgroup)
args+=(--setenv ENVBOX_SESSION "$name")   # метка для списка запущенных сред
(( net && ! net_log )) || args+=(--unshare-net)
if (( ! allow_userns )); then
  if bwrap_has --disable-userns; then
    args+=(--disable-userns)
  else
    warn "ваш bwrap не поддерживает --disable-userns (нужен >= 0.8): вложенные user namespaces внутри среды не запрещены"
  fi
fi

# Жизненный цикл и привилегии
(( ! iso_die_parent )) || args+=(--die-with-parent)
(( ! iso_caps )) || args+=(--cap-drop ALL)
(( ! iso_session )) || args+=(--new-session)

# /proc: свой (в своём пространстве процессов) или, если оно отключено, процессы компьютера
proc_args=(--proc /proc)
(( iso_pid )) || proc_args=(--ro-bind /proc /proc)

if [[ -n "$host_files" ]]; then
  # ВЫХОД ЗА ПЕСОЧНИЦУ: весь компьютер (ro или rw), поверх — свои /proc, /dev, /tmp, /run
  if [[ "$host_files" == rw ]]; then args+=(--bind / /); else args+=(--ro-bind / /); fi
  args+=("${proc_args[@]}" --dev /dev --tmpfs /dev/shm --tmpfs /tmp --tmpfs /run)
  hide_envbox_data
else
  # Системные каталоги: только чтение
  args+=(--ro-bind /usr /usr)
  for d in bin sbin lib lib32 lib64 libx32; do
    if [[ -L "/$d" ]]; then
      args+=(--symlink "$(readlink -- "/$d")" "/$d")
    elif [[ -d "/$d" ]]; then
      args+=(--ro-bind "/$d" "/$d")
    fi
  done

  # Виртуальные ФС и временные каталоги (не на диске хоста)
  args+=("${proc_args[@]}" --dev /dev --tmpfs /dev/shm --tmpfs /tmp --tmpfs /run
         --dir /var --tmpfs /var/tmp)
fi

# Мост внутри среды: сокет прокси хоста, порты для других сред, порты чужих сред
need_wrap=0
(( net_log || ${#expose_ports[@]} || ${#attach_names[@]} || inbox_on )) && need_wrap=1
args+=(--dir /run/envbox --bind "$run_dir/links" /run/envbox/links --ro-bind "$run_dir/bin" /run/envbox/bin)
if (( need_wrap )); then
  args+=(--ro-bind "$net_py" /run/envbox/net.py)
fi
if (( net_log )); then
  args+=(--bind "$sock" /run/envbox/proxy.sock)
fi
if (( ${#expose_ports[@]} )); then
  args+=(--bind "$run_dir/expose" /run/envbox/expose)
fi
if (( inbox_on )); then
  args+=(--bind "$run_dir/inbox" /run/envbox/inbox)
fi
for i in "${!attach_names[@]}"; do
  args+=(--ro-bind "$envbox_root/${attach_names[i]}/run/expose" "/run/envbox/attach/${attach_names[i]}")
done
if (( wayland )); then
  args+=(--perms 0700 --dir "/run/user/$uid" --bind "$wl_sock" "/run/user/$uid/$WAYLAND_DISPLAY")
fi

# DNS внутри среды: заданные серверы; в жёстком режиме без сети компьютера — нейтральный файл
# (адреса ваших DNS-серверов среде не раскрываются)
resolv=""
if (( ${#dns_servers[@]} )); then
  for d in "${dns_servers[@]}"; do resolv+="nameserver $d"$'\n'; done
elif (( iso_neutral_dns && ( ! net || net_log ) )); then
  resolv=$'# envbox: имена разрешает прокси на компьютере\nnameserver 127.0.0.1\n'
fi
if [[ -n "$resolv" ]]; then
  write_file "$box_dir/etc/resolv.conf" "$resolv"
fi

if [[ -z "$host_files" ]]; then
  # /etc: только нужное для динамической линковки, TLS, DNS, локали, времени
  etc_items=(ssl ca-certificates pki crypto-policies resolv.conf nsswitch.conf
    host.conf gai.conf localtime ld.so.cache ld.so.conf ld.so.conf.d alternatives
    terminfo os-release protocols services mime.types fonts)
  for i in "${etc_items[@]}"; do
    [[ "$i" == localtime && -n "$timezone" ]] && continue
    [[ "$i" == resolv.conf && -n "$resolv" ]] && continue
    [[ -e "/etc/$i" ]] && args+=(--ro-bind "/etc/$i" "/etc/$i")
  done
  if [[ -n "$timezone" ]]; then
    args+=(--symlink "/usr/share/zoneinfo/$timezone" /etc/localtime)
  fi
  if [[ -n "$resolv" ]]; then
    args+=(--ro-bind "$box_dir/etc/resolv.conf" /etc/resolv.conf)
  fi
  for f in passwd group hosts hostname; do
    args+=(--ro-bind "$box_dir/etc/$f" "/etc/$f")
  done
elif [[ -n "$resolv" ]]; then
  # настоящий /etc виден; подменяем только файл DNS (по ссылке, если это ссылка)
  args+=(--ro-bind "$box_dir/etc/resolv.conf" "$(realpath -m /etc/resolv.conf)")
fi

# Стартовые настройки оболочек: в пустом домашнем каталоге среды приглашение было бы голым «bash-5.3$».
# Файлы кладутся в домашний каталог среды, только если их там нет (ваши правки не затираются).
prepare_rc() {
  local d="$box_dir/rc" bashrc zshrc fishrc
  mkdir -p -- "$d"
  IFS= read -r -d '' bashrc <<'RC_EOF' || true
# envbox: настройки bash по умолчанию. Файл можно менять: пока он существует, envbox его не трогает.
[[ $- == *i* ]] || return 0
shopt -s histappend checkwinsize cmdhist 2>/dev/null
HISTSIZE=50000; HISTFILESIZE=100000; HISTCONTROL=ignoreboth:erasedups
[[ -r /usr/share/bash-completion/bash_completion ]] && . /usr/share/bash-completion/bash_completion
bind 'set completion-ignore-case on' 2>/dev/null
bind 'set show-all-if-ambiguous on' 2>/dev/null
bind '"\e[A": history-search-backward' 2>/dev/null
bind '"\e[B": history-search-forward' 2>/dev/null
PS1='\[\e[1;32m\][${ENVBOX_SESSION:-envbox}]\[\e[0m\] \[\e[1;34m\]\w\[\e[0m\] \$ '
alias ls='ls --color=auto'; alias ll='ls -lah'; alias la='ls -A'; alias grep='grep --color=auto'
RC_EOF
  write_file "$d/bashrc" "$bashrc"
  write_file "$d/bash_profile" $'[[ -f ~/.bashrc ]] && . ~/.bashrc\n'
  IFS= read -r -d '' zshrc <<'RC_EOF' || true
# envbox: настройки zsh по умолчанию. Файл можно менять: пока он существует, envbox его не трогает.
autoload -Uz compinit && compinit -u -d ~/.zcompdump
zstyle ':completion:*' menu select
zstyle ':completion:*' matcher-list 'm:{a-zA-Z}={A-Za-z}'
HISTFILE=~/.zsh_history; HISTSIZE=50000; SAVEHIST=50000
setopt SHARE_HISTORY HIST_IGNORE_ALL_DUPS AUTO_CD INTERACTIVE_COMMENTS PROMPT_SUBST
bindkey -e
bindkey '^[[A' history-beginning-search-backward
bindkey '^[[B' history-beginning-search-forward
bindkey '^[[3~' delete-char; bindkey '^[[H' beginning-of-line; bindkey '^[[F' end-of-line
PROMPT='%F{green}[${ENVBOX_SESSION:-envbox}]%f %F{blue}%~%f %# '
alias ls='ls --color=auto'; alias ll='ls -lah'; alias la='ls -A'; alias grep='grep --color=auto'
RC_EOF
  write_file "$d/zshrc" "$zshrc"
  IFS= read -r -d '' fishrc <<'RC_EOF' || true
# envbox: настройки fish по умолчанию. Файл можно менять: пока он существует, envbox его не трогает.
set -g fish_greeting
function fish_prompt
    set -l last $status
    set_color green; echo -n "[$ENVBOX_SESSION] "
    set_color blue; echo -n (prompt_pwd)
    if test $last -ne 0
        set_color red; echo -n " [$last]"
    end
    set_color normal; echo -n ' > '
end
alias ll 'ls -lah'
alias la 'ls -A'
RC_EOF
  write_file "$d/fish_config" "$fishrc"
}
seed_rc() {  # seed_rc <файл в rc> <путь в домашнем каталоге среды>
  # Домашний каталог среды пишет сама среда: она могла заменить .config ссылкой на каталог компьютера.
  # Ссылки в пути не раскрываются, а файл создаётся только если его ещё нет (noclobber = O_EXCL).
  local src="$box_dir/rc/$1" dst=$2 cur="$box_dir/home" comps i
  [[ ! -e "$dst" && ! -L "$dst" ]] || return 0
  IFS=/ read -ra comps <<<"${dst#"$cur"/}"
  for ((i = 0; i < ${#comps[@]} - 1; i++)); do
    cur="$cur/${comps[i]}"
    [[ ! -L "$cur" ]] || return 0
    [[ -d "$cur" ]] || mkdir -- "$cur" 2>/dev/null || return 0
  done
  ( set -C; cat -- "$src" > "$dst" ) 2>/dev/null || true
}

# Домашний каталог среды по пути реального HOME (при --host-files виден настоящий)
if [[ -z "$host_files" ]]; then
  if (( iso_home_real )); then
    args+=(--bind "$real_home" "$real_home")
    hide_envbox_data
  elif (( ephemeral )); then
    args+=(--tmpfs "$real_home")
    if (( want_rc )); then
      prepare_rc
      case "$shell_name" in
        bash) args+=(--ro-bind "$box_dir/rc/bashrc" "$real_home/.bashrc"
                     --ro-bind "$box_dir/rc/bash_profile" "$real_home/.bash_profile") ;;
        zsh)  args+=(--ro-bind "$box_dir/rc/zshrc" "$real_home/.zshrc") ;;
        fish) args+=(--ro-bind "$box_dir/rc/fish_config" "$real_home/.config/fish/config.fish") ;;
      esac
    fi
  else
    if (( want_rc )); then
      prepare_rc
      case "$shell_name" in
        bash) seed_rc bashrc "$box_dir/home/.bashrc"; seed_rc bash_profile "$box_dir/home/.bash_profile" ;;
        zsh)  seed_rc zshrc "$box_dir/home/.zshrc" ;;
        fish) seed_rc fish_config "$box_dir/home/.config/fish/config.fish" ;;
      esac
    fi
    args+=(--bind "$box_dir/home" "$real_home")
  fi

  # Пути только для чтения, лежащие вне мест с записью
  for rp in "${ro_paths[@]}"; do
    in_writable "$rp" || args+=(--ro-bind "$rp" "$rp")
  done
fi

# Дополнительные папки с записью (--rw); при --host-files ro они остаются доступными на запись
for rp in "${rw_paths[@]}"; do
  in_workdir "$rp" || args+=(--bind "$rp" "$rp")
done

# Глобальные папки: подключаются и при --host-files (там корень данных скрыт tmpfs)
for i in "${!global_paths[@]}"; do
  if [[ "${global_modes[i]}" == rw ]]; then
    args+=(--bind "${global_paths[i]}" "${global_paths[i]}")
  else
    args+=(--ro-bind "${global_paths[i]}" "${global_paths[i]}")
  fi
done

# Рабочий каталог: чтение и запись
if (( ! no_workdir )); then
  args+=(--bind "$workdir" "$workdir")
fi

# Пути только для чтения внутри мест с записью (поверх них)
for rp in "${ro_paths[@]}"; do
  if in_writable "$rp"; then args+=(--ro-bind "$rp" "$rp"); fi
done

# Защита Git: проект, папки --rw и глобальные папки с записью
for d in "${git_dirs[@]}"; do
  protect_git_dir "$d"
done

# Корень (tmpfs, созданный bwrap) — только чтение
(( ! iso_ro_root )) || [[ -n "$host_files" ]] || args+=(--remount-ro /)

if (( no_workdir )); then
  args+=(--chdir "$real_home")
else
  args+=(--chdir "$workdir")
fi

# Базовые переменные без секретов (через argv, это безопасно)
args+=(--setenv HOME "$real_home" --setenv USER "$user" --setenv LOGNAME "$user"
       --setenv SHELL "$login_shell" --setenv PATH "$sandbox_path")
[[ -n "${TERM:-}" ]] && args+=(--setenv TERM "$TERM")
[[ -n "${env_vals[BROWSER]+x}" ]] || args+=(--setenv BROWSER /run/envbox/bin/open-url)
if [[ -n "$lang" ]]; then
  args+=(--setenv LANG "$lang")
  if [[ "$lang" == *_* ]]; then
    args+=(--setenv LANGUAGE "${lang%%.*}:${lang%%_*}")
  fi
elif [[ -z "${env_vals[LANG]+x}" ]]; then
  args+=(--setenv LANG C.UTF-8)
fi
[[ -z "$timezone" ]] || args+=(--setenv TZ "$timezone")

if (( wayland )); then
  args+=(--setenv XDG_RUNTIME_DIR "/run/user/$uid" --setenv WAYLAND_DISPLAY "$WAYLAND_DISPLAY")
fi

final_cmd=("${cmd[@]}")
if (( need_wrap )); then
  wrap_args=()
  if (( net_log )); then
    proxy_url="http://127.0.0.1:$bridge_port"
    for v in HTTP_PROXY http_proxy HTTPS_PROXY https_proxy; do
      args+=(--setenv "$v" "$proxy_url")
    done
    args+=(--setenv NODE_USE_ENV_PROXY 1)
    wrap_args+=(--map "$bridge_port:/run/envbox/proxy.sock")
  fi
  # локальные адреса (в том числе проброшенный порт браузера) идут мимо прокси
  args+=(--setenv NO_PROXY "localhost,127.0.0.1,::1" --setenv no_proxy "localhost,127.0.0.1,::1")
  for pt in "${expose_ports[@]}"; do
    pt=$((10#$pt))
    wrap_args+=(--serve "/run/envbox/expose/$pt.sock:$pt")
  done
  for i in "${!attach_names[@]}"; do
    wrap_args+=(--map "${attach_local[i]}:/run/envbox/attach/${attach_names[i]}/${attach_remote[i]}.sock")
  done
  if (( ${#attach_names[@]} )); then
    args+=(--setenv ENVBOX_BROWSER_CDP_URL "http://127.0.0.1:${attach_local[0]}")
  fi
  if (( inbox_on )); then
    wrap_args+=(--inbox /run/envbox/inbox)
    [[ -z "$inbox_cmd" ]] || wrap_args+=(--inbox-cmd "$inbox_cmd")
    for sc in "${inbox_schemes[@]}"; do wrap_args+=(--inbox-scheme "$sc"); done
    if (( inbox_callback )); then wrap_args+=(--inbox-callback); fi
  fi
  final_cmd=(/usr/bin/python3 -I /run/envbox/net.py wrap "${wrap_args[@]}" -- "${cmd[@]}")
fi

# --- запуск ---------------------------------------------------------------------

# Фильтр системных вызовов: запрещает ptrace, bpf, io_uring, mount, perf и т. п.
seccomp_file=""
if (( iso_seccomp )); then
  seccomp_allow=()
  (( ! allow_userns )) || seccomp_allow=(--allow chroot)   # песочнице Chrome нужен chroot во вложенном пространстве имён
  # Фильтр зависит только от версии envbox и набора исключений: готовый переиспользуется (~65 мс экономии)
  seccomp_key="$(stat -c '%Y:%s' -- "$net_py" 2>/dev/null || echo ?):${seccomp_allow[*]:-}"
  if [[ -s "$box_dir/seccomp.bpf" && -r "$box_dir/seccomp.key" && "$(< "$box_dir/seccomp.key")" == "$seccomp_key" ]]; then
    seccomp_file="$box_dir/seccomp.bpf"
  elif /usr/bin/python3 -I "$net_py" seccomp "${seccomp_allow[@]}" >"$box_dir/seccomp.bpf.new" 2>/dev/null && [[ -s "$box_dir/seccomp.bpf.new" ]]; then
    mv -f -- "$box_dir/seccomp.bpf.new" "$box_dir/seccomp.bpf"
    printf '%s' "$seccomp_key" > "$box_dir/seccomp.key"
    seccomp_file="$box_dir/seccomp.bpf"
  else
    warn "фильтр системных вызовов недоступен (нужны x86_64 и /usr/bin/python3): среда запустится без него"
  fi
fi

if (( dry_run )); then
  printf '%s: seccomp-фильтр: %s\n' "$PROG" "${seccomp_file:-нет}"
  printf '%s: команда:\n' "$PROG"
  printf '%q ' "$bwrap_bin" "${args[@]}" -- "${final_cmd[@]}"
  printf '\n%s: дополнительные переменные (значения скрыты):' "$PROG"
  printf ' %s' "${env_keys[@]}"
  printf '\n'
  exit 0
fi

# Git: снимок состояния до запуска; после выхода envbox сравнит и предупредит об изменениях.
# Снимок делается и для проекта без .git: среда может создать его сама, подложив хук или config.
git_watch_dirs=(); git_watch_snaps=()
for gi in "${!git_snap_pids[@]}"; do
  if wait "${git_snap_pids[gi]}" 2>/dev/null; then
    git_watch_dirs+=("${git_dirs[gi]}"); git_watch_snaps+=("$box_dir/git.snapshot.$gi")
  fi
done
post_checks() {
  local k
  for k in "${!git_watch_dirs[@]}"; do
    /usr/bin/python3 -I "$net_py" gitcheck verify "${git_watch_dirs[k]}" "${git_watch_snaps[k]}" || true
  done
}

# Пользовательские переменные (в том числе секреты) передаются через окружение,
# а не через argv, иначе они видны в `ps` всем пользователям хоста.
declare -A allowed=()
for k in "${env_keys[@]}"; do allowed[$k]=1; done

run_sandbox() {
  local v leftovers=() sfd pfd perr true_bin probe_args
  unset -v ENVBOX_UPSTREAM_AUTH 2>/dev/null || true   # прокси уже получил пароль; среде он не нужен ни при каких настройках
  if (( iso_clean_env )); then
    while IFS= read -r v; do
      [[ -n "${allowed[$v]+x}" ]] && continue
      unset -v "$v" 2>/dev/null || true
    done < <(compgen -e)
    # Переменные, которые не удалось удалить (readonly), снимаем на стороне bwrap
    while IFS= read -r v; do
      [[ -n "${allowed[$v]+x}" ]] || leftovers+=("$v")
    done < <(compgen -e)
  fi
  for v in "${leftovers[@]}"; do
    if (( has_unsetenv )); then
      args=(--unsetenv "$v" "${args[@]}")
    else
      die "не удалось удалить переменную $v, а bwrap не поддерживает --unsetenv"
    fi
  done
  # bash сам добавляет '_' и SHLVL в окружение процесса при exec
  if (( has_unsetenv && iso_clean_env )); then
    args=(--unsetenv _ "${args[@]}")
    [[ -n "${allowed[SHLVL]+x}" ]] || args=(--unsetenv SHLVL "${args[@]}")
  fi
  # Переменные, меняющие работу загрузчика и libc (LD_PRELOAD, GCONV_PATH…), действовали бы на сам bwrap на
  # компьютере до создания среды. Их значения передаются через --setenv (в argv: это не секреты), остальные — окружением.
  for k in "${env_keys[@]}"; do
    if [[ "$k" =~ $loader_re ]]; then
      unset -v "$k" 2>/dev/null || true
      args=(--setenv "$k" "${env_vals[$k]}" "${args[@]}")
    else
      export "$k=${env_vals[$k]}"
    fi
  done
  umask 022
  probe_args=("${args[@]}")
  if [[ -n "$seccomp_file" ]]; then
    exec {sfd}<"$seccomp_file"
    exec {pfd}<"$seccomp_file"
    args+=(--seccomp "$sfd")
    probe_args+=(--seccomp "$pfd")
  fi
  # самопроверка: те же параметры с пустой командой; при ошибке — понятное сообщение
  true_bin=/usr/bin/true; [[ -x "$true_bin" ]] || true_bin=/bin/true
  if ! perr=$("$bwrap_bin" "${probe_args[@]}" -- "$true_bin" 2>&1 </dev/null); then
    die "bubblewrap не смог создать среду с этими настройками:
  $perr
Если дело в одной из защит, отключите её (раздел «Изоляция» в GUI или --iso КЛЮЧ=off) и пришлите это сообщение."
  fi
  [[ -z "$seccomp_file" ]] || exec {pfd}<&-
  exec "$bwrap_bin" "${args[@]}" -- "${final_cmd[@]}"
}

if (( ! net_log )); then
  rc=0
  ( run_sandbox ) || rc=$?
  post_checks
  exit "$rc"
fi

# С --net-log прокси на хосте уже запущен (см. выше); ждём его сокет
for ((i = 0; i < 500; i++)); do
  [[ -S "$sock" ]] && break
  kill -0 "$proxy_pid" 2>/dev/null || die "прокси сетевого журнала завершился при запуске"
  sleep 0.01
done
[[ -S "$sock" ]] || die "прокси не создал сокет за 5 секунд: $sock"

via=""
[[ -z "$upstream" ]] || via=", вышестоящий прокси: $upstream"
if (( ${#allow_domains[@]} )); then
  info "сеть: только через прокси, разрешены: ${allow_domains[*]}$via; журнал: $net_log_file"
else
  info "сеть: только через журналирующий прокси (все публичные адреса)$via; журнал: $net_log_file"
fi

rc=0
( run_sandbox ) || rc=$?
post_checks
exit "$rc"
''',
    'gui.css': '''.eb-title { font-size: 22px; font-weight: 700; }
.eb-h2 { font-size: 15px; font-weight: 700; }
.eb-card { background: alpha(currentColor, 0.05); border: 1px solid alpha(currentColor, 0.10);
           border-radius: 12px; padding: 16px; }
.eb-card-warn { background: alpha(#e5a50a, 0.14); border: 1px solid alpha(#e5a50a, 0.45);
                border-radius: 12px; padding: 16px; }
.eb-sidebar { background: alpha(currentColor, 0.04); }
.eb-badge { border-radius: 999px; padding: 2px 12px; font-size: 12px; background: alpha(currentColor, 0.10); }
.eb-badge-run { background: alpha(#26a269, 0.25); color: #26a269; font-weight: 700; }
.eb-badge-warn { background: alpha(#e5a50a, 0.25); }
.eb-dot { color: #26a269; font-size: 14px; }
.eb-ok { color: #26a269; font-weight: 700; }
.eb-warn { color: #e5a50a; font-weight: 700; }
.eb-info { opacity: 0.6; }
.eb-bad { color: #c01c28; font-weight: 700; }
.eb-status { padding: 4px 12px; font-size: 12px; }
.eb-welcome-title { font-size: 28px; font-weight: 800; }
''',
    'help.txt': '''envbox — изолированные среды на bubblewrap: всё в одном файле.

  python3 envbox.py                  графический интерфейс (при первом запуске установка)
  python3 envbox.py install [--force]  установить: ~/.local/share/envbox, команда ~/.local/bin/envbox
                                     (--force: заменить и более новую установленную версию)
  python3 envbox.py run ARGS...      консольный запуск: envbox -n имя -w проект -- команда
  python3 envbox.py build-appimage   собрать envbox-<архитектура>.AppImage
  python3 envbox.py root [ПУТЬ|--reset] [--move]   показать или сменить каталог данных (по умолчанию ~/.envbox)
  python3 envbox.py global [list|create ИМЯ|delete ИМЯ]   глобальные папки в <каталог данных>/_global
  python3 envbox.py --version        версия этого файла (то же показывает заголовок окна GUI)
  python3 envbox.py --install-desktop  ярлык и значок в меню приложений
  python3 envbox.py proxy|wrap|probe|report  внутренние команды сетевого шлюза

Что внутри этого файла:
  1. консольная утилита envbox (bash, извлекается в ~/.local/share/envbox/envbox.sh);
  2. сетевой шлюз: журналирующий прокси, мосты unix-сокет <-> localhost, проверка прокси;
  3. ядро: профили, запуск терминала, секреты в keyring, сеансы, описание среды;
  4. графический интерфейс GTK 4 (нужен системный python-gobject и gtk4);
  5. сборка AppImage.

Нужны: bubblewrap, системный /usr/bin/python3; для GUI — GTK 4 (Arch: sudo pacman -S
python-gobject gtk4 vte4; vte4 — встроенный терминал, без него терминал открывается во внешнем окне),
для секретов — libsecret (secret-tool), для сред-браузеров — Chrome/Chromium.

Горячие клавиши GUI: Ctrl+S сохранить, Ctrl+N новая среда, Ctrl+T терминал в среде,
Ctrl+R запустить команду/браузер, F5 обновить.
''',
    'icon.png.b64': '''
iVBORw0KGgoAAAANSUhEUgAAAQAAAAEACAYAAABccqhmAAAQAElEQVR4AexdC3wVxdU/swGCICIo
GKwPREioT1pIgPoAARWUBLAqL0UQLFJsQiuooC2hRVAenwS0aBVBFJDiJ48giICKiLxCq7XyQYh8
+KhERPBBkAC50zkbLtxc7s29e3dndnbvub+7ubuzM2fO+Z+Z/87unMwa4JHPxa1va9I8M7tDembO
fRmZPSZnZOYsTc/K2SiO/52R1WOP2L4VG6etB2GQJR0DbGt7sO1hG8S2mCHaZHpWjyEtMnOub5p5
S5pHuhVoSwDN2nZv0aJN9m/Ss3LmZ2Tm7K2dUvFVCjPeZYz9DRiMBMZyGLB24vhyAfbFYmsoNvoS
AioQwLZ2MbY9bIPYFkG0SQbwvMHYulRWcy+2WWy76YIUmrfueakKpRKpw0ikkIwy4R2+Jk8pNgzj
OQasLzDmGUaVgQ3J9CACos1i22WCFFJSeIkggi/ENrdFZvbAlq16NgVNPq4TQLOsXunpmT3G1Qik
rKQOr0mrIDUcR0AQwQViu9tgxuxATb4mPSsnPyMr+xLHK7IgELO6RgDprbtfm56Vs7wmBHYyBn8S
m7bDJASKNkLAKQSwrTNgYwGM3dgHsC84JduqHOUE0CIr51Zh9HqWkrKeAbvVqsKUnxDwEwLYB7Av
YJ9Ib5PdTbVtygggvU33rPSsHpsMYMuF0deqNpTqIwR0RgD7BDOMFdhHsK+o0tWQXdGlV/VqLIya
C8zYxADayq6P5BMCXkbA7COir2Cfwb4jy5agXHkE0LFjjRaZPUam1K7YJYy6m4lPsFL6JQQIgegI
iK7CsM9g30nPzHkQRF+KntveGSkEcGlmjwvTy+pvMBhMZsDOsqcilSYEkhMB7DuMsSnYl7BPyUDB
cQLIyMzpWoPBh4xBFtCHECAEbCOAfQn7FPYt28LCBDhGAJdddket9MzsiRxghagDI6XED30JAULA
IQQaYt8StwQTAO5IsSMztKwjBHBB+zvOOF63fAljxiNMfEIroH1CgBBwBgHRtfA7Oj2zfMn5rbPr
OCHVNgGkt84+t25F+XtCM+VzmE4AQDIIAa8hIPpa9zMN451mrbvUt6u7LQJIv7r7z8AwNgGwNkAf
QoAQUIYAY5BV06i7vnnbbhfYqTRhAmjetsdlkJqySShCIbx2PEBlCYFEEWBwpRGo9YGV/zYMryoh
Arig/c0NjQD/OwOwxT7hytAxIUAIWENAXIAvTDH4EuyT1kpW5rZMAM2bd0utczz1TcYY/h9+pRT6
SwgQAu4hwOCKOsdrr8S+aVUJiwRwR4rRoOZrovNnWq2I8hMChIA8BJh4JpDSoObfrU4RWiKAjMzy
qYyx7vLMIMmEACGQMAKM5WAfjVY+UnrcBJDRJicHGMuLJITSCAFCQBMERB9Nz8ruGa82cRHAJb+4
5WLO2EvxCqV8hAAh4CIC3Jh9Sduc8+LRIDYBdOxYo2aNGosYg7OBPoQAIaA9AthXawbYPKGomKgT
f6v5xiSAjEP1HmCM0UO/akCkU4SAbggwBp0z2mSfvGWPpl+1BGBGGRnsz9EKUzohQAhojIDou2Yf
rkbFagnACNSaAsDqAX0IAULAgwiwepV9OLrqUQmgeZueHcUwonf0onSGECAEdEcA+3BGVnanaHpG
JQCDBf4nWiFKJwQIAe8gAJxNjqZtRALAeUTG2C+iFaJ0QoAQ8BACjP0S+3QkjSMSgGCMP0XKTGmE
ACHgTQQYZ3+MpPlpBIBMwejqHwkrSiMEvItAlFHAaQRAV3/v+pg0JwTCEah6bDxS9RigCgE0b5vd
jq7+4RDRMSHgDwQYQFvs46HWVCGAlADrE3qS9gkBQsBfCIT38VME0LFjDc5YX3+ZS9YQAoRAKAKc
QR8QfT2YdpIA0g/X6y6GCI2DJ+iXECAEvI1AJO0ZsPMyys7qEjx3kgCAGzT8D6JCv4SAjxHgIEYB
J+wLEoB49gc3nkijH0KAEPAxAmIUgKt6MTTRJIAWmT2vFgf0Oi8BAn2TAwFeLwUCV9eFQIf6wLs3
hEDfRsDvSzM3cx/TxDnMg3l9hQqDc070+cppQINXdPSVgWQMIRABAX5uTeDt65mdHe45D9h19YFd
WRegaW1g59QESBXXQ7GZ+5gmzmEezGuSQrt6gDIiiNYuKZZCwT4vLAZx+8+IAGIhRuc9iwBvWAMC
Xc8G3vtcgNb1Kju7RWtMUmgjCEDI4F0bAK+fYlGCXtm5UdnnkQAYE1yol3qkDSFgHwF+pgG8i+j4
fRoBa14HGGO2hTImZDQ/A3j/xhDoWB+gLnYh22KVC2CcXSsqZUbLVj0vBgC6/xcg0Nc/CPALUwH6
ilntlqLjG6LTOmwaEzLZFXWB92sMZl0Oy5cujsE5LUXfN3jNQEugDyHgIwT4lXUAssU1TdzPSzcL
6xB18YwzpFcVbwXx5sO+L8ZInAggXsQon9YIiPlt4NeLYXmHswHEFVqZsljXjeK5QFvxjABQC2U1
26uI85aGuDFqak8KlSYENEHgCnHlv0o81XdLncx6AJe7WL9VuxlrigRAIwCgj9cR4Gk1AcS0nut2
iBEIb1LLdTXiUYAzaGpw4GnxZKY8hICuCODTfrhV3POnMPdVRB1uEbcDYgbCDWUs1tnUYBxqWyxE
2QkBrRDgncQ9/xkazcsLXUydtELpdGWw7xtiGCDQO/0kpRACXkCA/6wWsIv0u4ahTqib1hgyVlvM
AjD90NMaNVJOKwTanaWVOlWUEbMCVY41OxC3/4IAgBMBaOYYUic+BHgL0XR1fuB2firwZkLH+Myx
ncuyAA5nG4yxVMsFqQAhoAMCl+gffMMv0ZcAsO8bOviRdCAErCLAseU21f/axS4SowCrxinMjzAq
rI6qIgQcQgCH/rU80HzritkJjFFwyGynxXgAQadNJnm+QEDDJ/9RcVVwqxK17hgniABiAESn9USA
N6qhp2IRtNJZVyKACA6jJP0RYHU81HQ1vlXxEIr6N0rSUB0CvI64t1ZXnb2aNCYrIgB7rqXSbiGg
8VX1NEgkk9Vp9VlIIAKwABZl1QiBioBGysRQRWNdiQBi+M5vp5ukNYYB/W6Dgslj4Y3/nWVuuD+g
by/Ac16xlx32zsIbOutKBOCVFm9Tz3MaNoCReffBK7OegsED7oRWV/4czqxb19xwf/A9vc1zD+YO
AcxrszrpxfnhCul1OFWBzroSATjlZU3lYCe/f8hdsGB2AWR36ww1UqI/PMNzObd0gfki79DB/U1y
0NQsYGXeuQWQqatd/xAB2EVQ0/KpqbUAh/UL506Hvrd3BzyOV9Xaomy/O7IBy94tbg2slI23Drv5
+P6jdkUoK6+zrkQAypqBmorwKn5bj67w6pzpgMN6HAEkWjOWHSJuDVBWr5ybqx09JFpHouXY594h
AJ11JQJItAVqVo4xBjd3uQ7mzZoGecMGQsMGzq3zgrJG/HaQ+Yzgps7XAWPMfev3HwM45IHnAGVC
R9TVfcQiakAEEBEWbyVe074NvDjzSRgzcjikpTWSpnwTMYPw6KjhZl3XtGstrZ54BCMF8S/K48nq
ah6++wigrjKUcEImEYATKLok48rLM+C56Y/DhLEjoVnTi5RpgXVNyB9l1n1Zy+bK6g2viH1+JDxJ
u2OmOUkRAWjXZGIrhB1w0vjR8PTUcdAy/dLYBSTlwLpnThsPk8Y/opSAguawXYIANB5ew96jwMQI
IKivjr9EADp6JYpOaWJ4nz8mzxyCt21zdZRc6pPbtmll6jR2dJ7UW5CIln3wfcRkLRI3/aCFGtUp
QQRQHTqanMPAHAziwQd8N1zfHhjT766SMQadOrQH1FFlMBE+Yef/0e9ZABe3J+w/R6W1IKcEEwE4
haQEOTgNd3+cQTwSqk9IJE5Dqg4mYqsPAvwknrYnpLGEQkIXtvY7CYKdF0kE4DymtiVi4E2iQTy2
K3dIgMpgInYoALBCkECFBv8fgDq8ccAzkYpEAA41eKfE/LpHN1g4Z4btIB6n9LErB0cxGEyENqFt
duVFK8/EAzdYr8HzgHe+A1Z6LJqa2qUTAWjiEgziwU6SO+weaNCgviZaOacG2oS2oY03drrWOcEh
kti/DwP/uCwkRfHutkPAdvwkvVInKyACcBLNBGRhEM/sZydJD+IJV21H8acwbMRj8MCDYwH3w8/L
OsaZjMceegDQZhnBRMY6MQp4S/HtAA773xTD/o36P/UP9ysRQDgiio7dCuLZvedzGJM/GYbmPgrb
d5TAx5/sNPfHjJsCeE6R+WbcgKxgIlYsrsKL9wNgGK5sg7CO1/cDKzkiuyYp8okApMAaXahbQTx7
S/fB45OfgXuHPQwbNm07TcENG4vMcxOmPAOlpd+cdl5WgqxgIvM+fP4+gH8eAsArtNMGoMwPhWxR
B/vaO/f84TAQAYQjIukYh75uBPEcOPgdTPvrbLhr8O/hrbXrgfPoT8rx3Ko166H/4BFQMHMOHBBl
JcFxmlgZwUSsnAPbIIblr+wDXiyeD1Rj+2kKRUlAjABHGEIme/8HwDqiZJWS7LRQIgCnEQ2T51YQ
z6GyMnjhpYXQZ2AuLF62Co5XVIRpFv0Q876+9E2z7CwhA2VFz+3cGcbkBBOxHyvAeEs8nV+4H6Do
R+DfWr9im2W2/QhMyGDiGQPKdM5y9yQRAUjCHqe/3AjiOVJ+FOYvKoTeA3Lh5QWLoVwcJ2oilp0r
ZKCsBa8ttyXLig6ygonY/mPANv0IxgJxi/PS18DFtKE5a7DnSCUplAcAxGZ2dkzDGYX3xENFkRfL
sI2CAIQMK7bonpcIwGEPuRXEc1xc4ZetWAP9BuXBc7PmgZNXbZT17AuvQF8hu3DlWkujCTvwygwm
wiu48VEZ4KwBW37AJAX2fCngZnZ2TBMzCuxfZYB57dihc1kiAIe8g1et2xxaiceKSnhP+va6jeZ9
+9TpL8C3Bw5aKW4pL8qeUvC8Wdc7722s9nmCJcExMuNoCoOJXp0zHXRbmSiG6o6eliGMCMAmqozJ
W4knlmqbiz40n9yPm1ig9Mk9zhLkTygw695c9FEsNR07r+XKRI5Z544gIgAbuGMQz4sKVuIJVxED
dzCI56HHnlA6dx+uB8YNPPTYROXBRE00WpkoHBOvHRMBJOAxXYJ4ElBdShE/BhNJAUpDoUQAFpyi
axCPBROkZvVbMJFUsCwKl5WdCCAOZNNcWokHA3HiDeKJwwwlWfChpJ+CiZSA5mIlRADVgO/FIJ5q
zFF6Cqcl/RRMpBQ8hZURAUQAG6edvB7EE8EsV5L8FkzkCogSKyUCCAHXj0E8Iea5uuvHYCJVgMqs
hwhAoJsMQTzCTC2+FEykhRtOKpHUBMBY8gXxnPS8yzsUTOSyA05Un7QEgKvRJHMQzwn/u/5DwUTu
uiDpCOBkEE/+KHNVGlXwY0MfE7ISj6p6vVIPBRNF9pTs1KQhAArikd2UnJFPwUTO4BivFN8TQNp5
jSB/zAhzEUqVr9M6ePB7eGrGLHNRjVgr8cTrrGTJFwwm+RupmAAAEABJREFU6j3wdyaGiKUq23Fl
IlywFNtMWuNzVVXrWj2+JoBftWsNs2dOghuub6cMYJzuwpV4sPEueWO1snr9WhFiiFiqXJkIscQ2
M/vZyaDyooH1qt58SwCdO/wKJor7/Dp1zogLUx5XruiZnFyJJ3otyXnGrWAibDtP/uURwLbkBvIq
6vQlAVx80QXwp9G5lvBjIbmtkgGuxNP/3jzHV+IJUYl2BQI4usKVifoJrBFzkRT316pPg4IZY2Zb
uvBnTYJJvvr1JQH0vLWLLSeFkkE0QXifiivx4PAUV+LZ/628lXii6ZCs6Yg1Yo7Yx7syUTw+rQ7P
HJttqjrZbp7zJQH8otUVUjHd7NJKPFKN8qBwlcFEv2x1uQcRiq2yLwng/LTGsS1PIIcuK/EkoLqv
i2CMheyViRo3UjsjoMphviQA/KceVQBSPcmBwFn1zvSlob4kAFmekvUaK1n6Jotct4K8/IAvEUAC
XsRgkRdnPgljR+cBrhaUgAgq4gACiL0br1tzQHVtRBABJOgKxuS8xipBdZKqmFsrNakCWWU9RAA2
0ca1BHJu6QLzZxfA0MH9AVcTsimSikdBALF1Y6WmKOr4IpkIwCE3ynyNlUMqelYMPtQd0LcXLJw7
Hfre3h3w2LPGaKY4EYDDDsGrFL7GauGcGfDrHt0clp584hBDxHLwPb1pdCXB/clFAInGgyYAfIMG
9SF32D3w6pzpcFPn64Axu7FoCSjh0SKMVa7UhB0fMUQsPWqKZbVVF0guAnChDzZJawyPjhoOOGuA
qxCpdrDX6nPrdWtew8kpfZOLAJxCLQE5OFc9IX8UPDf9cbisZfMEJPi7yMmVmsaOVLpSk79RjW0d
EUBsjBzNQcFEVeFEYpw0fjQ8PXUcIDZVz9KRbASIAEIQxldxhRxK3U32YKI0F1+3JtWxNoS7UZQI
IAT1PgNzQeXKM4wx6NShPcybNQ0ezB0CGOASoo4vd9HGkXn3mTbfcH17ZQ9HcS0BXKkJfexLYBM0
igggBLjy8qMwd8Fi6D0gFxa8thzwOOS0tN1kCCbC6dH7h9wFC2YXQHa3zoA2SwM0RDCt1BQCRoRd
IoAIoODVAlee6TsoDwpXrgV80WWEbI4n+TGYCIN23AjiQZ/hqkH9hA+fmzUP0KeOO8wHAokAqnEi
vcaqGnBinMIr/G09uppxECqDeIIrNfUfPAJw1SD0YQxVtTjtlhJEAHEgr3LlmVB1GjY4G0b8dhC8
MuspzwQTMVYZxIPPNfKGDQS0IdQmmfu0UpN1dIkALGCmYuWZSOo08UgwEQY6YcDTmJHDlf6bNK3U
FKnVxJdGBBAfTlVy0WusqsABJ4N48ul1a1WR0f+ICMCGj5L9NVZuBfHsLd0Hj09+Bu4d9jBs2LTN
hgf1KOqmFkQANtHHh06r1qwHfOhUMHMOJEMwUZqLQTzT/job7hr8e6DXrdlsuCeKEwGcAMLuD047
vb70TfNdgH4NJtIhiGfxslXKpmXttgkvlCcCcNhLGDzkt2AiCuJxuJFoJI4IQJIzMPDE68FEFMQj
qXGEiHV7lwhAsgcwEGVKwfPmM4J4X2PlhEp41caViXBBkl45N1sKvaUgHic84A0ZRACK/OSFYCLG
KIhHUXPQphoiAMWu0DWYiIJ4FDcETaojAnDJEboEE1EQj0sNAAB0qJkIwGUvYDDRoPsfgglTnoGv
v/lWmTa4+s7MaeNB9Uo8aOP4SU8D2kxBPMrcHbUiIoCo0Kg9gcFEd949HJ6aMQsOHvxebeUKakOb
0Da0cfXb7yuokaqIBwEigHhQUphnyRuroffA3yldmUimeTgdiivxoE1om8y6SLZ1BIgArGMmvYRb
wUROGkYr8VSPpi5niQB08UQEPfDq6UYwUQRV4k7CkGhaiSduuFzPSATgugtiK+BWMFFszU7lwH+K
envdRjPgiVbiOYWL7ntEALp7KEQ/t4KJQlSIuEsr8USExROJRACecFNVJd0KJqqqBQCtxBOOSHzH
OuUiAtDJGxZ1cSuYCAloTP5kGJr7KGzfUWJRa8quEwJEADp5I0FdMJgIV8fBYCK8TUhQTMxitBJP
TIg8l4EIwHMui6wwPoRbJWllogMHvwNaiScy7l5PJQLwugfD9MdpOKdWJsJpSAziwddp0Uo8YUAn
eKhbMSIA3TzikD7BYKK+A/MAg3KsisUyWPblBYuVvSLNqo6U3z4CRAD2MdRawg8/HgJ85ZhVJbEM
lrVajvJ7CwEiAG/5i7QlBBxFgAjAUThJGCEQHQEdzxAB6OgV0okQUIQAEYAioKkaQkBHBIgAdPQK
6UQIKEKACEAR0FRNciOgq/VEALp6hvQiBBQgQASgAGSqghDQFQEiAF09Q3oRAgoQIAJQADJVkdwI
6Gw9EYDO3iHdCAHJCBABSAaYxBMCOiNABKCzd0g3QkAyAkQAkgEm8cmNgO7WEwHo7iHSjxCQiAAR
gERwSTQhoDsCRAC6e4j0IwQkIkAEIBFcEp3cCHjBeiIAL3iJdCQEJCFABCAJWBJLCHgBASIAL3iJ
dCQEJCFABCAJWBKb3Ah4xXoiAK94ivQkBCQgQAQgAVQSSQh4BQEiAK94ivQkBCQgQAQgAVQSmdwI
eMl6IgAveYt0JQQcRoAIwGFASRwh4CUEiAC85C3SlRBwGAEiAIcBJXHJjYDXrCcC8JrHSF9CwEEE
iAAcBJNEEQJeQ4AIwGseI30JAQcRIAIIAfOsemeGHNGuHxGQ6WMv4kUEEOK1BXMK4O6+vSA1tVZI
Ku36AQH06QDhW/SxH+xxygYigBAkz6xbF4bc0xtenTMdeuXcDDVSUkLO0q4XEUAf3tajq+nTwcK3
6GMv2iFLZyKACMg2bHA2jPjtIHhl1lNwU+frgDEWIRcl6YwAYwxu7nIdzJs1DfKGDQT0qc76uqUb
EUA1yDdJawyPjhoOL858Eq5p17qanHRKJwSuad/G9NmYkcMhLa2REtW8WokvCaCs7LCj/mjW9CKY
kD8KZj71F2h15c8dlU3CnEMAfYM+mjB2JKDPnJMMcKiszElx2sjyJQF8s/+AFIAv+3kLKJg8FiaN
f8TxBiZF4SQRip190vjRpm/QRzLM3vfNtzLEui7TlwTwz48+kQps2zatzCHm2NF5NMSUinT1wnF4
nz8mz/RF2zZXV5/Z5tl//PPfNiXoWdyXBLBk+WrpaDPGoFOH9rBwzgwYNeI3cO45DaTXSRVUIoBY
P/KH+03sb7i+vZKHtEtXrKmsPMJfLyf5kgD2fP4lTJw6U5lfunftBPNeLIChg/sDTTPJgx2xvX/I
XTBfYN3tpo7yKgqRzDmHP0+cDp9/8VVIqn92fUkA6J43V6+D0fmT4fDhn/BQ+lY7tRb0uyMbFs6d
TsFEDqMdDOJBbPve3l1ZoNYh8TD54T8+AWvXfeCwRfqI8y0BIMQfbNoGg4Y9BKvf2YCHSja8SmEw
Ed4a/LpHNyV1+rkSxBCxVB3Eg21msGg7m4s+8jO84GsCQM+Vfv0NjH9yBgy6/yFQ6cwGDepD7rB7
zAg0CiZCT8S/MVYZxIMdHzFELOMvbS/n5qIPzbaCbaZ03/6YwryewfcEEHTQ7j2fw0OPTYQHHhwL
O4o/DSZL/21CwUSWMHYriAfbxLARj4k28gRgW7GktIczJw0BBH308Sc7YWjuozBm3BSljsa56gn5
o+C56Y/DZS2bB9Wh3xMIXHl5homNjCCeE1VE/MHOPkY8K8I2sX1HScQ8fk5MOgIIOnPDxiK4d9jD
MGHKM1Ba+k0wWfpvy/RLYea08RRMdAJpJEYM4nl66jhAbE4kS//ZW7oPHp/8jNkGNohnRdIr1LSC
pCUA9AdO8axasx76Dx4BBTPnwIGD32Gyki3Zg4nS0hqBqiCeUIeij6f9dTbcNfj38Nba9YBtIPS8
lX0/5E1qAgg68HhFBby+9E3oMzAXZr20UFncN2PMDCbC/1h7MHcInNPQ/8FEaOPIvPsAbVYVxIN+
xlj+F4Rv0ceLl60C9DmmJ/tGBBDSAsrLj8LcBYuh94BcWPDacsDjkNPSdvF/1nNu6QLzZ/s3mAin
RzGIZ4GwMbtbZ2VrLRwRPp2/qND06cvCt6p8Kq2xOCyYCCACoHi1ePaFV6DvoDwoXLlW2dXCj8FE
bgXx4BV+2Yo10E/48LlZ85SN6iI0J62TiACqcc+3Bw7ClILnzWcE77y3Udn9Il4tMZjoVQ+vTISj
GjdW4sF7+rfXbTR9NnX6C4A+rMbFCZ/yS0EigDg8ibME+RMKzCfGmxVGhuEqNiM8tjIRY5VBPHiP
r3olns1FH5o+GjexQOnMThxNSNssRAAWXINzxhRMFB0wCuKJjo2uZ4gAEvAMBRNVBY2CeKri4aUj
IgAb3kr2YKJkDeKx0WS0K2qIhybl2mnlIYUEfpBswUQUxOOhBlqNqqLtlosRADtSTR46FScCOO3k
92AiCuKJszF4JRuD7wxgnAjAQYdhoInfgolwWpKCeBxsJJqIYsCOGIyDugB4SJ6PH4KJKIjn9Pbq
qxTOjxicMSIAiV7FQBS3g4kSNe/VOdNB5Uo84p4UKIgnUW9ZL4d93wDgpdaLUgmrCLgZTGRV12B+
DEQK7sv+pSAe2QhHks9L8RZgT6RTlCYHAbeCieRYY19qsq7EYx85+xJ4gO0wAgx22BdFEqwi4FYw
kVU9ZeVHIvTaSjyysHBNLgvsMHjAIAJwzQMAGEyEC5biykRf+/T1U6Hwoo3jJz1tLryZzCvxhGLi
1j7nKXuMGseBbgHA/Q8GE91593B4asYsOHjwe/cVclgDtAltQxtXv/2+w9JJXCIIHGdHdxg7Plzy
GXDw55sPE0HF5TJL3lgNvQf+TunKRDJNxulQXIkHbULbZNZFsi0h8NmerStKDVGEc8aJkgUQunzd
CiZy0n6/rcTjJDY6yBJTru+iHkgAwALcPMAE2vRBAK+ebqxMZAcBDImmlXjsIKimLIfKPm8SQICl
EAGowT2hWtwKJrKirLiiUBCPFcBczptyrLLPmwSwa+uSj+g5gMseiaN6t4KJYqlGQTyxENLu/Gc7
PlxiPvw3CUCoxznw5eKXvh5AAOfQ3ViZKByaZAniCbfb68ditHZyxB8kAGAAr3rdsGTT361gIiQg
CuLxbmsLcGNOUHsjuLOz7g9rxCjg6+Ax/XoHAQwmUvGaM3qdlnfaRDRNOcC+kqIlp48A4N13jzNO
o4BowOmeLoZ10lYmOnDwO6DXaeneAuLTj3G+IDTnyREAJlYYnG4DEAgPbzgN59TKRDgNiUE8yfw6
LQ83hYiqh/fxKgRQsrlwEwAviliSEj2FgJ1goiP0Oi1P+TpuZTn/R4nZx0+VqEIAmMwDMBV/afMH
AngVjzeYCEcPFMTjD79HsoIz/pfw9NMIoLgodRFwKA7PSMfeRiAYTHT3kD8AdvJwazANz9HrtMKR
8csx31W8pXBJuDWnEQDAoooABCaGZ6RjfyDw1d6vATt5h659IMlLVmoAAASJSURBVHTDNDznDyud
scJPUgKcT4hkTwQCANi1tfbLwPlXkQpQGiFACHgMAQ57zT4dQe2IBFA5CuCPRshPSYQAIeAxBMSI
fgz26UhqRyEAHAUUzuEc1kYqRGmEACHgEQQ4vLtra+HJyL9wraMSAGZknA/nABW4TxshkEwI+MFW
znn5MWYMrc6WaglgZ9GynYIEnq5OAJ0jBAgBPRHgnE3bvWVxtTN61RIAmlVWI3W0YJJPcJ82QoAQ
8AYCYuS+/aeatcbF0jYmAXy5cdFPAYPdKWYFDscSRucJAUJAAwQ4P8yPH78d+24sbWISAAoo2bx0
ewD4cNynjRDwOwJetw/76q5/vPF/8dgRFwGgIHySKG4FXsJ92ggBQkBPBLCPYl+NV7u4CQAFBg4e
GwpiWgH3aSMECAHNEBB90+yjFtSyRAAlJSvLD5TVyhYsQw8FLYBMWQkB2QiIPrkV+yb2USt1WSIA
FPzN9kWHygM1bhQV7sZj2ggBPyHgRVtEX/zkcI3yrtg3repvmQCwgs+2vb6XMd5FzAzQ/wsgILQR
Ai4hIDr/brwgf7lx1YFEVEiIALCinVsK/7/CONZWPBP4GI9pIwQIAbUIiM7/CRwNXI8X5ERrTpgA
sMKSzSu/PBYou45z2ILHtBEChIAiBDhfFzCO/ar4o+X/sVOjLQLAindvW/P9oUDgBsFG9F4BBIQ2
zyLgFcVFX1uZUpZ6k7gA/2BXZ9sEgAp8ta3wcPHW1J6cB57g4oNptBEChICzCIiuxQMBeFL0tezt
2xcddUK6IwRQqciiiuKthaMZwC3iOKEHEqIcfQkBQiACAvjODnGrffOuoqWPRPvf/gjFYiY5SACV
de3cuuzN4xxaiRmCdUAfQoAQsI2A6PzvVxxJuWpX0bLVtoWFCXCcAFD+p1uXfiGIoFMAArlCedv3
KSiTNkJAJgI6yjb7Ducjircs6/Dpvxbvk6GjFAI4oWhg15bCGUf58QwxdFl4Io1+CAFCIAYCeK8v
+swc7DviQlogsgfEJuUrkwBMhfdsXVFavHVpH6jgnfB/lM1E+kMIEAIREcA+EmCBa0SfGYR9J2Im
BxOlE0BQ153blr1TvKXWVcADvUXaNrHRlxAgBE4hsE1c9ftgHynZsnzjqWS5e8oIoNKMRRU7txb+
feeWpW0qAgxjB1ZWptNfQsA9BNysWQz3V+LoGPuEuOqLW+VFStfgVEwAp6AuKVrybvHWZWLKMNBM
POwYJ9jv01NnaY8Q8C8C2NaxzQMEmmEfwNGxW9a6RgBBg/F/CsRTznzBfs3F9OE1APxZcR/0ZfA8
/RICfkCgsk3zZ7GNY1vHNo9t323bXCeAUADE9OEHO7csG1a8ZemFFRWsuQDtPsGUC4Dz0tB8tE8I
aI+AaLPYdgOBwNBjrCId2zS2bWzjOumuFQGEAlOybcmnArQXBFP227l1WZNyfqxJgPMOSArAYYog
hWUC4E2cc1yc5DNRlqIPBQj0tYZAgrmxrX2GbQ/bILZFbJPi+DcVPNDxSEXK+dhmse3uKir82+7N
y3clWI/0Yv8FAAD//yAGnGsAAAAGSURBVAMAJHvtZGCZ/FYAAAAASUVORK5CYII=
''',
    'icon.svg': '''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128">
<rect width="128" height="128" rx="26" fill="#27364f"/>
<path d="M30 52 64 34l34 18v40L64 110 30 92z" fill="none" stroke="#e8eef7" stroke-width="7" stroke-linejoin="round"/>
<path d="M30 52 64 70l34-18M64 70v40" fill="none" stroke="#e8eef7" stroke-width="7" stroke-linejoin="round"/>
<circle cx="98" cy="30" r="11" fill="#26a269"/>
</svg>
''',
    'terminal_wrapper.sh': r'''
envbox_sh=$1 name=$2; shift 2
secrets=()
while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do secrets+=("$1"); shift; done
shift
printf '\033]0;envbox: %s\007' "$name"
for v in "${secrets[@]}"; do
  if ! command -v secret-tool >/dev/null 2>&1; then
    echo "envbox: для секретов нужен secret-tool — $ENVBOX_PKG_HINT"
    unset "$v"; continue
  fi
  if val=$(secret-tool lookup service envbox profile "$name" var "$v") && [ -n "$val" ]; then
    export "$v=$val"
  else
    echo "envbox: секрет $v для среды $name не найден в keyring — не передаю"
    unset "$v"   # значение из окружения рабочего стола в среду не попадёт
  fi
done
unset val
"$envbox_sh" "$@"
rc=$?
if [ -n "${ENVBOX_EMBEDDED:-}" ]; then
  printf '\n[envbox: сеанс завершён, код %d]\n' "$rc"
else
  printf '\n[envbox: сеанс завершён, код %d. Нажмите Enter, чтобы закрыть окно]' "$rc"
  read -r _
fi
''',
}


def resource_text(name):
    return _RESOURCES[name]


# ---- selfpath.py: Пути к самому envbox: точка запуска (SELF) и единый файл для установки (bundle_path).

BUNDLED = True   # build.py ставит True в собранном dist/envbox.py

# что перезапускать (execv) и откуда читать версию: собранный файл или dev.py
SELF = os.path.realpath(__file__ if BUNDLED else sys.argv[0])


def bundle_path():
    """Единый файл envbox.py для установки и AppImage.

    В собранном файле это он сам; при запуске из исходников — свежая сборка dist/envbox.py."""
    if BUNDLED:
        return SELF
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
    if root not in sys.path:
        sys.path.insert(0, root)
    import build
    return build.build_if_stale()


# ---- core/consts.py: Общие константы ядра: регулярные выражения, режимы сети, подписи, пути установки.

ENVBOX_SH_TEXT = resource_text("envbox.sh")


SHELLS = ("bash", "fish", "zsh")


NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,47}$")


VAR_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


DOMAIN_RE = re.compile(
    r"^(\*\.)?[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$")


RESERVED_VARS = {"HOME", "USER", "LOGNAME", "SHELL", "PATH", "PWD", "OLDPWD"}


KINDS = ("app", "browser")


KIND_LABELS = {"app": "Приложение (терминал)", "browser": "Браузер (Chromium)"}


CDP_PORT = 9222


BROWSER_NAMES = ("google-chrome-stable", "google-chrome", "chromium", "chromium-browser", "chrome")


UPSTREAM_AUTH_VAR = "ENVBOX_UPSTREAM_AUTH"


LANG_RE = re.compile(r"^([A-Za-z]{2,3}(_[A-Za-z]{2,3})?(\.[A-Za-z0-9-]+)?(@[A-Za-z0-9]+)?|C|POSIX|C\.[A-Za-z0-9-]+)$")


TZ_RE = re.compile(r"^[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+){0,2}$")


ATTACH_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]{0,47})(?::([0-9]{1,5})?)?(?::([0-9]{1,5}))?$")


NET_MODES = ("off", "log", "allowlist", "host")


# Что нужно Claude Code в сети (code.claude.com/docs/en/network-config): API, вход через claude.ai и
# обновление OAuth-токена на platform.claude.com. Без *.claude.com токен через несколько часов не обновляется,
# и Claude внутри среды «теряет сеть» (просит войти заново).
CLAUDE_DOMAINS = ("*.anthropic.com", "*.claude.ai", "*.claude.com")


# Claude Desktop дополнительно держит соединение с bridge.claudeusercontent.com. Если его закрыть, приложение
# повторяет попытку каждые несколько секунд и показывает «Connection problem». Вход проверяется через hCaptcha
# (js.hcaptcha.com и соседи): без него страница входа пишет «Couldn't verify your browser». Телеметрия
# (Sentry, Datadog) и GitHub не нужны для работы и остаются закрытыми.
CLAUDE_DESKTOP_DOMAINS = CLAUDE_DOMAINS + ("bridge.claudeusercontent.com", "*.hcaptcha.com")


# Прежний список пресета Claude Desktop (без hCaptcha): профили с ровно таким списком обновляются при загрузке.
OLD_CLAUDE_DESKTOP_DOMAINS = list(CLAUDE_DOMAINS) + ["bridge.claudeusercontent.com"]


# Прежний список пресета «Claude CLI»: профили с ровно таким списком обновляются при загрузке.
OLD_CLAUDE_DOMAINS = ["*.anthropic.com", "claude.ai"]


NET_LABELS = {
    "off": "Нет сети (офлайн)",
    "log": "Через прокси с журналом (любые сайты)",
    "allowlist": "Через прокси: только выбранные сайты",
    "host": "Общая с компьютером (небезопасно)",
}


NET_SHORT = {"off": "офлайн", "log": "сеть с журналом", "allowlist": "сеть: выбранные сайты",
             "host": "сеть компьютера"}


INSTALL_DIR = os.path.join(os.environ.get("XDG_DATA_HOME") or
                           os.path.join(os.path.expanduser("~"), ".local", "share"), "envbox")


INSTALLED_PY = os.path.join(INSTALL_DIR, "envbox.py")


INSTALLED_PYC = os.path.join(INSTALL_DIR, "envbox.pyc")   # предкомпилированная копия для быстрых служебных вызовов


INSTALLED_PYC_TAG = INSTALLED_PYC + ".python"        # каким Python собран .pyc (после его обновления .pyc негоден)


ENVBOX_SH = os.path.join(INSTALL_DIR, "envbox.sh")   # извлекается из envbox.py при установке


ENVBOX_NET = INSTALLED_PY                            # сетевой шлюз — этот же файл


SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]{0,30}$")


# ---- core/desktop.py: Ярлык и значок envbox в меню приложений.

# ------------------------------------------------------------ ярлык меню

def _desktop_quote(arg):
    """Кавычки по спецификации Desktop Entry (только двойные)."""
    if re.fullmatch(r"[A-Za-z0-9_./+-]+", arg):
        return arg
    return '"' + re.sub(r'(["`$\\])', r"\\\1", arg).replace("%", "%%") + '"'


ICON_SVG = resource_text("icon.svg")


def install_desktop_entry(gui_path=None):
    """Ярлык в меню приложений и значок. В AppImage ярлык указывает на сам файл AppImage."""
    data = os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share")
    apps = os.path.join(data, "applications")
    icons = os.path.join(data, "icons", "hicolor", "scalable", "apps")
    os.makedirs(apps, exist_ok=True)
    os.makedirs(icons, exist_ok=True)
    with open(os.path.join(icons, "envbox.svg"), "w", encoding="utf-8") as f:
        f.write(ICON_SVG)
    appimage = os.environ.get("APPIMAGE", "")
    if appimage and os.path.isfile(appimage):
        exec_line = _desktop_quote(os.path.realpath(appimage))
    else:
        exec_line = "/usr/bin/python3 " + _desktop_quote(INSTALLED_PY)
    path = os.path.join(apps, "envbox.desktop")
    text = ("[Desktop Entry]\nType=Application\nName=envbox\n"
            "Comment=Изолированные среды на bubblewrap\n"
            f"Exec={exec_line}\n"
            "Icon=envbox\nTerminal=false\nCategories=System;Security;\n")
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return path


# ---- core/fsutil.py: Файловые помощники: приватная запись, надёжное удаление, проверка вложенности путей.

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


# ---- appimage.py: Сборка AppImage.

ICON_PNG_B64 = resource_text("icon.png.b64")


APPRUN_TEXT = resource_text("AppRun.sh")


DESKTOP_TEXT = resource_text("envbox.desktop")


def build_appimage(args):
    """Собирает «тонкий» AppImage: внутри только envbox.py; Python, GTK и bubblewrap — из системы."""
    import tempfile
    import urllib.request

    arch = os.uname().machine
    if arch not in ("x86_64", "aarch64"):
        print(f"envbox: неподдерживаемая архитектура: {arch}", file=sys.stderr)
        return 1
    tool = os.environ.get("APPIMAGETOOL") or shutil.which("appimagetool") or ""
    if not tool:
        cache = os.path.join(os.environ.get("XDG_CACHE_HOME") or
                             os.path.join(os.path.expanduser("~"), ".cache"), "envbox-build")
        os.makedirs(cache, exist_ok=True)
        tool = os.path.join(cache, f"appimagetool-{arch}.AppImage")
        if not os.access(tool, os.X_OK):
            url = ("https://github.com/AppImage/appimagetool/releases/download/continuous/"
                   f"appimagetool-{arch}.AppImage")
            print(f"envbox: скачиваю appimagetool: {url}", file=sys.stderr)
            try:
                with urllib.request.urlopen(url, timeout=60) as r, open(tool + ".part", "wb") as f:
                    shutil.copyfileobj(r, f)
            except (OSError, ValueError) as e:
                print(f"envbox: не удалось скачать appimagetool: {e}\n"
                      "Установите его (AUR: appimagetool-bin) или задайте APPIMAGETOOL=/путь", file=sys.stderr)
                return 1
            with open(tool + ".part", "rb") as f:
                digest = hashlib.sha256(f.read()).hexdigest()
            want = os.environ.get("APPIMAGETOOL_SHA256", "").strip().lower()
            if digest != want:
                # скачанный файл потом запускается, поэтому без совпавшей суммы он не устанавливается
                os.unlink(tool + ".part")
                if want:
                    print(f"envbox: контрольная сумма appimagetool не совпала ({digest})", file=sys.stderr)
                else:
                    print(f"envbox: sha256 скачанного appimagetool: {digest}\n"
                          "        Файл не установлен. Сверьте сумму с релизом на GitHub и повторите с "
                          "APPIMAGETOOL_SHA256=<сумма>", file=sys.stderr)
                return 1
            os.chmod(tool + ".part", 0o755)
            os.replace(tool + ".part", tool)
    out = os.path.join(os.getcwd(), f"envbox-{arch}.AppImage")
    with tempfile.TemporaryDirectory() as work:
        appdir = os.path.join(work, "envbox.AppDir")
        os.makedirs(os.path.join(appdir, "usr", "share", "envbox"))
        with open(bundle_path(), "rb") as f:
            _atomic_write(os.path.join(appdir, "usr", "share", "envbox", "envbox.py"), f.read(), 0o755)
        with open(os.path.join(appdir, "envbox.png"), "wb") as f:
            f.write(base64.b64decode(ICON_PNG_B64))
        with open(os.path.join(appdir, "envbox.svg"), "w", encoding="utf-8") as f:
            f.write(ICON_SVG)
        with open(os.path.join(appdir, "envbox.desktop"), "w", encoding="utf-8") as f:
            f.write(DESKTOP_TEXT.rstrip("\n") + f"\nX-AppImage-Version={ENVBOX_VERSION}\n")
        _atomic_write(os.path.join(appdir, "AppRun"), APPRUN_TEXT.encode("utf-8"), 0o755)
        env = dict(os.environ, ARCH=arch, APPIMAGE_EXTRACT_AND_RUN="1")
        # Старый AppImage может быть запущен (окно envbox): запись в него даёт «Text file busy». Собираем рядом
        # под другим именем, а потом подменяем — rename запущенного файла разрешён, процесс держит старый inode.
        tmp_out = out + ".new"
        rc = subprocess.run([tool, appdir, tmp_out], env=env).returncode
        if rc == 0:
            try:
                os.replace(tmp_out, out)
            except OSError as e:
                print(f"envbox: не удалось заменить {out}: {e}", file=sys.stderr)
                rc = 1
        if rc != 0 and os.path.lexists(tmp_out):
            try:
                os.unlink(tmp_out)
            except OSError:
                pass
    if rc != 0:
        print("envbox: appimagetool завершился с ошибкой", file=sys.stderr)
        return rc
    print(f"Готово: {out} (версия {ENVBOX_VERSION}; проверка: {out} --version)")
    return 0


# ---- core/root.py: Каталог данных envbox и глобальные папки (_global): выбор, создание, перенос.

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


# ---- core/browser.py: Среды-браузеры: поиск Chrome/Chromium, монтирование, команда запуска, CDP-сокет.

def find_browser():
    for n in BROWSER_NAMES:
        p = shutil.which(n)
        if p:
            return p
    return ""


def browser_mounts(binpath):
    """Каталоги вне /usr, которые нужно смонтировать на чтение, чтобы браузер запустился.

    Версии из AUR (google-chrome) запускаются скриптом-обёрткой, а сам Chrome лежит в /opt:
    ищем такие каталоги и в тексте обёртки."""
    if not binpath:
        return []
    real = os.path.realpath(binpath)
    dirs = []
    if not real.startswith(("/usr/", "/bin/", "/lib/", "/lib64/")):
        dirs.append(os.path.dirname(real))
    try:
        if os.path.getsize(real) < 65536:
            with open(real, "rb") as f:
                head = f.read(65536)
            if head.startswith(b"#!"):
                for m in re.finditer(rb"/opt/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)?", head):
                    path = m.group(0).decode()
                    cand = path if os.path.isdir(path) else os.path.dirname(path)
                    if cand.count("/") >= 2 and os.path.isdir(cand) and cand not in dirs:
                        dirs.append(cand)
    except OSError:
        pass
    # вложенные каталоги не нужны, если родитель уже есть
    return [d for d in dirs if not any(d != o and d.startswith(o + "/") for o in dirs)]


def host_program_in_home(argv0):
    """Если программа установлена в домашний каталог (~/.local, ~/.npm-global…), вернуть
    (настоящий путь, каталог для монтирования на чтение), иначе None."""
    if not argv0:
        return None
    found = os.path.expanduser(argv0) if argv0.startswith("~") else argv0
    if "/" not in found:
        found = shutil.which(found) or ""
    if not found or not os.path.isabs(found):
        return None
    real = os.path.realpath(found)
    home = os.path.realpath(os.path.expanduser("~"))
    root = os.path.realpath(envbox_root())
    if not (real.startswith(home + os.sep)) or real.startswith(root + os.sep):
        return None
    parts = os.path.relpath(real, home).split(os.sep)
    # ~/.local/share/<программа>/… монтируем целиком (рядом лежат библиотеки и версии)
    if len(parts) >= 4 and parts[0] == ".local" and parts[1] == "share":
        mount = os.path.join(home, *parts[:3])
    elif len(parts) >= 3 and parts[0] in (".cargo", ".npm-global", ".nvm", ".bun", ".deno"):
        mount = os.path.join(home, parts[0])
    else:
        mount = os.path.dirname(real)
    return real, mount


def browser_display_flag(p):
    """Режим показа браузера.

    Режим --headless=new — это отдельная урезанная сборка: Chrome в нём называет себя «HeadlessChrome»,
    и Google (вход в Gmail), GitHub, Cloudflare и многие другие сайты такому браузеру отказывают. Поэтому
    без окна запускается обычный полноценный Chrome на платформе ozone «headless»: у него обычный
    User-Agent, окна и Wayland не нужны, а кадры для просмотра в envbox идут по CDP как раньше.
    Если установленная версия Chrome такую платформу не поддерживает и сразу завершается, запустите
    envbox с ENVBOX_BROWSER_HEADLESS=new — вернётся прежний режим."""
    if p.browser_visible:
        return "--ozone-platform=wayland"
    if os.environ.get("ENVBOX_BROWSER_HEADLESS", "").strip().lower() == "new":
        return "--headless=new"
    return "--ozone-platform=headless"


def browser_command(p):
    """argv браузера внутри среды."""
    exe = p.browser_bin or find_browser() or "chromium"
    profile_dir = os.path.join(os.path.realpath(os.path.expanduser("~")), "chrome-profile")
    argv = [exe, f"--user-data-dir={profile_dir}", f"--remote-debugging-port={CDP_PORT}",
            "--no-first-run", "--no-default-browser-check", "--disable-gpu",
            "--disable-background-networking", "--disable-component-update", "--disable-sync",
            "--disable-breakpad", "--password-store=basic",
            # Порт отладки включает признак автоматизации (navigator.webdriver = true); Google и Cloudflare по нему
            # отвечают «браузер не прошёл проверку» (this browser may not be secure). Флаг убирает признак.
            "--disable-blink-features=AutomationControlled"]
    if p.net != "off":
        argv.append("--proxy-server=http://127.0.0.1:3128")
    argv.append(browser_display_flag(p))
    if not p.browser_chrome_sandbox:
        argv.append("--no-sandbox")
    argv.append(p.browser_start_url.strip() or "about:blank")
    return argv


def cdp_socket_path(name):
    return os.path.join(box_dir(name), "run", "expose", f"{CDP_PORT}.sock")


def attach_snippets(spec):
    """Готовые строки подключения ИИ к браузеру (выполняются внутри ИИ-среды)."""
    m = ATTACH_RE.match(spec)
    local = (m.group(3) or m.group(2) or str(CDP_PORT)) if m else str(CDP_PORT)
    url = f"http://127.0.0.1:{local}"
    return [
        ("Адрес CDP внутри среды", url),
        ("Playwright MCP для Claude Code",
         f"claude mcp add playwright -- npx -y @playwright/mcp@latest --cdp-endpoint {url}"),
        ("Chrome DevTools MCP для Claude Code",
         f"claude mcp add chrome-devtools -- npx -y chrome-devtools-mcp@latest --browser-url={url}"),
        ("Playwright (Node.js)", f"const browser = await chromium.connectOverCDP('{url}');"),
    ]


# ---- cdp/http.py: CDP: HTTP-запросы к DevTools через unix-сокет.

def cdp_listening(name):
    """True, если unix-сокет CDP среды принимает соединения."""
    try:
        _unix_connect(cdp_socket_path(name), 1).close()
        return True
    except OSError:
        return False


# ----------------------------------------- встроенный просмотр браузера (CDP по закрытому сокету)
# Приложение подключается к тому же сокету CDP, что и ИИ-среды, и показывает кадры страницы
# (Page.startScreencast). Окна Chrome и доступа к Wayland не нужно.

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


CDP_MOD_ALT, CDP_MOD_CTRL, CDP_MOD_META, CDP_MOD_SHIFT = 1, 2, 4, 8


class CdpError(OSError):
    """Ошибка связи с браузером по CDP."""


def _unix_connect(path, timeout=5):
    """Подключение к unix-сокету, который лежит в каталоге среды и потому подконтролен самой среде.
    Среда могла подложить вместо сокета ссылку на чужой (ssh-agent, docker.sock): файл открывается без перехода
    по ссылке (O_NOFOLLOW), проверяется, что это сокет, и подключение идёт по этому же дескриптору."""
    try:
        fd = os.open(path, os.O_PATH | os.O_NOFOLLOW)
    except OSError as e:
        raise CdpError(f"сокет браузера недоступен: {e.strerror or e}") from None
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        if not stat.S_ISSOCK(os.fstat(fd).st_mode):
            raise CdpError("по пути сокета браузера лежит не сокет")
        sock.settimeout(timeout)
        sock.connect(f"/proc/self/fd/{fd}")
    except OSError:
        sock.close()
        raise
    finally:
        os.close(fd)
    return sock


def _read_http_head(sock):
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(65536)
        if not chunk:
            raise CdpError("браузер закрыл соединение")
        buf += chunk
        if len(buf) > (1 << 20):
            raise CdpError("слишком длинный ответ браузера")
    head, _, rest = buf.partition(b"\r\n\r\n")
    return head.decode("latin-1"), rest


def cdp_http(sock_path, request_path, method="GET", timeout=5):
    """Запрос к HTTP-части CDP (/json/list, /json/new) по unix-сокету; возвращает разобранный JSON."""
    sock = _unix_connect(sock_path, timeout)
    try:
        sock.sendall(f"{method} {request_path} HTTP/1.1\r\nHost: 127.0.0.1:{CDP_PORT}\r\n"
                     "Connection: close\r\n\r\n".encode())
        data = b""
        while True:
            head, sep, body = data.partition(b"\r\n\r\n")
            if sep:
                m = re.search(rb"(?i)content-length:\s*(\d+)", head)
                if m and len(body) >= int(m.group(1)):  # DevTools не закрывает соединение сам
                    break
                if b"transfer-encoding: chunked" in head.lower() and body.endswith(b"0\r\n\r\n"):
                    break
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
            if len(data) > (8 << 20):
                raise CdpError("слишком длинный ответ браузера")
    except socket.timeout:
        raise CdpError("браузер не ответил") from None
    finally:
        sock.close()
    head, _, body = data.partition(b"\r\n\r\n")
    first = head.split(b"\r\n", 1)[0].decode("latin-1")
    if " 200" not in first:
        raise CdpError(f"браузер ответил: {first or 'пусто'}")
    if b"transfer-encoding: chunked" in head.lower():
        out, rest = b"", body
        while rest:
            size_line, _, rest = rest.partition(b"\r\n")
            try:
                size = int(size_line.split(b";")[0], 16)
            except ValueError:
                break
            if size == 0:
                break
            out += rest[:size]
            rest = rest[size + 2:]
        body = out
    try:
        return json.loads(body.decode("utf-8"))
    except ValueError:
        raise CdpError("браузер вернул не JSON") from None


def cdp_pick_page(sock_path):
    """Страница (target) для просмотра: первая открытая или новая пустая."""
    pages = [t for t in cdp_http(sock_path, "/json/list")
             if t.get("type") == "page" and t.get("webSocketDebuggerUrl")]
    if not pages:
        pages = [cdp_http(sock_path, "/json/new?about:blank", "PUT")]
    return pages[0]


# ---- cdp/client.py: CDP: клиент WebSocket DevTools.

class CdpClient:
    """Минимальный клиент CDP: websocket поверх unix-сокета, вызовы с ответом и события."""

    def __init__(self, sock_path, on_event=None, on_close=None):
        self.sock_path = sock_path
        self.on_event = on_event
        self.on_close = on_close
        self.target = None
        self._sock = None
        self._buf = b""
        self._send_lock = threading.Lock()
        self._pending = {}
        self._ids = itertools.count(1)
        self._closed = False
        self.applied_size = None

    # ---- websocket
    def connect(self, target=None):
        target = target or cdp_pick_page(self.sock_path)
        path = urllib.parse.urlsplit(target["webSocketDebuggerUrl"]).path
        sock = _unix_connect(self.sock_path, 5)
        key = base64.b64encode(os.urandom(16)).decode()
        try:
            sock.sendall((f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{CDP_PORT}\r\nUpgrade: websocket\r\n"
                          f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
                          "Sec-WebSocket-Version: 13\r\n\r\n").encode())
            head, rest = _read_http_head(sock)
            accept = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
            if " 101" not in head.split("\r\n", 1)[0] or ("sec-websocket-accept: " + accept.lower()) not in head.lower():
                raise CdpError("браузер не принял websocket-подключение: " + head.split("\r\n", 1)[0])
            sock.settimeout(None)
        except BaseException:
            sock.close()
            raise
        self._sock, self._buf, self.target = sock, rest, target
        threading.Thread(target=self._reader, name="envbox-cdp", daemon=True).start()

    def _read_exact(self, n):
        while len(self._buf) < n:
            chunk = self._sock.recv(262144)
            if not chunk:
                raise CdpError("соединение с браузером закрыто")
            self._buf += chunk
        data, self._buf = self._buf[:n], self._buf[n:]
        return data

    def _send_frame(self, opcode, payload):
        header = bytearray([0x80 | opcode])
        n = len(payload)
        if n < 126:
            header.append(0x80 | n)
        elif n < 65536:
            header += bytes([0x80 | 126]) + struct.pack(">H", n)
        else:
            header += bytes([0x80 | 127]) + struct.pack(">Q", n)
        mask = os.urandom(4)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload)) if n < 4096 else \
            (int.from_bytes(payload, "big") ^ int.from_bytes((mask * (n // 4 + 1))[:n], "big")).to_bytes(n, "big")
        with self._send_lock:
            self._sock.sendall(bytes(header) + mask + masked)

    def _recv_message(self):
        """Следующее текстовое сообщение (фрагменты склеиваются, ping отвечается pong)."""
        parts = []
        while True:
            b0, b1 = self._read_exact(2)
            fin, opcode = b0 & 0x80, b0 & 0x0F
            length = b1 & 0x7F
            if length == 126:
                length = struct.unpack(">H", self._read_exact(2))[0]
            elif length == 127:
                length = struct.unpack(">Q", self._read_exact(8))[0]
            if length > (64 << 20):
                raise CdpError("слишком большое сообщение браузера")
            mask = self._read_exact(4) if b1 & 0x80 else None
            payload = self._read_exact(length)
            if mask:
                payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
            if opcode == 0x8:
                raise CdpError("браузер закрыл соединение")
            if opcode == 0x9:
                self._send_frame(0xA, payload)
                continue
            if opcode == 0xA:
                continue
            parts.append(payload)
            if fin:
                return b"".join(parts).decode("utf-8", "replace")

    # ---- сообщения CDP
    def _reader(self):
        try:
            while True:
                data = json.loads(self._recv_message())
                if "id" in data:
                    waiter = self._pending.pop(data["id"], None)
                    if waiter:
                        waiter["reply"] = data
                        waiter["event"].set()
                elif "method" in data and self.on_event:
                    try:
                        self.on_event(data["method"], data.get("params") or {})
                    except Exception:  # noqa: BLE001
                        pass
        except (OSError, ValueError, AttributeError):
            pass
        finally:
            self._closed = True
            for waiter in list(self._pending.values()):
                waiter["event"].set()
            self._pending.clear()
            if self.on_close:
                try:
                    self.on_close()
                except Exception:  # noqa: BLE001
                    pass

    @property
    def closed(self):
        return self._closed

    def notify(self, method, params=None):
        """Команда без ожидания ответа (ввод, подтверждение кадров)."""
        if self._closed:
            raise CdpError("соединение с браузером закрыто")
        msg = {"id": next(self._ids), "method": method, "params": params or {}}
        self._send_frame(0x1, json.dumps(msg).encode())

    def call(self, method, params=None, timeout=10):
        if self._closed:
            raise CdpError("соединение с браузером закрыто")
        mid = next(self._ids)
        waiter = {"event": threading.Event(), "reply": None}
        self._pending[mid] = waiter
        try:
            self._send_frame(0x1, json.dumps({"id": mid, "method": method, "params": params or {}}).encode())
        except OSError as e:
            self._pending.pop(mid, None)
            raise CdpError(str(e)) from None
        if not waiter["event"].wait(timeout):
            self._pending.pop(mid, None)
            raise CdpError(f"{method}: браузер не ответил за {timeout} с")
        reply = waiter["reply"]
        if reply is None:
            raise CdpError("соединение с браузером закрыто")
        if "error" in reply:
            raise CdpError(f"{method}: {reply['error'].get('message', reply['error'])}")
        return reply.get("result") or {}

    def close(self):
        self._closed = True
        sock = self._sock  # ссылку не обнуляем: поток чтения должен получить обычную OSError, а не AttributeError
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()


# ---- cdp/browser.py: CDP: управление страницей браузера (навигация, вкладки, скрипты).

class CdpBrowser:
    """Подключение к браузеру целиком: список вкладок в реальном времени, создание, закрытие, переключение."""

    def __init__(self, sock_path, on_tabs=None, on_close=None):
        self.sock_path = sock_path
        self.on_tabs = on_tabs
        self.tabs = {}
        self.order = []
        self._lock = threading.Lock()
        self.client = CdpClient(sock_path, self._event, on_close)

    def connect(self):
        ver = cdp_http(self.sock_path, "/json/version")
        self.client.connect({"webSocketDebuggerUrl": ver["webSocketDebuggerUrl"]})
        self.client.call("Target.setDiscoverTargets", {"discover": True})

    def _event(self, method, params):
        created = destroyed = None
        if method in ("Target.targetCreated", "Target.targetInfoChanged"):
            info = params.get("targetInfo") or {}
            if info.get("type") != "page" or not info.get("targetId"):
                return
            tid = info["targetId"]
            with self._lock:
                if tid not in self.tabs:
                    self.order.append(tid)
                    created = tid
                self.tabs[tid] = {"id": tid, "title": info.get("title") or "", "url": info.get("url") or "",
                                  "opener": info.get("openerId") or ""}
        elif method == "Target.targetDestroyed":
            tid = params.get("targetId")
            with self._lock:
                if tid not in self.tabs:
                    return
                del self.tabs[tid]
                self.order.remove(tid)
            destroyed = tid
        else:
            return
        if self.on_tabs:
            self.on_tabs(self.snapshot(), created, destroyed)

    def snapshot(self):
        with self._lock:
            return [dict(self.tabs[t]) for t in self.order]

    def new_tab(self, url="about:blank"):
        return self.client.call("Target.createTarget", {"url": url})["targetId"]

    def close_tab(self, tid):
        self.client.call("Target.closeTarget", {"targetId": tid})

    def activate(self, tid):
        self.client.call("Target.activateTarget", {"targetId": tid})

    def close(self):
        self.client.close()


# Кадры идут в размере страницы в CSS-пикселях: при масштабе 25% это 4x по каждой стороне, поэтому ниже 50% не уходим
ZOOM_STEPS = [0.5, 0.67, 0.75, 0.8, 0.9, 1.0, 1.1, 1.25, 1.5, 1.75, 2.0, 2.5, 3.0]


_JS_SELECTION = (
    "(function(){var e=document.activeElement;"
    "if(e&&/^(INPUT|TEXTAREA)$/.test(e.tagName)&&typeof e.selectionStart==='number'&&e.selectionEnd>e.selectionStart)"
    "{return e.value.substring(e.selectionStart,e.selectionEnd);}return String(window.getSelection());})()")


def _js_hit_info(x, y):
    return ("(function(x,y){var e=document.elementFromPoint(x,y);"
            "var a=e&&e.closest?e.closest('a[href]'):null,i=e&&e.closest?e.closest('img'):null,"
            "v=e&&e.closest?e.closest('video'):null;"
            "var ed=!!(e&&(e.isContentEditable||/^(INPUT|TEXTAREA)$/.test(e.tagName)));"
            "return JSON.stringify({link:a?a.href:'',image:i?(i.currentSrc||i.src):'',"
            "video:v?(v.currentSrc||v.src):'',editable:ed});})(%s,%s)" % (json.dumps(x), json.dumps(y)))


# ---- cdp/keys.py: CDP: перевод координат, клавиш и масштаба.

def normalize_url(text):
    """Адрес из строки ввода: только http/https (и about:blank); без схемы добавляется https://."""
    t = text.strip()
    if not t:
        return "about:blank"
    if t == "about:blank":
        return t
    if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", t):
        if not re.match(r"^https?://", t, re.I):
            raise ValueError("поддерживаются только адреса http и https")
        url = t
    else:
        url = "https://" + t
    if any(c.isspace() for c in url):
        raise ValueError("адрес не может содержать пробелы")
    return url


def map_point(x, y, widget_w, widget_h, frame_w, frame_h):
    """Точка в виджете (картинка вписана с сохранением пропорций) -> точка на странице; None вне кадра."""
    if min(widget_w, widget_h, frame_w, frame_h) <= 0:
        return None
    scale = min(widget_w / frame_w, widget_h / frame_h)
    off_x, off_y = (widget_w - frame_w * scale) / 2, (widget_h - frame_h * scale) / 2
    px, py = (x - off_x) / scale, (y - off_y) / scale
    if px < 0 or py < 0 or px > frame_w or py > frame_h:
        return None
    return px, py


_CDP_KEYS = {
    "Return": ("Enter", "Enter", 13, "\r"), "KP_Enter": ("Enter", "NumpadEnter", 13, "\r"),
    "BackSpace": ("Backspace", "Backspace", 8, ""), "Tab": ("Tab", "Tab", 9, ""),
    "ISO_Left_Tab": ("Tab", "Tab", 9, ""), "Escape": ("Escape", "Escape", 27, ""),
    "Delete": ("Delete", "Delete", 46, ""), "Insert": ("Insert", "Insert", 45, ""),
    "Left": ("ArrowLeft", "ArrowLeft", 37, ""), "Up": ("ArrowUp", "ArrowUp", 38, ""),
    "Right": ("ArrowRight", "ArrowRight", 39, ""), "Down": ("ArrowDown", "ArrowDown", 40, ""),
    "Home": ("Home", "Home", 36, ""), "End": ("End", "End", 35, ""),
    "Page_Up": ("PageUp", "PageUp", 33, ""), "Page_Down": ("PageDown", "PageDown", 34, ""),
}


_CDP_EDIT_COMMANDS = {"a": "selectAll", "c": "copy", "x": "cut", "z": "undo", "y": "redo"}


def cdp_key_events(keyname, char, mods, pressed):
    """Параметры Input.dispatchKeyEvent для нажатия/отпускания клавиши (список; бывает пустым)."""
    if keyname in _CDP_KEYS:
        key, code, vk, text = _CDP_KEYS[keyname]
        if not pressed:
            return [{"type": "keyUp", "key": key, "code": code, "windowsVirtualKeyCode": vk, "modifiers": mods}]
        ev = {"type": "keyDown" if text else "rawKeyDown", "key": key, "code": code,
              "windowsVirtualKeyCode": vk, "modifiers": mods}
        if text:
            ev["text"] = ev["unmodifiedText"] = text
        return [ev]
    if not char or not char.isprintable():
        return []
    if mods & (CDP_MOD_CTRL | CDP_MOD_ALT | CDP_MOD_META):
        ev = {"type": ("rawKeyDown" if pressed else "keyUp"), "key": char, "modifiers": mods}
        if pressed and mods & CDP_MOD_CTRL and char.lower() in _CDP_EDIT_COMMANDS:
            ev["commands"] = [_CDP_EDIT_COMMANDS[char.lower()]]
        return [ev]
    if pressed:
        return [{"type": "keyDown", "key": char, "text": char, "unmodifiedText": char, "modifiers": mods}]
    return [{"type": "keyUp", "key": char, "modifiers": mods}]


# ---- cdp/viewer.py: CDP: просмотр страницы в окне (кадры экрана, ввод).

# Схемы, которые браузер открывает сам. Всё остальное (claude://, mailto:…) — запуск внешней программы.
_OWN_SCHEMES = ("http", "https", "about", "data", "blob", "file", "filesystem", "javascript", "ws", "wss", "ftp",
                "chrome", "chrome-error", "chrome-untrusted", "chrome-extension", "devtools", "view-source")


def external_scheme(url):
    """Схема адреса, если по нему браузер запускает внешнюю программу (claude://…), иначе пустая строка."""
    m = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*):", url or "")
    return m.group(1).lower() if m and m.group(1).lower() not in _OWN_SCHEMES else ""


def local_callback_url(url):
    """Адрес на этом же компьютере (http://127.0.0.1:порт/…), если он такой, иначе пустая строка.

    Так завершается вход в программу внутри другой среды (Claude CLI): сайт перенаправляет браузер на порт, который
    слушает программа, а у браузера-среды свой localhost, и страница пишет «refused to connect»."""
    try:
        u = urllib.parse.urlsplit(url or "")
        return url if u.scheme in ("http", "https") and (u.hostname or "").lower() in ("localhost", "127.0.0.1", "::1") \
            and u.port else ""
    except ValueError:
        return ""


class CdpViewer:
    """Просмотр браузера среды: вкладки, кадры (JPEG) в on_frame, ввод мышью и клавиатурой, масштаб.

    on_tabs(список вкладок, id активной) вызывается из потока чтения при любом изменении вкладок.
    on_external(адрес) — страница пыталась открыть внешнюю программу (claude://…): Chrome без окна показывает
    запрос, который нельзя закрыть, и вкладка перестаёт принимать ввод, поэтому вкладку мы закрываем сами.
    Туда же приходит адрес колбэка входа (http://127.0.0.1:порт/callback…), на котором страница «не открылась»:
    его слушает программа в другой среде; вкладка при этом остаётся."""

    def __init__(self, sock_path, on_frame, on_url=None, on_close=None, on_tabs=None, on_external=None):
        self.sock_path = sock_path
        self.on_frame, self.on_url, self.on_close, self.on_tabs = on_frame, on_url, on_close, on_tabs
        self.on_external = on_external
        self.windows = {}
        self.browser = CdpBrowser(sock_path, self._tabs_event, self._browser_closed)
        self.client = None
        self.clients = {}
        self.active = None
        self.size = (0, 0)
        self.zoom = {}
        self._attach_lock = threading.RLock()
        self._closing = False

    # ---- подключение и вкладки
    def connect(self, width, height):
        self.size = (max(200, int(width)), max(150, int(height)))
        self.browser.connect()
        page = cdp_pick_page(self.sock_path)
        self.attach(page["id"], activate=False)

    def _emit_tabs(self):
        if self.on_tabs:
            self.on_tabs(self.browser.snapshot(), self.active)

    def _open_page(self, tid):
        """Сеанс CDP для вкладки: создаётся один раз и живёт, пока вкладка открыта (сброс сеанса ломает размер кадров)."""
        cell = {}
        client = CdpClient(self.sock_path, lambda m, p: self._page_event(cell["c"], m, p), None)
        cell["c"] = client
        client.connect({"webSocketDebuggerUrl": f"ws://127.0.0.1:{CDP_PORT}/devtools/page/{tid}"})
        try:
            client.call("Page.enable")
            self.client = client
            self._apply_metrics(tid)
        except BaseException:
            client.close()
            raise
        return client

    def attach(self, tid, activate=True):
        """Показывать вкладку tid: трансляция кадров переключается на неё, сеансы остальных остаются открытыми.

        Порядок важен: сначала вкладка делается видимой, потом задаётся размер, потом идут кадры — иначе Chrome
        отдаёт кадры размера окна (780x437), а не заданного вьюпорта."""
        with self._attach_lock:
            old, old_active = self.client, self.active
            try:
                if activate:
                    try:
                        self.browser.activate(tid)
                    except CdpError:
                        pass
                client = self.clients.get(tid)
                if client is None or client.closed:
                    client = self._open_page(tid)
                    self.clients[tid] = client
                if old is not None and old is not client and not old.closed:
                    try:
                        old.notify("Page.stopScreencast")
                    except OSError:
                        pass
                self.client, self.active = client, tid
                self._apply_metrics()
                client.call("Page.startScreencast", {"format": "jpeg", "quality": 75, "everyNthFrame": 1})
                try:
                    info = client.call("Page.getNavigationHistory")
                    url = info["entries"][info["currentIndex"]].get("url", "")
                    if self.on_url:
                        self.on_url(url)
                except (CdpError, KeyError, IndexError):
                    pass
            except BaseException:
                self.client, self.active = old, old_active
                raise
        self._emit_tabs()

    def _safe_attach(self, tid):
        try:
            self.attach(tid)
        except (OSError, KeyError, ValueError):
            pass

    def _tabs_event(self, tabs, created, destroyed):
        ids = [t["id"] for t in tabs]
        if destroyed is not None:
            self.windows.pop(destroyed, None)
            gone = self.clients.pop(destroyed, None)
            if gone is not None:
                gone.close()
        if destroyed is not None and destroyed == self.active and not self._closing:
            target = ids[-1] if ids else None
            if target:
                threading.Thread(target=self._safe_attach, args=(target,), daemon=True).start()
            else:  # вкладок не осталось — открываем пустую, чтобы окно не было мёртвым
                threading.Thread(target=self._safe_new_tab, daemon=True).start()
        elif created is not None and not self._closing:
            tab = next((t for t in tabs if t["id"] == created), None)
            if tab and self.active and tab["opener"] == self.active:  # ссылка в новой вкладке, window.open
                threading.Thread(target=self._safe_attach, args=(created,), daemon=True).start()
        self._emit_tabs()

    def _safe_new_tab(self):
        try:
            self.new_tab("about:blank")
        except (OSError, KeyError, ValueError):
            pass

    def _browser_closed(self):
        if self.on_close:
            self.on_close()

    def new_tab(self, url="about:blank"):
        url = normalize_url(url)
        tid = self.browser.new_tab(url)
        self.attach(tid)
        return tid

    def close_tab(self, tid):
        self.browser.close_tab(tid)

    def switch_tab(self, tid):
        if tid != self.active:
            self.attach(tid)

    # ---- события страницы
    def _page_event(self, client, method, params):
        if method == "Page.javascriptDialogOpening":
            # Пока диалог (alert, confirm, beforeunload) не закрыт, страница стоит и кадры не идут: после входа
            # через Google окно «зависало». Закрываем в любой вкладке: alert и «уйти со страницы?» принимаем,
            # confirm и prompt отклоняем.
            accept = (params or {}).get("type") in ("alert", "beforeunload")
            try:
                client.notify("Page.handleJavaScriptDialog", {"accept": accept})
            except OSError:
                pass
            return
        if method == "Page.frameRequestedNavigation":
            url = (params or {}).get("url", "")
            if external_scheme(url):
                self._external(client, url)
            return
        if method == "Page.frameNavigated":
            frame = (params or {}).get("frame") or {}
            if "parentId" not in frame and local_callback_url(frame.get("unreachableUrl", "")):
                self._external(client, frame["unreachableUrl"], close=False)
        if client is not self.client:
            return
        if method == "Page.screencastFrame":
            try:
                client.notify("Page.screencastFrameAck", {"sessionId": params["sessionId"]})
            except OSError:
                return
            try:
                data = base64.b64decode(params["data"])
            except (KeyError, ValueError):
                return
            self.on_frame(data, params.get("metadata") or {})
        elif method == "Page.frameNavigated":
            frame = params.get("frame") or {}
            if "parentId" not in frame and self.on_url:
                self.on_url(frame.get("url", ""))
        elif method == "Page.navigatedWithinDocument" and self.on_url:
            self.on_url(params.get("url", ""))

    def _external(self, client, url, close=True):
        """Страница запросила запуск внешней программы: сообщаем наружу и закрываем вкладку (она уже зависла)."""
        tid = next((t for t, c in self.clients.items() if c is client), None)

        def work():
            if self.on_external:
                try:
                    self.on_external(url)
                except Exception:  # noqa: BLE001  ошибка обработчика не должна оставить вкладку висеть
                    pass
            if close and tid is not None and not self._closing:
                try:
                    self.close_tab(tid)
                except (OSError, CdpError, KeyError, ValueError):
                    pass

        threading.Thread(target=work, daemon=True).start()

    def _page(self):
        c = self.client
        if c is None or c.closed:
            raise CdpError("нет открытой вкладки")
        return c

    # ---- размер и масштаб
    @property
    def cur_zoom(self):
        return self.zoom.get(self.active, 1.0)

    def _apply_metrics(self, tid=None):
        """Размер страницы, экрана и окна браузера.

        Страница читает размер окна сама: innerWidth/outerWidth, screen.width, devicePixelRatio. Безоконный Chrome
        по умолчанию отвечает ей «окно 500x87, экран 1x1», и сайты (например, страница подтверждения входа) пишут
        «окно слишком маленькое». Масштаб — настоящий, как в браузере: страница видит innerWidth = ширина / масштаб
        и devicePixelRatio = масштаб, адаптивная вёрстка перестраивается. Кадры идут в размере CSS-пикселей, поэтому
        координаты кадра = координаты страницы."""
        tid = tid or self.active
        w, h = self.size
        z = self.zoom.get(tid, 1.0)
        cw, ch = max(1, round(w / z)), max(1, round(h / z))
        c = self._page()
        c.call("Emulation.setDeviceMetricsOverride", {"width": cw, "height": ch, "deviceScaleFactor": z,
                                                      "mobile": False, "screenWidth": cw, "screenHeight": ch})
        self._fit_window(tid, w, h)
        c.applied_size = (w, h)

    def _fit_window(self, tid, w, h):
        """Окно браузера не меньше показываемой области (только увеличиваем: настоящее окно не трогаем)."""
        try:
            win = self.windows.get(tid)
            if win is None:
                info = self.browser.client.call("Browser.getWindowForTarget", {"targetId": tid})
                win = self.windows[tid] = {"id": info["windowId"], "size": (info["bounds"].get("width", 0),
                                                                           info["bounds"].get("height", 0))}
            if win["size"][0] < w or win["size"][1] < h:
                bounds = {"left": 0, "top": 0, "width": max(w, win["size"][0]), "height": max(h, win["size"][1]),
                          "windowState": "normal"}
                self.browser.client.call("Browser.setWindowBounds", {"windowId": win["id"], "bounds": bounds})
                win["size"] = (bounds["width"], bounds["height"])
        except (CdpError, KeyError, TypeError, AttributeError):
            pass   # не все сборки Chrome умеют управлять окном: страница получит то, что есть

    def set_size(self, width, height):
        width, height = max(200, int(width)), max(150, int(height))
        if (width, height) == self.size:
            return
        self.size = (width, height)
        if self.client is not None:
            self._apply_metrics()

    def set_zoom(self, value):
        value = round(min(ZOOM_STEPS[-1], max(ZOOM_STEPS[0], float(value))), 2)
        self.zoom[self.active] = value
        self._apply_metrics()
        return value

    def zoom_step(self, direction):
        z = self.cur_zoom
        if direction > 0:
            nxt = next((x for x in ZOOM_STEPS if x > z + 1e-6), ZOOM_STEPS[-1])
        else:
            nxt = next((x for x in reversed(ZOOM_STEPS) if x < z - 1e-6), ZOOM_STEPS[0])
        return self.set_zoom(nxt)

    def _css(self, x, y):
        return x, y  # кадр идёт в CSS-пикселях страницы (см. _apply_metrics): пересчёт не нужен

    # ---- навигация
    def navigate(self, text):
        self._page().call("Page.navigate", {"url": normalize_url(text)})

    def reload(self):
        self._page().call("Page.reload")

    def history(self, step):
        c = self._page()
        info = c.call("Page.getNavigationHistory")
        idx = info["currentIndex"] + step
        if 0 <= idx < len(info["entries"]):
            c.call("Page.navigateToHistoryEntry", {"entryId": info["entries"][idx]["id"]})

    # ---- ввод
    def mouse(self, kind, x, y, button="none", clicks=0, mods=0, buttons=0):
        x, y = self._css(x, y)
        self._page().notify("Input.dispatchMouseEvent", {"type": kind, "x": x, "y": y, "button": button,
                                                          "clickCount": clicks, "modifiers": mods,
                                                          "buttons": buttons})

    def wheel(self, x, y, dx, dy, mods=0):
        x, y = self._css(x, y)
        self._page().notify("Input.dispatchMouseEvent", {"type": "mouseWheel", "x": x, "y": y,
                                                          "deltaX": dx, "deltaY": dy, "modifiers": mods})

    def key(self, keyname, char, mods, pressed):
        c = self._page()
        for ev in cdp_key_events(keyname, char, mods, pressed):
            c.notify("Input.dispatchKeyEvent", ev)

    def insert_text(self, text):
        self._page().notify("Input.insertText", {"text": text})

    # ---- выделение, поиск, содержимое под курсором
    def evaluate(self, expression, timeout=5):
        r = self._page().call("Runtime.evaluate", {"expression": expression, "returnByValue": True,
                                                    "timeout": 3000}, timeout=timeout)
        return (r.get("result") or {}).get("value")

    def selection_text(self):
        value = self.evaluate(_JS_SELECTION)
        return value if isinstance(value, str) else ""

    def select_all(self):
        self.evaluate("document.execCommand('selectAll')")

    def hit_info(self, x, y):
        """Что под точкой (координаты в кадре): ссылка, картинка, видео, поле ввода, выделенный текст."""
        cx, cy = self._css(x, y)
        raw = self.evaluate(_js_hit_info(cx, cy))
        try:
            info = json.loads(raw) if isinstance(raw, str) else {}
        except ValueError:
            info = {}
        info.setdefault("link", "")
        info.setdefault("image", "")
        info.setdefault("video", "")
        info.setdefault("editable", False)
        info["selection"] = self.selection_text()
        return info

    def find(self, text, backwards=False):
        if not text:
            return False
        return bool(self.evaluate(f"window.find({json.dumps(text)}, false, {'true' if backwards else 'false'}, true)"))

    def close(self):
        self._closing = True
        c = self.client
        try:
            if c is not None and not c.closed:
                c.notify("Page.stopScreencast")
        except OSError:
            pass
        for client in list(self.clients.values()):
            client.close()
        if c is not None:
            c.close()
        self.browser.close()


# ------------------- ссылки В среду: вход по ссылке (claude://…), обратные вызовы localhost (канал inbox)

LINK_MAX = 2048


# ---- core/sessions.py: Запущенные сеансы сред: поиск в /proc, остановка.

@dataclass
class Session:
    pid: int
    name: str
    seconds: int
    command: str
    inner: tuple = ()


def _proc_args(pid, proc="/proc"):
    with open(f"{proc}/{pid}/cmdline", "rb") as f:
        return [a.decode("utf-8", "replace") for a in f.read().split(b"\0") if a]


def _proc_stat(pid, proc="/proc"):
    with open(f"{proc}/{pid}/stat", encoding="utf-8", errors="replace") as f:
        rest = f.read().rsplit(")", 1)[1].split()
    return int(rest[1]), int(rest[19])  # ppid, starttime (тики с загрузки)


def _session_name(args):
    """Имя среды по аргументам bwrap: метка ENVBOX_SESSION или (старые версии) имя компьютера."""
    for i in range(len(args) - 2):
        if args[i] == "--setenv" and args[i + 1] == "ENVBOX_SESSION":
            return args[i + 2]
    if "--hostname" in args:
        host = args[args.index("--hostname") + 1]
        if host.startswith("envbox-"):
            return host[len("envbox-"):]
    return ""


def _session_command(args):
    try:
        cmd = args[args.index("--") + 1:]
    except ValueError:
        return ""
    if cmd[:4] == ["/usr/bin/python3", "-I", "/run/envbox/net.py", "wrap"] and "--" in cmd:
        cmd = cmd[cmd.index("--") + 1:]
    return shlex.join(cmd)


def list_sessions(proc="/proc"):
    """Запущенные среды текущего пользователя (внешние процессы bwrap)."""
    uid = os.getuid()
    found = {}
    for entry in os.listdir(proc):
        if not entry.isdigit():
            continue
        pid = int(entry)
        try:
            # название процесса читается одним коротким файлом; тяжёлое (cmdline, stat) — только для bwrap.
            # Раньше cmdline читался у всех процессов компьютера каждую секунду.
            with open(f"{proc}/{pid}/comm", "rb") as f:
                if f.read(16).rstrip(b"\n") != b"bwrap":
                    continue
            if os.stat(f"{proc}/{pid}").st_uid != uid:
                continue
            args = _proc_args(pid, proc)
            if not args or os.path.basename(args[0]) != "bwrap":
                continue
            name = _session_name(args)
            if not name:
                continue
            ppid, start = _proc_stat(pid, proc)
        except (OSError, IndexError, ValueError):
            continue
        found[pid] = (name, ppid, start, _session_command(args))
    try:
        with open(f"{proc}/uptime") as f:
            uptime = float(f.read().split()[0])
    except OSError:
        uptime = 0.0
    tck = os.sysconf("SC_CLK_TCK")
    out = []
    for pid, (name, ppid, start, cmd) in found.items():
        if ppid in found and found[ppid][0] == name:
            continue  # внутренний bwrap (pid 1 в namespace) той же среды
        inner = tuple(q for q, v in found.items() if v[1] == pid and v[0] == name)
        out.append(Session(pid, name, max(0, int(uptime - start / tck)), cmd, inner))
    return sorted(out, key=lambda s: (s.name, s.pid))


def stop_session(session):
    """SIGTERM внешнему bwrap и pid 1 среды; процессы внутри завершит ядро."""
    os.kill(session.pid, signal.SIGTERM)
    for q in session.inner:
        try:
            os.kill(q, signal.SIGTERM)
        except ProcessLookupError:
            pass


def format_duration(sec):
    h, rem = divmod(sec, 3600)
    m, s = divmod(rem, 60)
    return f"{h}:{m:02d}:{s:02d}" if h else f"{m}:{s:02d}"


# ---- core/keyring.py: Секреты в keyring (secret-tool).

def _secret_attrs(name, var):
    return ["service", "envbox", "profile", name, "var", var]


def secret_tool_available():
    return shutil.which("secret-tool") is not None


def secret_store(name, var, value):
    r = subprocess.run(["secret-tool", "store", "--label", f"envbox {name} {var}",
                        *_secret_attrs(name, var)],
                       input=value, capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip() or "secret-tool store завершился с ошибкой")


def secret_exists(name, var):
    r = subprocess.run(["secret-tool", "lookup", *_secret_attrs(name, var)],
                       stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
    return r.returncode == 0 and bool(r.stdout)


def secret_lookup(name, var):
    """Значение секрета или пустая строка."""
    r = subprocess.run(["secret-tool", "lookup", *_secret_attrs(name, var)],
                       stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
    return r.stdout if r.returncode == 0 else ""


def secret_clear(name, var):
    subprocess.run(["secret-tool", "clear", *_secret_attrs(name, var)],
                   stdin=subprocess.DEVNULL, capture_output=True, timeout=30)


# ---- core/system.py: Сведения о системе: доступные оболочки, дистрибутив, подсказки по установке пакетов.

def installed_shells():
    """Оболочки, доступные в среде: берутся с компьютера (bash есть всегда)."""
    return [x for x in SHELLS if x == "bash" or shutil.which(x)]


def _distro_id():
    try:
        with open("/etc/os-release", encoding="utf-8") as f:
            data = f.read()
    except OSError:
        return ""
    ids = re.findall(r"^(?:ID|ID_LIKE)=(.*)$", data, re.M)
    return " ".join(x.strip().strip('"') for x in ids).lower()


_PKGS = {
    "secret-tool": {"arch": "libsecret", "debian": "libsecret-tools", "fedora": "libsecret"},
    "bubblewrap": {"arch": "bubblewrap", "debian": "bubblewrap", "fedora": "bubblewrap"},
    "vte": {"arch": "vte4", "debian": "gir1.2-vte-3.91", "fedora": "vte291-gtk4"},
    "chromium": {"arch": "chromium", "debian": "chromium", "fedora": "chromium"},
    "fish": {"arch": "fish", "debian": "fish", "fedora": "fish"},
    "zsh": {"arch": "zsh", "debian": "zsh", "fedora": "zsh"},
    "nodejs": {"arch": "nodejs npm", "debian": "nodejs npm", "fedora": "nodejs npm"},
    "unzip": {"arch": "unzip", "debian": "unzip", "fedora": "unzip"},
    "gcc": {"arch": "base-devel", "debian": "build-essential", "fedora": "gcc"},
}


def pkg_hint(what):
    """Команда установки пакета для вашего дистрибутива (по /etc/os-release)."""
    ids = _distro_id()
    row = _PKGS[what]
    if "arch" in ids:
        return "sudo pacman -S " + row["arch"]
    if "fedora" in ids or "rhel" in ids:
        return "sudo dnf install " + row["fedora"]
    if "debian" in ids or "ubuntu" in ids:
        return "sudo apt install " + row["debian"]
    return "установите пакет «" + row["arch"] + "» средствами вашего дистрибутива"


# ---- core/isolation.py: Параметры изоляции, пресеты и рецепты установки программ.

ISO_OPTIONS = [
    dict(key="protect_git", group="Файлы", store="protect_git", invert=False, warn_off=True, app_only=True,
         title="Защита хуков Git",
         text="Каталог .git/hooks и файл .git/config нельзя изменить изнутри среды.",
         risk="программа может подложить git-хук, который выполнится у вас при следующей команде git."),
    dict(key="ephemeral", group="Файлы", store="ephemeral", invert=False, warn_off=False, presets=False,
         title="Стирать домашний каталог после выхода",
         text="Всё, что программа сохранила у себя дома (история, вход в аккаунт), удаляется при выходе из среды.",
         risk=""),
    dict(key="ro_root", group="Файлы", store="iso", warn_off=True,
         title="Корень среды только для чтения",
         text="Программа не может создавать файлы в системных каталогах среды, только в разрешённых местах.",
         risk="программа сможет создавать временные файлы в корне среды (они исчезнут при выходе)."),
    dict(key="pid", group="Процессы и система", store="iso", warn_off=True,
         title="Скрывать процессы компьютера",
         text="Внутри видны только процессы самой среды: ps не показывает ваши программы.",
         risk="программа видит все ваши процессы, читает их окружение (там могут быть токены) и может их завершать."),
    dict(key="ipc", group="Процессы и система", store="iso", warn_off=True,
         title="Своя общая память и очереди сообщений",
         text="Отдельное пространство IPC: программа не видит общую память других ваших программ.",
         risk="программа может читать общую память и очереди сообщений других ваших программ."),
    dict(key="uts", group="Процессы и система", store="iso", warn_off=True,
         title="Своё имя компьютера",
         text="Внутри среды другое имя компьютера (envbox-<имя>) вместо настоящего.",
         risk="программа узнаёт настоящее имя вашего компьютера."),
    dict(key="cgroup", group="Процессы и система", store="iso", warn_off=True,
         title="Скрывать группы ресурсов (cgroup)",
         text="Программа не видит, в какой группе systemd и сеансе работает ваш рабочий стол.",
         risk="программа видит структуру ваших сеансов и служб."),
    dict(key="seccomp", group="Процессы и система", store="iso", warn_off=True,
         title="Фильтр системных вызовов",
         text="Запрещены опасные вызовы ядра: ptrace, bpf, io_uring, mount, perf, загрузка модулей, смена часов.",
         risk="больше возможностей атаковать ядро; отключайте, только если какая-то программа не работает с фильтром."),
    dict(key="no_userns", group="Процессы и система", store="allow_userns", invert=True, warn_off=True,
         title="Запретить вложенные изолированные среды",
         text="Внутри нельзя создать ещё одно пространство имён (user namespace).",
         risk="шире поверхность атаки на ядро. Включать нужно только для Chrome со своим sandbox, podman и вложенного bwrap."),
    dict(key="session", group="Процессы и система", store="iso", warn_off=True,
         title="Отключить управляющий терминал",
         text="Защита от TIOCSTI: программа не может подсунуть команды в ваш настоящий терминал.",
         risk="программа может вводить текст в ваш терминал (если ядро это допускает)."),
    dict(key="die_parent", group="Процессы и система", store="iso", warn_off=True,
         title="Завершать среду вместе с envbox",
         text="Если окно или терминал закрыты, все процессы среды завершаются.",
         risk="процессы могут остаться работать в фоне после закрытия окна."),
    dict(key="caps", group="Процессы и система", store="iso", warn_off=True,
         title="Сбросить особые привилегии (capabilities)",
         text="У процессов внутри нет ни одной особой привилегии.",
         risk="у процессов внутри остаются привилегии пространства имён."),
    dict(key="host_net_forbidden", group="Сеть", store="iso", warn_off=True,
         title="Запретить сеть компьютера",
         text="Выход в сеть возможен только через прокси с журналом; режим «общая с компьютером» недоступен.",
         risk="можно выбрать общую сеть: программа тогда видит все сервисы компьютера на localhost."),
    dict(key="neutral_dns", group="Сеть", store="iso", warn_off=True,
         title="Скрывать адреса ваших DNS-серверов",
         text="В /etc/resolv.conf внутри среды нейтральная запись вместо адресов вашего роутера и провайдера.",
         risk="программа видит адреса DNS-серверов вашей сети."),
    dict(key="clean_env", group="Окружение", store="iso", warn_off=True,
         title="Передавать только перечисленные переменные",
         text="Из окружения компьютера в среду попадают только переменные, которые вы указали.",
         risk="в среду попадают все переменные компьютера, в том числе токены и пути."),
]


ISO_KEYS = {o["key"] for o in ISO_OPTIONS if o["store"] == "iso"} | {"home_real"}


ISO_PRESETS = [
    ("max", "Максимум (рекомендуется)", "Все защиты включены.", {}),
    ("compat", "Совместимость",
     "Как максимум, но без фильтра системных вызовов и нейтрального resolv.conf, а вложенные пространства "
     "имён разрешены (Chrome со своим sandbox, podman).",
     {"seccomp": False, "no_userns": False, "neutral_dns": False}),
    ("min", "Минимум — только для отладки",
     "Дополнительно без своих IPC и cgroup, с записью в корень среды и с возможностью выбрать сеть компьютера.",
     {"seccomp": False, "no_userns": False, "neutral_dns": False, "ipc": False, "cgroup": False,
      "ro_root": False, "host_net_forbidden": False}),
]


ISO_RISKY_DEFAULT = {"home_real": False}


# Рецепты установки: команда вводится в установочном терминале (её можно поправить до запуска).
# domains — сайты, нужные установщику; пусто = заранее неизвестно, сеть открывается на любые публичные
# адреса с журналом (после установки список можно сузить по журналу).
INSTALL_RECIPES = [
    dict(id="node", title="Node.js (LTS, официальный архив)", domains=["nodejs.org"],
         command=r"""cd /tmp && b=https://nodejs.org/dist/latest-v24.x && a=x64; [ "$(uname -m)" = aarch64 ] && a=arm64; f=$(curl -fsSL $b/SHASUMS256.txt | grep -o "node-v[0-9.]*-linux-$a.tar.xz" | head -1) && curl -fsSLO $b/$f && curl -fsSL $b/SHASUMS256.txt | grep " $f\$" | sha256sum -c - && mkdir -p ~/.local && tar -xJf $f --strip-components=1 -C ~/.local --exclude='*.md' --exclude=LICENSE && node -v""",
         note="Ставит node и npm в домашний каталог среды, ничего не меняя на компьютере (pacman не нужен). "
              "Контрольная сумма проверяется."),
    dict(id="claude-native", title="Claude Code (официальный установщик, без Node)", domains=[],
         command="curl -fsSL https://claude.ai/install.sh | bash",
         note="Рекомендуемый способ: Node не нужен, команда claude появится в ~/.local/bin. Установщик "
              "скачивает файлы с нескольких сайтов, поэтому сеть открыта на любые публичные адреса с журналом."),
    dict(id="claude-desktop", title="Claude Desktop (неофициальная сборка для Linux, AppImage)", domains=[],
         command=r"""mkdir -p ~/.local/opt ~/.local/bin && cd ~/.local/opt && u=$(curl -fsSL https://api.github.com/repos/patrickjaja/claude-desktop-bin/releases/latest | grep -o 'https://[^"]*x86_64\.AppImage' | head -1) && [ -n "$u" ] && curl -fL --retry 8 --retry-all-errors --retry-delay 2 -C - -o cd.AppImage "$u" && chmod +x cd.AppImage && rm -rf squashfs-root claude-desktop && ./cd.AppImage --appimage-extract >/dev/null && mv squashfs-root claude-desktop && rm -f cd.AppImage && printf '%s\n' '#!/bin/sh' 'exec "$HOME/.local/opt/claude-desktop/AppRun" --no-sandbox --disable-gpu --ozone-platform=wayland --password-store=basic --proxy-server=http://127.0.0.1:3128 "$@"' > ~/.local/bin/claude-desktop && chmod +x ~/.local/bin/claude-desktop && echo "Готово: запускайте командой claude-desktop" """.strip(),
         note="Сообщество перепаковывает официальное приложение (не подписано Anthropic). Скачивается с GitHub и "
              "распаковывается без FUSE в ~/.local/opt; запуск — командой claude-desktop. Нужен шаблон среды "
              "«Claude Desktop» (окно через Wayland). Если не запускается из-за библиотеки, поставьте её на "
              "компьютере через pacman. Файл большой (~220 МБ): при обрыве загрузка сама докачивается, а если не помогло — "
              "запустите команду ещё раз (докачка продолжится). Весь трафик идёт через ваш прокси. Сайты загрузки "
              "заранее неизвестны, поэтому сеть открыта на любые публичные адреса."),
    dict(id="npm-claude", title="Claude Code (через npm)", domains=["registry.npmjs.org"], needs=["node"],
         command="npm config set prefix ~/.local && npm install -g --allow-scripts=@anthropic-ai/claude-code @anthropic-ai/claude-code && claude --version",
         note="Устаревший способ (есть официальный установщик выше). Нужен node внутри среды. Флаг "
              "--allow-scripts разрешает пакету его установочный скрипт (новые версии npm о нём предупреждают)."),
    dict(id="npm-codex", title="Codex CLI (через npm)", domains=["registry.npmjs.org"], needs=["node"],
         command="npm config set prefix ~/.local && npm install -g @openai/codex",
         note="Нужен node внутри среды. Команда codex появится в ~/.local/bin."),
    dict(id="npm-gemini", title="Gemini CLI (через npm)", domains=["registry.npmjs.org"], needs=["node"],
         command="npm config set prefix ~/.local && npm install -g @google/gemini-cli",
         note="Нужен node внутри среды. Команда gemini появится в ~/.local/bin."),
    dict(id="pnpm", title="pnpm (менеджер пакетов Node)", domains=["registry.npmjs.org"], needs=["node"],
         command="npm config set prefix ~/.local && npm install -g pnpm",
         note="Нужен node внутри среды."),
    dict(id="bun", title="Bun (среда выполнения JavaScript)", domains=[], needs=["unzip"],
         command="curl -fsSL https://bun.sh/install | bash",
         note="Ставится в ~/.bun. Установщик скачивает архив с GitHub, поэтому сеть открыта на любые "
              "публичные адреса с журналом."),
    dict(id="deno", title="Deno (среда выполнения JavaScript/TypeScript)", domains=[], needs=["unzip"],
         command="curl -fsSL https://deno.land/install.sh | sh -s -- --no-modify-path",
         note="Ставится в ~/.deno. Сайты загрузки заранее неизвестны, поэтому сеть открыта на любые "
              "публичные адреса с журналом."),
    dict(id="rust", title="Rust (rustup, cargo)", domains=["sh.rustup.rs", "static.rust-lang.org"], needs=["cc"],
         command="curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path",
         note="Ставится в ~/.cargo и ~/.rustup. Для сборки программ нужен компилятор C на компьютере. "
              "Чтобы cargo скачивал пакеты, потом разрешите crates.io, index.crates.io, static.crates.io."),
    dict(id="go", title="Go (официальный архив)", domains=["go.dev", "dl.google.com"],
         command=r"""cd /tmp && v=$(curl -fsSL "https://go.dev/VERSION?m=text" | head -1) && a=amd64; [ "$(uname -m)" = aarch64 ] && a=arm64; mkdir -p ~/.local && curl -fsSL https://go.dev/dl/$v.linux-$a.tar.gz | tar -xz -C ~/.local && go version""",
         note="Ставится в ~/.local/go. Для go get потом нужны proxy.golang.org и sum.golang.org."),
    dict(id="uv", title="uv и uvx (Python, MCP-серверы на Python)", domains=[],
         command="curl -LsSf https://astral.sh/uv/install.sh | sh",
         note="Установщик скачивает файлы с нескольких сайтов, поэтому сеть открыта на любые публичные "
              "адреса с журналом."),
    dict(id="aider", title="Aider (ИИ-помощник для кода, через uv)", domains=[], needs=["uv"],
         command="uv tool install --python 3.12 aider-chat",
         note="Нужен uv (см. выше). uv сам скачает Python 3.12, поэтому сеть открыта на любые публичные адреса."),
    dict(id="pip", title="Python-пакет (pip, в свой каталог)", domains=["pypi.org", "files.pythonhosted.org"],
         command="python3 -m pip install --user --break-system-packages <пакет>",
         note="Замените <пакет> на название. Пакет ставится в домашний каталог среды, система не меняется."),
    dict(id="npm", title="Другой инструмент Node (npm)", domains=["registry.npmjs.org"], needs=["node"],
         command="npm config set prefix ~/.local && npm install -g <пакет>",
         note="Замените <пакет> на название."),
    dict(id="git-clone", title="Склонировать репозиторий GitHub", domains=["github.com"],
         command="git clone https://github.com/<владелец>/<репозиторий>",
         note="Замените <владелец>/<репозиторий>. Репозиторий окажется в домашнем каталоге среды."),
    dict(id="archive", title="Скачать архив и распаковать (Blender и другие программы)", domains=[],
         command="mkdir -p ~/.local/opt && cd ~/.local/opt && curl -fLO <ссылка на архив> && tar -xf <файл>",
         note="Замените ссылку и имя файла. Сайты загрузки заранее неизвестны, поэтому сеть открыта на любые "
              "публичные адреса с журналом."),
]


# где в домашнем каталоге среды лежат программы, поставленные рецептами (они же добавлены в PATH среды)
RECIPE_TOOL_DIRS = [".local/bin", ".local/go/bin", "go/bin", ".cargo/bin", ".bun/bin", ".deno/bin"]


def env_has_tool(name, tool):
    """Есть ли программа внутри среды: на компьютере (/usr) или в её домашнем каталоге."""
    found = shutil.which(tool)
    if found and os.path.realpath(found).startswith(("/usr/", "/bin/")):
        return True
    home = os.path.join(box_dir(name), "home")
    return any(os.access(os.path.join(home, d, tool), os.X_OK) for d in RECIPE_TOOL_DIRS)


def recipe_warning(recipe, name):
    """Чего не хватает для рецепта (текст на русском) или пустая строка."""
    out = []
    for tool in recipe.get("needs", []):
        if env_has_tool(name, tool):
            continue
        if tool == "node":
            out.append("в среде нет node: сначала установите «Node.js (LTS, официальный архив)» "
                       "из этого списка (или на компьютере: " + pkg_hint("nodejs") + ")")
        elif tool == "uv":
            out.append("в среде нет uv: сначала установите «uv и uvx» из этого списка")
        elif tool == "unzip":
            out.append("на компьютере нет unzip: " + pkg_hint("unzip"))
        elif tool == "cc":
            out.append("на компьютере нет компилятора C: " + pkg_hint("gcc"))
        else:
            out.append(f"не найден {tool}")
    return ("⚠ " + "; ".join(out) + ".") if out else ""


def recipe_placeholders(command):
    """Незаполненные места вида <пакет> в команде."""
    return re.findall(r"<[^<>\n]+>", command)


# ---- core/upstream.py: Вышестоящий прокси профиля: разбор URL, чтение из файла, проверка.

def split_proxy_url(text, allow_auth=True):
    """Разобрать адрес одного прокси.

    Возвращает (чистый_url, 'логин:пароль' или ''). Допускает 'host:port' (= http://).
    Списки адресов не поддерживаются сознательно: один прокси на среду.
    """
    text = text.strip()
    if not text:
        raise ValueError("пустой адрес")
    if any(c.isspace() for c in text):
        raise ValueError("ожидается один адрес без пробелов (списки и ротация прокси не поддерживаются)")
    if "://" not in text:
        text = "http://" + text
    u = urllib.parse.urlsplit(text)
    scheme = u.scheme.lower()
    if scheme not in ("http", "socks5", "socks5h"):
        raise ValueError("поддерживаются http://, socks5:// и socks5h://")
    if not u.hostname:
        raise ValueError("не указан хост")
    try:
        port = u.port
    except ValueError:
        raise ValueError("неверный порт") from None
    if not port:
        raise ValueError("не указан порт")
    if u.path not in ("", "/") or u.query or u.fragment:
        raise ValueError("адрес прокси не должен содержать путь")
    auth = ""
    if u.username is not None or u.password is not None:
        if not allow_auth:
            raise ValueError("логин и пароль хранятся в keyring, а не в адресе профиля")
        auth = f"{urllib.parse.unquote(u.username or '')}:{urllib.parse.unquote(u.password or '')}"
    host = f"[{u.hostname}]" if ":" in u.hostname else u.hostname
    return f"{scheme}://{host}:{port}", auth


def read_proxy_file(path):
    """Прочитать адрес одного прокси из файла (пустые строки и # игнорируются)."""
    with open(path, encoding="utf-8", errors="replace") as f:
        lines = [l.strip() for l in f if l.strip() and not l.lstrip().startswith("#")]
    if not lines:
        raise ValueError("в файле нет адреса прокси")
    if len(lines) > 1:
        raise ValueError(f"в файле {len(lines)} адресов: поддерживается один прокси на среду "
                         "(списки и ротация не поддерживаются)")
    return lines[0]


def probe_upstream(url, auth="", target="example.com:443"):
    """Проверить прокси: (успех, сообщение)."""
    env = dict(os.environ)
    env.pop(UPSTREAM_AUTH_VAR, None)
    if auth:
        env[UPSTREAM_AUTH_VAR] = auth
    try:
        r = subprocess.run(["/usr/bin/python3", "-I", ENVBOX_NET, "probe", "--upstream", url,
                            "--target", target], env=env, stdin=subprocess.DEVNULL,
                           capture_output=True, text=True, timeout=40)
    except (OSError, subprocess.SubprocessError) as e:
        return False, str(e)
    return r.returncode == 0, (r.stdout + r.stderr).strip()


# ---- core/profile.py: Профиль среды (dataclass Profile) и его проверка.

@dataclass
class Profile:
    name: str
    workdir: str = ""
    command: str = "bash"
    net: str = "log"
    allow_domains: list = field(default_factory=list)
    net_allow_private: bool = False
    direct_domains: list = field(default_factory=list)  # сайты, к которым прокси envbox идёт напрямую, мимо upstream
    env: list = field(default_factory=lambda: ["LANG", "COLORTERM"])
    secrets: list = field(default_factory=list)
    ro: list = field(default_factory=list)
    rw: list = field(default_factory=list)              # дополнительные папки компьютера с записью (для любой среды)
    global_on: bool = False                             # глобальные папки разрешены этой среде (по умолчанию выкл.)
    global_folders: list = field(default_factory=list)  # подключаемые глобальные папки: «имя:ro» или «имя:rw»
    path: list = field(default_factory=list)
    ephemeral: bool = False
    protect_git: bool = True
    allow_userns: bool = False
    kind: str = "app"
    upstream: str = ""
    upstream_auth: bool = False
    attach: list = field(default_factory=list)
    browser_bin: str = ""
    browser_start_url: str = "about:blank"
    browser_visible: bool = False
    browser_chrome_sandbox: bool = True
    lang: str = ""
    timezone: str = ""
    dns: list = field(default_factory=list)
    isolation: dict = field(default_factory=dict)
    host_files: str = ""
    host_confirmed: bool = False
    no_workdir: bool = False
    expose_ports: list = field(default_factory=list)
    install_domains: list = field(default_factory=list)
    gui_wayland: bool = False
    shell: str = ""
    link_handler: str = ""            # команда внутри среды, которой передаётся ссылка (например claude-desktop)
    link_schemes: list = field(default_factory=list)   # схемы ссылок приложения, например claude (claude://…)
    link_callback: bool = False       # принимать http://localhost:порт/… и выполнять запрос внутри среды (вход в CLI)
    link_browser: str = ""            # браузер (среда), в котором открываются ссылки из этой среды
    link_out_auto: bool = False       # открывать ссылки из этой среды в браузере без вопроса

    @classmethod
    def codex_preset(cls, name):
        """Шаблон для Codex и других ИИ-агентов: сеть через прокси с журналом, ключ — секрет."""
        return cls(name=name, command="codex", net="log", env=["LANG", "COLORTERM"],
                   secrets=["OPENAI_API_KEY"])

    @classmethod
    def claude_desktop_preset(cls, name):
        """Claude Desktop (Electron) в песочнице: окно через Wayland, сеть только к доменам Claude, без проекта."""
        return cls(name=name, command="claude-desktop", net="allowlist",
                   allow_domains=list(CLAUDE_DESKTOP_DOMAINS),
                   no_workdir=True, gui_wayland=True, protect_git=False, env=["LANG", "COLORTERM"],
                   link_handler="claude-desktop", link_schemes=["claude"])

    @classmethod
    def service_preset(cls, name):
        """Приложение-сервис для ИИ (например Blender): без сети; порты открываются только подключённым средам."""
        return cls(name=name, command="bash", net="off")

    def install_view(self, domains=None):
        """Профиль на время установки: без проекта, секретов, браузеров и открытых портов.
        Сеть: только перечисленные сайты, а если список пуст — любые публичные адреса с журналом."""
        import copy
        q = copy.deepcopy(self)
        q.no_workdir = True
        q.secrets, q.attach, q.expose_ports = [], [], []
        q.rw, q.global_on = [], False   # на время установки чужие папки не нужны
        q.gui_wayland = False
        q.link_handler, q.link_schemes, q.link_callback = "", [], False
        q.env = [e for e in self.env if e.split("=", 1)[0] in ("LANG", "COLORTERM")]
        q.net_allow_private = False
        q.command = "bash"
        sites = list(self.install_domains if domains is None else domains)
        if sites:
            q.net, q.allow_domains = "allowlist", sites
        else:
            q.net, q.allow_domains = "log", []
        return q

    @classmethod
    def claude_preset(cls, name):
        """Шаблон «Claude CLI, жёсткая изоляция»: только домены Anthropic, без лишнего трафика."""
        return cls(name=name, command="claude", net="allowlist",
                   allow_domains=list(CLAUDE_DOMAINS),
                   env=["LANG", "COLORTERM", "DISABLE_TELEMETRY=1", "DISABLE_AUTOUPDATER=1",
                        "DISABLE_ERROR_REPORTING=1", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1"],
                   link_callback=True)

    @classmethod
    def from_dict(cls, d):
        p = cls(name=str(d.get("name", "")))
        for f in fields(cls):
            if f.name == "name" or f.name not in d:
                continue
            v, default = d[f.name], getattr(p, f.name)
            if isinstance(default, bool):
                setattr(p, f.name, bool(v))
            elif isinstance(default, list):
                setattr(p, f.name, [str(x) for x in v] if isinstance(v, list) else default)
            elif isinstance(default, dict):
                setattr(p, f.name, {str(k): bool(x) for k, x in v.items() if str(k) in ISO_KEYS}
                        if isinstance(v, dict) else {})
            else:
                setattr(p, f.name, str(v))
        if d.get("strict") is False and "isolation" not in d:  # профиль старой версии: «мягкий режим»
            p.isolation = {"host_net_forbidden": False, "seccomp": False, "neutral_dns": False}
        if p.net not in NET_MODES:
            p.net = "log"
        if p.net == "allowlist" and p.allow_domains == OLD_CLAUDE_DOMAINS:
            p.allow_domains = list(CLAUDE_DOMAINS)   # старый пресет не пускал обновление токена на claude.com
        if (p.net == "allowlist" and p.link_handler == "claude-desktop"
                and p.allow_domains in (list(CLAUDE_DOMAINS), OLD_CLAUDE_DOMAINS, OLD_CLAUDE_DESKTOP_DOMAINS)):
            p.allow_domains = list(CLAUDE_DESKTOP_DOMAINS)   # пресет Claude Desktop без bridge и hCaptcha
        if p.kind not in KINDS:
            p.kind = "app"
        return p

    def iso_on(self, key):
        """True, если защита `key` включена (для home_real: True — настоящий домашний каталог)."""
        opt = next((o for o in ISO_OPTIONS if o["key"] == key), None)
        if opt is None:
            return bool(self.isolation.get(key, ISO_RISKY_DEFAULT.get(key, True)))
        if opt["store"] == "iso":
            return bool(self.isolation.get(key, True))
        value = bool(getattr(self, opt["store"]))
        return (not value) if opt.get("invert") else value

    def iso_set(self, key, on):
        opt = next((o for o in ISO_OPTIONS if o["key"] == key), None)
        if opt is None or opt["store"] == "iso":
            default = ISO_RISKY_DEFAULT.get(key, True)
            if bool(on) == default:
                self.isolation.pop(key, None)
            else:
                self.isolation[key] = bool(on)
            return
        setattr(self, opt["store"], (not on) if opt.get("invert") else bool(on))

    def apply_iso_preset(self, name):
        preset = next(pr for pr in ISO_PRESETS if pr[0] == name)[3]
        for opt in ISO_OPTIONS:
            if opt.get("presets", True):
                self.iso_set(opt["key"], preset.get(opt["key"], True))

    def detect_iso_preset(self):
        """Имя набора, если защиты совпадают с ним, иначе 'custom'."""
        for name, _title, _text, preset in ISO_PRESETS:
            if all(self.iso_on(o["key"]) == preset.get(o["key"], True)
                   for o in ISO_OPTIONS if o.get("presets", True)):
                return name
        return "custom"

    def isolation_summary(self):
        """(короткий текст, предупреждение?) для метки в обзоре."""
        if self.host_files or self.iso_on("home_real"):
            return "⚠ доступ к компьютеру", True
        off = [o for o in ISO_OPTIONS if o["warn_off"] and not self.iso_on(o["key"])
               and not (self.is_browser and (o.get("app_only")
                                             or (o["key"] == "no_userns" and self.browser_chrome_sandbox)))]
        if not off:
            return "максимальная изоляция", False
        return f"изоляция: выключено защит — {len(off)}", True

    @property
    def is_browser(self):
        return self.kind == "browser"

    @property
    def shell_cmd(self):
        """Оболочка для кнопки «Терминал»."""
        return self.shell if self.shell in SHELLS else "bash"

    def wrapper_secrets(self):
        """Переменные, которые обёртка достаёт из keyring для envbox.sh (не все уходят в среду)."""
        return list(self.secrets) + ([UPSTREAM_AUTH_VAR] if self.upstream_auth and self.upstream else [])

    def validate(self):
        """Список ошибок на русском; пустой список — профиль готов к запуску."""
        err = []
        if not NAME_RE.match(self.name):
            err.append(f"недопустимое имя профиля: '{self.name}'")
        if self.is_browser:
            if self.net == "host":
                err.append("браузер нельзя запускать с сетью хоста: выберите режим через журнал или «Выключена»")
            if self.browser_bin:
                if not os.path.isabs(self.browser_bin) or not os.access(self.browser_bin, os.X_OK):
                    err.append(f"браузер не найден или не исполняемый: {self.browser_bin}")
            elif not find_browser():
                err.append("не найден Chrome/Chromium (google-chrome-stable, chromium…): "
                           "установите его или укажите путь в профиле")
            real = os.path.realpath(self.browser_bin or find_browser() or "/")
            if real.startswith(("/snap/", "/var/lib/flatpak/")):
                err.append("snap- и flatpak-версии браузера не подходят: у них свой sandbox; "
                           "установите пакет из репозитория или с сайта Google")
            if (not self.browser_start_url.strip() or any(c.isspace() for c in self.browser_start_url)
                    or self.browser_start_url.strip().startswith("-")):
                err.append("стартовая страница должна быть одним адресом без пробелов и не начинаться с «-»")
        else:
            if self.shell and self.shell not in SHELLS:
                err.append(f"оболочка '{self.shell}' не поддерживается (bash, fish, zsh)")
            elif self.shell_cmd != "bash" and not shutil.which(self.shell_cmd):
                err.append(f"оболочка {self.shell_cmd} не установлена на компьютере: {pkg_hint(self.shell_cmd)}")
            wd = os.path.expanduser(self.workdir)
            if self.no_workdir:
                pass
            elif not self.workdir:
                err.append("не выбран рабочий каталог (или включите «Без каталога проекта»)")
            elif not os.path.isdir(wd):
                err.append(f"рабочий каталог не существует: {self.workdir}")
            try:
                if not shlex.split(self.command):
                    err.append("не задана команда")
            except ValueError as e:
                err.append(f"ошибка в команде: {e}")
        if self.iso_on("host_net_forbidden") and self.net == "host":
            err.append("сеть компьютера запрещена защитой «Запретить сеть компьютера»: выберите режим через "
                       "прокси или выключите эту защиту на вкладке «Изоляция»")
        if self.iso_on("home_real") and not self.host_confirmed:
            err.append("настоящий домашний каталог не подтверждён")
        if self.host_files:
            if self.host_files not in ("ro", "rw"):
                err.append(f"доступ к компьютеру: недопустимое значение '{self.host_files}'")
            elif not self.host_confirmed:
                err.append("доступ к файлам компьютера не подтверждён")
            if self.net == "host":
                err.append("доступ к файлам компьютера несовместим с сетью компьютера")
        for port in self.expose_ports:
            if not (port.isdigit() and 0 < int(port) < 65536):
                err.append(f"порт для других сред '{port}': нужно число от 1 до 65535")
        if self.expose_ports and self.net == "host":
            err.append("открывать порты другим средам можно только при сети через прокси или без сети")
        for d in self.install_domains:
            if not DOMAIN_RE.match(d):
                err.append(f"сайт для установки: недопустимый домен '{d}'")
        if self.lang and not LANG_RE.match(self.lang):
            err.append(f"язык: недопустимая локаль '{self.lang}' (пример: ru_RU.UTF-8)")
        if self.timezone and not timezone_exists(self.timezone):
            err.append(f"часовой пояс '{self.timezone}' не найден в /usr/share/zoneinfo (пример: Europe/Moscow)")
        for d in self.dns:
            try:
                ipaddress.ip_address(d)
            except ValueError:
                err.append(f"DNS: '{d}' — не IP-адрес")
        if self.dns:
            if self.net == "off":
                err.append("DNS не нужен без сети: уберите серверы или включите сеть")
            elif self.upstream and self.net in ("log", "allowlist"):
                err.append("DNS-серверы несовместимы с вышестоящим прокси: имена разрешает он")
        if self.upstream:
            try:
                split_proxy_url(self.upstream, allow_auth=False)
            except ValueError as e:
                err.append(f"прокси: {e}")
            if self.net not in ("log", "allowlist"):
                err.append("вышестоящий прокси работает только в режимах сети «через журнал»")
        for spec in self.attach:
            m = ATTACH_RE.match(spec)
            if not m:
                err.append(f"подключение браузера: недопустимый формат '{spec}' (среда[:порт[:локальный порт]])")
                continue
            if m.group(1) == self.name:
                err.append("среда не может подключаться к самой себе")
            elif not os.path.isdir(box_dir(m.group(1))):
                err.append(f"подключение браузера: среда '{m.group(1)}' не найдена")
            for g in (m.group(2), m.group(3)):
                if g and not 0 < int(g) < 65536:
                    err.append(f"подключение браузера: недопустимый порт в '{spec}'")
        for sc in self.link_schemes:
            if not SCHEME_RE.match(sc) or sc in ("http", "https", "file", "ftp", "mailto"):
                err.append(f"схема ссылок «{sc}» не подходит (строчные латинские буквы и цифры; не http, https, file, ftp, mailto)")
        if self.link_schemes and not self.link_handler:
            err.append("схемы ссылок заданы, а команды открытия ссылок нет: приложению нечем их открыть")
        if self.link_handler:
            try:
                if not shlex.split(self.link_handler):
                    err.append("пустая команда открытия ссылок")
            except ValueError:
                err.append("команда открытия ссылок: незакрытые кавычки")
        if (self.attach or self.is_browser) and self.net == "host":
            err.append("подключение браузера требует режим сети не «общая с хостом»")
        if self.net == "allowlist" and not self.allow_domains:
            err.append("режим «только разрешённые домены», но список доменов пуст")
        for d in self.allow_domains:
            if not DOMAIN_RE.match(d):
                err.append(f"недопустимый домен: '{d}'")
        for d in self.direct_domains:
            if not DOMAIN_RE.match(d):
                err.append(f"сайт для прямого доступа: недопустимый домен '{d}'")
        for e in self.env:
            key = e.split("=", 1)[0]
            if not VAR_RE.match(key) or key in RESERVED_VARS or key.startswith("ENVBOX_"):
                err.append(f"недопустимая переменная окружения: '{e}'")
        for s in self.secrets:
            if not VAR_RE.match(s) or s in RESERVED_VARS or s.startswith("ENVBOX_"):
                err.append(f"недопустимое имя секрета: '{s}'")
        env_keys = {e.split("=", 1)[0] for e in self.env}
        for s in self.secrets:
            if s in env_keys:
                err.append(f"{s} указан и в переменных, и в секретах")
        for r in self.ro:
            if not os.path.exists(os.path.expanduser(r)):
                err.append(f"путь только для чтения не существует: {r}")
        for r in self.rw:
            if not os.path.isdir(os.path.expanduser(r)):
                err.append(f"папка с записью не существует или не каталог: {r}")
        seen_global = set()
        for g in self.global_folders:
            m = GLOBAL_ENTRY_RE.match(g)
            if not m:
                err.append(f"глобальная папка: недопустимая запись '{g}' (нужно имя:ro или имя:rw)")
            elif m.group(1) in seen_global:
                err.append(f"глобальная папка «{m.group(1)}» указана дважды")
            else:
                seen_global.add(m.group(1))
                if self.global_on and not os.path.isdir(global_path(m.group(1))):
                    err.append(f"глобальная папка «{m.group(1)}» не найдена: {global_path(m.group(1))}")
        # пути в каталоге данных: свои среды недоступны никогда, глобальные папки — только если включены
        groot = os.path.normpath(global_root())
        data = os.path.normpath(envbox_root())
        checked = [("рабочий каталог", self.workdir)] if not (self.is_browser or self.no_workdir) else []
        checked += [("путь только для чтения", x) for x in self.ro] + [("папка с записью", x) for x in self.rw]
        for label, v in checked:
            if not v:
                continue
            full = os.path.normpath(os.path.expanduser(v))
            in_global = full.startswith(groot + os.sep)
            if in_global and not self.global_on:
                err.append(f"{label} «{v}» лежит среди глобальных папок: включите «Глобальные папки» для этой среды")
            elif not in_global and (_is_under(full, data) or _is_under(data, full)):
                err.append(f"{label} «{v}» пересекается с каталогом данных envbox ({data}): "
                           "для общих данных используйте глобальные папки")
        for p in self.path:
            if not os.path.expanduser(p).startswith("/") or ":" in p:
                err.append(f"каталог PATH должен быть абсолютным и без ':': {p}")
        return err

    def envbox_args(self, command=None):
        """Аргументы для envbox.sh (без самого скрипта)."""
        a = ["-n", self.name, "--root", envbox_root()]
        if self.is_browser or self.no_workdir:
            a.append("--no-workdir")
        else:
            a += ["-w", os.path.expanduser(self.workdir)]
        if self.net == "off":
            a.append("--no-net")
        elif self.net == "log":
            a.append("--net-log")
        elif self.net == "allowlist":
            for d in self.allow_domains:
                a += ["--allow-domain", d]
        if self.upstream and self.net in ("log", "allowlist"):
            a += ["--upstream", self.upstream]
            for d in self.direct_domains:
                a += ["--direct-domain", d]
        if self.lang:
            a += ["--lang", self.lang]
        if self.timezone:
            a += ["--timezone", self.timezone]
        for d in self.dns:
            a += ["--dns", d]
        if self.net_allow_private and self.net in ("log", "allowlist"):
            a.append("--net-allow-private")
        for e in self.env + self.secrets:
            a += ["--env", e]
        ro = [os.path.expanduser(r) for r in self.ro]
        if self.is_browser:
            for d in browser_mounts(self.browser_bin or find_browser()):
                if d not in ro:
                    ro.append(d)
            a += ["--expose-port", str(CDP_PORT)]
            if self.browser_visible:
                a.append("--wayland")
        else:
            for port in self.expose_ports:
                a += ["--expose-port", str(int(port))]
            if self.gui_wayland:
                a.append("--wayland")
        for r in ro:
            a += ["--ro", r]
        for r in self.rw:
            a += ["--rw", os.path.expanduser(r)]
        if self.global_on:
            for g in self.global_folders:
                if GLOBAL_ENTRY_RE.match(g):
                    a += ["--global", g]
        for p in self.path:
            a += ["--path", os.path.expanduser(p)]
        for spec in self.attach:
            a += ["--attach", spec]
        if self.ephemeral:
            a.append("--ephemeral")
        if not self.protect_git:
            a.append("--no-protect-git")
        if self.allow_userns or (self.is_browser and self.browser_chrome_sandbox):
            a.append("--allow-userns")
        if not self.is_browser:
            if self.link_handler:
                a += ["--inbox-cmd", self.link_handler]
                for sc in self.link_schemes:
                    a += ["--inbox-scheme", sc]
            if self.link_callback:
                a.append("--inbox-callback")
        for opt in ISO_OPTIONS:
            if opt["store"] == "iso" and not self.iso_on(opt["key"]):
                a += ["--iso", f"{opt['key']}=off"]
        if self.iso_on("home_real"):
            a += ["--iso", "home_real=on"]
        if self.host_files:
            a += ["--host-files", self.host_files]
        if (self.host_files or self.iso_on("home_real")) and self.host_confirmed:
            a.append("--confirm-host-access")
        a.append("--")
        if self.is_browser:
            a += browser_command(self)
        else:
            argv = shlex.split(command if command is not None else self.command)
            hp = host_program_in_home(argv[0]) if argv else None
            extra = []
            found = shutil.which(argv[0]) if argv and "/" not in argv[0] else (argv[0] if argv else "")
            for d in browser_mounts(found) if found else []:
                if d.startswith("/opt/"):  # пакеты из AUR и сторонние установщики лежат в /opt
                    if d not in ro and ["--ro", d] != extra[-2:]:
                        extra += ["--ro", d]
                    real_opt = os.path.realpath(found)
                    if real_opt.startswith("/opt/") and argv[0] != real_opt:
                        argv[0] = real_opt  # в PATH среды /opt нет: запускаем по полному пути
            if hp and not self.iso_on("home_real") and not self.host_files:
                real, mount = hp
                if mount not in ro:
                    extra += ["--ro", mount]
                argv[0] = real
            if argv and os.path.basename(argv[0]) in ("fish", "zsh"):
                extra += ["--shell", os.path.basename(argv[0])]
            if extra:
                a[a.index("--"):a.index("--")] = extra
            a += argv
        return a


_LOCALES = None


def locale_available(lang):
    """True/False — есть ли локаль на компьютере; None — проверить не удалось."""
    global _LOCALES
    if re.fullmatch(r"C|POSIX|C\..*", lang):
        return True
    if _LOCALES is None:
        try:
            out = subprocess.run(["locale", "-a"], capture_output=True, text=True, timeout=10).stdout
        except (OSError, subprocess.SubprocessError):
            return None
        _LOCALES = {l.strip().lower().replace("utf-8", "utf8") for l in out.splitlines() if l.strip()}
    return lang.lower().replace("utf-8", "utf8") in _LOCALES


def timezone_exists(tz):
    return bool(TZ_RE.match(tz)) and os.path.isfile("/usr/share/zoneinfo/" + tz)


def new_profile(kind_key, name):
    """Профиль по типу из диалога «Новая среда»: claude, claude-desktop, codex, service, app, browser."""
    if kind_key == "claude":
        return Profile.claude_preset(name)
    if kind_key == "codex":
        return Profile.codex_preset(name)
    if kind_key == "claude-desktop":
        return Profile.claude_desktop_preset(name)
    if kind_key == "service":
        return Profile.service_preset(name)
    p = Profile(name=name, kind="browser" if kind_key == "browser" else "app")
    if kind_key == "browser":
        p.env = ["LANG"]
        p.protect_git = False
    return p


# ---- core/store.py: Хранение профилей и настроек на диске.

def browser_profiles():
    out = []
    for n in list_profiles():
        try:
            if load_profile(n).is_browser:
                out.append(n)
        except (OSError, ValueError):
            pass
    return out


def profile_path(name):
    return os.path.join(box_dir(name), "profile.json")


def list_profiles():
    root = envbox_root()
    if not os.path.isdir(root):
        return []
    return sorted(n for n in os.listdir(root)
                  if NAME_RE.match(n) and os.path.isfile(profile_path(n)))


def load_profile(name):
    with open(profile_path(name), encoding="utf-8") as f:
        d = json.load(f)
    d["name"] = name  # имя профиля — это имя каталога
    return Profile.from_dict(d)


def save_profile(p):
    if not NAME_RE.match(p.name):
        raise ValueError(f"недопустимое имя профиля: '{p.name}'")
    if "@" in p.upstream:
        raise ValueError("в адресе прокси не должно быть логина и пароля: они хранятся в keyring")
    _write_private(profile_path(p.name), json.dumps(asdict(p), ensure_ascii=False, indent=2) + "\n")


def copy_profile(src, dst):
    if not NAME_RE.match(dst):
        raise ValueError(f"недопустимое имя профиля: '{dst}'")
    if os.path.exists(box_dir(dst)) or os.path.exists(profile_path(dst)):
        raise ValueError(f"среда '{dst}' уже существует")
    p = load_profile(src)
    p.name = dst
    p.upstream_auth = False  # пароль прокси лежит в keyring под именем исходной среды
    p.host_confirmed = False  # доступ к файлам компьютера подтверждается заново для каждой среды
    save_profile(p)  # домашний каталог новой среды будет пустым


def delete_profile(name, with_home=False):
    if not NAME_RE.match(name):
        raise ValueError(f"недопустимое имя профиля: '{name}'")
    if any(s.name == name for s in list_sessions()):
        raise ValueError(f"среда «{name}» сейчас запущена: сначала остановите её")
    try:
        p = load_profile(name)
        secrets = p.wrapper_secrets()
    except (OSError, ValueError):
        secrets = []
    d = box_dir(name)
    if with_home:
        if os.path.isdir(d) and not os.path.islink(d):
            _force_rmtree(d)
        if os.path.lexists(profile_path(name)):
            os.unlink(profile_path(name))
        if secrets and secret_tool_available():
            for var in secrets:
                try:
                    secret_clear(name, var)
                except (OSError, subprocess.SubprocessError):
                    pass
    else:
        os.unlink(profile_path(name))


def settings_path():
    return os.path.join(envbox_root(), "gui.json")


def load_settings():
    try:
        with open(settings_path(), encoding="utf-8") as f:
            s = json.load(f)
    except (OSError, ValueError):
        s = {}
    return {"terminal": str(s.get("terminal", "")), "embedded": bool(s.get("embedded", True))}


def save_settings(s):
    _write_private(settings_path(), json.dumps(s, ensure_ascii=False, indent=2) + "\n")


# ---- core/terminal.py: Запуск терминала со средой (внешнее окно, пробный запуск, фон).

# (бинарник, аргументы перед командой); команда добавляется в конец как argv
TERMINALS = [
    ("gnome-terminal", ["--"]),
    ("ptyxis", ["--"]),
    ("konsole", ["-e"]),
    ("xfce4-terminal", ["-x"]),
    ("ghostty", ["-e"]),
    ("kitty", []),
    ("alacritty", ["-e"]),
    ("foot", []),
    ("wezterm", ["start", "--"]),
    ("terminator", ["-x"]),
    ("xterm", ["-e"]),
    ("x-terminal-emulator", ["-e"]),
]


def detect_terminal(settings=None):
    """Префикс argv терминала или None. Свой вариант задаётся в настройках."""
    custom = (settings or {}).get("terminal", "").strip()
    if custom:
        return shlex.split(custom)
    env_term = os.environ.get("TERMINAL", "")
    for binary, prefix in TERMINALS:
        if env_term and os.path.basename(env_term) == binary and shutil.which(env_term):
            return [env_term] + prefix
    for binary, prefix in TERMINALS:
        if shutil.which(binary):
            return [binary] + prefix
    return None


# Скрипт внутри окна терминала (на хосте): достаёт секреты из keyring,
# экспортирует их (значения не попадают в argv) и запускает envbox.sh.
TERMINAL_WRAPPER = resource_text("terminal_wrapper.sh")


def terminal_argv(prefix, profile, command=None, install=False, install_domains=None):
    """argv терминала. install=True — режим установки (см. Profile.install_view)."""
    if install:
        profile = profile.install_view(install_domains)
    inner = ["env", "ENVBOX_PKG_HINT=" + pkg_hint("secret-tool"),
             "bash", "-c", TERMINAL_WRAPPER, "envbox-term", ENVBOX_SH, profile.name,
             *profile.wrapper_secrets(), "--", *profile.envbox_args(command)]
    return list(prefix) + inner


def dry_run(profile, command=None, install=False, install_domains=None):
    """(код возврата, вывод) для envbox.sh --dry-run."""
    if install:
        profile = profile.install_view(install_domains)
    # Секреты подставит обёртка терминала из keyring; для проверки хватит заглушки
    # (envbox --dry-run печатает только имена переменных, не значения).
    env = dict(os.environ)
    for s in profile.wrapper_secrets():
        env.setdefault(s, "x:x" if s == UPSTREAM_AUTH_VAR else "<keyring>")
    r = subprocess.run([ENVBOX_SH, "--dry-run", *profile.envbox_args(command)], env=env,
                       stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
    return r.returncode, (r.stdout + r.stderr).strip()


def launch_background(profile, command=None):
    """Запуск без окна терминала (для браузера). Секреты берутся из keyring и
    передаются через окружение; вывод пишется в ~/.envbox/<имя>/launch.log."""
    env = dict(os.environ)
    env.pop(UPSTREAM_AUTH_VAR, None)
    missing = []
    for var in profile.wrapper_secrets():
        if secret_tool_available():
            r = subprocess.run(["secret-tool", "lookup", *_secret_attrs(profile.name, var)],
                               stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
            if r.returncode == 0 and r.stdout:
                env[var] = r.stdout
                continue
        env.pop(var, None)
        missing.append(var)
    os.makedirs(box_dir(profile.name), mode=0o700, exist_ok=True)
    log_path = os.path.join(box_dir(profile.name), "launch.log")
    fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as log:
        if missing:
            log.write("envbox: в keyring не найдено: " + ", ".join(missing) + "\n")
            log.flush()
        proc = subprocess.Popen([ENVBOX_SH, *profile.envbox_args(command)], env=env,
                                stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                start_new_session=True)
    return proc, log_path


def read_tail(path, max_bytes=4000):
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            f.seek(max(0, f.tell() - max_bytes))
            return f.read().decode("utf-8", "replace").strip()
    except OSError:
        return ""


# ---- core/links.py: Ссылки из среды: очередь, выбор браузера, отправка в среду.

def parse_link(text):
    """Проверка адреса, пришедшего из среды (недоверенные данные): только http/https, без логина в адресе."""
    t = (text or "").strip()
    if not t or len(t) > LINK_MAX:
        raise ValueError("пустая или слишком длинная ссылка")
    if any(ord(c) < 32 or ord(c) == 127 or c.isspace() for c in t):
        raise ValueError("в ссылке есть пробелы или управляющие символы")
    if not re.match(r"^https?://", t, re.I):
        raise ValueError("открываются только ссылки http и https")
    u = urllib.parse.urlsplit(t)
    if not u.hostname:
        raise ValueError("в ссылке нет адреса сайта")
    if "@" in u.netloc:
        raise ValueError("в ссылке указан логин или пароль перед адресом сайта: так часто маскируют поддельные сайты")
    return t


def link_spool_dir(name):
    return os.path.join(box_dir(name), "run", "links")


def read_link_spool(name, max_age=600, limit=20):
    """Запросы на открытие ссылок от среды `name`: [(адрес, ошибка)] — прочитанные файлы удаляются.

    Каталог доступен среде на запись, поэтому всё из него недоверенное: символические ссылки, FIFO и
    большие файлы пропускаются, число запросов за раз ограничено, старые стираются без показа."""
    d = link_spool_dir(name)
    try:
        st = os.lstat(d)
        if not stat.S_ISDIR(st.st_mode):
            return []
        entries = sorted(os.listdir(d))
    except OSError:
        return []
    out = []
    now_ts = time.time()
    for fname in entries:
        path = os.path.join(d, fname)
        if fname.endswith(".tmp"):
            try:
                if now_ts - os.lstat(path).st_mtime > 60:
                    os.unlink(path)
            except OSError:
                pass
            continue
        fd = None
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            fst = os.fstat(fd)
            if not stat.S_ISREG(fst.st_mode):
                os.close(fd)
                fd = None
                try:
                    os.unlink(path)
                except OSError:
                    pass
                continue
            data = os.read(fd, LINK_MAX + 64)
            stale = now_ts - fst.st_mtime > max_age
        except OSError:
            if fd is not None:
                os.close(fd)
            try:
                os.unlink(path)  # символическая ссылка и прочее подозрительное
            except OSError:
                pass
            continue
        os.close(fd)
        try:
            os.unlink(path)
        except OSError:
            pass
        if stale:
            continue
        if len(out) >= limit:
            continue  # лишние запросы отбрасываются: среда не должна заваливать вас окнами
        try:
            out.append((parse_link(data.decode("utf-8", "replace").splitlines()[0] if data else ""), ""))
        except ValueError as e:
            out.append(("", str(e)))
    return out


def link_spool_pending(name):
    """Есть ли в канале ссылок среды необработанные запросы (дешёвая проверка для опроса)."""
    try:
        return any(not f.endswith(".tmp") for f in os.listdir(link_spool_dir(name)))
    except OSError:
        return False


def cdp_open_url(name, url):
    """Открыть ссылку новой вкладкой в запущенном браузере-среде; возвращает id вкладки."""
    url = parse_link(url)
    b = CdpBrowser(cdp_socket_path(name))
    try:
        b.connect()
        return b.new_tab(url)
    finally:
        b.close()


def browser_profiles_names():
    """Имена сред-браузеров."""
    out = []
    for n in list_profiles():
        try:
            if load_profile(n).is_browser:
                out.append(n)
        except (OSError, ValueError):
            pass
    return out


def url_scheme(url):
    m = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*):", url or "")
    return m.group(1).lower() if m else ""


def parse_inbound(text, schemes=()):
    """Ссылка, которую пользователь отправляет в среду: http/https или схема приложения (claude://…)."""
    t = (text or "").strip()
    if not t or len(t) > LINK_MAX:
        raise ValueError("пустая или слишком длинная ссылка")
    if any(ord(c) < 32 or ord(c) == 127 or c.isspace() for c in t):
        raise ValueError("в ссылке есть пробелы или управляющие символы")
    sc = url_scheme(t)
    if sc in ("http", "https"):
        return parse_link(t)
    if sc and sc in [x.lower() for x in schemes]:
        return t
    raise ValueError(f"схема «{sc or '?'}» не разрешена для этой среды (разрешены http, https"
                     + "".join(f", {x}" for x in schemes) + ")")


def inbox_dir(name):
    return os.path.join(box_dir(name), "run", "inbox")


def send_link(name, url):
    """Положить ссылку в канал inbox запущенной среды (её читает наблюдатель внутри песочницы)."""
    p = load_profile(name)
    if not (p.link_handler or p.link_callback):
        raise ValueError(f"в среде «{name}» не включён приём ссылок: задайте «Команду открытия ссылок» в настройках")
    url = parse_inbound(url, p.link_schemes)
    run = os.path.join(box_dir(name), "run")
    d = inbox_dir(name)
    for path in (run, d):
        if os.path.islink(path):
            raise ValueError(f"{path} — символическая ссылка; это запрещено")
    os.makedirs(d, mode=0o700, exist_ok=True)
    fname = f"{int(time.time() * 1000)}.{os.getpid()}"
    tmp = os.path.join(d, fname + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, (url + "\n").encode("utf-8"))
    finally:
        os.close(fd)
    os.replace(tmp, os.path.join(d, fname))
    return fname


def inbox_result(name, fname, wait=8.0):
    """Ответ среды на отправленную ссылку; пустая строка, если за wait секунд ответа не было."""
    path = os.path.join(inbox_dir(name), fname + ".result")
    end = time.monotonic() + wait
    while time.monotonic() < end:
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError:
            time.sleep(0.2)
            continue
        try:
            data = os.read(fd, 400).decode("utf-8", "replace").strip()
        finally:
            os.close(fd)
        try:
            os.unlink(path)
        except OSError:
            pass
        return data
    return ""


def env_running(name):
    return any(s.name == name for s in list_sessions())


def find_env_for_url(url):
    """Подходящие среды для ссылки (запущенные первыми): по схеме приложения или для вызова localhost."""
    sc = url_scheme(url)
    host = (urllib.parse.urlsplit(url).hostname or "").lower() if sc in ("http", "https") else ""
    found = []
    for n in list_profiles():
        try:
            p = load_profile(n)
        except (OSError, ValueError):
            continue
        if p.is_browser:
            continue
        if sc in [x.lower() for x in p.link_schemes] or (p.link_callback and sc == "http" and host in ("localhost", "127.0.0.1", "::1")):
            found.append(n)
    return sorted(found, key=lambda n: (not env_running(n), n))


def open_link_in_env(url, env=None, start=True):
    """Открыть ссылку в приложении внутри среды. Возвращает (имя среды, сообщение).

    Запущенной среде ссылка передаётся через inbox; если среда не запущена, запускается её приложение со ссылкой."""
    if env is None:
        cands = find_env_for_url(url.strip())
        if not cands:
            raise ValueError("не нашёл среду для этой ссылки: укажите среду вручную или задайте у среды «Схемы ссылок»")
        env = cands[0]
    p = load_profile(env)
    url = parse_inbound(url, p.link_schemes)
    if env_running(env):
        fname = send_link(env, url)
        answer = inbox_result(env, fname)
        return env, answer or "ссылка отправлена, ответа от среды нет (смотрите окно приложения)"
    if not start:
        raise ValueError(f"среда «{env}» не запущена")
    if not p.link_handler:
        raise ValueError(f"среда «{env}» не запущена, а запускать с этой ссылкой нечем: задайте «Команду открытия ссылок»")
    errs = p.validate()
    if errs:
        raise ValueError("среда не готова к запуску: " + "; ".join(errs))
    launch_background(p, f"{p.link_handler} {shlex.quote(url)}")
    return env, "среда запущена, приложение открывается со ссылкой"


def open_in_host_browser(url):
    """Открыть http/https-ссылку в обычном браузере на компьютере (вне песочницы); возвращает имя программы."""
    url = parse_link(url)
    for tool in (["xdg-open"], ["gio", "open"]):
        if shutil.which(tool[0]):
            subprocess.Popen(tool + [url], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, start_new_session=True)
            return tool[0]
    raise OSError("не найден xdg-open (пакет xdg-utils): откройте ссылку в браузере вручную")


def open_in_file_manager(path):
    """Открыть каталог в файловом менеджере компьютера (вне песочницы); возвращает имя программы."""
    if not os.path.isdir(path):
        raise OSError(f"каталог не существует: {path}")
    for tool in (["xdg-open"], ["gio", "open"]):
        if shutil.which(tool[0]):
            subprocess.Popen(tool + [path], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, start_new_session=True)
            return tool[0]
    raise OSError("не найден xdg-open (пакет xdg-utils): откройте каталог вручную")


def notify_desktop(title, text):
    """Уведомление рабочего стола (если есть notify-send): ссылки приходят из браузера без окна envbox."""
    if not shutil.which("notify-send"):
        return False
    try:
        subprocess.run(["notify-send", "-a", "envbox", title, text], timeout=5, capture_output=True,
                       stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return False
    return True


def safe_link_label(url):
    """Адрес без параметров и части после «#»: в них коды входа, их нельзя писать в журнал и уведомления."""
    try:
        u = urllib.parse.urlsplit(url or "")
    except ValueError:
        return "?"
    base = f"{u.scheme}://{u.netloc}{u.path}"
    return base if len(base) <= 100 else base[:100] + "…"


def log_link_event(label, outcome):
    """Журнал <каталог данных>/open-link.log: что приходило из браузера и что с этим сделали (без кодов входа)."""
    try:
        root = envbox_root()
        os.makedirs(root, mode=0o700, exist_ok=True)
        path = os.path.join(root, "open-link.log")
        try:
            if os.path.getsize(path) > 200_000:
                os.replace(path, path + ".1")
        except OSError:
            pass
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(f"{dt.datetime.now().isoformat(timespec='seconds')} {label} — {outcome}\n")
    except OSError:
        pass


# ---- core/link_handler.py: Обработчик ссылок envbox в системе (xdg desktop) и команда open-link.

def link_handler_desktop(scheme):
    data = os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share")
    return os.path.join(data, "applications", f"envbox-link-{scheme}.desktop")


def install_link_handler(scheme):
    """Связывает схему (например claude) с envbox: ссылки claude://… из браузера пойдут в среду.

    Меняет ассоциации вашего рабочего стола (файл ~/.local/share/applications/envbox-link-<схема>.desktop и xdg-mime)."""
    scheme = scheme.lower().strip()
    if not SCHEME_RE.match(scheme) or scheme in ("http", "https", "file", "ftp", "mailto"):
        raise ValueError(f"схема «{scheme}» не подходит (нельзя http, https, file, ftp, mailto)")
    path = link_handler_desktop(scheme)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    text = ("[Desktop Entry]\nType=Application\n"
            f"Name=envbox: открыть {scheme}:// в песочнице\n"
            f"Comment=Передаёт ссылки {scheme}:// приложению в среде envbox\n"
            f"Exec=/usr/bin/python3 -I {_desktop_quote(INSTALLED_PY)} open-link %u\n"
            f"Terminal=false\nNoDisplay=true\nMimeType=x-scheme-handler/{scheme};\n")
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    note = ""
    if shutil.which("xdg-mime"):
        r = subprocess.run(["xdg-mime", "default", os.path.basename(path), f"x-scheme-handler/{scheme}"],
                           capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            note = " xdg-mime не сработал: " + (r.stderr.strip() or "ошибка")
    else:
        note = " Не найден xdg-mime (пакет xdg-utils): назначьте обработчик вручную в настройках браузера."
    if shutil.which("update-desktop-database"):
        subprocess.run(["update-desktop-database", "-q", os.path.dirname(path)], capture_output=True, timeout=30)
    return path, note.strip()


def link_handler_installed(scheme):
    if not os.path.exists(link_handler_desktop(scheme)):
        return False
    if shutil.which("xdg-mime"):
        r = subprocess.run(["xdg-mime", "query", "default", f"x-scheme-handler/{scheme}"],
                           capture_output=True, text=True, timeout=30)
        return r.stdout.strip() == os.path.basename(link_handler_desktop(scheme))
    return True


def remove_link_handler(scheme):
    try:
        os.unlink(link_handler_desktop(scheme))
    except OSError:
        pass


def cmd_open_link(argv):
    """envbox.py open-link [--env ИМЯ] [--no-start] ССЫЛКА: передать ссылку приложению в среде."""
    env, start, url = None, True, None
    it = iter(argv)
    for arg in it:
        if arg == "--env":
            env = next(it, None)
        elif arg == "--no-start":
            start = False
        elif arg in ("-h", "--help"):
            print(cmd_open_link.__doc__)
            return 0
        elif url is None:
            url = arg
        else:
            print("envbox open-link: лишний аргумент: " + arg, file=sys.stderr)
            return 2
    if not url or env == "":
        print("envbox open-link: нужна ссылка. Пример: envbox.py open-link claude://...", file=sys.stderr)
        return 2
    label = safe_link_label(url)
    from_desktop = not sys.stderr.isatty()   # запущено браузером: окна и терминала нет, ошибки нужно показать иначе
    try:
        name, msg = open_link_in_env(url, env, start)
    except (ValueError, OSError, subprocess.SubprocessError) as e:
        log_link_event(label, f"ошибка: {e}")
        if from_desktop:
            notify_desktop("envbox: ссылка не передана", str(e))
        print(f"envbox open-link: {e}", file=sys.stderr)
        return 1
    log_link_event(label, f"среда «{name}»: {msg}")
    if from_desktop:
        notify_desktop("envbox: ссылка передана", f"Среда «{name}»: {msg}")
    print(f"envbox: «{name}»: {msg}")
    return 0


# ---- core/rootops.py: Операции над каталогом данных и глобальными папками, затрагивающие профили и сеансы: перенос, удаление, список пользователей.

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


# ---- install.py: Установка: самокопирование в ~/.local/share/envbox, извлечение envbox.sh, команда envbox.

def file_version_text(path):
    """Версия envbox в файле строкой (как в version.py, например 2026.11.01.2) или None."""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            m = re.search(r'^ENVBOX_VERSION = "([0-9.]+)"', f.read(), re.M)
    except OSError:
        return None
    return m.group(1) if m else None


def file_version(path):
    """Версия envbox в файле (кортеж чисел) или None."""
    text = file_version_text(path)
    return tuple(int(x) for x in text.split(".")) if text else None


def _system_python():
    """Настоящий путь к /usr/bin/python3 (например /usr/bin/python3.14): .pyc годится только для этой версии."""
    return os.path.realpath("/usr/bin/python3")


def _tag_matches():
    try:
        with open(INSTALLED_PYC_TAG, encoding="utf-8") as f:
            return f.read() == _system_python()
    except OSError:
        return False


def compile_installed():
    """Кладёт рядом с установленным envbox.py скомпилированную копию (служебные вызовы ~20 мс вместо ~150 мс).

    Копия проверяется запуском; при любой неудаче удаляется, и envbox.sh пользуется обычным файлом.
    После обновления Python (на Arch это бывает часто) .pyc становится нечитаемым: рядом хранится метка версии,
    и по её несовпадению копия собирается заново, а до тех пор envbox.sh пользуется обычным файлом."""
    try:
        if (os.path.exists(INSTALLED_PYC) and os.path.exists(INSTALLED_PY)
                and os.path.getmtime(INSTALLED_PYC) >= os.path.getmtime(INSTALLED_PY) and _tag_matches()):
            return False
        want = file_version(INSTALLED_PY)
        tmp = INSTALLED_PYC + ".new"
        r = subprocess.run(["/usr/bin/python3", "-I", "-c",
                            "import py_compile,sys; py_compile.compile(sys.argv[1], cfile=sys.argv[2], doraise=True)",
                            INSTALLED_PY, tmp], capture_output=True, timeout=120)
        if r.returncode == 0 and want:
            v = subprocess.run(["/usr/bin/python3", "-I", tmp, "version"], capture_output=True, text=True, timeout=60)
            # сравнение по числам: в строке версии бывают ведущие нули (2026.11.01.1), в кортеже их нет
            if v.returncode == 0 and tuple(int(x) for x in v.stdout.strip().split(".")) == want:
                os.chmod(tmp, 0o644)
                _atomic_write(INSTALLED_PYC_TAG, _system_python().encode("utf-8"), 0o644)
                os.replace(tmp, INSTALLED_PYC)
                return True
        if os.path.exists(tmp):
            os.unlink(tmp)
    except (OSError, subprocess.SubprocessError):
        pass
    for stale in (INSTALLED_PYC, INSTALLED_PYC_TAG):   # устаревшая копия опаснее её отсутствия
        try:
            os.unlink(stale)
        except OSError:
            pass
    return False


def ensure_installed(force=False):
    """Копирует envbox.py в ~/.local/share/envbox, извлекает envbox.sh и создаёт команду envbox.

    Запущенные среды используют установленные копии, поэтому не зависят от того,
    откуда запущен GUI (папка загрузок, смонтированный AppImage). Возвращает список изменений.
    Установленная более новая версия по умолчанию не затирается (force=True — затирается).
    """
    changed = []
    SELF = bundle_path()
    os.makedirs(INSTALL_DIR, mode=0o755, exist_ok=True)
    if not force and SELF != os.path.realpath(INSTALLED_PY) and os.path.exists(INSTALLED_PY):
        mine, theirs = file_version(SELF), file_version(INSTALLED_PY)
        if mine and theirs and mine < theirs:
            # установлена более новая версия: старый запуск (например, из AppImage) её не затирает
            if not os.environ.get("ENVBOX_NO_REEXEC"):
                os.environ["ENVBOX_NO_REEXEC"] = "1"
                os.execv("/usr/bin/python3", ["/usr/bin/python3", "-I", INSTALLED_PY, *sys.argv[1:]])
            return changed
    if SELF != os.path.realpath(INSTALLED_PY):
        with open(SELF, "rb") as f:
            data = f.read()
        try:
            with open(INSTALLED_PY, "rb") as f:
                same = f.read() == data
        except OSError:
            same = False
        if not same:
            _atomic_write(INSTALLED_PY, data, 0o755)
            changed.append(INSTALLED_PY)
    sh_data = ENVBOX_SH_TEXT.replace("__ENVBOX_PY__", shlex.quote(INSTALLED_PY)).encode("utf-8")
    try:
        with open(ENVBOX_SH, "rb") as f:
            same = f.read() == sh_data
    except OSError:
        same = False
    if not same:
        _atomic_write(ENVBOX_SH, sh_data, 0o755)
        changed.append(ENVBOX_SH)
    link = os.path.join(os.path.expanduser("~"), ".local", "bin", "envbox")
    if not os.path.lexists(link) or os.path.islink(link):
        os.makedirs(os.path.dirname(link), exist_ok=True)
        if os.path.realpath(link) != os.path.realpath(ENVBOX_SH):
            tmp = link + ".new"
            if os.path.lexists(tmp):
                os.unlink(tmp)
            os.symlink(ENVBOX_SH, tmp)
            os.replace(tmp, link)
            changed.append(link)
    if compile_installed():
        changed.append(INSTALLED_PYC)
    return changed


# ---- cli.py: Точка входа: разбор подкоманд (gui, install, run, root, global, net-команды…).

def cmd_root(argv):
    """envbox root [ПУТЬ | --reset] [--move]: показать или сменить каталог данных."""
    move = "--move" in argv
    rest = [a for a in argv if a != "--move"]
    try:
        if not rest:
            print(envbox_root())
            src = ("ENVBOX_ROOT" if os.environ.get("ENVBOX_ROOT", "").strip() else
                   "выбран пользователем" if configured_root() else "стандартный")
            print(f"({src}; глобальные папки: {global_root()})", file=sys.stderr)
            return 0
        if len(rest) != 1:
            raise ValueError("ожидается один путь или --reset")
        if os.environ.get("ENVBOX_ROOT", "").strip():
            raise ValueError("каталог задан переменной ENVBOX_ROOT: уберите её, чтобы менять выбор")
        old = envbox_root()
        target = os.path.realpath(default_root()) if rest[0] == "--reset" else os.path.realpath(
            os.path.expanduser(rest[0]))
        if rest[0] != "--reset" and not os.path.isabs(os.path.expanduser(rest[0])):
            raise ValueError("нужен абсолютный путь")
        err = root_error(target)
        if err:
            raise ValueError(err)
        if move:
            move_root(old, target)
        set_root("" if target == os.path.realpath(default_root()) else target)
        print(f"Каталог данных: {envbox_root()}" + (" (данные перенесены)" if move and old != target else ""))
        return 0
    except (OSError, ValueError) as e:
        print(f"envbox: {e}", file=sys.stderr)
        return 1


def cmd_global(argv):
    """envbox global [list | create ИМЯ | delete ИМЯ]: глобальные папки."""
    sub = argv[0] if argv else "list"
    try:
        if sub == "list" and len(argv) <= 1:
            for n in list_global_folders():
                print(n)
            return 0
        if sub == "create" and len(argv) == 2:
            print(create_global_folder(argv[1]))
            return 0
        if sub == "delete" and len(argv) == 2:
            delete_global_folder(argv[1])
            print(f"Глобальная папка «{argv[1]}» удалена")
            return 0
        raise ValueError("использование: envbox.py global [list | create ИМЯ | delete ИМЯ]")
    except (OSError, ValueError) as e:
        print(f"envbox: {e}", file=sys.stderr)
        return 1


def main():
    argv = sys.argv[1:]
    cmd = argv[0] if argv else "gui"
    if cmd in NET_COMMANDS:          # сетевой шлюз: вызывается из envbox.sh и из песочницы
        return net_main()
    if cmd in ("-h", "--help", "help"):
        print(resource_text("help.txt"))
        return 0
    if cmd in ("-V", "--version"):
        print(ENVBOX_VERSION)
        return 0
    if cmd == "build-appimage":
        return build_appimage(argv[1:])
    if cmd == "root":
        return cmd_root(argv[1:])
    if cmd == "global":
        return cmd_global(argv[1:])
    if cmd == "install":
        changed = ensure_installed(force="--force" in argv[1:])
        print("Установлено в", INSTALL_DIR if changed else f"{INSTALL_DIR} (уже актуально)")
        print("Команда: ~/.local/bin/envbox  (добавьте ~/.local/bin в PATH, если его там нет)")
        installed = file_version_text(INSTALLED_PY)
        print(f"Версия этого файла: {ENVBOX_VERSION}; установленной копии: {installed or 'нет'}")
        if installed != ENVBOX_VERSION:
            print("⚠ Установленная копия отличается от этого файла: шлюз и среды работают из неё. "
                  "Повторите: python3 envbox.py install --force", file=sys.stderr)
            return 1
        return 0
    if cmd == "run":
        ensure_installed()
        os.execv(ENVBOX_SH, [ENVBOX_SH, *argv[1:]])
    if cmd == "open-link":
        return cmd_open_link(argv[1:])
    if cmd == "--install-desktop":
        ensure_installed()
        print("Ярлык создан:", install_desktop_entry())
        return 0
    if cmd == "gui":
        argv = argv[1:]
    if argv:
        print(f"envbox: неизвестная команда: {argv[0]} (см. python3 envbox.py --help)", file=sys.stderr)
        return 2
    ensure_installed()
    return _build_gui()()


# ---- core/describe.py: Человеческое описание того, что получит среда (для вкладки «Обзор»).

def describe(p):
    """Что получает среда — простыми словами: список (уровень, текст).

    Уровни: ok — защита, info — справка, warn — то, что ослабляет изоляцию.
    """
    out = []
    home = f"{tilde(box_dir(p.name))}/home"
    if p.host_files:
        mode = "только чтение (писать можно в проект)" if p.host_files == "ro" else "чтение и запись"
        out.append(("warn", f"ДОСТУП К КОМПЬЮТЕРУ: среда видит все ваши файлы, включая настоящий домашний "
                            f"каталог, ключи SSH и браузерные профили — {mode}. Это почти не песочница: "
                            "всё, что программа прочитает, она может отправить на разрешённые сайты. "
                            "Сеть, язык, пояс и DNS остаются заданными; данные других сред envbox скрыты."))
    elif p.ephemeral:
        out.append(("ok", "Домашний каталог временный: после выхода всё в нём стирается. "
                          "Ваши настоящие файлы скрыты."))
    else:
        out.append(("ok", f"Свой домашний каталог {home}. Ваши настоящие файлы, ключи SSH и "
                          "браузерные профили скрыты."))
    if p.host_files:
        pass
    elif p.no_workdir and not p.is_browser:
        out.append(("ok", "Каталога проекта нет: записывает только в свой домашний каталог."))
    elif p.is_browser:
        out.append(("ok", "Записывает только в собственный профиль браузера внутри этого каталога."))
    else:
        out.append(("ok", f"Записывать может только в проект: {p.workdir or '— не выбран —'}."))
    if p.rw:
        out.append(("warn", "Дополнительно может записывать в папки: " + ", ".join(p.rw) + ". "
                            "Всё, что программа там изменит или удалит, на вашем компьютере изменится по-настоящему."))
    if p.global_on:
        active = [g for g in p.global_folders if GLOBAL_ENTRY_RE.match(g)]
        if active:
            names = ", ".join(f"{g.split(':')[0]} ({'чтение и запись' if g.endswith(':rw') else 'только чтение'})"
                              for g in active)
            level = "warn" if any(g.endswith(":rw") for g in active) else "info"
            out.append((level, f"Глобальные папки ({tilde(global_root())}): {names}. Они лежат отдельно от среды: "
                               "при удалении среды остаются на месте."))
        else:
            out.append(("info", "Глобальные папки разрешены, но ни одна не выбрана."))
    off = [o for o in ISO_OPTIONS if o["warn_off"] and not p.iso_on(o["key"])
           and not (p.is_browser and (o.get("app_only")
                                      or (o["key"] == "no_userns" and p.browser_chrome_sandbox)))]
    if p.iso_on("home_real") and not p.host_files:
        out.append(("warn", "Среда работает с настоящим домашним каталогом: личные файлы, ключи SSH и "
                            "браузерные профили доступны и могут быть изменены. Изоляция от вашей "
                            "учётной записи практически отсутствует."))
    if not off:
        out.append(("ok", "Все защиты включены: фильтр системных вызовов, скрытые процессы, свой IPC и "
                          "имя компьютера, только прокси для сети, адреса ваших DNS скрыты."))
    for o in off:
        out.append(("warn", f"Выключено: «{o['title']}» — {o['risk']}"))
    reads = "Системные программы и библиотеки (/usr) видны только на чтение"
    if p.ro:
        reads += "; дополнительно читает: " + ", ".join(p.ro)
    out.append(("info", reads + "."))
    if not p.is_browser and p.shell_cmd != "bash":
        out.append(("info", f"Оболочка в терминале: {p.shell_cmd} (программа берётся с компьютера, только чтение; "
                            "стартовые настройки лежат в домашнем каталоге среды)."))
    names = [e.split("=", 1)[0] for e in p.env] + list(p.secrets)
    if names:
        tail = " (значения секретов берутся из keyring)" if p.secrets else ""
        out.append(("info", "Из окружения получает только: " + ", ".join(names) + tail + "."))
    else:
        out.append(("ok", "Переменные окружения компьютера не передаются."))

    if p.lang or p.timezone:
        bits = ([f"язык {p.lang}"] if p.lang else []) + ([f"часовой пояс {p.timezone}"] if p.timezone else [])
        out.append(("info", "Система внутри среды: " + ", ".join(bits) + "."))
    if p.net == "off":
        out.append(("ok", "Сети нет: программа работает офлайн."))
    elif p.net == "log":
        out.append(("info", "В сеть выходит только через прокси на вашем компьютере; "
                            "каждое обращение записывается в журнал."))
    elif p.net == "allowlist":
        out.append(("ok", "В сеть выходит только к: " + (", ".join(p.allow_domains) or "— список пуст —")
                    + ". Всё остальное блокируется и записывается в журнал."))
        out.append(("info", "Список ограничивает сайты, но не порты, и не мешает передать данные "
                            "самим разрешённым сервисам (например, в облачное хранилище). "
                            "Для строгого контроля смотрите журнал сети."))
    else:
        out.append(("warn", "Сеть общая с компьютером: доступны все сервисы на localhost "
                            "(базы данных, отладочные порты). Для ИИ этот режим не подходит."))
    if p.dns and p.net != "off" and not (p.upstream and p.net in ("log", "allowlist")):
        out.append(("info", "Имена сайтов разрешают DNS-серверы " + ", ".join(p.dns)
                    + ": запросы идут по сети без шифрования, их видит сеть и владелец сервера."))
    if p.upstream and p.net in ("log", "allowlist"):
        who = "логином и паролем из keyring" if p.upstream_auth else "без логина"
        out.append(("info", f"Дальше трафик идёт через ваш прокси {p.upstream} ({who}); "
                            "имена сайтов разрешает он."))
        if p.direct_domains:
            out.append(("warn", "Напрямую, мимо этого прокси, пойдут: " + ", ".join(p.direct_domains) +
                        ". Эти сайты увидят ваш настоящий адрес. Программа в среде по-прежнему видит только "
                        "прокси envbox."))
    if not p.is_browser and (p.link_handler or p.link_callback):
        bits = []
        if p.link_handler:
            bits.append("ссылки " + ", ".join(f"{x}://" for x in p.link_schemes + ["http(s)"]) +
                        f" передаются приложению внутри среды командой «{p.link_handler}»")
        if p.link_callback:
            bits.append("адреса вида http://localhost:порт/… (вход по ссылке в CLI) выполняются внутри среды")
        out.append(("info", "Приём ссылок: " + "; ".join(bits) + ". Отправляете их вы: кнопкой «Ссылка…» или "
                            "из браузера, если схема связана с этой средой."))
    if p.net_allow_private and p.net in ("log", "allowlist"):
        out.append(("warn", "Прокси пускает и на частные адреса (localhost, локальная сеть): "
                            "среда сможет обращаться к сервисам вашего компьютера."))
    if p.is_browser:
        if p.browser_visible:
            out.append(("warn", "Окно браузера показывается через Wayland: доступ к сокету Wayland "
                                "ослабляет изоляцию (композитор может отдавать снимки экрана)."))
        else:
            out.append(("ok", "Браузер без отдельного окна: страницу видно на вкладке «Окно браузера» в приложении; "
                              "управлять им могут только подключённые к нему среды (через CDP по закрытому "
                              "unix-сокету)."))
        if not p.browser_chrome_sandbox:
            out.append(("warn", "Встроенный sandbox Chrome выключен: защита держится только на bubblewrap."))
    else:
        if p.protect_git:
            out.append(("ok", "Хуки и config в .git защищены от записи, сам .git нельзя заменить; "
                              "после выхода envbox сравнит их с состоянием до запуска и предупредит, "
                              "если что-то изменилось (проверяйте перед git-командами на компьютере)."))
        else:
            out.append(("warn", "Защита .git/hooks выключена: программа может подложить хук, "
                                "который выполнится у вас при git-командах."))
    if p.allow_userns:
        out.append(("warn", "Разрешены вложенные user namespaces: шире поверхность атаки на ядро."))
    if not p.is_browser:
        if p.expose_ports:
            out.append(("info", "Порты " + ", ".join(p.expose_ports) + " доступны подключённым средам через "
                                "закрытый сокет (никому больше); сама среда к ним не подключается."))
        if p.gui_wayland:
            out.append(("warn", "Окно приложения показывается через Wayland: доступ к сокету Wayland ослабляет "
                                "изоляцию (композитор может отдавать снимки экрана)."))
        out.append(("info", "Установка («Установить…»): без вашего проекта и секретов; сеть — "
                            + ("только " + ", ".join(p.install_domains) if p.install_domains
                               else "любые публичные сайты с журналом") + "."))
    for spec in p.attach:
        m = ATTACH_RE.match(spec)
        target = m.group(1) if m else spec
        out.append(("warn", f"Подключён браузер «{target}»: среда получает полный контроль над ним "
                            "(страницы, cookies, сеансы в его профиле)."))
        if p.net == "off":
            out.append(("warn", "Своей сети нет, но через браузер выход в интернет возможен."))
        elif p.net == "allowlist":
            out.append(("warn", "Список сайтов этой среды не ограничивает браузер: "
                                "у него действуют собственные правила сети."))
    return out


# ---- core/diagnostics.py: Диагностика: что есть на компьютере для работы envbox.

def diagnostics(settings=None):
    """Список (статус, заголовок, подробности); статус: ok | warn | fail."""
    res = []

    def add(st, title, detail=""):
        res.append((st, title, detail))

    for path, label in ((ENVBOX_SH, "envbox.sh"), (ENVBOX_NET, "envbox.py")):
        if os.path.isfile(path):
            add("ok" if os.access(path, os.X_OK) or path == ENVBOX_NET else "fail",
                f"{label} найден", path)
        else:
            add("fail", f"{label} не найден", "запустите: python3 envbox.py install")

    bwrap = shutil.which("bwrap")
    if not bwrap:
        add("fail", "bwrap не установлен", pkg_hint("bubblewrap"))
    else:
        real = os.path.realpath(bwrap)
        ver = subprocess.run([real, "--version"], capture_output=True, text=True).stdout.strip()
        ver = ver.splitlines()[0] if ver else ""
        add("ok", f"bwrap: {ver or 'версия неизвестна'}", real)
        if os.stat(real).st_mode & 0o4000:
            add("fail", "bwrap установлен с setuid-битом", "envbox работает только с bwrap без setuid")
        helptext = subprocess.run([real, "--help"], capture_output=True, text=True)
        helptext = helptext.stdout + helptext.stderr
        if "--disable-userns" in helptext:
            add("ok", "поддерживается --disable-userns")
        else:
            add("warn", "нет --disable-userns", "нужен bwrap >= 0.8: вложенные userns не запрещаются")
        probe = subprocess.run([real, "--unshare-user", "--ro-bind", "/", "/", "--", "/usr/bin/true"],
                               capture_output=True, text=True)
        if probe.returncode == 0:
            add("ok", "user namespaces работают")
        else:
            detail = probe.stderr.strip()
            try:
                with open("/proc/sys/kernel/apparmor_restrict_unprivileged_userns") as f:
                    if f.read().strip() == "1":
                        detail += ("\nAppArmor ограничивает userns. Запустите envbox.sh из терминала: "
                                   "он напечатает профиль AppArmor только для bwrap.")
            except OSError:
                pass
            add("fail", "bwrap не может создать user namespace", detail)

    try:
        with open("/proc/sys/dev/tty/legacy_tiocsti") as f:
            v = f.read().strip()
        add("ok", f"dev.tty.legacy_tiocsti = {v}",
            "TIOCSTI запрещён ядром" if v == "0" else "защита от TIOCSTI — через --new-session")
    except OSError:
        add("ok", "legacy_tiocsti недоступен", "защита от TIOCSTI — через --new-session")

    browser = find_browser()
    if browser:
        real = os.path.realpath(browser)
        try:
            ver = subprocess.run([browser, "--version"], capture_output=True, text=True,
                                 stdin=subprocess.DEVNULL, timeout=15).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            ver = ""
        if real.startswith(("/snap/", "/var/lib/flatpak/")):
            add("fail", f"браузер: {browser}", "snap/flatpak-версия не подходит для изолированной среды")
        else:
            add("ok", f"браузер: {ver or browser}", real)
    else:
        add("warn", "Chrome/Chromium не найден", "нужен только для сред-браузеров: "
            + pkg_hint("chromium"))
    add("ok" if os.access("/usr/bin/python3", os.X_OK) else "fail",
        "/usr/bin/python3" + ("" if os.access("/usr/bin/python3", os.X_OK) else " не найден"),
        "нужен для сетевого журнала")
    if secret_tool_available():
        add("ok", "secret-tool найден", "секреты хранятся в системном keyring")
    else:
        add("warn", "secret-tool не найден", "для секретов: " + pkg_hint("secret-tool"))
    term = detect_terminal(settings)
    if term:
        add("ok", "терминал: " + shlex.join(term))
    else:
        add("fail", "терминал не найден", "укажите команду терминала в настройках, например 'xterm -e'")
    return res


# ---- core/netlog.py: Журнал сети среды: чтение с хвоста, сводка, очистка.

# --------------------------------------------------------- сетевой журнал

format_event = fmt_event


human_size = human


def net_log_path(name):
    return os.path.join(box_dir(name), "net.log")


class LogTail:
    """Чтение новых событий из net.log; переживает очистку файла."""

    def __init__(self, path):
        self.path = path
        self.pos = 0
        self.partial = ""

    def read_new(self):
        try:
            size = os.path.getsize(self.path)
        except OSError:
            return []
        if size < self.pos:
            self.pos, self.partial = 0, ""
        if size == self.pos:
            return []
        with open(self.path, encoding="utf-8", errors="replace") as f:
            f.seek(self.pos)
            chunk = f.read()
            self.pos = f.tell()
        data = self.partial + chunk
        lines = data.split("\n")
        self.partial = lines.pop()
        out = []
        for line in lines:
            try:
                out.append(json.loads(line))
            except ValueError:
                pass
        return out


class NetSummary:
    """Сводка по хостам, которая дополняется новыми событиями. Пересчитывать весь журнал каждую секунду
    (а он бывает на десятки тысяч записей) в потоке окна не нужно."""

    def __init__(self):
        self.agg = {}

    def add(self, events):
        agg = self.agg
        for e in events:
            if "host" not in e:
                continue
            key = (e["host"], e.get("port"))
            s = agg.get(key)
            if s is None:
                s = agg[key] = {"host": e["host"], "port": e.get("port"), "open": 0,
                                "deny": 0, "error": 0, "up": 0, "down": 0,
                                "last": e.get("ts", ""), "ips": set(), "via": ""}
            s["last"] = e.get("ts", s["last"])
            ev = e.get("event")
            if e.get("via"):
                s["via"] = e["via"]
            if ev == "open":
                s["open"] += 1
                if e.get("ip"):
                    s["ips"].add(e["ip"])
            elif ev in ("deny", "error"):
                s[ev] += 1
            elif ev == "close":
                s["up"] += e.get("up", 0)
                s["down"] += e.get("down", 0)

    def rows(self):
        """Список словарей, последние обращения в конце."""
        return sorted(self.agg.values(), key=lambda s: s["last"])


def summarize(events):
    """Сводка по хостам: список словарей, последние обращения в конце."""
    s = NetSummary()
    s.add(events)
    return s.rows()


def clear_net_log(name):
    p = net_log_path(name)
    if os.path.exists(p):
        with open(p, "w"):
            pass


# ---- gui/*: графический интерфейс. Классы требуют импортированного GTK, поэтому
# весь раздел собирается внутри функции и выполняется только при запуске окна.
def _build_gui():
    """Определяет классы интерфейса и возвращает gui_main."""
    # ---- gui/gtk.py: Импорт GTK 4 (с перезапуском под системным Python и понятной ошибкой).

    def _load_gtk():
        """Импорт GTK; при неудаче перезапуск под системным Python или понятная ошибка."""
        try:
            import gi
            gi.require_version("Gtk", "4.0")
            gi.require_version("Gdk", "4.0")
            from gi.repository import Gdk, Gio, GLib, GObject, Gtk, Pango
            try:  # встроенный терминал; без него терминал открывается во внешнем окне
                gi.require_version("Vte", "3.91")
                from gi.repository import Vte
            except (ImportError, ValueError):
                Vte = None
            return Gdk, Gio, GLib, GObject, Gtk, Pango, Vte
        except (ImportError, ValueError) as exc:
            # GTK-привязки ставятся для системного Python; если скрипт запущен другим
            # интерпретатором (pyenv, mise, conda, uv, linuxbrew), перезапускаемся под системным.
            system_py = "/usr/bin/python3"
            try:
                same = os.path.samefile(sys.executable, system_py)
            except OSError:
                same = True
            if not same and os.access(system_py, os.X_OK) and not os.environ.get("ENVBOX_GUI_REEXEC"):
                os.environ["ENVBOX_GUI_REEXEC"] = "1"
                os.execv(system_py, [system_py, SELF, *sys.argv[1:]])
            sys.stderr.write("envbox: нужен GTK 4 для Python (системный /usr/bin/python3):\n"
                             "  Arch:          sudo pacman -S python-gobject gtk4\n"
                             "  Debian/Ubuntu: sudo apt install python3-gi gir1.2-gtk-4.0\n"
                             "  Fedora:        sudo dnf install python3-gobject gtk4\n"
                             f"(интерпретатор: {sys.executable}; ошибка: {exc})\n")
            sys.exit(1)


    Gdk, Gio, GLib, GObject, Gtk, Pango, Vte = _load_gtk()
    if Gtk.get_major_version() != 4 or Gtk.get_minor_version() < 10:
        sys.stderr.write("envbox: нужен GTK >= 4.10 (Ubuntu 24.04 и новее)\n")
        sys.exit(1)


    # ---- gui/consts.py: Константы GUI: CSS, значки, метки.

    HOME = os.path.expanduser("~")


    SHELL_COMMAND = "@shell"   # метка: подставляется оболочка выбранной среды


    STATUS_SECONDS = 8


    CSS = resource_text("gui.css")


    LEVEL_ICONS = {"ok": ("✔", "eb-ok"), "info": ("•", "eb-info"), "warn": ("⚠", "eb-warn")}


    KIND_ICONS = {"app": "utilities-terminal-symbolic", "browser": "web-browser-symbolic"}


    # ---- gui/widgets.py: Мелкие виджеты и диалоги GTK: кнопки, карточки, переключатели, alert/choose/prompt.

    def to_home(path):
        if path == HOME:
            return "~"
        if path.startswith(HOME + "/"):
            return "~" + path[len(HOME):]
        return path


    def margins(widget, m=12):
        widget.set_margin_top(m)
        widget.set_margin_bottom(m)
        widget.set_margin_start(m)
        widget.set_margin_end(m)
        return widget


    def text_area(editable=True, height=60):
        view = Gtk.TextView(monospace=True, editable=editable, wrap_mode=Gtk.WrapMode.WORD_CHAR)
        view.set_left_margin(6)
        view.set_right_margin(6)
        view.set_top_margin(4)
        view.set_bottom_margin(4)
        scroll = Gtk.ScrolledWindow(hexpand=True)
        scroll.set_min_content_height(height)
        scroll.set_child(view)
        scroll.add_css_class("frame")
        return view, scroll


    def get_text(view):
        buf = view.get_buffer()
        return buf.get_text(buf.get_start_iter(), buf.get_end_iter(), False)


    def get_lines(view):
        return [line.strip() for line in get_text(view).splitlines() if line.strip()]


    def set_text(view, text):
        view.get_buffer().set_text(text)


    def hint(text):
        lbl = Gtk.Label(label=text, xalign=0, wrap=True)
        lbl.set_max_width_chars(72)
        lbl.add_css_class("dim-label")
        return lbl


    def alert(parent, message, detail=""):
        dlg = Gtk.AlertDialog()
        dlg.set_message(message)
        dlg.set_detail(detail)
        dlg.show(parent)


    def choose(parent, message, detail, buttons, callback):
        """Диалог выбора; callback(индекс кнопки). Кнопка 0 — отмена."""
        dlg = Gtk.AlertDialog()
        dlg.set_message(message)
        dlg.set_detail(detail)
        dlg.set_buttons(buttons)
        dlg.set_cancel_button(0)
        dlg.set_default_button(0)

        def done(d, res):
            try:
                idx = d.choose_finish(res)
            except GLib.Error:
                idx = 0
            callback(idx)

        dlg.choose(parent, None, done)


    def prompt(parent, title, label, callback, initial="", secret=False):
        """Окно ввода строки; callback(значение) вызывается только по OK."""
        win = Gtk.Window(title=title, transient_for=parent, modal=True)
        win.set_default_size(480, -1)
        box = margins(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10))
        box.append(Gtk.Label(label=label, xalign=0, wrap=True))
        entry = Gtk.PasswordEntry(show_peek_icon=True) if secret else Gtk.Entry(text=initial)
        entry.set_hexpand(True)
        box.append(entry)
        buttons = Gtk.Box(spacing=8, halign=Gtk.Align.END)
        cancel = Gtk.Button(label="Отмена")
        ok = Gtk.Button(label="OK")
        ok.add_css_class("suggested-action")
        buttons.append(cancel)
        buttons.append(ok)
        box.append(buttons)

        def finish(*_):
            value = entry.get_text()
            win.destroy()
            callback(value)

        ok.connect("clicked", finish)
        entry.connect("activate", finish)
        cancel.connect("clicked", lambda *_: win.destroy())
        win.set_child(box)
        win.present()
        entry.grab_focus()


    def icon_button(icon, text, css=None, tooltip=None):
        """Кнопка «значок + подпись»; подпись меняется через set_button_text."""
        btn = Gtk.Button()
        line = Gtk.Box(spacing=6)
        line.append(Gtk.Image.new_from_icon_name(icon))
        btn.lbl = Gtk.Label(label=text)
        line.append(btn.lbl)
        btn.set_child(line)
        if css:
            btn.add_css_class(css)
        if tooltip:
            btn.set_tooltip_text(tooltip)
        return btn


    def set_button_text(btn, text):
        btn.lbl.set_text(text)


    def badge(text="", css=None):
        lbl = Gtk.Label(label=text)
        lbl.add_css_class("eb-badge")
        if css:
            lbl.add_css_class(css)
        return lbl


    def card(css="eb-card", spacing=10):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=spacing)
        box.add_css_class(css)
        return box


    def toggle(title, subtitle=None):
        """Переключатель с подписью: (строка, Gtk.Switch)."""
        line = Gtk.Box(spacing=12)
        text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2, hexpand=True)
        text.append(Gtk.Label(label=title, xalign=0, wrap=True))
        if subtitle:
            text.append(hint(subtitle))
        sw = Gtk.Switch(valign=Gtk.Align.CENTER)
        line.append(text)
        line.append(sw)
        return line, sw


    def section(title, subtitle=None):
        """Карточка раздела: (карточка, сетка внутри)."""
        box = card()
        lbl = Gtk.Label(label=title, xalign=0)
        lbl.add_css_class("eb-h2")
        box.append(lbl)
        if subtitle:
            box.append(hint(subtitle))
        grid = Gtk.Grid(column_spacing=12, row_spacing=8)
        box.append(grid)
        return box, grid


    def expander_section(title, subtitle):
        """Свёрнутый по умолчанию раздел «для опытных»: (карточка, сетка внутри)."""
        box = card()
        exp = Gtk.Expander()
        head = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        t = Gtk.Label(label=title, xalign=0)
        t.add_css_class("eb-h2")
        head.append(t)
        head.append(hint(subtitle))
        exp.set_label_widget(head)
        grid = Gtk.Grid(column_spacing=12, row_spacing=8, margin_top=12)
        exp.set_child(grid)
        box.append(exp)
        return box, grid


    class Rows:
        """Добавление строк «подпись — виджет — подсказка» в сетку."""

        def __init__(self, grid):
            self.grid = grid
            self.r = 0

        def add(self, label, widget, note=None):
            made = []
            if label is not None:
                lbl = Gtk.Label(label=label, xalign=1, valign=Gtk.Align.START, margin_top=6, wrap=True)
                lbl.set_max_width_chars(24)
                self.grid.attach(lbl, 0, self.r, 1, 1)
                made.append(lbl)
            self.grid.attach(widget, 1, self.r, 1, 1)
            made.append(widget)
            self.r += 1
            if note:
                h = hint(note)
                self.grid.attach(h, 1, self.r, 1, 1)
                made.append(h)
                self.r += 1
            return made


    def clear_children(box):
        child = box.get_first_child()
        while child is not None:
            nxt = child.get_next_sibling()
            box.remove(child)
            child = nxt


    def show_all(widgets, visible):
        for w in widgets:
            w.set_visible(visible)


    # ---- gui/browser/page.py: Страница встроенного браузера: подключение, отключение, запуск.

    class BrowserPageMixin:
        """Страница встроенного браузера: подключение, отключение, запуск."""

        # ------------------------------------------------------- окно браузера (кадры по CDP)

        def build_browser_page(self):
            self.viewer = None
            self.viewer_env = None
            self.b_connecting = False
            self.b_manual_off = False
            self.b_frame = None
            self.b_frame_size = (0, 0)
            self.b_paint_pending = False
            self.b_ptr = (0.0, 0.0)
            self.b_buttons = 0
            self.b_last_move = 0.0
            self.b_wheel = None
            self.b_tabs = []
            self.b_active = None
            self.b_tabs_sig = None
            self.b_ctx = {}
            self.b_detached = None        # отдельное окно браузера (Gtk.Window) или None
            self.b_ext_busy = False       # открыт вопрос «передать ссылку приложению?»
            self.b_detached_env = ""
            self.b_want_url = ""          # ссылка, которую нужно открыть вкладкой сразу после подключения
            self.link_queue = []          # запросы на открытие ссылок из сред: (среда, адрес)
            self.link_dialog_open = False
            outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)

            # --- полоса вкладок
            strip = Gtk.Box(spacing=4, margin_top=4, margin_start=6, margin_end=6)
            self.b_tabs_box = Gtk.Box(spacing=2)
            scroller = Gtk.ScrolledWindow(hexpand=True)
            scroller.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.NEVER)
            scroller.set_child(self.b_tabs_box)
            strip.append(scroller)
            btn_new = Gtk.Button(icon_name="tab-new-symbolic", tooltip_text="Новая вкладка (Ctrl+T)")
            btn_new.add_css_class("flat")
            btn_new.connect("clicked", lambda *_a: self.browser_new_tab())
            strip.append(btn_new)
            outer.append(strip)

            # --- панель: назад, вперёд, обновить, адрес, масштаб, подключение
            bar = Gtk.Box(spacing=4, margin_top=4, margin_bottom=4, margin_start=6, margin_end=6)

            def tool(icon, tip, fn):
                btn = Gtk.Button(icon_name=icon, tooltip_text=tip)
                btn.add_css_class("flat")
                btn.connect("clicked", lambda *_a: fn())
                bar.append(btn)

            tool("go-previous-symbolic", "Назад (Alt+←)", lambda: self.browser_cmd(lambda v: v.history(-1)))
            tool("go-next-symbolic", "Вперёд (Alt+→)", lambda: self.browser_cmd(lambda v: v.history(1)))
            tool("view-refresh-symbolic", "Обновить (F5)", lambda: self.browser_cmd(lambda v: v.reload()))
            self.e_b_url = Gtk.Entry(hexpand=True, placeholder_text="Адрес: https://…  (Ctrl+L)")
            self.e_b_url.connect("activate", self.on_browser_go)
            bar.append(self.e_b_url)
            for text, tip, step in (("A−", "Мельче (Ctrl −)", -1), ("A+", "Крупнее (Ctrl +)", 1)):
                btn = Gtk.Button(label=text, tooltip_text=tip)
                btn.add_css_class("flat")
                btn.connect("clicked", lambda *_a, st=step: self.browser_zoom(st))
                bar.append(btn)
            self.btn_b_zoom = Gtk.Button(label="100%", tooltip_text="Масштаб страницы; клик — вернуть 100% (Ctrl 0)")
            self.btn_b_zoom.add_css_class("flat")
            self.btn_b_zoom.connect("clicked", lambda *_a: self.browser_zoom(0))
            bar.append(self.btn_b_zoom)
            self.btn_b_conn = Gtk.Button(label="Подключиться")
            self.btn_b_conn.connect("clicked", self.on_browser_toggle)
            bar.append(self.btn_b_conn)
            self.btn_b_detach = Gtk.Button(label="Отдельное окно",
                                           tooltip_text="Показать браузер в отдельном окне (можно держать рядом с другими)")
            self.btn_b_detach.connect("clicked", self.on_browser_detach_toggle)
            bar.append(self.btn_b_detach)
            outer.append(bar)

            # --- поиск по странице (Ctrl+F)
            self.b_find_bar = Gtk.Box(spacing=4, margin_start=6, margin_end=6, margin_bottom=4)
            self.e_b_find = Gtk.Entry(hexpand=True, placeholder_text="Найти на странице")
            self.e_b_find.connect("activate", lambda *_a: self.browser_find(False))
            self.b_find_bar.append(self.e_b_find)
            for text, back in (("Далее", False), ("Назад", True)):
                btn = Gtk.Button(label=text)
                btn.connect("clicked", lambda *_a, bk=back: self.browser_find(bk))
                self.b_find_bar.append(btn)
            btn_close = Gtk.Button(icon_name="window-close-symbolic", tooltip_text="Закрыть поиск")
            btn_close.add_css_class("flat")
            btn_close.connect("clicked", lambda *_a: self.browser_find_close())
            self.b_find_bar.append(btn_close)
            self.b_find_bar.set_visible(False)
            outer.append(self.b_find_bar)

            # --- страница
            self.b_picture = Gtk.Picture(hexpand=True, vexpand=True)
            try:
                self.b_picture.set_content_fit(Gtk.ContentFit.CONTAIN)
            except Exception:  # noqa: BLE001
                self.b_picture.set_keep_aspect_ratio(True)
            self.b_picture.set_can_shrink(True)
            self.b_picture.set_focusable(True)
            click = Gtk.GestureClick()
            click.set_button(0)
            click.connect("pressed", lambda g, n, x, y: self.on_b_mouse(g, "mousePressed", n, x, y))
            click.connect("released", lambda g, n, x, y: self.on_b_mouse(g, "mouseReleased", n, x, y))
            self.b_picture.add_controller(click)
            motion = Gtk.EventControllerMotion()
            motion.connect("motion", self.on_b_motion)
            self.b_picture.add_controller(motion)
            scroll = Gtk.EventControllerScroll.new(Gtk.EventControllerScrollFlags.BOTH_AXES)
            scroll.connect("scroll", self.on_b_scroll)
            self.b_picture.add_controller(scroll)
            keys = Gtk.EventControllerKey()
            keys.connect("key-pressed", lambda c, kv, kc, st: self.on_b_key(kv, kc, st, True))
            keys.connect("key-released", lambda c, kv, kc, st: self.on_b_key(kv, kc, st, False))
            self.b_picture.add_controller(keys)
            self.build_browser_menu()

            off = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, valign=Gtk.Align.CENTER, halign=Gtk.Align.CENTER)
            msg = Gtk.Label(wrap=True, justify=Gtk.Justification.CENTER, max_width_chars=60,
                            label="Здесь будет видна страница изолированного браузера.\n"
                                  "Запустите его кнопкой «Запустить браузер» — вкладка подключится сама.\n"
                                  "ИИ-среды управляют тем же браузером, поэтому вы увидите всё, что они делают.")
            msg.add_css_class("dim-label")
            off.append(msg)
            self.btn_b_start = Gtk.Button(label="Запустить браузер", halign=Gtk.Align.CENTER, margin_top=10)
            self.btn_b_start.add_css_class("suggested-action")
            self.btn_b_start.connect("clicked", self.on_browser_start)
            off.append(self.btn_b_start)
            self.b_stack = Gtk.Stack(vexpand=True, hexpand=True)
            self.b_stack.add_named(off, "off")
            self.b_stack.add_named(self.b_picture, "view")
            outer.append(self.b_stack)
            self.b_status = hint("")
            outer.append(self.b_status)
            GLib.timeout_add(1500, self.browser_tick)
            GLib.timeout_add(1500, self.poll_links)
            return outer

        # ---- служебное

        def bg(self, fn):
            """Вызов с ожиданием ответа браузера — не в потоке интерфейса."""
            def run():
                try:
                    fn()
                except (OSError, ValueError, KeyError) as e:
                    GLib.idle_add(self.browser_note, str(e))

            threading.Thread(target=run, daemon=True).start()

        def browser_note(self, text):
            self.b_status.set_text(text)
            return False

        def safe(self, fn):
            """Быстрая отправка ввода (без ожидания ответа) прямо из обработчика события."""
            try:
                fn()
            except OSError as e:
                self.browser_note(f"Связь с браузером потеряна: {e}")

        def browser_cmd(self, fn):
            v = self.viewer
            if v is None:
                self.browser_note("Браузер не подключён")
                return
            self.bg(lambda: fn(v))

        def set_clipboard(self, text):
            try:
                self.get_clipboard().set_text(text)
            except Exception:  # noqa: BLE001
                try:
                    self.get_clipboard().set(text)
                except Exception:  # noqa: BLE001
                    return False
            return True

        # ---- подключение

        def b_target(self):
            """Имя браузера, который показывается: в отдельном окне — его, иначе выбранная среда-браузер."""
            if self.b_detached is not None:
                return self.b_detached_env or None
            cur = self.current
            return cur.name if cur is not None and cur.is_browser else None

        def b_visible(self):
            if self.b_detached is not None:
                return True
            return self.nb.get_current_page() == self.nb.page_num(self.page_browser)

        def browser_tick(self):
            try:
                target = self.b_target()
                if self.viewer is not None:
                    if target is None or target != self.viewer_env:
                        self.browser_disconnect()
                    else:
                        w, h = int(self.b_picture.get_width()), int(self.b_picture.get_height())
                        vw, vh = self.viewer.size
                        if w > 200 and h > 150 and (abs(w - vw) > 8 or abs(h - vh) > 8):
                            v = self.viewer
                            self.bg(lambda: v.set_size(w, h))
                elif (target is not None and not self.b_connecting and not self.b_manual_off
                      and self.b_visible() and cdp_listening(target)):
                    self.browser_connect(target)
            except Exception:  # noqa: BLE001
                pass
            return True

        def browser_connect(self, name=None):
            name = name or self.b_target()
            if self.viewer is not None or self.b_connecting or not name:
                return
            w = max(400, int(self.b_picture.get_width()) or 1000)
            h = max(300, int(self.b_picture.get_height()) or 700)
            self.b_connecting = True
            self.browser_note("Подключаюсь к браузеру…")
            holder = {}

            def work():
                v = None
                try:
                    v = CdpViewer(cdp_socket_path(name), self.browser_on_frame, self.browser_on_url,
                                       lambda: GLib.idle_add(self.browser_closed, holder.get("v")),
                                       lambda tabs, active: GLib.idle_add(self.browser_set_tabs, tabs, active),
                                       lambda url: GLib.idle_add(self.browser_ask_external, url))
                    holder["v"] = v
                    v.connect(w, h)
                    GLib.idle_add(self.browser_connected, v, name)
                except (OSError, ValueError, KeyError) as e:
                    if v is not None:
                        v.close()
                    GLib.idle_add(self.browser_failed, str(e))

            threading.Thread(target=work, daemon=True).start()

        def browser_connected(self, v, name):
            self.b_connecting = False
            if self.b_target() != name or self.viewer is not None:
                v.close()
                return False
            self.viewer, self.viewer_env = v, name
            self.b_buttons = 0
            self.b_stack.set_visible_child_name("view")
            self.btn_b_conn.set_label("Отключить")
            self.browser_note(f"Показан браузер «{name}». Клики, прокрутка и клавиши идут на страницу; ИИ работает "
                              "с теми же вкладками. Звука нет: у среды нет доступа к аудио. Правая кнопка — меню.")
            if self.b_want_url:  # ссылка из приложения среды: открыть новой вкладкой и показать
                url, self.b_want_url = self.b_want_url, ""
                self.bg(lambda: v.new_tab(url))
            return False

        def browser_ask_external(self, url):
            """Страница в браузере-среде открывает приложение (claude://…): спросить и передать приложению в среде.

        Сам браузер без окна запускать программы не умеет и показывает запрос, который нельзя закрыть, поэтому
        вкладку он закрывает, а ссылку отдаёт сюда. Адрес приходит со страницы (недоверенный): показываем без
        параметров (в них коды входа), передаёт только среда с такой схемой в «Схемах ссылок»."""
            if self.b_ext_busy:
                return False
            label = safe_link_label(url)
            local = url.lower().startswith(("http:", "https:"))   # колбэк входа на 127.0.0.1:порт, а не запуск программы
            try:
                envs = find_env_for_url(url)
            except (OSError, ValueError):
                envs = []
            if not envs and local:
                q = urllib.parse.urlsplit(url)
                if "callback" in q.path.lower() and "code=" in q.query:   # похоже на колбэк входа, а принять его некому
                    alert(self, "Вход вернулся на адрес внутри компьютера, но принять его некому",
                          f"Адрес: {label}\n\nЭтот порт слушает программа в какой-то среде (например, Claude CLI при "
                          "входе). Откройте настройки той среды и включите «Принимать вход по ссылке localhost», "
                          "затем перезапустите её и повторите вход.")
                return False   # обычная недоступная локальная страница: окно с ошибкой не нужно
            if not envs:
                alert(self, "Страница хочет передать ссылку программе",
                      f"Адрес: {label}\n\nНи у одной среды нет для этого настройки, передавать некуда. "
                      "Для Claude Desktop укажите схему claude в настройках его среды.")
                return False
            self.b_ext_busy = True

            def answer(idx):
                self.b_ext_busy = False
                if idx == 1:
                    self.send_link_to_env(url, envs[0])

            what = ("Сайт вернул вход на адрес, который слушает программа внутри среды (так завершается вход в Claude CLI). "
                    "Браузер до неё не дотянется, но envbox может сделать этот запрос внутри среды."
                    if local else "Так завершается вход в Claude Desktop.")
            choose(self, "Страница хочет передать ссылку программе",
                   f"Адрес: {label}\nСреда: {envs[0]}\n\n{what}\nПередать? Не передавайте ссылки с сайтов, "
                   "которым не доверяете.", ["Отмена", "Передать"], answer)
            return False

        def browser_failed(self, msg):
            self.b_connecting = False
            self.browser_note(f"Не удалось подключиться к браузеру: {msg}")
            return False

        def browser_closed(self, v):
            if v is not None and v is self.viewer:
                self.viewer = None
                self.viewer_env = None
                self.b_stack.set_visible_child_name("off")
                self.btn_b_conn.set_label("Подключиться")
                self.browser_set_tabs([], None)
                self.browser_note("Соединение с браузером закрыто (он остановлен?). Вкладка подключится снова сама.")
            return False

        def browser_disconnect(self):
            v, self.viewer, self.viewer_env = self.viewer, None, None
            self.b_buttons = 0
            self.b_stack.set_visible_child_name("off")
            self.btn_b_conn.set_label("Подключиться")
            self.browser_set_tabs([], None)
            if v is not None:
                try:
                    v.close()
                except OSError:
                    pass

        def browser_detach(self, name=None):
            """Показать браузер в отдельном окне (страница переезжает из вкладки envbox)."""
            name = name or self.b_target()
            if not name:
                self.browser_note("Выберите среду-браузер, чтобы открыть его в отдельном окне")
                return
            if self.b_detached is not None:
                if self.b_detached_env != name:
                    self.b_detached_env = name
                    self.b_detached.set_title(f"Браузер «{name}»")
                    self.browser_disconnect()
                self.b_detached.present()
                return
            win = Gtk.Window(title=f"Браузер «{name}»")
            win.set_default_size(1180, 800)
            try:
                self.nb.detach_tab(self.page_browser)
            except Exception:  # noqa: BLE001
                n = self.nb.page_num(self.page_browser)
                if n >= 0:
                    self.nb.remove_page(n)
            self.page_browser.set_visible(True)
            win.set_child(self.page_browser)
            win.connect("close-request", self.on_browser_window_close)
            self.b_detached, self.b_detached_env = win, name
            self.btn_b_detach.set_label("Вернуть в окно envbox")
            if self.viewer is not None and self.viewer_env != name:
                self.browser_disconnect()
            self.b_manual_off = False
            win.present()
            GLib.timeout_add(300, lambda: (self.browser_connect(name), False)[1])

        def on_browser_window_close(self, win):
            """Закрытие отдельного окна возвращает браузер во вкладку envbox."""
            if self.b_detached is not win:
                return False
            self.b_detached, self.b_detached_env = None, ""
            win.set_child(None)
            self.nb.insert_page(self.page_browser, Gtk.Label(label="Окно браузера"), 2)
            cur = self.current
            self.page_browser.set_visible(bool(cur is not None and cur.is_browser))
            self.btn_b_detach.set_label("Отдельное окно")
            return False

        def on_browser_detach_toggle(self, *_):
            if self.b_detached is not None:
                self.b_detached.close()
            else:
                self.browser_detach()

        def on_browser_start(self, *_):
            name = self.b_target()
            if not name:
                return
            if name in self.running:
                self.browser_note(f"Браузер «{name}» уже запущен; подождите подключения")
                return
            try:
                bp = load_profile(name)
            except (OSError, ValueError) as e:
                alert(self, "Не удалось прочитать среду", str(e))
                return
            errs = bp.validate()
            if errs:
                alert(self, f"Браузер «{name}» не готов к запуску", "\n".join(errs))
                return
            self.launch_browser(bp)

        def on_browser_toggle(self, *_):
            if self.viewer is not None:
                self.b_manual_off = True
                self.browser_disconnect()
                self.browser_note("Отключено. Нажмите «Подключиться», чтобы снова увидеть страницу.")
            else:
                self.b_manual_off = False
                self.browser_connect()


    # ---- gui/browser/view.py: Встроенный браузер: вкладки, масштаб, поиск, меню, мышь и клавиатура.

    class BrowserViewMixin:
        """Встроенный браузер: вкладки, масштаб, поиск, меню, мышь и клавиатура."""

        # ---- вкладки

        @staticmethod
        def b_tab_title(tab):
            title = (tab.get("title") or "").strip()
            if title and title != tab.get("url"):
                return title
            url = tab.get("url") or ""
            if not url or url == "about:blank":
                return "Новая вкладка"
            return re.sub(r"^https?://", "", url).split("/")[0] or url

        def browser_set_tabs(self, tabs, active):
            self.b_tabs, self.b_active = list(tabs), active
            sig = tuple((t["id"], self.b_tab_title(t), t["id"] == active) for t in tabs)
            if self.viewer is not None:
                self.btn_b_zoom.set_label(f"{round(self.viewer.cur_zoom * 100)}%")
            if sig == self.b_tabs_sig:
                return False
            self.b_tabs_sig = sig
            child = self.b_tabs_box.get_first_child()
            while child is not None:
                nxt = child.get_next_sibling()
                self.b_tabs_box.remove(child)
                child = nxt
            for t in tabs:
                tid = t["id"]
                cell = Gtk.Box(spacing=0)
                btn = Gtk.ToggleButton(label=self.b_tab_title(t), tooltip_text=f"{t.get('title') or ''}\n{t.get('url') or ''}")
                btn.set_active(tid == active)
                btn.add_css_class("flat")
                lbl = btn.get_child()
                try:
                    lbl.set_ellipsize(Pango.EllipsizeMode.END)
                    lbl.set_max_width_chars(18)
                except Exception:  # noqa: BLE001
                    pass
                btn.connect("clicked", lambda *_a, i=tid, b=btn: (b.set_active(i == self.b_active),
                                                                  self.browser_cmd(lambda v: v.switch_tab(i))))
                close = Gtk.Button(icon_name="window-close-symbolic", tooltip_text="Закрыть вкладку (Ctrl+W)")
                close.add_css_class("flat")
                close.connect("clicked", lambda *_a, i=tid: self.browser_cmd(lambda v: v.close_tab(i)))
                cell.append(btn)
                cell.append(close)
                self.b_tabs_box.append(cell)
            return False

        def browser_new_tab(self):
            self.browser_cmd(lambda v: v.new_tab("about:blank"))
            GLib.timeout_add(300, lambda: (self.e_b_url.grab_focus(), False)[1])

        def browser_cycle_tab(self, step):
            ids = [t["id"] for t in self.b_tabs]
            if len(ids) < 2 or self.b_active not in ids:
                return
            target = ids[(ids.index(self.b_active) + step) % len(ids)]
            self.browser_cmd(lambda v: v.switch_tab(target))

        # ---- адрес, масштаб, поиск, копирование

        def on_browser_go(self, *_):
            v = self.viewer
            if v is None:
                self.browser_note("Браузер не подключён: запустите его кнопкой «Запустить браузер»")
                return
            try:
                url = normalize_url(self.e_b_url.get_text())
            except ValueError as e:
                self.browser_note(str(e))
                return
            self.bg(lambda: v.navigate(url))
            self.b_picture.grab_focus()

        def browser_zoom(self, step):
            v = self.viewer
            if v is None:
                return

            def work():
                z = v.set_zoom(1.0) if step == 0 else v.zoom_step(step)
                GLib.idle_add(self.btn_b_zoom.set_label, f"{round(z * 100)}%")

            self.bg(work)

        def browser_find(self, back):
            text = self.e_b_find.get_text()
            v = self.viewer
            if v is None or not text:
                return

            def work():
                found = v.find(text, back)
                if not found:
                    GLib.idle_add(self.browser_note, f"«{text}» на странице не найдено")

            self.bg(work)

        def browser_find_open(self):
            self.b_find_bar.set_visible(True)
            self.e_b_find.grab_focus()

        def browser_find_close(self):
            self.b_find_bar.set_visible(False)
            self.b_picture.grab_focus()

        def browser_copy_selection(self):
            v = self.viewer
            if v is None:
                return

            def work():
                text = v.selection_text()
                if text:
                    GLib.idle_add(self.browser_copied, text)
                else:
                    GLib.idle_add(self.browser_note, "Ничего не выделено")

            self.bg(work)

        def browser_copied(self, text):
            if self.set_clipboard(text):
                self.browser_note(f"Скопировано символов: {len(text)}")
            return False

        def paste_into_browser(self):
            def done(clip, res):
                try:
                    text = clip.read_text_finish(res)
                except Exception:  # noqa: BLE001
                    return
                v = self.viewer
                if text and v is not None:
                    self.safe(lambda: v.insert_text(text))

            self.get_clipboard().read_text_async(None, done)

        # ---- меню правой кнопки

        def build_browser_menu(self):
            group = Gio.SimpleActionGroup()
            self.b_actions = {}

            def add(name, fn):
                act = Gio.SimpleAction.new(name, None)
                act.connect("activate", lambda *_a: fn())
                group.add_action(act)
                self.b_actions[name] = act

            def open_url(key):
                url = self.b_ctx.get(key) or ""
                if not re.match(r"^https?://", url, re.I):
                    self.browser_note("Этот адрес нельзя открыть во вкладке (только http и https); его можно скопировать")
                    return
                self.browser_cmd(lambda v: v.new_tab(url))

            def copy_url(key):
                url = self.b_ctx.get(key) or ""
                if url and self.set_clipboard(url):
                    self.browser_note("Адрес скопирован")

            add("back", lambda: self.browser_cmd(lambda v: v.history(-1)))
            add("forward", lambda: self.browser_cmd(lambda v: v.history(1)))
            add("reload", lambda: self.browser_cmd(lambda v: v.reload()))
            add("copy", self.browser_copy_selection)
            add("paste", self.paste_into_browser)
            add("select-all", lambda: self.browser_cmd(lambda v: v.select_all()))
            add("open-link", lambda: open_url("link"))
            add("copy-link", lambda: copy_url("link"))
            add("open-image", lambda: open_url("image"))
            add("copy-image", lambda: copy_url("image"))
            add("open-video", lambda: open_url("video"))
            add("copy-video", lambda: copy_url("video"))
            add("zoom-in", lambda: self.browser_zoom(1))
            add("zoom-out", lambda: self.browser_zoom(-1))
            add("zoom-reset", lambda: self.browser_zoom(0))
            add("find", self.browser_find_open)
            self.b_picture.insert_action_group("web", group)
            self.b_popover = Gtk.PopoverMenu.new_from_model(Gio.Menu())
            self.b_popover.set_parent(self.b_picture)
            self.b_popover.set_has_arrow(False)

        def browser_show_menu(self, info, x, y):
            self.b_ctx = info
            menu = Gio.Menu()
            for key, items in (("link", (("Открыть ссылку в новой вкладке", "web.open-link"),
                                         ("Скопировать адрес ссылки", "web.copy-link"))),
                               ("image", (("Открыть картинку в новой вкладке", "web.open-image"),
                                          ("Скопировать адрес картинки", "web.copy-image"))),
                               ("video", (("Открыть видео в новой вкладке", "web.open-video"),
                                          ("Скопировать адрес видео", "web.copy-video")))):
                if info.get(key):
                    sec = Gio.Menu()
                    for label, act in items:
                        sec.append(label, act)
                    menu.append_section(None, sec)
            edit = Gio.Menu()
            if info.get("selection"):
                edit.append("Копировать (Ctrl+C)", "web.copy")
            if info.get("editable"):
                edit.append("Вставить (Ctrl+V)", "web.paste")
            edit.append("Выделить всё (Ctrl+A)", "web.select-all")
            edit.append("Найти на странице… (Ctrl+F)", "web.find")
            menu.append_section(None, edit)
            nav = Gio.Menu()
            nav.append("Назад", "web.back")
            nav.append("Вперёд", "web.forward")
            nav.append("Обновить", "web.reload")
            menu.append_section(None, nav)
            view = Gio.Menu()
            view.append("Крупнее (Ctrl +)", "web.zoom-in")
            view.append("Мельче (Ctrl −)", "web.zoom-out")
            view.append("Масштаб 100% (Ctrl 0)", "web.zoom-reset")
            menu.append_section(None, view)
            self.b_popover.set_menu_model(menu)
            rect = Gdk.Rectangle()
            rect.x, rect.y, rect.width, rect.height = int(x), int(y), 1, 1
            self.b_popover.set_pointing_to(rect)
            self.b_popover.popup()
            return False

        # ---- кадры

        def browser_on_frame(self, data, meta):  # поток чтения: только запоминаем кадр
            self.b_frame = data
            if not self.b_paint_pending:
                self.b_paint_pending = True
                GLib.idle_add(self.browser_paint, priority=GLib.PRIORITY_DEFAULT)

        def browser_paint(self):
            self.b_paint_pending = False
            data = self.b_frame
            if data is None:
                return False
            try:
                tex = Gdk.Texture.new_from_bytes(GLib.Bytes.new(data))
            except Exception:  # noqa: BLE001
                return False
            self.b_frame_size = (tex.get_width(), tex.get_height())
            self.b_picture.set_paintable(tex)
            return False

        def browser_on_url(self, url):
            def apply():
                if not self.e_b_url.has_focus():
                    self.e_b_url.set_text(url)
                return False

            GLib.idle_add(apply)

        # ---- ввод: мышь, колесо, клавиатура

        def b_point(self, x, y):
            fw, fh = getattr(self, "b_frame_size", (0, 0))
            return map_point(x, y, self.b_picture.get_width(), self.b_picture.get_height(), fw, fh)

        @staticmethod
        def b_mods(state):
            m = 0
            if state & Gdk.ModifierType.SHIFT_MASK:
                m |= CDP_MOD_SHIFT
            if state & Gdk.ModifierType.CONTROL_MASK:
                m |= CDP_MOD_CTRL
            if state & Gdk.ModifierType.ALT_MASK:
                m |= CDP_MOD_ALT
            if state & Gdk.ModifierType.SUPER_MASK:
                m |= CDP_MOD_META
            return m

        def on_b_mouse(self, gesture, kind, n, x, y):
            v = self.viewer
            if v is None:
                return
            if kind == "mousePressed":
                self.b_picture.grab_focus()
            pt = self.b_point(x, y)
            if pt is None:
                return
            num = gesture.get_current_button()
            if num == 3:  # правая кнопка — наше меню (содержимое под курсором узнаём у страницы)
                if kind == "mousePressed":
                    def work():
                        info = v.hit_info(pt[0], pt[1])
                        GLib.idle_add(self.browser_show_menu, info, x, y)

                    self.bg(work)
                return
            button = {1: "left", 2: "middle"}.get(num, "left")
            bit = {1: 1, 2: 4}.get(num, 1)
            self.b_buttons = (self.b_buttons | bit) if kind == "mousePressed" else (self.b_buttons & ~bit)
            mods = self.b_mods(gesture.get_current_event_state())
            self.safe(lambda: v.mouse(kind, pt[0], pt[1], button, max(1, n), mods, self.b_buttons))

        def on_b_motion(self, _ctrl, x, y):
            self.b_ptr = (x, y)
            v = self.viewer
            now = time.monotonic()
            if v is None or now - self.b_last_move < 0.04:
                return
            pt = self.b_point(x, y)
            if pt is None:
                return
            self.b_last_move = now
            button = "left" if self.b_buttons & 1 else "none"
            self.safe(lambda: v.mouse("mouseMoved", pt[0], pt[1], button, 0, 0, self.b_buttons))

        def on_b_scroll(self, ctrl, dx, dy):
            v = self.viewer
            if v is None:
                return False
            try:
                state = ctrl.get_current_event_state()
            except Exception:  # noqa: BLE001
                state = 0
            if state & Gdk.ModifierType.CONTROL_MASK and dy:  # Ctrl + колесо — масштаб, как в браузерах
                self.browser_zoom(-1 if dy > 0 else 1)
                return True
            pt = self.b_point(*self.b_ptr)
            if pt is None:
                return False
            # события колеса склеиваются: не чаще раза в кадр (≈60 Гц), иначе быстрая прокрутка тормозит
            if self.b_wheel is None:
                self.b_wheel = [0.0, 0.0, pt[0], pt[1]]
                GLib.timeout_add(16, self.flush_wheel)
            self.b_wheel[0] += dx * 100
            self.b_wheel[1] += dy * 100
            self.b_wheel[2], self.b_wheel[3] = pt
            return True

        def flush_wheel(self):
            w, self.b_wheel = self.b_wheel, None
            v = self.viewer
            if w is not None and v is not None and (w[0] or w[1]):
                self.safe(lambda: v.wheel(w[2], w[3], w[0], w[1]))
            return False

        # физические клавиши (evdev + 8): сочетания работают в любой раскладке, в том числе русской
        KC_A, KC_C, KC_F, KC_L, KC_R, KC_T, KC_V, KC_W = 38, 54, 41, 46, 27, 28, 55, 25

        def on_b_key(self, keyval, keycode, state, pressed):
            v = self.viewer
            if v is None:
                return False
            mods = self.b_mods(state)
            ctrl, alt = bool(mods & CDP_MOD_CTRL), bool(mods & CDP_MOD_ALT)
            name = Gdk.keyval_name(keyval) or ""
            if pressed:
                handled = True
                if ctrl and not alt:
                    if keycode == self.KC_V:
                        self.paste_into_browser()
                    elif keycode == self.KC_C:
                        self.browser_copy_selection()
                    elif keycode == self.KC_A:
                        self.browser_cmd(lambda vv: vv.select_all())
                    elif keycode == self.KC_T:
                        self.browser_new_tab()
                    elif keycode == self.KC_W:
                        tid = self.b_active
                        self.browser_cmd(lambda vv: vv.close_tab(tid))
                    elif keycode == self.KC_L:
                        self.e_b_url.grab_focus()
                        self.e_b_url.select_region(0, -1)
                    elif keycode == self.KC_F:
                        self.browser_find_open()
                    elif keycode == self.KC_R:
                        self.browser_cmd(lambda vv: vv.reload())
                    elif name in ("plus", "equal", "KP_Add"):
                        self.browser_zoom(1)
                    elif name in ("minus", "KP_Subtract"):
                        self.browser_zoom(-1)
                    elif name in ("0", "KP_0"):
                        self.browser_zoom(0)
                    elif name == "Tab":
                        self.browser_cycle_tab(1)
                    elif name == "ISO_Left_Tab":
                        self.browser_cycle_tab(-1)
                    else:
                        handled = False
                elif alt and not ctrl and name in ("Left", "Right"):
                    self.browser_cmd(lambda vv: vv.history(-1 if name == "Left" else 1))
                elif name == "F5":
                    self.browser_cmd(lambda vv: vv.reload())
                else:
                    handled = False
                if handled:
                    return True
            elif ctrl and keycode in (self.KC_V, self.KC_C, self.KC_A, self.KC_T, self.KC_W, self.KC_L, self.KC_F,
                                      self.KC_R) or name in ("F5",):
                return True  # отпускание уже обработанного сочетания странице не нужно
            uni = Gdk.keyval_to_unicode(keyval)
            char = chr(uni) if uni else ""
            self.safe(lambda: v.key(name, char, mods, pressed))
            return True


    # ---- gui/pages/folders.py: Глобальные папки и каталог данных.

    class FoldersMixin:
        """Глобальные папки и каталог данных."""

        # ---- глобальные папки (на странице профиля)

        def update_global_visibility(self):
            show_all(self.global_widgets, self.cb_global.get_active())

        def refresh_global_rows(self, entries):
            """Список глобальных папок с отметками; entries — записи профиля «имя:режим»."""
            chosen = {}
            for g in entries:
                m = GLOBAL_ENTRY_RE.match(g)
                if m:
                    chosen[m.group(1)] = m.group(2)
            clear_children(self.global_list)
            self.global_rows = {}
            names = list_global_folders()
            missing = [n for n in chosen if n not in names]
            if not names and not missing:
                self.global_list.append(hint("Глобальных папок пока нет: создайте первую кнопкой ниже."))
                return
            is_browser = bool(self.current and self.current.is_browser)
            for name in names + missing:
                line = Gtk.Box(spacing=8)
                chk = Gtk.CheckButton(label=name if name in names else f"{name} (папка не найдена)", hexpand=True)
                chk.set_active(name in chosen)
                dd = Gtk.DropDown.new_from_strings(["чтение и запись", "только чтение"])
                dd.set_selected(1 if chosen.get(name) == "ro" else 0)
                line.append(chk)
                line.append(dd)
                if name in names and not is_browser:
                    b = Gtk.Button(label="Сделать проектом")
                    b.connect("clicked", lambda _b, n=name: self.set_workdir_global(n))
                    line.append(b)
                self.global_list.append(line)
                self.global_rows[name] = (chk, dd)

        def collect_global(self):
            out = []
            for name, (chk, dd) in self.global_rows.items():
                if chk.get_active():
                    out.append(f"{name}:{'ro' if dd.get_selected() == 1 else 'rw'}")
            return out

        def set_workdir_global(self, name):
            self.e_workdir.set_text(to_home(global_path(name)))
            self.cb_nowd.set_active(False)
            self.cb_global.set_active(True)   # путь в глобальной папке требует включённых глобальных папок
            self.status(f"Каталог проекта: глобальная папка «{name}». Нажмите «Сохранить».")

        def on_global_create(self):
            def got(name):
                try:
                    create_global_folder(name)
                except (OSError, ValueError) as e:
                    alert(self, "Не удалось создать папку", str(e))
                    return
                self.refresh_global_rows(self.collect_global())
                self.status(f"Глобальная папка «{name.strip()}» создана")

            prompt(self, "Новая глобальная папка", "Имя папки (латиница, цифры, «.», «_», «-»):", got)

        # ---- окно «Папки и каталог данных»

        def on_folders(self, *_):
            win = Gtk.Window(title="Папки и каталог данных", transient_for=self, modal=True)
            win.set_default_size(660, 600)
            outer = margins(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14), 16)

            root_box = card()
            t = Gtk.Label(label="Каталог данных", xalign=0)
            t.add_css_class("eb-h2")
            root_box.append(t)
            root_box.append(hint("Здесь лежат домашние каталоги сред, профили, журналы сети и глобальные папки."))
            lbl_root = Gtk.Label(xalign=0, wrap=True, selectable=True)
            root_box.append(lbl_root)
            lbl_note = hint("")
            root_box.append(lbl_note)
            move_line, move_sw = toggle(
                "Перенести существующие данные",
                "Среды, профили и глобальные папки переедут на новое место. Если выключить, на новом месте "
                "envbox начнёт с чистого листа, а старые данные останутся нетронутыми.")
            move_sw.set_active(True)
            root_box.append(move_line)
            rbtns = Gtk.Box(spacing=8)
            b_change = Gtk.Button(label="Изменить…")
            b_reset = Gtk.Button(label="Вернуть стандартный")
            b_open_root = Gtk.Button(label="Открыть")
            for b in (b_change, b_reset, b_open_root):
                rbtns.append(b)
            root_box.append(rbtns)
            outer.append(root_box)

            glob_box = card()
            t = Gtk.Label(label="Глобальные папки", xalign=0)
            t.add_css_class("eb-h2")
            glob_box.append(t)
            glob_box.append(hint(
                "Папки, которые не принадлежат ни одной среде. Удаление среды их не затрагивает, поэтому "
                "там удобно хранить код. Среде они доступны, только если включить «Глобальные папки» "
                "на вкладке «Настройки» и отметить нужные."))
            glist = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
            gscroll = Gtk.ScrolledWindow(vexpand=True, min_content_height=160)
            gscroll.set_child(glist)
            glob_box.append(gscroll)
            gbtns = Gtk.Box(spacing=8)
            b_new = Gtk.Button(label="Создать папку…")
            b_open_glob = Gtk.Button(label="Открыть каталог глобальных папок")
            gbtns.append(b_new)
            gbtns.append(b_open_glob)
            glob_box.append(gbtns)
            outer.append(glob_box)

            close = Gtk.Button(label="Закрыть", halign=Gtk.Align.END)
            close.connect("clicked", lambda *_: win.destroy())
            outer.append(close)

            def refresh():
                root = envbox_root()
                lbl_root.set_text(to_home(root))
                env = os.environ.get("ENVBOX_ROOT", "").strip()
                if env:
                    lbl_note.set_text("Задан переменной окружения ENVBOX_ROOT: пока она есть, выбор здесь не "
                                      "действует.")
                elif root == os.path.realpath(default_root()):
                    lbl_note.set_text("Стандартное место.")
                else:
                    lbl_note.set_text(f"Выбрано вами. Стандартное место: {to_home(default_root())}.")
                b_change.set_sensitive(not env)
                b_reset.set_sensitive(not env and root != os.path.realpath(default_root()))
                clear_children(glist)
                names = list_global_folders()
                if not names:
                    glist.append(hint("Глобальных папок пока нет."))
                for name in names:
                    users = global_folder_users(name)
                    row = Gtk.Box(spacing=8)
                    text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2, hexpand=True)
                    text.append(Gtk.Label(label=name, xalign=0))
                    text.append(hint("Использует: " + ", ".join(users) if users else "Пока никем не используется"))
                    b_o = Gtk.Button(label="Открыть")
                    b_o.connect("clicked", lambda _b, n=name: self.open_folder_path(global_path(n)))
                    b_d = Gtk.Button(label="Удалить…")
                    b_d.add_css_class("destructive-action")
                    b_d.connect("clicked", lambda _b, n=name, u=users: delete_global(n, u))
                    row.append(text)
                    row.append(b_o)
                    row.append(b_d)
                    glist.append(row)

            def delete_global(name, users):
                def done(idx):
                    if idx != 1:
                        return
                    try:
                        delete_global_folder(name)
                    except (OSError, ValueError) as e:
                        alert(win, "Не удалось удалить папку", str(e))
                        return
                    refresh()
                    self.refresh_global_rows(self.collect_global())
                    self.status(f"Глобальная папка «{name}» удалена")

                extra = ("\nЕё используют среды: " + ", ".join(users) + ". Они потеряют эту папку." if users else "")
                choose(win, f"Удалить глобальную папку «{name}»?",
                       f"Всё содержимое {to_home(global_path(name))} будет удалено без возможности "
                       "восстановления." + extra, ["Отмена", "Удалить навсегда"], done)

            def create():
                def got(name):
                    try:
                        create_global_folder(name)
                    except (OSError, ValueError) as e:
                        alert(win, "Не удалось создать папку", str(e))
                        return
                    refresh()
                    self.refresh_global_rows(self.collect_global())

                prompt(win, "Новая глобальная папка", "Имя папки (латиница, цифры, «.», «_», «-»):", got)

            def pick_root():
                self.choose_folder(lambda path: self.apply_new_root(path, move_sw.get_active(), refresh))

            b_change.connect("clicked", lambda *_: pick_root())
            b_reset.connect("clicked", lambda *_: self.apply_new_root("", move_sw.get_active(), refresh))
            b_open_root.connect("clicked", lambda *_: self.open_folder_path(envbox_root()))
            b_new.connect("clicked", lambda *_: create())
            b_open_glob.connect("clicked", lambda *_: self.open_folder_path(global_root(), create=True))
            refresh()
            win.set_child(outer)
            win.present()

        def open_folder_path(self, path, create=False):
            try:
                if create:
                    os.makedirs(path, mode=0o700, exist_ok=True)
                open_in_file_manager(path)
            except OSError as e:
                alert(self, "Не удалось открыть папку", str(e))

        def apply_new_root(self, new, move, after=None):
            """Сменить каталог данных (new пусто — стандартный); move — перенести существующие данные."""
            if os.environ.get("ENVBOX_ROOT", "").strip():
                alert(self, "Каталог задан переменной ENVBOX_ROOT",
                      "Пока переменная задана, выбор в приложении не действует: уберите её и перезапустите envbox.")
                return
            old = envbox_root()
            target = os.path.realpath(os.path.expanduser(new)) if new else os.path.realpath(default_root())
            if target == old:
                self.status("Каталог данных уже там")
                return
            err = root_error(target)
            if err:
                alert(self, "Этот каталог не подходит", f"{to_home(target)}: {err}")
                return
            if any(True for _ in list_sessions()):
                alert(self, "Есть запущенные среды", "Остановите все среды и повторите.")
                return
            if move and os.path.isdir(target) and os.listdir(target):
                alert(self, "Каталог не пуст", f"{to_home(target)}: для переноса нужен пустой или новый каталог. "
                                               "Выберите другой или выключите «Перенести существующие данные».")
                return
            what = (f"Данные будут перенесены из {to_home(old)} в {to_home(target)}." if move else
                    f"envbox начнёт работать в {to_home(target)} с чистого листа; данные в {to_home(old)} "
                    "останутся нетронутыми, среды из них не будут видны.")

            def go(idx):
                if idx != 1:
                    return
                self.save_current(quiet=True)
                if hasattr(self, "browser_disconnect"):
                    try:
                        self.browser_disconnect()
                    except Exception:  # noqa: BLE001 — просмотр браузера не должен мешать смене каталога
                        pass

                def work():
                    if move:
                        move_root(old, target)
                    set_root("" if target == os.path.realpath(default_root()) else target)

                def done(res):
                    reset_root_cache()
                    if isinstance(res, Exception):
                        alert(self, "Не удалось сменить каталог данных", str(res))
                        return
                    self.settings = load_settings()
                    self.current = None
                    self.reload_profiles()
                    self.refresh_sessions()
                    if after:
                        after()
                    self.status(f"Каталог данных: {to_home(envbox_root())}")

                self.status("Меняю каталог данных…")
                self.run_async(work, done)

            choose(self, "Сменить каталог данных?", what + "\nЗапущенных сред быть не должно.",
                   ["Отмена", "Сменить"], go)


    # ---- gui/pages/isolation.py: Вкладка «Изоляция».

    class IsolationMixin:
        """Вкладка «Изоляция»."""

        def build_isolation_page(self):
            """Каждая защита — отдельный переключатель с названием, объяснением и последствием отключения."""
            self.iso_lock = False
            self.iso_switches = {}
            self.iso_risks = {}
            page = margins(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16), 16)

            box = card()
            title = Gtk.Label(label="Уровень изоляции", xalign=0)
            title.add_css_class("eb-h2")
            box.append(title)
            box.append(hint("Каждую защиту ниже можно включать и выключать отдельно. Набор — быстрый способ "
                            "выставить их все сразу; при ручных правках он станет «Свой набор»."))
            self.dd_preset = Gtk.DropDown.new_from_strings([pr[1] for pr in ISO_PRESETS] + ["Свой набор"])
            self.dd_preset.connect("notify::selected", self.on_preset_changed)
            box.append(self.dd_preset)
            self.lbl_preset = hint("")
            box.append(self.lbl_preset)
            page.append(box)

            for group in ISO_GROUPS:
                box = card()
                title = Gtk.Label(label=group, xalign=0)
                title.add_css_class("eb-h2")
                box.append(title)
                if group == "Файлы":
                    box.append(self.build_files_choices())
                for opt in ISO_OPTIONS:
                    if opt["group"] == group:
                        row = self.iso_row(opt)
                        box.append(row)
                        if opt.get("app_only"):
                            self.app_only.append(row)
                if group == "Сеть":
                    box.append(hint("Режим сети, список сайтов, DNS и свой прокси настраиваются на вкладке «Настройки»."))
                    box.append(self.build_direct_sites())
                page.append(box)

            scroll = Gtk.ScrolledWindow(vexpand=True)
            scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)  # по ширине окна, без растягивания
            scroll.set_child(page)
            return scroll

        def build_files_choices(self):
            grid = Gtk.Grid(column_spacing=12, row_spacing=8)
            rows = Rows(grid)
            self.dd_host = Gtk.DropDown.new_from_strings([
                "Только нужное (рекомендуется)",
                "Весь компьютер, писать только в проект",
                "Весь компьютер, писать везде"])
            self.dd_host.connect("notify::selected", self.on_host_changed)
            rows.add("Какие файлы видит программа", self.dd_host,
                     "По умолчанию: свой домашний каталог, проект и системные программы только на чтение. "
                     "Два других варианта открывают ваши настоящие файлы; сеть, язык, пояс и DNS остаются "
                     "заданными. Не проверено на вашей системе.")
            self.dd_home = Gtk.DropDown.new_from_strings([
                "Свой, отдельный (рекомендуется)",
                "Настоящий домашний каталог (опасно)"])
            self.dd_home.connect("notify::selected", self.on_home_changed)
            rows.add("Домашний каталог", self.dd_home,
                     f"Свой — отдельная папка {to_home(envbox_root())}/<имя>/home. Настоящий открывает ключи SSH, профили "
                     "браузеров и все личные файлы.")
            return grid

        def build_direct_sites(self):
            """Сайты, к которым прокси envbox подключается сам, минуя свой прокси (upstream)."""
            col = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
            title = Gtk.Label(xalign=0, wrap=True)
            title.set_markup("<b>Сайты напрямую, мимо своего прокси</b>")
            col.append(title)
            col.append(hint("Для сайтов, которые не открываются через ваш прокси или VPN (например, не пускают его адрес). "
                            "По одному в строке: example.com — только он, *.example.com — он и все поддомены. "
                            "Программа в среде по-прежнему выходит только через прокси envbox и ваш настоящий адрес не "
                            "видит; его увидят только эти сайты. Работает, когда задан «Свой прокси»; в режиме «только "
                            "разрешённые домены» такие сайты разрешены автоматически."))
            self.tv_direct, sw = text_area(height=56)
            col.append(sw)
            warn = Gtk.Label(label="⚠ Эти сайты узнают ваш настоящий IP-адрес и обходят защиту вашего VPN.",
                             xalign=0, wrap=True)
            warn.add_css_class("eb-warn")
            col.append(warn)
            return col

        def iso_row(self, opt):
            line = Gtk.Box(spacing=12)
            text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2, hexpand=True)
            title = Gtk.Label(xalign=0, wrap=True)
            title.set_markup("<b>" + GLib.markup_escape_text(opt["title"]) + "</b>")
            text.append(title)
            text.append(hint(opt["text"]))
            risk = Gtk.Label(label="⚠ Если выключить: " + opt["risk"], xalign=0, wrap=True)
            risk.add_css_class("eb-warn")
            risk.set_visible(False)
            text.append(risk)
            sw = Gtk.Switch(valign=Gtk.Align.CENTER)
            sw.connect("notify::active", lambda *_: self.on_iso_toggled())
            line.append(text)
            line.append(sw)
            self.iso_switches[opt["key"]] = sw
            self.iso_risks[opt["key"]] = (risk, opt)
            return line

        def on_iso_toggled(self):
            if self.loading or self.iso_lock:
                return
            self.update_iso_views()

        def on_preset_changed(self, *_):
            if self.loading or self.iso_lock:
                return
            idx = self.dd_preset.get_selected()
            if idx >= len(ISO_PRESETS):
                return
            preset = ISO_PRESETS[idx][3]
            self.iso_lock = True
            for opt in ISO_OPTIONS:
                if opt.get("presets", True):
                    self.iso_switches[opt["key"]].set_active(preset.get(opt["key"], True))
            self.iso_lock = False
            self.update_iso_views()

        def update_iso_views(self):
            """Показывает последствия выключенных защит и определяет, какому набору соответствует состояние."""
            state = {key: sw.get_active() for key, sw in self.iso_switches.items()}
            for key, (risk, opt) in self.iso_risks.items():
                risk.set_visible(bool(opt["warn_off"]) and not state[key])
            names = [pr[0] for pr in ISO_PRESETS] + ["custom"]
            found = "custom"
            for pname, _title, _text, preset in ISO_PRESETS:
                if all(state[o["key"]] == preset.get(o["key"], True)
                       for o in ISO_OPTIONS if o.get("presets", True)):
                    found = pname
                    break
            self.iso_lock = True
            self.dd_preset.set_selected(names.index(found))
            self.iso_lock = False
            if found == "custom":
                off = sum(1 for o in ISO_OPTIONS if o["warn_off"] and not state[o["key"]])
                self.lbl_preset.set_text(f"Свой набор. Выключено защит: {off}. Последствия показаны под каждой.")
            else:
                self.lbl_preset.set_text(next(pr[2] for pr in ISO_PRESETS if pr[0] == found))

        def show_isolation(self, p):
            self.iso_lock = True
            for key, sw in self.iso_switches.items():
                sw.set_active(p.iso_on(key))
            self.dd_host.set_selected({"": 0, "ro": 1, "rw": 2}.get(p.host_files, 0))
            self.dd_home.set_selected(1 if p.iso_on("home_real") else 0)
            set_text(self.tv_direct, "\n".join(p.direct_domains))
            self.iso_lock = False
            self.update_iso_views()

        def read_isolation(self, prof):
            for key, sw in self.iso_switches.items():
                prof.iso_set(key, sw.get_active())
            prof.host_files = ("", "ro", "rw")[self.dd_host.get_selected()]
            prof.iso_set("home_real", self.dd_home.get_selected() == 1)
            prof.direct_domains = get_lines(self.tv_direct)
            prof.host_confirmed = bool((prof.host_files or prof.iso_on("home_real"))
                                       and self.current is not None and self.current.host_confirmed)

        def confirm_host_access(self, widget, text, ok_message):
            """Подтверждение опасного доступа к файлам; при отказе возвращает переключатель назад."""
            def done(choice):
                if choice == 1:
                    self.current.host_confirmed = True
                    self.status(ok_message)
                else:
                    self.loading = True
                    widget.set_selected(0)
                    self.loading = False

            choose(self, "Открыть среде ваши настоящие файлы?", text,
                   ["Отмена", "Подтверждаю: дать доступ"], done)

        def on_host_changed(self, *_):
            if self.loading or not self.current:
                return
            idx = self.dd_host.get_selected()
            if idx == 0:
                if self.dd_home.get_selected() == 0:
                    self.current.host_confirmed = False
                return
            self.confirm_host_access(
                self.dd_host,
                "Программа внутри сможет читать " + ("и изменять " if idx == 2 else "") +
                "все ваши настоящие файлы, включая ключи SSH и профили браузеров. Сеть останется только через прокси.",
                "Доступ к файлам компьютера включён после сохранения")

        def on_home_changed(self, *_):
            if self.loading or not self.current:
                return
            if self.dd_home.get_selected() == 0:
                if self.dd_host.get_selected() == 0:
                    self.current.host_confirmed = False
                return
            self.confirm_host_access(
                self.dd_home,
                "Программа внутри будет работать с вашим настоящим домашним каталогом: личные файлы, ключи SSH, "
                "профили браузеров. Сеть останется только через прокси.",
                "Настоящий домашний каталог включён после сохранения")

        def update_system_hints(self):
            lang = self.e_lang.get_text().strip()
            if not lang:
                self.lbl_lang.set_text("Пусто — язык как на компьютере.")
            elif not LANG_RE.match(lang):
                self.lbl_lang.set_text("✖ Неверный формат. Пример: ru_RU.UTF-8")
            else:
                ok = locale_available(lang)
                self.lbl_lang.set_text("✔ Локаль есть в системе." if ok else
                                       "⚠ Такой локали нет на компьютере (locale -a): программы вернутся к "
                                       "английскому. Сгенерируйте её (Arch: /etc/locale.gen и sudo locale-gen)."
                                       if ok is False else "Не удалось проверить локаль.")
            tz = self.e_tz.get_text().strip()
            if not tz:
                self.lbl_tz.set_text("Пусто — пояс как на компьютере. Это часовой пояс, а не подмена часов.")
            elif timezone_exists(tz):
                self.lbl_tz.set_text("✔ Пояс найден. Это часовой пояс, а не подмена часов.")
            else:
                self.lbl_tz.set_text("✖ Не найден в /usr/share/zoneinfo. Пример: Europe/Moscow")


    # ---- gui/pages/launch.py: Запуск среды: терминал, браузер, установка программ, остановка.

    class LaunchMixin:
        """Запуск среды: терминал, браузер, установка программ, остановка."""

        def update_buttons(self):
            p = self.current
            has = p is not None
            is_browser = has and p.is_browser
            is_running = has and p.name in self.running
            self.lbl_toolbar.set_text(p.name if has else "")
            self.btn_shell.set_visible(has and not is_browser)
            self.btn_shell.set_sensitive(has)
            if has and not is_browser:
                set_button_text(self.btn_shell, f"Терминал ({p.shell_cmd})")
                self.btn_shell.set_tooltip_text(f"Оболочка внутри среды: {p.shell_cmd} (Ctrl+T)")
            self.btn_install.set_visible(has and not is_browser)
            self.btn_link.set_visible(has and not is_browser)
            set_button_text(self.btn_run, "Запустить браузер" if is_browser else "Запустить")
            if has:
                self.btn_run.set_tooltip_text(
                    "Запустить браузер без окна (Ctrl+R)" if is_browser
                    else f"Запустить в терминале: {p.command or '—'} (Ctrl+R)")
            self.btn_run.set_visible(has)
            self.btn_run.set_sensitive(has and not (is_browser and is_running))
            self.btn_stop.set_visible(has and is_running)

        def preflight(self):
            """Сохраняет и проверяет профиль; возвращает Profile или None."""
            p = self.save_current(quiet=True)
            if p is None:
                return None
            errs = p.validate()
            if errs:
                alert(self, "Профиль не готов к запуску", "\n".join(errs))
                return None
            return p

        def launch(self, command):
            if not self.current:
                return
            p = self.preflight()
            if p is None:
                return
            if command == SHELL_COMMAND:
                command = p.shell_cmd
            # Пробный запуск (dry-run) здесь не нужен: проверка профиля уже пройдена, а ошибки envbox
            # показывает прямо в терминале (для браузера — в окне после запуска). Это экономит ~0,2 с.
            if p.is_browser:
                self.launch_browser(p)
                return
            if self.use_embedded():
                self.open_embedded(p, command)
                return
            term = detect_terminal(self.settings)
            if not term:
                alert(self, "Не найден эмулятор терминала",
                      "Установите встроенный терминал (Arch: sudo pacman -S vte4) или укажите команду "
                      "внешнего терминала в настройках (кнопка с шестерёнкой).")
                return
            try:
                proc = subprocess.Popen(terminal_argv(term, p, command),
                                        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL, start_new_session=True)
            except OSError as e:
                alert(self, "Не удалось запустить терминал", f"{term[0]}: {e}")
                return
            self.procs.append(proc)
            self.status(f"Терминал для «{p.name}» запущен")
            GLib.timeout_add(1500, self.refresh_sessions_once)

        def on_install(self, *_):
            """Установка программ внутрь среды: отдельный терминал без проекта и секретов."""
            if not self.current or self.current.is_browser:
                return
            p = self.save_current(quiet=True)
            if p is None:
                return
            recipes = INSTALL_RECIPES
            win = Gtk.Window(title="Установка внутрь среды", transient_for=self, modal=True)
            win.set_default_size(680, -1)
            box = margins(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10), 16)
            box.append(hint("Откроется отдельный терминал этой среды. В нём нет вашего проекта и секретов, "
                            "а сеть открыта только на время установки. Программы ставятся в домашний каталог "
                            "среды и не могут выбраться за её пределы."))
            box.append(Gtk.Label(label="Что установить:", xalign=0))
            dd = Gtk.DropDown.new_from_strings([r["title"] for r in recipes])
            box.append(dd)
            note = hint("")
            box.append(note)
            box.append(Gtk.Label(label="Команда (можно поправить; Enter нажмёте в терминале):", xalign=0))
            entry = Gtk.Entry(hexpand=True)
            box.append(entry)
            line, only = toggle("Ограничить сеть сайтами рецепта",
                                "Выключено — сеть открыта на любые публичные сайты с журналом.")
            box.append(line)

            def refresh(*_):
                r = recipes[dd.get_selected()]
                entry.set_text(r["command"])
                sites = ", ".join(r["domains"]) if r["domains"] else "заранее неизвестны"
                warning = recipe_warning(r, p.name)
                note.set_text(r["note"] + "  Сайты: " + sites + "." + (("\n" + warning) if warning else ""))
                only.set_active(bool(r["domains"]))
                only.set_sensitive(bool(r["domains"]))

            dd.connect("notify::selected", refresh)
            refresh()
            buttons = Gtk.Box(spacing=8, halign=Gtk.Align.END)
            cancel = Gtk.Button(label="Отмена")
            ok = Gtk.Button(label="Открыть установочный терминал")
            ok.add_css_class("suggested-action")
            buttons.append(cancel)
            buttons.append(ok)
            box.append(buttons)

            def start(*_):
                r = recipes[dd.get_selected()]
                domains = list(r["domains"]) if (only.get_active() and r["domains"]) else []
                text = entry.get_text().strip()
                holes = recipe_placeholders(text)
                if holes:
                    alert(win, "Заполните команду", "В ней остались места для подстановки: " + ", ".join(holes))
                    return
                win.destroy()
                errs = p.install_view(domains).validate()
                if errs:
                    alert(self, "Профиль не готов к установке", "\n".join(errs))
                    return
                if self.use_embedded():
                    self.open_embedded(p, "bash", install=True, feed=text, install_domains=domains)
                    where = "только " + ", ".join(domains) if domains else "любые публичные сайты (с журналом)"
                    self.status(f"Режим установки: нет проекта и секретов; сеть: {where}")
                else:
                    term = detect_terminal(self.settings)
                    if not term:
                        alert(self, "Не найден эмулятор терминала", "Установите vte4 или задайте терминал в настройках.")
                        return
                    subprocess.Popen(terminal_argv(term, p, "bash", install=True, install_domains=domains),
                                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL, start_new_session=True)
                    try:
                        self.get_clipboard().set_text(text)
                    except Exception:  # noqa: BLE001
                        pass
                    self.status("Установочный терминал открыт; команда скопирована, вставьте её и нажмите Enter")

            ok.connect("clicked", start)
            cancel.connect("clicked", lambda *_: win.destroy())
            win.set_child(box)
            win.present()

        def launch_browser(self, p):
            if p.name in self.running:
                self.status(f"Браузер «{p.name}» уже запущен")
                return
            try:
                proc, log_path = launch_background(p)
            except (OSError, subprocess.SubprocessError) as e:
                alert(self, "Не удалось запустить браузер", str(e))
                return
            self.procs.append(proc)
            self.pending[p.name] = (proc, log_path)
            self.status(f"Браузер «{p.name}» запускается; CDP внутри ИИ-сред: http://127.0.0.1:{CDP_PORT}")
            self.b_manual_off = False
            if self.b_detached is None:
                try:
                    self.nb.set_current_page(self.nb.page_num(self.page_browser))
                except Exception:  # noqa: BLE001
                    pass
            GLib.timeout_add(2500, lambda: self.check_launch(p.name))
            GLib.timeout_add(1500, self.refresh_sessions_once)

        def check_launch(self, name):
            entry = self.pending.pop(name, None)
            if entry is None:
                return False
            proc, log_path = entry
            if proc.poll() is not None:
                tail = read_tail(log_path)
                alert(self, f"Браузер «{name}» завершился сразу после запуска",
                      (tail or "вывода нет") + f"\n\nЖурнал: {to_home(log_path)}\n"
                      "Частые причины: встроенная защита Chrome (sandbox) не запускается — снимите флажок "
                      "«Встроенная защита Chrome (sandbox)» на вкладке «Настройки»; или фильтр "
                      "системных вызовов мешает — см. «Изоляция». Если ваш Chrome не поддерживает режим "
                      "без окна на платформе ozone «headless», запустите envbox с переменной "
                      "ENVBOX_BROWSER_HEADLESS=new (прежний режим; сайты вроде Gmail его не принимают).")
            return False

        def on_stop_current(self, *_):
            if not self.current:
                return
            name = self.current.name
            sessions = [s for s in list_sessions() if s.name == name]
            if not sessions:
                self.status("Среда не запущена")
                return

            def done(idx):
                if idx != 1:
                    return
                for s in sessions:
                    try:
                        stop_session(s)
                    except ProcessLookupError:
                        pass
                    except OSError as e:
                        alert(self, "Не удалось остановить", str(e))
                GLib.timeout_add(700, self.refresh_sessions_once)
                self.status(f"Среда «{name}» остановлена")

            choose(self, f"Остановить среду «{name}»?",
                   "Все процессы внутри среды будут завершены.", ["Отмена", "Остановить"], done)


    # ---- gui/pages/links.py: Ссылки: очередь запросов, выбор браузера, привязка схем.

    class LinksMixin:
        """Ссылки: очередь запросов, выбор браузера, привязка схем."""

        # ------------------------------------- ссылки из приложений среды -> изолированный браузер

        def pick_link_browser(self, p):
            """Браузер для ссылок среды: выбранный ранее или единственный; иначе None (спросим)."""
            names = browser_profiles_names()
            if p is not None and p.link_browser in names:
                return p.link_browser
            return names[0] if len(names) == 1 else None

        def poll_links(self):
            try:
                for name in list_profiles():
                    if not link_spool_pending(name):
                        continue
                    try:
                        q = load_profile(name)
                    except (OSError, ValueError):
                        continue
                    reqs = read_link_spool(name)   # читает и очищает канал в любом случае
                    if q.is_browser:
                        continue
                    for url, err in reqs:
                        if err:
                            self.status(f"Среда «{name}» просила открыть ссылку, но она отклонена: {err}")
                        else:
                            self.link_queue.append((name, url))
                self.process_link_queue()
            except Exception:  # noqa: BLE001
                pass
            return True

        def process_link_queue(self):
            """Автоматические ссылки открываются сразу; вопросы показываются по одному, остальные ждут своей очереди."""
            waiting = []
            for name, url in self.link_queue:
                try:
                    q = load_profile(name)
                except (OSError, ValueError):
                    continue
                browser = self.pick_link_browser(q)
                if q.link_out_auto and browser:
                    self.open_url_in_browser(browser, url)
                    self.status(f"Среда «{name}» открыла ссылку в браузере «{browser}»")
                    continue
                waiting.append((name, url, q))
            self.link_queue = [(n, u) for n, u, _q in waiting]
            if waiting and not self.link_dialog_open:
                name, url, q = waiting[0]
                self.link_queue = self.link_queue[1:]
                self.show_link_request(name, url, q)

        def remember_link_choice(self, name, browser, auto):
            """Запомнить браузер (и «не спрашивать») для среды; для выбранной среды — через её профиль в окне."""
            if self.current is not None and self.current.name == name:
                self.current.link_browser = browser or self.current.link_browser
                if auto:
                    self.cb_link_auto.set_active(True)
                self.save_current(quiet=True)
                return
            try:
                q = load_profile(name)
                q.link_browser = browser or q.link_browser
                q.link_out_auto = q.link_out_auto or auto
                save_profile(q)
            except (OSError, ValueError):
                pass

        def show_link_request(self, name, url, q):
            self.link_dialog_open = True
            browsers = browser_profiles_names()
            host = urllib.parse.urlsplit(url).hostname or "?"
            win = Gtk.Window(title=f"Среда «{name}» просит открыть ссылку", transient_for=self, modal=True)
            win.set_default_size(640, -1)
            box = margins(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10), 16)
            title = Gtk.Label(label=f"Сайт: {host}", xalign=0)
            title.add_css_class("eb-h2")
            box.append(title)
            full = Gtk.Label(label=url, xalign=0, wrap=True, selectable=True)
            full.set_wrap_mode(Pango.WrapMode.CHAR)
            full.set_max_width_chars(80)
            full.add_css_class("monospace")
            box.append(full)
            box.append(hint("Ссылка придёт из программы внутри песочницы. Прочитайте адрес: подставные сайты "
                            "выглядят правдоподобно. Откроется в изолированном браузере, у которого своя сеть."))
            dd = None
            if browsers:
                box.append(Gtk.Label(label="В каком браузере открыть:", xalign=0))
                dd = Gtk.DropDown.new_from_strings(browsers)
                pre = q.link_browser if q.link_browser in browsers else browsers[0]
                dd.set_selected(browsers.index(pre))
                box.append(dd)
            else:
                box.append(hint("Нет среды-браузера: создайте её («Новая среда» → «Браузер») или скопируйте ссылку."))
            auto_cb = Gtk.CheckButton(label="Всегда открывать ссылки из этой среды без вопроса")
            if browsers:
                box.append(auto_cb)
            buttons = Gtk.Box(spacing=8, halign=Gtk.Align.END)
            reject = Gtk.Button(label="Отклонить")
            copy_btn = Gtk.Button(label="Копировать")
            open_btn = Gtk.Button(label="Открыть в браузере")
            open_btn.add_css_class("suggested-action")
            open_btn.set_sensitive(bool(browsers))
            buttons.append(reject)
            buttons.append(copy_btn)
            buttons.append(open_btn)
            box.append(buttons)
            state = {"done": False}

            def finish():
                if state["done"]:
                    return
                state["done"] = True
                self.link_dialog_open = False
                GLib.idle_add(self.process_link_queue)

            def do_open(*_):
                browser = browsers[dd.get_selected()] if dd is not None and browsers else None
                if not browser:
                    return
                self.remember_link_choice(name, browser, auto_cb.get_active())
                win.destroy()
                self.open_url_in_browser(browser, url)
                self.status(f"Ссылка из среды «{name}» открыта в браузере «{browser}»")
                finish()

            def do_copy(*_):
                self.set_clipboard(url)
                self.status("Ссылка скопирована")
                win.destroy()
                finish()

            def do_reject(*_):
                self.status(f"Ссылка из среды «{name}» отклонена")
                win.destroy()
                finish()

            open_btn.connect("clicked", do_open)
            copy_btn.connect("clicked", do_copy)
            reject.connect("clicked", do_reject)
            win.connect("close-request", lambda *_a: (finish(), False)[1])
            win.set_child(box)
            win.present()

        def open_url_in_browser(self, browser, url):
            """Открыть ссылку новой вкладкой в браузере-среде; запустить его, если не запущен; показать его окно."""
            try:
                url = parse_link(url)
            except ValueError as e:
                alert(self, "Ссылку нельзя открыть", str(e))
                return
            self.browser_show(browser)
            if cdp_listening(browser):
                self.finish_open_url(browser, url)
                return
            try:
                bp = load_profile(browser)
            except (OSError, ValueError) as e:
                alert(self, "Не удалось прочитать среду-браузер", str(e))
                return
            errs = bp.validate()
            if errs:
                alert(self, f"Браузер «{browser}» не готов к запуску", "\n".join(errs))
                return
            if browser not in self.running:
                self.launch_browser(bp)
            tries = {"n": 0}

            def wait_ready():
                tries["n"] += 1
                if cdp_listening(browser):
                    self.finish_open_url(browser, url)
                    return False
                if tries["n"] > 60:
                    alert(self, "Браузер не запустился", f"«{browser}» не отозвался за 30 секунд. Смотрите launch.log среды.")
                    return False
                return True

            GLib.timeout_add(500, wait_ready)

        def finish_open_url(self, browser, url):
            v = self.viewer
            if v is not None and self.viewer_env == browser:
                self.bg(lambda: v.new_tab(url))
            else:
                self.b_want_url = url            # откроется сразу после подключения окна к браузеру
                self.browser_connect(browser)
                if self.b_connecting is False and self.viewer is None:
                    self.bg(lambda: cdp_open_url(browser, url))   # окно не подключилось: хотя бы открыть вкладку
                    self.b_want_url = ""

        def browser_show(self, name):
            """Сделать браузер видимым: во вкладке, если она открыта, иначе в отдельном окне."""
            if self.b_detached is not None:
                if self.b_detached_env != name:
                    self.browser_detach(name)
                else:
                    self.b_detached.present()
                return
            cur = self.current
            if cur is not None and cur.is_browser and cur.name == name:
                try:
                    self.nb.set_current_page(self.nb.page_num(self.page_browser))
                except Exception:  # noqa: BLE001
                    pass
                return
            self.browser_detach(name)   # другая среда выбрана: не трогаем её, открываем браузер отдельным окном

        def open_term_link(self, term, text):
            """Ctrl+клик по ссылке в терминале: открыть в браузере (явное действие, без вопроса)."""
            try:
                url = parse_link(text)
            except ValueError as e:
                self.status(f"Ссылка не открыта: {e}")
                return
            env = self.term_entries.get(term, {}).get("env")
            try:
                q = load_profile(env) if env else None
            except (OSError, ValueError):
                q = None
            browser = self.pick_link_browser(q)
            if browser:
                self.open_url_in_browser(browser, url)
                self.status(f"Ссылка открыта в браузере «{browser}»")
            else:
                self.show_link_request(env or "терминал", url, q or Profile(name="x"))

        # ---------------------------------------------- ссылки в приложение внутри среды

        def link_envs(self):
            """Среды, принимающие ссылки (не браузеры)."""
            out = []
            for n in list_profiles():
                try:
                    q = load_profile(n)
                except (OSError, ValueError):
                    continue
                if not q.is_browser and (q.link_handler or q.link_callback):
                    out.append(n)
            return out

        def on_open_link(self, *_):
            if self.current and not self.current.is_browser:
                self.save_current(quiet=True)
            envs = self.link_envs()
            if not envs:
                alert(self, "Нет среды, принимающей ссылки",
                      "Откройте «Настройки» среды-приложения и задайте «Команду открытия ссылок» "
                      "(для Claude Desktop она уже задана в шаблоне). Для входа в Claude CLI включите «Принимать вход "
                      "по ссылке localhost».")
                return
            win = Gtk.Window(title="Ссылка", transient_for=self, modal=True)
            win.set_default_size(660, -1)
            box = margins(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10), 16)
            box.append(hint("Вход в Claude Desktop по ссылке из письма (https://claude.ai/magic-link…): нажмите «В браузере "
                            "envbox». Страница предложит открыть приложение, envbox спросит и передаст ссылку Claude Desktop "
                            "внутри песочницы. Ссылки claude://… и http://localhost:…/ передавайте кнопкой «Передать "
                            "приложению»: обычную https-ссылку приложение само не понимает."))
            entry = Gtk.Entry(hexpand=True, placeholder_text="https://claude.ai/magic-link…   claude://…   http://localhost:…")
            box.append(entry)
            box.append(Gtk.Label(label="Среда с приложением:", xalign=0))
            labels = ["Подобрать по ссылке"] + envs
            dd = Gtk.DropDown.new_from_strings(labels)
            if self.current and self.current.name in envs:
                dd.set_selected(1 + envs.index(self.current.name))
            box.append(dd)
            note = hint("")
            box.append(note)
            buttons = Gtk.Box(spacing=8, halign=Gtk.Align.END)
            cancel = Gtk.Button(label="Отмена")
            send_btn = Gtk.Button(label="Передать приложению в среде")
            web_btn = Gtk.Button(label="В браузере компьютера")
            eb_browsers = browser_profiles_names()
            eb_btn = Gtk.Button(label="В браузере envbox")
            buttons.append(cancel)
            buttons.append(send_btn)
            buttons.append(web_btn)
            if eb_browsers:
                buttons.append(eb_btn)
            box.append(buttons)

            def selected_env():
                idx = dd.get_selected()
                return None if idx <= 0 else envs[idx - 1]

            def classify(text):
                t = text.strip()
                if not re.match(r"^https?://", t, re.I):
                    return "app"
                host = (urllib.parse.urlsplit(t).hostname or "").lower() if len(t) < 2100 else ""
                return "app" if host in ("localhost", "127.0.0.1", "::1") else "web"

            def refresh(*_):
                kind = classify(entry.get_text())
                web_btn.set_visible(True)
                for btn, primary in ((eb_btn, kind == "web" and bool(eb_browsers)),
                                     (web_btn, kind == "web" and not eb_browsers), (send_btn, kind != "web")):
                    if primary:
                        btn.add_css_class("suggested-action")
                    else:
                        btn.remove_css_class("suggested-action")
                if kind == "web":
                    note.set_text("Обычная веб-ссылка: откройте её в браузере. После входа он предложит открыть приложение "
                                  "(claude://…), и envbox передаст это в песочницу. Если среда не запущена, она запустится сама. "
                                  + ("Надёжнее всего — «В браузере envbox»: ссылку перехватывает сам envbox."
                                     if eb_browsers else "Среды-браузера нет: создайте её («Новая среда» → «Браузер»)."))
                else:
                    note.set_text("Ссылка будет передана приложению внутри песочницы. Если среда не запущена, запустится "
                                  "её приложение с этой ссылкой.")

            def prefill(clip, res):
                try:
                    text = (clip.read_text_finish(res) or "").strip()
                except Exception:  # noqa: BLE001
                    return
                if not entry.get_text() and 0 < len(text) <= 2048 and re.match(r"^[a-z][a-z0-9+.-]*://\S+$", text, re.I):
                    entry.set_text(text)

            try:
                self.get_clipboard().read_text_async(None, prefill)
            except Exception:  # noqa: BLE001
                pass

            def to_env(*_):
                url = entry.get_text().strip()
                env = selected_env()
                win.destroy()
                self.send_link_to_env(url, env)

            def to_browser(*_):
                url = entry.get_text().strip()
                env = selected_env()
                win.destroy()
                self.open_link_in_browser(url, env)

            def to_envbox_browser(*_):
                raw = entry.get_text().strip()
                env = selected_env()
                try:
                    url = parse_link(raw)
                except ValueError as e:
                    alert(self, "Ссылку нельзя открыть", str(e))
                    return
                try:
                    q = load_profile(env) if env else None
                except (OSError, ValueError):
                    q = None
                browser = self.pick_link_browser(q) or eb_browsers[0]
                win.destroy()
                self.open_url_in_browser(browser, url)
                log_link_event(safe_link_label(url), f"открыта в браузере envbox «{browser}»")
                self.status(f"Ссылка открыта в браузере envbox «{browser}»: страница предложит открыть приложение")

            entry.connect("changed", refresh)
            send_btn.connect("clicked", to_env)
            web_btn.connect("clicked", to_browser)
            eb_btn.connect("clicked", to_envbox_browser)
            entry.connect("activate", lambda *_a: ((to_envbox_browser() if eb_browsers else to_browser())
                                                   if classify(entry.get_text()) == "web" else to_env()))
            cancel.connect("clicked", lambda *_a: win.destroy())
            refresh()
            win.set_child(box)
            win.present()
            entry.grab_focus()

        def send_link_to_env(self, url, env):
            """Передать ссылку приложению внутри среды (в потоке: ждёт ответа до 8 секунд)."""
            self.status("Передаю ссылку в среду…")

            def work():
                try:
                    name, msg = open_link_in_env(url, env, True)
                except (ValueError, OSError, subprocess.SubprocessError) as e:
                    GLib.idle_add(self.link_done, None, str(e))
                else:
                    GLib.idle_add(self.link_done, name, msg)

            threading.Thread(target=work, daemon=True).start()

        def open_link_in_browser(self, url, env):
            """Открыть веб-ссылку в обычном браузере; перед этим убедиться, что ссылки claude:// из браузера дойдут до среды."""
            try:
                url = parse_link(url)
            except ValueError as e:
                alert(self, "Ссылку нельзя открыть", str(e))
                return
            unbound = []
            for n in ([env] if env else self.link_envs()):
                try:
                    q = load_profile(n)
                except (OSError, ValueError):
                    continue
                for sc in q.link_schemes:
                    if sc not in unbound and not link_handler_installed(sc):
                        unbound.append(sc)

            def do_open(bind):
                if bind:
                    try:
                        for sc in unbound:
                            install_link_handler(sc)
                    except (ValueError, OSError, subprocess.SubprocessError) as e:
                        alert(self, "Не удалось связать ссылки со средой", str(e))
                        return
                try:
                    tool = open_in_host_browser(url)
                except OSError as e:
                    alert(self, "Не удалось открыть браузер", str(e))
                    return
                log_link_event(safe_link_label(url), f"открыта в браузере ({tool})")
                self.status("Ссылка открыта в браузере. Подтвердите там открытие приложения: вход завершится в песочнице")
                try:
                    self.update_bind_status()
                except Exception:  # noqa: BLE001
                    pass

            if unbound:
                choose(self, "Ссылки claude:// пока не идут в песочницу",
                       "После входа браузер попробует открыть приложение по ссылке " +
                       ", ".join(f"{x}://" for x in unbound) +
                       ", но сейчас она не связана с envbox, и вход не завершится (одноразовый код пропадёт).\n\n"
                       "«Связать и открыть» меняет ассоциации вашего рабочего стола для этой схемы (отключается в «Настройках»).",
                       ["Отмена", "Открыть без привязки", "Связать и открыть"],
                       lambda idx: do_open(idx == 2) if idx in (1, 2) else None)
            else:
                do_open(False)

        def link_done(self, name, msg):
            if name is None:
                alert(self, "Не удалось передать ссылку", msg)
                self.status("Ссылка не передана")
            else:
                self.status(f"Среда «{name}»: {msg}")
                GLib.timeout_add(1500, self.refresh_sessions_once)
            return False

        def update_bind_status(self):
            schemes = self.e_link_schemes.get_text().replace(",", " ").split()
            self.btn_bind.set_visible(bool(schemes))
            if not schemes:
                self.lbl_bind.set_text("")
                return
            installed = [x for x in schemes if link_handler_installed(x)]
            if installed:
                self.btn_bind.set_label("Больше не открывать эти ссылки из браузера через envbox")
                self.lbl_bind.set_text("Сейчас ссылки " + ", ".join(f"{x}://" for x in installed) +
                                       " из браузера передаются envbox, а он отдаёт их среде с такой схемой "
                                       "(запущенной в первую очередь).")
            else:
                self.btn_bind.set_label("Открывать ссылки из браузера в этой среде")
                self.lbl_bind.set_text("Меняет ассоциации вашего рабочего стола: ссылки " +
                                       ", ".join(f"{x}://" for x in schemes) + " из браузера будут идти в envbox "
                                       "и дальше в приложение внутри среды. Можно отключить здесь же.")

        def on_bind_scheme(self, *_):
            schemes = self.e_link_schemes.get_text().replace(",", " ").split()
            if not schemes:
                return
            self.save_current(quiet=True)
            try:
                if all(link_handler_installed(x) for x in schemes):
                    for x in schemes:
                        remove_link_handler(x)
                    self.status("Обработчик ссылок отключён")
                else:
                    notes = []
                    for x in schemes:
                        _path, note = install_link_handler(x)
                        if note:
                            notes.append(note)
                    self.status("Обработчик ссылок включён" + ((": " + " ".join(notes)) if notes else ""))
            except (ValueError, OSError, subprocess.SubprocessError) as e:
                alert(self, "Не удалось изменить обработчик ссылок", str(e))
            self.update_bind_status()


    # ---- gui/tables.py: Таблицы и строки списков GUI.

    class Row(GObject.Object):
        def __init__(self, cells, key=None, data=None):
            super().__init__()
            self.cells = cells
            self.key = key
            self.data = data


    class Table:
        """ColumnView из строковых ячеек; при обновлении сохраняет выбор по ключу."""

        def __init__(self, titles, expand_col=0, empty_text="Пока пусто"):
            self.store = Gio.ListStore(item_type=Row)
            self.sel = Gtk.SingleSelection(model=self.store, autoselect=False, can_unselect=True)
            self.view = Gtk.ColumnView(model=self.sel, show_row_separators=True)
            for i, title in enumerate(titles):
                factory = Gtk.SignalListItemFactory()
                factory.connect("setup", self._setup)
                factory.connect("bind", self._bind, i)
                col = Gtk.ColumnViewColumn(title=title, factory=factory)
                col.set_expand(i == expand_col)
                col.set_resizable(True)
                self.view.append_column(col)
            scroll = Gtk.ScrolledWindow(vexpand=True, hexpand=True)
            scroll.set_child(self.view)
            scroll.add_css_class("frame")
            empty = Gtk.Label(label=empty_text, wrap=True, justify=Gtk.Justification.CENTER)
            empty.add_css_class("dim-label")
            self.stack = Gtk.Stack(vexpand=True, hexpand=True)
            self.stack.add_named(scroll, "table")
            self.stack.add_named(empty, "empty")
            self.widget = self.stack

        @staticmethod
        def _setup(_factory, item):
            lbl = Gtk.Label(xalign=0)
            lbl.set_ellipsize(Pango.EllipsizeMode.END)
            item.set_child(lbl)

        @staticmethod
        def _bind(_factory, item, i):
            item.get_child().set_text(item.get_item().cells[i])

        def selected(self):
            return self.sel.get_selected_item()

        def set_rows(self, rows):
            cur = self.selected()
            key = cur.key if cur is not None else None
            self.store.splice(0, self.store.get_n_items(), rows)
            self.stack.set_visible_child_name("table" if rows else "empty")
            pos = Gtk.INVALID_LIST_POSITION
            for n, r in enumerate(rows):
                if key is not None and r.key == key:
                    pos = n
                    break
            self.sel.set_selected(pos)


    # ---- gui/pages/net_page.py: Вкладка «Сеть»: журнал, фильтр, разрешение доменов, сеансы.

    class NetPageMixin:
        """Вкладка «Сеть»: журнал, фильтр, разрешение доменов, сеансы."""

        def build_net_page(self):
            box = margins(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8))
            self.lbl_net = Gtk.Label(xalign=0, wrap=True)
            box.append(self.lbl_net)
            self.net_search = Gtk.SearchEntry(placeholder_text="Фильтр по хосту")
            self.net_search.connect("search-changed", self.on_net_filter)
            box.append(self.net_search)
            self.net_table = Table(["Куда (хост:порт)", "Соединений", "Запрещено", "Ошибок", "Отправлено",
                                    "Получено", "Последнее", "Через / IP"],
                                   empty_text="Пока ни одного обращения.\nЗапустите среду в режиме "
                                              "«через прокси с журналом» — здесь появится, куда она ходит.")
            buttons = Gtk.Box(spacing=8)
            b_allow = Gtk.Button(label="Разрешить выбранный домен")
            b_allow.connect("clicked", self.on_allow_domain)
            b_clear = Gtk.Button(label="Очистить журнал")
            b_clear.connect("clicked", self.on_clear_log)
            buttons.append(b_allow)
            buttons.append(b_clear)
            self.tv_events, sw = text_area(editable=False, height=120)
            buf = self.tv_events.get_buffer()
            self.events_end = buf.create_mark("end", buf.get_end_iter(), False)
            upper = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
            upper.append(self.net_table.widget)
            upper.append(buttons)
            lower = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
            lower.append(hint("События в реальном времени:"))
            lower.append(sw)
            upper.set_vexpand(True)
            sw.set_vexpand(False)
            box.append(upper)
            box.append(lower)
            box.append(hint("Журнал пишет прокси на хосте, среда его не видит. Для HTTPS видны только "
                            "хост, порт, IP, объём и время; содержимое и пути не расшифровываются."))
            return box

        def on_net_filter(self, entry):
            self.net_filter = entry.get_text().strip().lower()
            self.render_summary()

        def reset_net_view(self):
            set_text(self.tv_events, "")
            self.net_summary = NetSummary()
            self.net_table.set_rows([])
            if not self.current:
                self.tail = None
                self.lbl_net.set_text("")
                return
            p = self.current
            self.tail = LogTail(net_log_path(p.name))
            mode = NET_LABELS[p.net]
            via = f", через {p.upstream}" if p.upstream and p.net in ("log", "allowlist") else ""
            if p.net in ("log", "allowlist"):
                self.lbl_net.set_text(f"Режим сети: {mode}{via}. Журнал: {to_home(net_log_path(p.name))}")
            else:
                self.lbl_net.set_text(f"Режим сети: {mode}. Журнал ведётся только в режимах «Через журнал» "
                                      "— ниже показаны записи прошлых запусков, если они есть.")
            self.poll_net()

        def render_summary(self):
            rows = []
            for s in self.net_summary.rows():
                label = f"{s['host']}:{s['port']}"
                if self.net_filter and self.net_filter not in label.lower():
                    continue
                rows.append(Row([label, str(s["open"]), str(s["deny"]), str(s["error"]),
                                 human_size(s["up"]), human_size(s["down"]),
                                 s["last"].replace("T", " ")[:19],
                                 s["via"] or ", ".join(sorted(s["ips"]))],
                                key=(s["host"], s["port"]), data=s["host"]))
            self.net_table.set_rows(rows)

        def poll_net(self):
            if self.tail is None:
                return
            new = self.tail.read_new()
            if not new:
                return
            self.net_summary.add(new)
            buf = self.tv_events.get_buffer()
            buf.insert(buf.get_end_iter(), "\n".join(format_event(e) for e in new) + "\n")
            lines = buf.get_line_count()
            if lines > 3000:
                res = buf.get_iter_at_line(lines - 2000)
                it = res[1] if isinstance(res, tuple) else res
                buf.delete(buf.get_start_iter(), it)
            self.tv_events.scroll_mark_onscreen(self.events_end)
            self.render_summary()

        def on_allow_domain(self, *_):
            row = self.net_table.selected()
            if row is None or not self.current:
                alert(self, "Выберите строку в таблице")
                return
            host = row.data
            if not DOMAIN_RE.match(host):
                alert(self, f"«{host}» нельзя добавить как домен", "Поддерживаются имена и IPv4-адреса.")
                return
            lines = get_lines(self.tv_domains)
            if host not in lines:
                lines.append(host)
            set_text(self.tv_domains, "\n".join(lines))
            self.dd_net.set_selected(NET_MODES.index("allowlist"))
            if self.save_current(quiet=True):
                alert(self, f"Домен {host} разрешён",
                      "Режим сети переключён на «только разрешённые домены». "
                      "Изменение вступит в силу при следующем запуске среды.")

        def on_clear_log(self, *_):
            if not self.current:
                return
            name = self.current.name

            def done(idx):
                if idx == 1:
                    try:
                        clear_net_log(name)
                    except OSError as e:
                        alert(self, "Не удалось очистить журнал", str(e))
                    self.reset_net_view()

            choose(self, "Очистить сетевой журнал?", to_home(net_log_path(name)),
                   ["Отмена", "Очистить"], done)

        def refresh_sessions_async(self):
            """Просмотр /proc не в потоке окна: на компьютере с тысячами процессов он занимает заметное время."""
            if getattr(self, "scanning", False):
                return
            self.scanning = True

            def done(res):
                self.scanning = False
                if not isinstance(res, Exception):
                    self.apply_sessions(res)

            self.run_async(lambda: {s.name for s in list_sessions()}, done)

        def refresh_sessions(self):
            self.apply_sessions({s.name for s in list_sessions()})

        def apply_sessions(self, names):
            if names != self.running:
                self.running = names
                for name, dot in self.row_dots.items():
                    dot.set_text("●" if name in names else "")
                self.update_buttons()
                if self.current:
                    self.update_overview()

        def refresh_sessions_once(self):
            self.refresh_sessions()
            return False


    # ---- gui/pages/overview.py: Страницы «Добро пожаловать» и «Обзор».

    class OverviewMixin:
        """Страницы «Добро пожаловать» и «Обзор»."""

        # ------------------------------------------------------- приветствие и обзор

        def build_welcome_page(self):
            outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, valign=Gtk.Align.CENTER,
                            halign=Gtk.Align.CENTER, spacing=16)
            outer.set_margin_start(40)
            outer.set_margin_end(40)
            title = Gtk.Label(label="Изолированные среды для программ и ИИ")
            title.add_css_class("eb-welcome-title")
            title.set_wrap(True)
            outer.append(title)
            intro = Gtk.Label(wrap=True, justify=Gtk.Justification.CENTER, max_width_chars=64,
                              label="Программа запускается в «песочнице»: она не видит ваши личные файлы, "
                                    "записывает только в выбранный проект, а выход в сеть можно выключить "
                                    "или записывать в журнал.")
            intro.add_css_class("dim-label")
            outer.append(intro)
            steps = card()
            for text in ("1.  Создайте среду — для программы (например claude) или для браузера.",
                         "2.  Выберите рабочий каталог и режим сети.",
                         "3.  Нажмите «Терминал» — всё внутри будет изолировано."):
                steps.append(Gtk.Label(label=text, xalign=0))
            outer.append(steps)
            buttons = Gtk.Box(spacing=10, halign=Gtk.Align.CENTER)
            b_claude = icon_button("utilities-terminal-symbolic", "Claude CLI (жёсткая изоляция)",
                                   "suggested-action")
            b_claude.connect("clicked", lambda *_: self.on_new(kind="claude"))
            b_app = icon_button("utilities-terminal-symbolic", "Среда для другой программы")
            b_app.connect("clicked", lambda *_: self.on_new(kind="app"))
            b_browser = icon_button("web-browser-symbolic", "Среда-браузер")
            b_browser.connect("clicked", lambda *_: self.on_new(kind="browser"))
            buttons.append(b_claude)
            buttons.append(b_app)
            buttons.append(b_browser)
            outer.append(buttons)
            return outer

        def build_overview_page(self):
            page = margins(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16), 16)

            banner = card()
            top = Gtk.Box(spacing=16)
            self.img_kind = Gtk.Image.new_from_icon_name(KIND_ICONS["app"])
            self.img_kind.set_pixel_size(40)
            top.append(self.img_kind)
            info = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6, hexpand=True)
            self.lbl_title = Gtk.Label(xalign=0)
            self.lbl_title.add_css_class("eb-title")
            info.append(self.lbl_title)
            self.lbl_where = hint("")
            info.append(self.lbl_where)
            row = Gtk.Box(spacing=8)
            self.badge_kind = badge()
            self.badge_state = badge()
            self.badge_net = badge()
            self.badge_strict = badge()
            for b in (self.badge_kind, self.badge_state, self.badge_net, self.badge_strict):
                row.append(b)
            info.append(row)
            top.append(info)
            banner.append(top)
            self.lbl_next = Gtk.Label(xalign=0, wrap=True)
            banner.append(self.lbl_next)
            page.append(banner)

            self.problems_card = card("eb-card-warn")
            title = Gtk.Label(label="Что нужно исправить, чтобы запустить", xalign=0)
            title.add_css_class("eb-h2")
            self.problems_card.append(title)
            self.problems_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
            self.problems_card.append(self.problems_box)
            page.append(self.problems_card)

            summary = card()
            title = Gtk.Label(label="Что получает эта среда", xalign=0)
            title.add_css_class("eb-h2")
            summary.append(title)
            summary.append(hint("Описание по текущим настройкам, включая ещё не сохранённые."))
            self.summary_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
            summary.append(self.summary_box)
            page.append(summary)

            exp = Gtk.Expander(label="Показать итоговую команду bwrap")
            inner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8, margin_top=8)
            b_preview = Gtk.Button(label="Собрать команду", halign=Gtk.Align.START)
            b_preview.connect("clicked", self.on_preview)
            inner.append(b_preview)
            self.tv_preview, sw = text_area(editable=False, height=150)
            inner.append(sw)
            exp.set_child(inner)
            page.append(exp)

            scroll = Gtk.ScrolledWindow(vexpand=True)
            scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)  # по ширине окна, без растягивания
            scroll.set_child(page)
            return scroll

        def update_overview(self, p=None):
            p = p or self.current
            if p is None:
                return
            self.img_kind.set_from_icon_name(KIND_ICONS.get(p.kind, KIND_ICONS["app"]))
            self.lbl_title.set_text(p.name)
            self.lbl_where.set_text(f"Данные среды: {to_home(box_dir(p.name))}")
            self.badge_kind.set_text(KIND_LABELS[p.kind])
            running = p.name in self.running
            self.badge_state.set_text("● запущена" if running else "остановлена")
            if running:
                self.badge_state.add_css_class("eb-badge-run")
            else:
                self.badge_state.remove_css_class("eb-badge-run")
            text, warn = p.isolation_summary()
            self.badge_strict.set_text(text)
            if warn:
                self.badge_strict.add_css_class("eb-badge-warn")
            else:
                self.badge_strict.remove_css_class("eb-badge-warn")
            self.badge_net.set_text("сеть: " + NET_SHORT[p.net])
            if p.net == "host":
                self.badge_net.add_css_class("eb-badge-warn")
            else:
                self.badge_net.remove_css_class("eb-badge-warn")
            if p.is_browser:
                self.lbl_next.set_text("Нажмите «Запустить браузер». Затем подключите его к ИИ-среде: в её "
                                       "настройках, раздел «Браузер для ИИ». Страница появится на вкладке «Окно браузера».")
            elif p.gui_wayland and p.command == "claude-desktop":
                self.lbl_next.set_text("Первый раз: «Установить…» → «Claude Desktop». Затем «Запустить»: окно появится на "
                                       "рабочем столе через Wayland. Вход: войдите в обычном браузере, а полученную "
                                       "ссылку claude://… вставьте через «Ссылка…» (или свяжите её с этой средой в "
                                       "«Настройках», тогда браузер сам передаст её сюда). Если что-то блокируется, "
                                       "смотрите «Журнал сети».")
            else:
                self.lbl_next.set_text("Нажмите «Терминал», чтобы получить оболочку внутри среды, или "
                                       "«Запустить», чтобы сразу выполнить: " + (p.command or "—"))
            clear_children(self.problems_box)
            errs = p.validate()
            for e in errs:
                lbl = Gtk.Label(label="✖  " + e, xalign=0, wrap=True)
                self.problems_box.append(lbl)
            self.problems_card.set_visible(bool(errs))
            clear_children(self.summary_box)
            for level, text in describe(p):
                mark, css = LEVEL_ICONS[level]
                line = Gtk.Box(spacing=10)
                m = Gtk.Label(label=mark, valign=Gtk.Align.START)
                m.add_css_class(css)
                line.append(m)
                line.append(Gtk.Label(label=text, xalign=0, wrap=True, hexpand=True))
                self.summary_box.append(line)


    # ---- gui/pages/profile_net.py: Настройки сети среды: секрет, прокси, подключение приложений, CDP.

    class ProfileNetMixin:
        """Настройки сети среды: секрет, прокси, подключение приложений, CDP."""

        # ---- секреты

        def update_secret_status(self):
            if not self.current or not self.current.secrets:
                self.lbl_secrets.set_text("Имена переменных, значения которых хранятся в системном keyring "
                                          "и передаются в среду при запуске.")
                return
            if not secret_tool_available():
                self.lbl_secrets.set_text("secret-tool не найден: " + pkg_hint("secret-tool"))
                return
            parts = []
            for s in self.current.secrets:
                try:
                    ok = secret_exists(self.current.name, s)
                except (OSError, subprocess.SubprocessError):
                    ok = False
                parts.append(f"{s}: {'в keyring ✔' if ok else 'не задан ✖'}")
            self.lbl_secrets.set_text("   ".join(parts))

        def on_set_secret(self, *_):
            if not self.current:
                return
            if not secret_tool_available():
                alert(self, "Нужен secret-tool", pkg_hint("secret-tool"))
                return
            names = get_lines(self.tv_secrets)
            name = self.current.name

            def got_var(var):
                var = var.strip()
                if (not VAR_RE.match(var) or var in RESERVED_VARS
                        or var.startswith("ENVBOX_")):
                    alert(self, f"Недопустимое имя переменной: {var}")
                    return

                def got_value(value):
                    if not value:
                        return
                    try:
                        secret_store(name, var, value)
                    except (OSError, RuntimeError, subprocess.SubprocessError) as e:
                        alert(self, "Не удалось сохранить секрет", str(e))
                        return
                    lines = get_lines(self.tv_secrets)
                    if var not in lines:
                        lines.append(var)
                        set_text(self.tv_secrets, "\n".join(lines))
                    self.save_current(quiet=True)
                    self.update_secret_status()
                    self.status(f"Секрет {var} сохранён в keyring")

                prompt(self, "Значение секрета",
                       f"Значение {var} для среды «{name}». Оно сохранится в системном keyring "
                       "и не попадёт ни в профиль, ни в командную строку.", got_value, secret=True)

            prompt(self, "Секрет", "Имя переменной окружения:", got_var,
                   initial=names[0] if names else "ANTHROPIC_API_KEY")

        # ---- прокси

        def update_upstream_status(self):
            if not self.current:
                return
            if not self.current.upstream:
                self.lbl_up.set_text("Весь трафик идёт напрямую с этого компьютера. Один прокси на среду; "
                                     "списки и ротация не поддерживаются.")
            elif self.current.upstream_auth:
                self.lbl_up.set_text("Логин и пароль прокси хранятся в keyring. Имена сайтов разрешает сам "
                                     "прокси, а не этот компьютер.")
            else:
                self.lbl_up.set_text("Без логина. Имена сайтов разрешает сам прокси, а не этот компьютер.")

        def on_proxy_file(self, *_):
            dlg = Gtk.FileDialog(title="Файл с адресом прокси")

            def done(d, res):
                try:
                    f = d.open_finish(res)
                except GLib.Error:
                    return
                try:
                    text = read_proxy_file(f.get_path())
                    split_proxy_url(text)  # проверка формата
                except (OSError, ValueError) as e:
                    alert(self, "Не удалось загрузить прокси", str(e))
                    return
                self.e_upstream.set_text(text)
                self.status("Прокси загружен из файла; нажмите «Сохранить»")

            dlg.open(self, None, done)

        def on_proxy_test(self, *_):
            if not self.current:
                return
            try:
                url, auth = split_proxy_url(self.e_upstream.get_text())
            except ValueError as e:
                alert(self, "Адрес прокси неверен", str(e))
                return
            name = self.current.name
            if not auth and self.current.upstream_auth and secret_tool_available():
                try:
                    auth = secret_lookup(name, UPSTREAM_AUTH_VAR)
                except (OSError, subprocess.SubprocessError):
                    auth = ""
            self.status("Проверяю прокси…")

            def done(res):
                if isinstance(res, Exception):
                    alert(self, "Проверка не удалась", str(res))
                    return
                ok, msg = res
                self.status(msg if ok else "Прокси не работает")
                alert(self, "Прокси работает" if ok else "Прокси не работает", msg)

            self.run_async(lambda: probe_upstream(url, auth), done)

        def on_proxy_auth(self, *_):
            if not self.current:
                return
            if not secret_tool_available():
                alert(self, "Нужен secret-tool", pkg_hint("secret-tool"))
                return
            name = self.current.name

            def got(value):
                value = value.strip()
                try:
                    if value:
                        if ":" not in value:
                            alert(self, "Нужен формат логин:пароль")
                            return
                        secret_store(name, UPSTREAM_AUTH_VAR, value)
                        self.current.upstream_auth = True
                    else:
                        secret_clear(name, UPSTREAM_AUTH_VAR)
                        self.current.upstream_auth = False
                except (OSError, RuntimeError, subprocess.SubprocessError) as e:
                    alert(self, "Не удалось обновить keyring", str(e))
                    return
                self.save_current(quiet=True)
                self.update_upstream_status()
                self.status("Логин и пароль прокси сохранены в keyring" if value else "Логин и пароль прокси удалены")

            prompt(self, "Логин и пароль прокси",
                   "В формате логин:пароль. Они хранятся в системном keyring, не в профиле и не в командной "
                   "строке. Пустое значение удаляет сохранённые данные.", got, secret=True)

        # ---- браузер для ИИ

        def on_attach_add(self, *_):
            item = self.dd_browsers.get_selected_item()
            name = item.get_string() if item is not None else "—"
            if name == "—":
                alert(self, "Нет сред-браузеров",
                      "Создайте среду типа «Браузер» кнопкой «Новая», затем вернитесь сюда.")
                return
            lines = get_lines(self.tv_attach)
            if not any(l.split(":")[0] == name for l in lines):
                lines.append(name)
            set_text(self.tv_attach, "\n".join(lines))

        def show_snippets(self, spec, title):
            win = Gtk.Window(title=title, transient_for=self, modal=False)
            win.set_default_size(820, 420)
            box = margins(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10))
            box.append(hint("Команды выполняются внутри ИИ-среды (Claude Code хранит настройки MCP в её "
                            "домашнем каталоге). Для npx нужен доступ к registry.npmjs.org в списке сети. "
                            "Параметры MCP-серверов проверьте по их документации."))
            for label, text in attach_snippets(spec):
                box.append(Gtk.Label(label=label, xalign=0))
                line = Gtk.Box(spacing=6)
                entry = Gtk.Entry(text=text, editable=False, hexpand=True)
                copy = Gtk.Button(label="Копировать")

                def do_copy(_b, t=text):
                    try:
                        self.get_clipboard().set_text(t)
                        self.status("Скопировано")
                    except Exception as e:  # noqa: BLE001
                        alert(self, "Не удалось скопировать", str(e))

                copy.connect("clicked", do_copy)
                line.append(entry)
                line.append(copy)
                box.append(line)
            win.set_child(box)
            win.present()

        def on_attach_help(self, *_):
            lines = get_lines(self.tv_attach)
            if not lines:
                alert(self, "Сначала добавьте среду-браузер")
                return
            self.show_snippets(lines[0], f"Подключение ИИ к {lines[0].split(':')[0]}")

        def on_browser_help(self, *_):
            if self.current:
                self.show_snippets(self.current.name, f"Подключение ИИ к {self.current.name}")

        def update_cdp_label(self):
            if not self.current or not self.current.is_browser:
                return
            state = "слушает" if cdp_listening(self.current.name) else "браузер не запущен"
            self.lbl_cdp.set_text(f"{to_home(cdp_socket_path(self.current.name))}  —  {state}")

        def on_preview(self, *_):
            p = self.save_current(quiet=True)
            if p is None:
                return
            errs = p.validate()
            if errs:
                set_text(self.tv_preview, "Профиль не готов:\n" + "\n".join(errs))
                return
            try:
                rc, out = dry_run(p)
            except (OSError, subprocess.SubprocessError) as e:
                rc, out = 1, str(e)
            set_text(self.tv_preview, out if rc == 0 else f"[код {rc}]\n{out}")


    # ---- gui/pages/profile_page.py: Страница настроек среды: сбор формы, сохранение.

    class ProfilePageMixin:
        """Страница настроек среды: сбор формы, сохранение."""

        def build_profile_page(self):
            page = margins(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16), 16)
            self.app_only = []       # виджеты, видимые только у сред-приложений
            self.browser_only = []   # виджеты, видимые только у сред-браузеров
            adv = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16, margin_top=12)
            adv_exp = Gtk.Expander()
            adv_exp.set_label_widget(Gtk.Label(label="Дополнительные настройки: прокси, язык и DNS, браузер для ИИ, "
                                                     "переменные", wrap=True, xalign=0))
            adv_exp.set_child(adv)

            # --- Что запускать
            box, grid = section("Что запускать")
            rows = Rows(grid)
            self.e_workdir = Gtk.Entry(hexpand=True, placeholder_text="~/projects/app")
            b = Gtk.Button(label="Выбрать…")
            b.connect("clicked", lambda *_: self.choose_folder(
                lambda p: self.e_workdir.set_text(to_home(p))))
            wbox = Gtk.Box(spacing=6)
            wbox.append(self.e_workdir)
            wbox.append(b)
            self.app_only += rows.add("Каталог проекта", wbox,
                                      "Единственное место на компьютере, куда программа сможет записывать.")
            self.e_command = Gtk.Entry(hexpand=True, placeholder_text="claude")
            self.app_only += rows.add("Команда", self.e_command,
                                      "Запускается кнопкой «Запустить». «Терминал» открывает оболочку (её можно выбрать ниже).")

            self.shell_choices = ["bash"]
            self.dd_shell = Gtk.DropDown.new_from_strings(["bash"])
            others = [x for x in SHELLS if x != "bash" and not shutil.which(x)]
            self.app_only += rows.add(
                "Оболочка", self.dd_shell,
                "Что открывает кнопка «Терминал». bash есть всегда. fish удобнее: подсказки из истории и "
                "подсветка работают сразу; zsh — привычный. Оболочка берётся с компьютера"
                + (": не найдены — " + ", ".join(f"{x} ({pkg_hint(x)})" for x in others) if others else "")
                + ".")

            self.e_start_url = Gtk.Entry(hexpand=True, placeholder_text="about:blank")
            self.browser_only += rows.add("Стартовая страница", self.e_start_url)
            self.e_browser_bin = Gtk.Entry(hexpand=True, placeholder_text="найти автоматически")
            found = find_browser()
            self.browser_only += rows.add("Путь к браузеру", self.e_browser_bin,
                                          f"Найден: {found}" if found else
                                          "Chrome/Chromium не найден: sudo pacman -S chromium "
                                          "или: " + pkg_hint("chromium"))
            line, self.cb_visible = toggle(
                "Показывать окно браузера",
                "Обычно не нужно: ИИ управляет браузером без окна, а вы видите страницу на вкладке "
                "«Окно браузера» внутри приложения. Отдельное окно требует доступа к Wayland "
                "и ослабляет изоляцию.")
            self.browser_only += rows.add(None, line)
            line, self.cb_chrome_sandbox = toggle(
                "Встроенная защита Chrome (sandbox)",
                "Нужны вложенные user namespaces. Если браузер сразу закрывается — выключите "
                f"(причина будет в {to_home(envbox_root())}/<имя>/launch.log).")
            self.browser_only += rows.add(None, line)
            page.append(box)

            # --- Папки: доступ к дополнительным каталогам и глобальные папки
            self.global_rows = {}
            box, grid = section("Папки", "Что ещё среда может видеть на компьютере. Свой домашний каталог "
                                         "и проект подключены всегда.")
            rows = Rows(grid)
            self.tv_rw, sw = text_area(height=50)
            b_rw = Gtk.Button(label="Добавить…", valign=Gtk.Align.START)
            b_rw.connect("clicked", lambda *_: self.choose_folder(self.add_rw_path))
            rwbox = Gtk.Box(spacing=6)
            rwbox.append(sw)
            rwbox.append(b_rw)
            rows.add("Папки с записью", rwbox,
                     "Каталоги компьютера, куда программа сможет записывать, кроме проекта: например папка "
                     "для загрузок браузера или общий каталог с данными. По одному в строке. "
                     "Только для чтения — в «Переменные и файлы».")
            line, self.cb_global = toggle(
                "Глобальные папки",
                "Папки внутри каталога данных envbox, которые не принадлежат ни одной среде: при удалении "
                "среды они остаются на месте. Удобно хранить там код, чтобы случайно не потерять его вместе "
                "с профилем. По умолчанию выключено.")
            self.cb_global.connect("notify::active", lambda *_: self.update_global_visibility())
            rows.add(None, line)
            self.global_list = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
            gbtns = Gtk.Box(spacing=6)
            b_gnew = Gtk.Button(label="Создать папку…")
            b_gnew.connect("clicked", lambda *_: self.on_global_create())
            b_gmanage = Gtk.Button(label="Управление папками…")
            b_gmanage.connect("clicked", self.on_folders)
            gbtns.append(b_gnew)
            gbtns.append(b_gmanage)
            gcol = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
            gcol.append(self.global_list)
            gcol.append(gbtns)
            self.global_widgets = rows.add(
                "Подключить", gcol,
                "Отметьте папки и выберите режим для каждой. Папка подключается по своему настоящему пути. "
                "«Сделать проектом» ставит её каталогом проекта (работа с кодом внутри неё).")
            page.append(box)

            # --- Сеть
            box, grid = section("Сеть")
            rows = Rows(grid)
            self.dd_net = Gtk.DropDown.new_from_strings([NET_LABELS[m] for m in NET_MODES])
            self.dd_net.connect("notify::selected", lambda *_: self.update_net_sensitivity())
            rows.add("Режим", self.dd_net,
                     "Рекомендуется «через прокси с журналом»: программа не видит ваш localhost, "
                     "а все обращения записываются.")
            self.tv_domains, sw = text_area(height=56)
            self.domain_widgets = rows.add("Разрешённые сайты", sw,
                                           "По одному в строке: example.com — только он, *.example.com — "
                                           "он и все его поддомены. Удобно добавлять из «Журнала сети».")
            line, self.cb_private = toggle(
                "Пускать на частные адреса",
                "Открывает среде localhost и локальную сеть через прокси. Обычно не нужно.")
            self.private_widgets = rows.add(None, line)
            page.append(box)

            box, grid = section("Свой прокси",
                                "Необязательно: весь трафик среды пойдёт через ваш прокси (HTTP или SOCKS5).")
            rows = Rows(grid)
            self.e_upstream = Gtk.Entry(hexpand=True,
                                        placeholder_text="socks5://хост:порт или http://хост:порт")
            up_box = Gtk.Box(spacing=6)
            up_box.append(self.e_upstream)
            for label, handler in (("Из файла…", self.on_proxy_file), ("Проверить", self.on_proxy_test),
                                   ("Логин и пароль…", self.on_proxy_auth)):
                bt = Gtk.Button(label=label)
                bt.connect("clicked", handler)
                up_box.append(bt)
            self.up_widgets = rows.add("Свой прокси", up_box)
            self.lbl_up = hint("")
            rows.grid.attach(self.lbl_up, 1, rows.r, 1, 1)
            rows.r += 1
            self.e_upstream.connect("changed", lambda *_: self.update_net_sensitivity())
            adv.append(box)


            # --- Система внутри среды
            box, grid = section("Система внутри среды",
                                "Язык, часовой пояс и DNS, которые увидит программа внутри среды.")
            rows = Rows(grid)
            self.e_lang = Gtk.Entry(hexpand=True, placeholder_text="как на компьютере; например ru_RU.UTF-8")
            self.e_lang.connect("changed", lambda *_: self.update_system_hints())
            rows.add("Язык", self.e_lang)
            self.lbl_lang = hint("")
            rows.grid.attach(self.lbl_lang, 1, rows.r, 1, 1)
            rows.r += 1
            self.e_tz = Gtk.Entry(hexpand=True, placeholder_text="как на компьютере; например Europe/Moscow")
            self.e_tz.connect("changed", lambda *_: self.update_system_hints())
            rows.add("Часовой пояс", self.e_tz)
            self.lbl_tz = hint("")
            rows.grid.attach(self.lbl_tz, 1, rows.r, 1, 1)
            rows.r += 1
            self.tv_dns, sw = text_area(height=44)
            self.dns_widgets = rows.add("DNS-серверы", sw,
                                        "По одному IP в строке, например адрес вашего роутера. Пусто — системные.")
            self.lbl_dns = hint("")
            rows.grid.attach(self.lbl_dns, 1, rows.r, 1, 1)
            rows.r += 1
            self.dns_widgets.append(self.lbl_dns)
            adv.append(box)

            # --- Браузер для ИИ (приложения)
            box, grid = section("Браузер для ИИ",
                                "Дайте программе внутри среды управляемый изолированный браузер.")
            rows = Rows(grid)
            self.tv_attach, sw = text_area(height=40)
            self.dd_browsers = Gtk.DropDown.new_from_strings(["—"])
            b_add = Gtk.Button(label="Добавить")
            b_add.connect("clicked", self.on_attach_add)
            b_help = Gtk.Button(label="Как подключить ИИ…")
            b_help.connect("clicked", self.on_attach_help)
            pick = Gtk.Box(spacing=6)
            pick.append(self.dd_browsers)
            pick.append(b_add)
            pick.append(b_help)
            rows.add("Подключено", sw,
                     "Внутри этой среды браузер виден как http://127.0.0.1:9222. Ни компьютеру, ни другим "
                     "средам он недоступен. Формат строки: среда[:порт[:локальный порт]].")
            rows.add("Среда-браузер", pick)
            self.app_only.append(box)
            adv.append(box)

            # --- Приложение как сервис и установка (приложения)
            box, grid = section("Приложение как сервис и установка",
                                "Запуск программ внутри среды, к которым ИИ-среды подключаются по закрытому сокету.")
            rows = Rows(grid)
            self.tv_expose, sw = text_area(height=40)
            rows.add("Открыть порты для других сред", sw,
                     "Номера портов, по одному в строке (например 9876 для Blender MCP). Порт виден внутри "
                     "среды на 127.0.0.1 и доступен только тем средам, которые вы подключили к ней в блоке "
                     "«Браузер для ИИ». Среда должна быть без сети или через прокси.")
            line, self.cb_nowd = toggle("Без каталога проекта",
                                        "Среда видит только свой домашний каталог: удобно для сервисов и установки.")
            rows.add(None, line)
            line, self.cb_gui = toggle("Показывать окно приложения (Wayland)",
                                       "Нужно приложениям с окном (Blender и т. п.). Ослабляет изоляцию: "
                                       "доступ к сокету Wayland. Графического ускорения в среде нет.")
            rows.add(None, line)
            self.tv_install_domains, sw = text_area(height=40)
            rows.add("Сайты для установки", sw,
                     "Пусто — при установке открыты любые публичные сайты с журналом. Иначе — только эти домены.")
            self.e_link_handler = Gtk.Entry(hexpand=True, placeholder_text="claude-desktop")
            rows.add("Команда открытия ссылок", self.e_link_handler,
                     "Что запустить внутри среды, чтобы приложение открыло ссылку (получит её последним аргументом). "
                     "Если приложение уже запущено, оно примет ссылку у себя. Пусто — приём ссылок выключен.")
            self.e_link_schemes = Gtk.Entry(hexpand=True, placeholder_text="claude")
            rows.add("Схемы ссылок приложения", self.e_link_schemes,
                     "Через пробел, например: claude (ссылки claude://…). Ссылки http и https разрешены всегда.")
            line, self.cb_link_cb = toggle("Принимать вход по ссылке localhost",
                                           "Для Claude CLI: адрес вида http://localhost:порт/… выполняется внутри среды, "
                                           "потому что браузер на компьютере не может достучаться до порта среды.")
            rows.add(None, line)
            line, self.cb_link_auto = toggle("Открывать ссылки из этой среды в браузере без вопроса",
                                             "Программа внутри среды просит открыть сайт (вход, документация) — envbox открывает "
                                             "его в изолированном браузере сразу. Выключено: сначала покажет адрес и спросит. "
                                             "Включайте только для сред, которым доверяете: через ссылку можно отправить данные "
                                             "на любой сайт, доступный браузеру.")
            rows.add(None, line)
            self.btn_bind = Gtk.Button(label="Открывать ссылки из браузера в этой среде", halign=Gtk.Align.START)
            self.btn_bind.connect("clicked", self.on_bind_scheme)
            rows.add(None, self.btn_bind)
            self.lbl_bind = hint("")
            rows.add(None, self.lbl_bind)
            self.app_only.append(box)
            adv.append(box)

            # --- Доступ ИИ (браузер)
            box, grid = section("Доступ ИИ к этому браузеру")
            rows = Rows(grid)
            self.lbl_cdp = Gtk.Label(xalign=0, wrap=True, selectable=True)
            rows.add("Сокет CDP", self.lbl_cdp)
            b_snip = Gtk.Button(label="Строки подключения…", halign=Gtk.Align.START)
            b_snip.connect("clicked", self.on_browser_help)
            rows.add(None, b_snip,
                     "ИИ получает полный контроль над браузером, включая cookies и сеансы в его профиле. "
                     "Не входите в личные аккаунты в этой среде.")
            self.browser_only.append(box)
            adv.append(box)

            # --- Для опытных: окружение и файлы
            box, grid = expander_section("Переменные и файлы",
                                         "Для опытных: что ещё передать в среду и что разрешить читать.")
            rows = Rows(grid)
            self.tv_env, sw = text_area(height=50)
            rows.add("Переменные", sw,
                     "VAR — взять значение у компьютера; VAR=значение — задать явно "
                     "(хранится в профиле открытым текстом, не для паролей).")
            self.tv_secrets, sw = text_area(height=40)
            b_secret = Gtk.Button(label="Задать значение…", valign=Gtk.Align.START)
            b_secret.connect("clicked", self.on_set_secret)
            sbox = Gtk.Box(spacing=6)
            sbox.append(sw)
            sbox.append(b_secret)
            rows.add("Секреты", sbox)
            self.lbl_secrets = hint("")
            rows.grid.attach(self.lbl_secrets, 1, rows.r, 1, 1)
            rows.r += 1
            self.tv_ro, sw = text_area(height=50)
            b_ro = Gtk.Button(label="Добавить…", valign=Gtk.Align.START)
            b_ro.connect("clicked", lambda *_: self.choose_folder(self.add_ro_path))
            rbox = Gtk.Box(spacing=6)
            rbox.append(sw)
            rbox.append(b_ro)
            rows.add("Читать (без записи)", rbox, "Пути, видимые в среде только на чтение, например ~/.nvm.")
            self.tv_path, sw = text_area(height=40)
            rows.add("Каталоги PATH", sw, "Добавляются в начало PATH внутри среды.")
            adv.append(box)

            # --- Для опытных: защита
            page.append(adv_exp)

            scroll = Gtk.ScrolledWindow(vexpand=True)
            scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)  # по ширине окна, без растягивания
            scroll.set_child(page)

            wrapper = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
            wrapper.append(scroll)
            wrapper.append(Gtk.Separator())
            bar = margins(Gtk.Box(spacing=10), 10)
            b_save = icon_button("document-save-symbolic", "Сохранить", "suggested-action", "Ctrl+S")
            b_save.connect("clicked", lambda *_: self.save_current(quiet=False))
            bar.append(b_save)
            bar.append(hint("Настройки применятся при следующем запуске среды."))
            wrapper.append(bar)
            return wrapper

        def update_net_sensitivity(self):
            mode = NET_MODES[self.dd_net.get_selected()]
            show_all(self.domain_widgets, mode == "allowlist")
            show_all(self.private_widgets, mode in ("log", "allowlist"))
            show_all(self.up_widgets + [self.lbl_up], mode in ("log", "allowlist"))
            via_upstream = mode in ("log", "allowlist") and bool(self.e_upstream.get_text().strip())
            show_all(self.dns_widgets, mode in ("log", "allowlist", "host") and not via_upstream)
            if mode == "host":
                self.lbl_dns.set_text("Серверы запишутся в /etc/resolv.conf среды.")
            else:
                self.lbl_dns.set_text("Имена сайтов разрешает прокси на компьютере через эти серверы. "
                                      "Обычный DNS не шифруется: запросы видит сеть и владелец сервера.")

        def show_profile(self, p):
            self.loading = True
            self.current = p
            if p is None:
                self.main_stack.set_visible_child_name("welcome")
                self.loading = False
                self.update_buttons()
                self.reset_net_view()
                if self.b_detached is None:
                    self.browser_disconnect()
                return
            self.main_stack.set_visible_child_name("main")
            is_browser = p.is_browser
            detached = self.b_detached is not None
            self.page_browser.set_visible(is_browser or detached)
            if self.viewer is not None and not detached and (not is_browser or self.viewer_env != p.name):
                self.browser_disconnect()
            if not detached:
                self.b_manual_off = False
            show_all(self.app_only, not is_browser)
            show_all(self.browser_only, is_browser)
            self.e_workdir.set_text(p.workdir)
            self.e_command.set_text(p.command)
            self.shell_choices = installed_shells()
            if p.shell_cmd not in self.shell_choices:
                self.shell_choices.append(p.shell_cmd)
            self.dd_shell.set_model(Gtk.StringList.new(
                [x if x in installed_shells() else f"{x} (не установлена)" for x in self.shell_choices]))
            self.dd_shell.set_selected(self.shell_choices.index(p.shell_cmd))
            self.e_start_url.set_text(p.browser_start_url)
            self.e_browser_bin.set_text(p.browser_bin)
            self.cb_visible.set_active(p.browser_visible)
            self.cb_chrome_sandbox.set_active(p.browser_chrome_sandbox)
            self.dd_net.set_selected(NET_MODES.index(p.net))
            set_text(self.tv_domains, "\n".join(p.allow_domains))
            self.cb_private.set_active(p.net_allow_private)
            self.e_upstream.set_text(p.upstream)
            self.e_lang.set_text(p.lang)
            self.e_tz.set_text(p.timezone)
            set_text(self.tv_dns, "\n".join(p.dns))
            set_text(self.tv_attach, "\n".join(p.attach))
            set_text(self.tv_expose, "\n".join(p.expose_ports))
            set_text(self.tv_install_domains, "\n".join(p.install_domains))
            self.e_link_handler.set_text(p.link_handler)
            self.e_link_schemes.set_text(" ".join(p.link_schemes))
            self.cb_link_cb.set_active(p.link_callback)
            self.cb_link_auto.set_active(p.link_out_auto)
            self.cb_nowd.set_active(p.no_workdir)
            self.cb_gui.set_active(p.gui_wayland)
            self.update_bind_status()
            set_text(self.tv_env, "\n".join(p.env))
            set_text(self.tv_secrets, "\n".join(p.secrets))
            set_text(self.tv_ro, "\n".join(p.ro))
            set_text(self.tv_rw, "\n".join(p.rw))
            self.cb_global.set_active(p.global_on)
            self.refresh_global_rows(p.global_folders)
            self.update_global_visibility()
            set_text(self.tv_path, "\n".join(p.path))
            self.show_isolation(p)
            set_text(self.tv_preview, "")
            names = [n for n in browser_profiles() if n != p.name] or ["—"]
            self.dd_browsers.set_model(Gtk.StringList.new(names))
            self.update_net_sensitivity()
            self.update_system_hints()
            self.loading = False
            self.update_secret_status()
            self.update_upstream_status()
            self.update_cdp_label()
            self.update_buttons()
            self.update_overview(p)
            self.reset_net_view()

        def selected_shell(self):
            i = self.dd_shell.get_selected()
            choices = getattr(self, "shell_choices", ["bash"])
            sh = choices[i] if 0 <= i < len(choices) else "bash"
            return "" if sh == "bash" else sh

        def collect(self):
            prof = Profile(
                name=self.current.name,
                kind=self.current.kind,
                workdir=self.e_workdir.get_text().strip(),
                command=self.e_command.get_text().strip(),
                net=NET_MODES[self.dd_net.get_selected()],
                allow_domains=get_lines(self.tv_domains),
                net_allow_private=self.cb_private.get_active(),
                upstream=self.e_upstream.get_text().strip(),
                upstream_auth=self.current.upstream_auth,
                attach=get_lines(self.tv_attach),
                expose_ports=get_text(self.tv_expose).replace(",", " ").split(),
                install_domains=get_lines(self.tv_install_domains),
                link_handler=self.e_link_handler.get_text().strip(),
                link_schemes=self.e_link_schemes.get_text().replace(",", " ").split(),
                link_callback=self.cb_link_cb.get_active(),
                link_out_auto=self.cb_link_auto.get_active(),
                link_browser=self.current.link_browser,
                no_workdir=self.cb_nowd.get_active(),
                gui_wayland=self.cb_gui.get_active(),
                shell=self.selected_shell(),
                env=get_lines(self.tv_env),
                secrets=get_lines(self.tv_secrets),
                ro=get_lines(self.tv_ro),
                rw=get_lines(self.tv_rw),
                global_on=self.cb_global.get_active(),
                global_folders=self.collect_global(),
                path=get_lines(self.tv_path),
                browser_bin=self.e_browser_bin.get_text().strip(),
                browser_start_url=self.e_start_url.get_text().strip() or "about:blank",
                browser_visible=self.cb_visible.get_active(),
                browser_chrome_sandbox=self.cb_chrome_sandbox.get_active(),
                lang=self.e_lang.get_text().strip(),
                timezone=self.e_tz.get_text().strip(),
                dns=get_text(self.tv_dns).replace(",", " ").split(),
            )
            self.read_isolation(prof)
            return prof

        def commit_upstream(self):
            """Если в поле прокси указан логин:пароль, переносим их в keyring, а поле очищаем."""
            text = self.e_upstream.get_text().strip()
            if "@" not in text:
                return None
            try:
                url, auth = split_proxy_url(text)
            except ValueError as e:
                return (f"Адрес прокси неверен ({e}). Поле очищено, чтобы логин и пароль "
                        "не попали в файл профиля.")
            if not auth:
                return None
            if not secret_tool_available():
                return "Для хранения пароля прокси нужен secret-tool: " + pkg_hint("secret-tool")
            try:
                secret_store(self.current.name, UPSTREAM_AUTH_VAR, auth)
            except (OSError, RuntimeError, subprocess.SubprocessError) as e:
                return f"Не удалось сохранить пароль прокси в keyring: {e}"
            self.current.upstream_auth = True
            self.e_upstream.set_text(url)
            return None

        def save_current(self, quiet):
            if not self.current:
                return None
            err = self.commit_upstream()
            if err:
                if not quiet:
                    alert(self, "Пароль прокси не сохранён", err)
                self.e_upstream.set_text("")
            p = self.collect()
            try:
                save_profile(p)
            except (OSError, ValueError) as e:
                if not quiet:
                    alert(self, "Не удалось сохранить профиль", str(e))
                return None
            self.current = p
            self.update_upstream_status()
            self.update_overview(p)
            if not quiet:
                errs = p.validate()
                if errs:
                    alert(self, "Профиль сохранён, но пока не готов к запуску", "\n".join(errs))
                else:
                    self.status("Сохранено")
            return p

        def choose_folder(self, callback):
            dlg = Gtk.FileDialog(title="Выберите каталог")

            def done(d, res):
                try:
                    f = d.select_folder_finish(res)
                except GLib.Error:
                    return
                if f is not None and f.get_path():
                    callback(f.get_path())

            dlg.select_folder(self, None, done)

        def add_ro_path(self, path):
            lines = get_lines(self.tv_ro)
            if to_home(path) not in lines:
                lines.append(to_home(path))
            set_text(self.tv_ro, "\n".join(lines))

        def add_rw_path(self, path):
            lines = get_lines(self.tv_rw)
            if to_home(path) not in lines:
                lines.append(to_home(path))
            set_text(self.tv_rw, "\n".join(lines))


    # ---- gui/pages/settings.py: Настройки приложения, диагностика, ярлык.

    def version_line():
        """Строка проверки: версия запущенного envbox и установленной копии (из неё работают шлюз и запущенные среды)."""
        installed = file_version_text(INSTALLED_PY)
        if installed is None:
            return f"⚠ версия envbox {ENVBOX_VERSION}: установленной копии нет (выполните python3 envbox.py install)"
        if file_version(INSTALLED_PY) == tuple(int(x) for x in ENVBOX_VERSION.split(".")):
            return f"✔ версия envbox {ENVBOX_VERSION}: запущенная совпадает с установленной"
        return (f"⚠ версия envbox: запущена {ENVBOX_VERSION}, установлена {installed}. Шлюз и среды работают из "
                "установленной копии: выполните python3 envbox.py install и перезапустите среды")


    class SettingsMixin:
        """Настройки приложения, диагностика, ярлык."""

        def on_settings(self, *_):
            win = Gtk.Window(title="Настройки терминала", transient_for=self, modal=True)
            win.set_default_size(560, -1)
            box = margins(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12), 16)
            line, sw = toggle("Открывать терминал во вкладке внутри окна",
                              "Отдельный эмулятор терминала не нужен." if Vte is not None else
                              "Недоступно: не найден VTE. Arch: sudo pacman -S vte4")
            sw.set_active(self.use_embedded())
            sw.set_sensitive(Vte is not None)
            box.append(line)
            box.append(Gtk.Label(label="Внешний терминал (если не во вкладке):", xalign=0))
            entry = Gtk.Entry(text=self.settings.get("terminal", ""), hexpand=True,
                              placeholder_text="пусто — определить автоматически")
            box.append(entry)
            auto = detect_terminal({"terminal": ""})
            box.append(hint("Сейчас определён: " + (" ".join(auto) if auto else "не найден") +
                            ". Команда среды добавляется в конец. Примеры: «kitty», «alacritty -e», "
                            "«foot», «ghostty -e», «konsole -e», «gnome-terminal --»."))
            buttons = Gtk.Box(spacing=8, halign=Gtk.Align.END)
            cancel = Gtk.Button(label="Отмена")
            ok = Gtk.Button(label="Сохранить")
            ok.add_css_class("suggested-action")
            buttons.append(cancel)
            buttons.append(ok)
            box.append(buttons)

            def save(*_):
                self.settings["terminal"] = entry.get_text().strip()
                self.settings["embedded"] = sw.get_active()
                try:
                    save_settings(self.settings)
                except OSError as e:
                    alert(win, "Не удалось сохранить настройки", str(e))
                    return
                win.destroy()
                self.status("Настройки терминала сохранены")

            ok.connect("clicked", save)
            cancel.connect("clicked", lambda *_: win.destroy())
            win.set_child(box)
            win.present()

        def on_diag(self, *_):
            win = Gtk.Window(title="Проверка системы", transient_for=self)
            win.set_default_size(760, 520)
            win.set_child(self.build_diag_page())
            self.run_diagnostics()
            win.present()

        def build_diag_page(self):
            box = margins(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8))
            buttons = Gtk.Box(spacing=8)
            b_check = Gtk.Button(label="Проверить снова")
            b_check.connect("clicked", lambda *_: self.run_diagnostics())
            b_desktop = Gtk.Button(label="Добавить в меню приложений")
            b_desktop.connect("clicked", self.on_install_desktop)
            buttons.append(b_check)
            buttons.append(b_desktop)
            box.append(buttons)
            self.tv_diag, sw = text_area(editable=False, height=300)
            sw.set_vexpand(True)
            box.append(sw)
            return box

        def run_diagnostics(self):
            icons = {"ok": "✔", "warn": "⚠", "fail": "✖"}
            out = [version_line()]
            try:
                for st, title, detail in diagnostics(self.settings):
                    out.append(f"{icons.get(st, '?')} {title}")
                    for line in detail.splitlines():
                        out.append(f"      {line}")
            except (OSError, subprocess.SubprocessError) as e:
                out.append(f"✖ ошибка диагностики: {e}")
            out.append(("✔ " if Vte is not None else "⚠ ") + "встроенный терминал (VTE): " +
                       ("есть" if Vte is not None else "нет — Arch: sudo pacman -S vte4"))
            set_text(self.tv_diag, "\n".join(out))

        def on_install_desktop(self, *_):
            try:
                path = install_desktop_entry()
            except OSError as e:
                alert(self, "Не удалось создать ярлык", str(e))
                return
            alert(self, "Ярлык создан", to_home(path))


    # ---- gui/pages/sidebar.py: Боковая панель: список сред, создание, копирование, удаление.

    class SidebarMixin:
        """Боковая панель: список сред, создание, копирование, удаление."""

        # ------------------------------------------------------------ боковая панель

        def build_sidebar(self):
            box = margins(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10), 12)
            box.add_css_class("eb-sidebar")
            box.set_hexpand(False)
            box.set_size_request(250, -1)
            title = Gtk.Label(label="Мои среды", xalign=0)
            title.add_css_class("eb-h2")
            box.append(title)
            self.plist = Gtk.ListBox(selection_mode=Gtk.SelectionMode.SINGLE)
            self.plist.add_css_class("navigation-sidebar")
            self.plist.connect("row-selected", self.on_profile_selected)
            scroll = Gtk.ScrolledWindow(vexpand=True)
            scroll.set_child(self.plist)
            box.append(scroll)
            b_new = icon_button("list-add-symbolic", "Новая среда", "suggested-action", "Ctrl+N")
            b_new.connect("clicked", self.on_new)
            box.append(b_new)
            small = Gtk.Box(spacing=6, homogeneous=True)
            b_copy = icon_button("edit-copy-symbolic", "Копия")
            b_copy.connect("clicked", self.on_copy)
            b_del = icon_button("user-trash-symbolic", "Удалить")
            b_del.connect("clicked", self.on_delete)
            small.append(b_copy)
            small.append(b_del)
            box.append(small)
            b_folders = icon_button("folder-symbolic", "Папки и каталог данных", None,
                                    "Где лежат данные envbox и глобальные папки")
            b_folders.connect("clicked", self.on_folders)
            box.append(b_folders)
            tools = Gtk.Box(spacing=6, homogeneous=True)
            b_diag = icon_button("dialog-information-symbolic", "Проверка", None, "Проверка системы")
            b_diag.connect("clicked", self.on_diag)
            b_term = icon_button("preferences-system-symbolic", "Терминал", None, "Настройки терминала")
            b_term.connect("clicked", self.on_settings)
            tools.append(b_diag)
            tools.append(b_term)
            box.append(tools)
            box.append(hint("● — среда сейчас запущена"))
            return box

        def reload_profiles(self, select=None):
            self.loading = True
            while (row := self.plist.get_row_at_index(0)) is not None:
                self.plist.remove(row)
            self.row_dots = {}
            target = None
            for name in list_profiles():
                try:
                    kind = load_profile(name).kind
                except (OSError, ValueError):
                    kind = "app"
                row = Gtk.ListBoxRow()
                row.envname = name
                line = margins(Gtk.Box(spacing=10), 6)
                line.append(Gtk.Image.new_from_icon_name(KIND_ICONS.get(kind, KIND_ICONS["app"])))
                lbl = Gtk.Label(label=name, xalign=0, hexpand=True)
                lbl.set_ellipsize(Pango.EllipsizeMode.END)
                dot = Gtk.Label(label="")
                dot.add_css_class("eb-dot")
                line.append(lbl)
                line.append(dot)
                row.set_child(line)
                self.row_dots[name] = dot
                dot.set_text("●" if name in self.running else "")
                self.plist.append(row)
                if name == select or (select is None and self.current and self.current.name == name):
                    target = row
            self.loading = False
            if target is None:
                target = self.plist.get_row_at_index(0)
            if target is not None:
                self.plist.select_row(target)
            else:
                self.show_profile(None)

        def on_profile_selected(self, _lb, row):
            if self.loading or row is None:
                return
            name = row.envname
            if self.current and self.current.name == name:
                return
            self.save_current(quiet=True)
            try:
                self.show_profile(load_profile(name))
            except (OSError, ValueError) as e:
                alert(self, f"Не удалось прочитать профиль {name}", str(e))

        def on_new(self, _btn=None, kind="app"):
            win = Gtk.Window(title="Новая среда", transient_for=self, modal=True)
            win.set_default_size(460, -1)
            box = margins(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10))
            box.append(Gtk.Label(label=f"Имя среды (каталог {to_home(envbox_root())}/<имя>):", xalign=0))
            entry = Gtk.Entry(hexpand=True)
            box.append(entry)
            box.append(Gtk.Label(label="Тип:", xalign=0))
            kinds = ("claude", "claude-desktop", "codex", "service", "app", "browser")
            kind_labels = {"claude": "Claude CLI — жёсткий шаблон (рекомендуется для ИИ)",
                           "claude-desktop": "Claude Desktop — окно через Wayland, сеть только к Claude",
                           "codex": "Codex или другой ИИ-агент — сеть с журналом, ключ как секрет",
                           "service": "Приложение-сервис для ИИ (Blender и т. п.) — без сети",
                           "app": KIND_LABELS["app"], "browser": KIND_LABELS["browser"]}
            kind_dd = Gtk.DropDown.new_from_strings([kind_labels[k] for k in kinds])
            kind_dd.set_selected(kinds.index(kind))
            box.append(kind_dd)
            box.append(hint("Claude CLI: сеть только к доменам Anthropic, без телеметрии и автообновления. "
                            "Codex и другие агенты: сеть с журналом — после первого запуска сузьте список по журналу. "
                            "Claude Desktop: Electron-приложение в песочнице; ставится через «Установить…» («Claude Desktop»), "
                            "окно показывается через Wayland (это слегка ослабляет изоляцию). "
                            "Приложение-сервис: программа без сети, порты открываются только подключённым ИИ-средам; "
                            "ставится через «Установить…». Браузер: Chromium без окна, к которому ИИ подключается по CDP."))
            buttons = Gtk.Box(spacing=8, halign=Gtk.Align.END)
            cancel = Gtk.Button(label="Отмена")
            ok = Gtk.Button(label="Создать")
            ok.add_css_class("suggested-action")
            buttons.append(cancel)
            buttons.append(ok)
            box.append(buttons)

            def create(*_):
                name = entry.get_text().strip()
                chosen = kinds[kind_dd.get_selected()]
                if not NAME_RE.match(name):
                    alert(win, "Недопустимое имя",
                          "Латиница, цифры, '.', '_', '-'; первый символ — буква или цифра; до 48 символов.")
                    return
                if os.path.exists(box_dir(name)) or os.path.exists(profile_path(name)):
                    alert(win, f"Среда «{name}» уже существует")
                    return
                win.destroy()
                self.save_current(quiet=True)
                p = new_profile(chosen, name)
                try:
                    save_profile(p)
                except OSError as e:
                    alert(self, "Не удалось создать среду", str(e))
                    return
                self.reload_profiles(select=name)

            ok.connect("clicked", create)
            entry.connect("activate", create)
            cancel.connect("clicked", lambda *_: win.destroy())
            win.set_child(box)
            win.present()
            entry.grab_focus()

        def on_copy(self, *_):
            if not self.current:
                return
            self.save_current(quiet=True)
            src = self.current.name

            def do_copy(name):
                try:
                    copy_profile(src, name.strip())
                except (OSError, ValueError) as e:
                    alert(self, "Не удалось скопировать", str(e))
                    return
                self.reload_profiles(select=name.strip())

            prompt(self, "Копия среды",
                   f"Имя новой среды. Скопируются настройки «{src}»; домашний каталог, профиль браузера "
                   "и пароль прокси из keyring не копируются:",
                   do_copy, initial=f"{src}-copy")

        def on_delete(self, *_):
            if not self.current:
                return
            name = self.current.name

            def done(idx):
                if idx == 0:
                    return
                try:
                    delete_profile(name, with_home=(idx == 2))
                except (OSError, ValueError) as e:
                    alert(self, "Не удалось удалить", str(e))
                    return
                self.current = None
                self.reload_profiles()
                self.status(f"Среда «{name}» удалена")

            choose(self, f"Удалить среду «{name}»?",
                   f"Домашний каталог среды: {to_home(box_dir(name))}/home\n"
                   "Там лежат данные приложения (и профиль браузера, если это браузер).\n"
                   "Рабочий каталог проекта, папки с записью и глобальные папки не затрагиваются "
                   "в любом случае.",
                   ["Отмена", "Удалить только профиль", "Удалить вместе с домашним каталогом"], done)


    # ---- gui/pages/terminal.py: Встроенный терминал (VTE).

    class TerminalMixin:
        """Встроенный терминал (VTE)."""

        def build_terminal_page(self):
            self.term_stack = Gtk.Stack()
            empty = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14,
                            valign=Gtk.Align.CENTER, halign=Gtk.Align.CENTER)
            msg = Gtk.Label(wrap=True, justify=Gtk.Justification.CENTER, max_width_chars=60,
                            label="Здесь откроются терминалы выбранной среды.\n"
                                  "Нажмите «Терминал» наверху.")
            msg.add_css_class("dim-label")
            empty.append(msg)
            if Vte is None:
                warn = Gtk.Label(wrap=True, justify=Gtk.Justification.CENTER, max_width_chars=60,
                                 label="Встроенный терминал недоступен: не найден VTE для GTK 4.\n"
                                       "Установка: " + pkg_hint("vte") + "\n"
                                       "Пока терминал откроется во внешнем окне.")
                warn.add_css_class("eb-warn")
                empty.append(warn)
            self.term_nb = Gtk.Notebook(scrollable=True, vexpand=True, hexpand=True)
            self.term_stack.add_named(empty, "empty")
            self.term_stack.add_named(self.term_nb, "tabs")

            # панель действий над текущим терминалом (то же, что меню по правой кнопке)
            bar = Gtk.Box(spacing=4, margin_top=4, margin_bottom=2, margin_start=6, margin_end=6)
            for text, action, tip in (("Копировать", "copy", "Скопировать выделенное (Ctrl+Shift+C)"),
                                      ("Вставить", "paste", "Вставить из буфера (Ctrl+Shift+V, Shift+Insert)"),
                                      ("Выделить всё", "select-all", "Выделить весь вывод (Ctrl+Shift+A)"),
                                      ("Очистить", "clear", "Очистить экран и историю"),
                                      ("A−", "zoom-out", "Мельче (Ctrl −)"),
                                      ("A+", "zoom-in", "Крупнее (Ctrl +)")):
                btn = Gtk.Button(label=text, tooltip_text=tip)
                btn.add_css_class("flat")
                btn.connect("clicked", lambda *_a, act=action: self.term_do(self.current_term(), act))
                bar.append(btn)
            bar.append(Gtk.Label(label="Выделение мышью копируется само; средняя кнопка вставляет",
                                 hexpand=True, xalign=1, css_classes=["dim-label"]))
            bar.set_visible(False)
            self.term_stack.connect("notify::visible-child-name",
                                    lambda st, *_a: bar.set_visible(st.get_visible_child_name() == "tabs"))
            outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
            outer.append(bar)
            outer.append(self.term_stack)
            return outer

        def use_embedded(self):
            return Vte is not None and bool(self.settings.get("embedded", True))

        # ---- копирование, вставка, масштаб: сочетания клавиш, меню по правой кнопке, панель сверху

        def term_do(self, term, action):
            """Действие над терминалом: copy, paste, select-all, clear, zoom-in, zoom-out, zoom-reset."""
            if term is None:
                return
            try:
                if action == "copy":
                    if term.get_has_selection():
                        term.copy_clipboard_format(Vte.Format.TEXT)
                elif action == "paste":
                    term.paste_clipboard()
                elif action == "select-all":
                    term.select_all()
                elif action == "clear":
                    term.reset(True, True)
                elif action == "zoom-in":
                    term.set_font_scale(min(4.0, term.get_font_scale() * 1.1))
                elif action == "zoom-out":
                    term.set_font_scale(max(0.4, term.get_font_scale() / 1.1))
                elif action == "zoom-reset":
                    term.set_font_scale(1.0)
            except Exception as e:  # noqa: BLE001
                self.status(f"Не удалось выполнить действие терминала: {e}")
            term.grab_focus()

        def current_term(self):
            page = self.term_nb.get_current_page()
            term = self.term_nb.get_nth_page(page) if page >= 0 else None
            return term if term in self.term_entries else None

        def attach_term_controls(self, term):
            """Сочетания клавиш и меню правой кнопки; возвращает popover (его нужно отсоединить при закрытии)."""
            keys = Gtk.ShortcutController()
            # CAPTURE: иначе клавиши сначала достанутся самому терминалу и уйдут в программу как ввод
            keys.set_propagation_phase(Gtk.PropagationPhase.CAPTURE)
            for accel, action in (("<Control><Shift>c", "copy"), ("<Control>Insert", "copy"),
                                  ("<Control><Shift>v", "paste"), ("<Shift>Insert", "paste"),
                                  ("<Control><Shift>a", "select-all"),
                                  ("<Control>plus", "zoom-in"), ("<Control>equal", "zoom-in"),
                                  ("<Control>KP_Add", "zoom-in"), ("<Control>minus", "zoom-out"),
                                  ("<Control>KP_Subtract", "zoom-out"), ("<Control>0", "zoom-reset")):
                keys.add_shortcut(Gtk.Shortcut.new(
                    Gtk.ShortcutTrigger.parse_string(accel),
                    Gtk.CallbackAction.new(lambda *_a, act=action: (self.term_do(term, act), True)[1])))
            term.add_controller(keys)

            group = Gio.SimpleActionGroup()
            actions = {}
            for name in ("copy", "paste", "select-all", "clear", "zoom-in", "zoom-out", "zoom-reset"):
                act = Gio.SimpleAction.new(name, None)
                act.connect("activate", lambda *_a, n=name: self.term_do(term, n))
                group.add_action(act)
                actions[name] = act
            term.insert_action_group("term", group)
            link_state = {"url": ""}
            open_act = Gio.SimpleAction.new("open-link", None)
            open_act.connect("activate", lambda *_a: self.open_term_link(term, link_state["url"]))
            open_act.set_enabled(False)
            group.add_action(open_act)
            actions["open-link"] = open_act
            tag = None
            try:  # подсветка и распознавание ссылок: Vte.Regex (PCRE2_UTF | NO_UTF_CHECK | MULTILINE)
                regex = Vte.Regex.new_for_match(r"https?://[^\s<>\"'`]+[^\s<>\"'`.,;:!?)\]}]", -1, 0x40080400)
                tag = term.match_add_regex(regex, 0)
                term.match_set_cursor_name(tag, "pointer")
            except Exception:  # noqa: BLE001
                tag = None

            def link_at(x, y):
                if tag is None:
                    return ""
                try:
                    m = term.check_match_at(x, y)
                except Exception:  # noqa: BLE001
                    return ""
                text = m[0] if isinstance(m, (tuple, list)) else m
                return text or ""

            lclick = Gtk.GestureClick()
            lclick.set_button(1)

            def on_lclick(g, _n, x, y):
                if g.get_current_event_state() & Gdk.ModifierType.CONTROL_MASK:
                    url = link_at(x, y)
                    if url:
                        self.open_term_link(term, url)

            lclick.connect("pressed", on_lclick)
            term.add_controller(lclick)
            menu = Gio.Menu()
            top = Gio.Menu()
            top.append("Копировать (Ctrl+Shift+C)", "term.copy")
            top.append("Вставить (Ctrl+Shift+V)", "term.paste")
            top.append("Выделить всё (Ctrl+Shift+A)", "term.select-all")
            top.append("Открыть ссылку в браузере (Ctrl+клик)", "term.open-link")
            menu.append_section(None, top)
            view = Gio.Menu()
            view.append("Очистить экран и историю", "term.clear")
            view.append("Крупнее (Ctrl +)", "term.zoom-in")
            view.append("Мельче (Ctrl −)", "term.zoom-out")
            view.append("Обычный размер (Ctrl 0)", "term.zoom-reset")
            menu.append_section(None, view)
            popover = Gtk.PopoverMenu.new_from_model(menu)
            popover.set_parent(term)
            popover.set_has_arrow(False)
            click = Gtk.GestureClick()
            click.set_button(3)

            def on_press(_gesture, _n, x, y):
                rect = Gdk.Rectangle()
                rect.x, rect.y, rect.width, rect.height = int(x), int(y), 1, 1
                popover.set_pointing_to(rect)
                actions["copy"].set_enabled(bool(term.get_has_selection()))
                link_state["url"] = link_at(x, y)
                actions["open-link"].set_enabled(bool(link_state["url"]))
                popover.popup()

            click.connect("pressed", on_press)
            term.add_controller(click)
            return popover

        def open_embedded(self, p, command, install=False, feed="", install_domains=None):
            """Терминал во вкладке: оболочка/команда внутри среды, секреты берутся из keyring.
            install — режим установки; feed — текст, набранный в терминале (Enter нажимаете вы)."""
            term = Vte.Terminal()
            term.set_hexpand(True)
            term.set_vexpand(True)
            term.set_scrollback_lines(20000)
            term.set_mouse_autohide(True)
            term.set_scroll_on_keystroke(True)
            popover = self.attach_term_controls(term)

            title = f"{p.name} · " + ("установка" if install else (command or p.command))
            label = Gtk.Label(label=title)
            label.set_ellipsize(Pango.EllipsizeMode.END)
            label.set_max_width_chars(30)
            close = Gtk.Button(icon_name="window-close-symbolic", tooltip_text="Закрыть и завершить")
            close.add_css_class("flat")
            head = Gtk.Box(spacing=6)
            head.append(label)
            head.append(close)
            entry = {"pid": None, "alive": True, "title": title, "label": label, "popover": popover, "env": p.name}
            self.term_entries[term] = entry
            self.term_nb.append_page(term, head)
            self.term_nb.set_current_page(self.term_nb.page_num(term))
            self.term_stack.set_visible_child_name("tabs")
            self.nb.set_current_page(self.nb.page_num(self.page_terminal))
            close.connect("clicked", lambda *_: self.close_embedded(term))
            term.connect("child-exited", lambda t, status, *_: self.on_term_exit(t))

            def spawned(_t, pid, error, *_rest):
                if error is not None:
                    entry["alive"] = False
                    term.feed(f"envbox: не удалось запустить: {error.message}\r\n".encode())
                else:
                    entry["pid"] = pid

            env = [f"{k}={v}" for k, v in os.environ.items()] + ["ENVBOX_EMBEDDED=1"]
            argv = terminal_argv([], p, command, install=install, install_domains=install_domains)
            args = (Vte.PtyFlags.DEFAULT, HOME, argv, env, GLib.SpawnFlags.DEFAULT,
                    None, None, -1, None, spawned)
            try:
                term.spawn_async(*args, None)
            except TypeError:  # другая версия привязок: без user_data
                term.spawn_async(*args)
            term.grab_focus()
            if feed:
                def type_command():
                    try:
                        term.feed_child(feed.encode())
                    except TypeError:
                        term.feed_child(feed)
                    return False

                GLib.timeout_add(1200, type_command)
            self.status(f"Терминал «{p.name}» открыт во вкладке")
            GLib.timeout_add(1500, self.refresh_sessions_once)

        def on_term_exit(self, term):
            entry = self.term_entries.get(term)
            if entry:
                entry["alive"] = False
                entry["label"].set_text(entry["title"] + "  (завершён)")
            GLib.timeout_add(700, self.refresh_sessions_once)

        def kill_group(self, pid):
            """Завершает всю группу процессов терминала (обёртка, envbox, прокси, bwrap)."""
            try:
                os.killpg(pid, signal.SIGTERM)
            except OSError:
                return

            def hard():
                try:
                    os.killpg(pid, signal.SIGKILL)
                except OSError:
                    pass
                return False

            GLib.timeout_add(3000, hard)

        def close_embedded(self, term):
            entry = self.term_entries.pop(term, None)
            if entry and entry.get("popover") is not None:
                try:
                    entry["popover"].unparent()
                except Exception:  # noqa: BLE001
                    pass
            if entry and entry["alive"] and entry["pid"]:
                self.kill_group(entry["pid"])
            page = self.term_nb.page_num(term)
            if page >= 0:
                self.term_nb.remove_page(page)
            if self.term_nb.get_n_pages() == 0:
                self.term_stack.set_visible_child_name("empty")
            GLib.timeout_add(900, self.refresh_sessions_once)


    # ---- gui/window.py: Главное окно: собирается из миксинов страниц (gui/pages/*, gui/browser/*).

    class EnvboxWindow(
        SidebarMixin,
        OverviewMixin,
        ProfilePageMixin,
        IsolationMixin,
        FoldersMixin,
        ProfileNetMixin,
        LaunchMixin,
        BrowserPageMixin,
        BrowserViewMixin,
        LinksMixin,
        TerminalMixin,
        SettingsMixin,
        NetPageMixin,
        Gtk.ApplicationWindow,
    ):
        """Главное окно."""

        def __init__(self, app):
            super().__init__(application=app, title=f"envbox {ENVBOX_VERSION}")
            self.set_default_size(1180, 800)
            self.settings = load_settings()
            self.current = None          # загруженный Profile
            self.loading = False         # подавляет обработчики при заполнении
            self.procs = []              # Popen терминалов и браузеров
            self.pending = {}            # имя среды -> (Popen, путь к launch.log) для проверки старта
            self.running = set()         # имена сред с запущенным bwrap
            self.tail = None
            self.net_summary = NetSummary()
            self.net_filter = ""
            self.term_entries = {}       # виджет терминала -> {"pid", "alive", "title", "label"}
            self.row_dots = {}
            self.status_token = 0
            self.attach_snippet_cache = {}

            self.install_css()
            # Кнопки запуска — внутри окна: в тайловых оконных менеджерах заголовок окна не рисуется
            self.btn_run = icon_button("media-playback-start-symbolic", "Запустить", "suggested-action",
                                       "Запустить команду среды (Ctrl+R)")
            self.btn_run.connect("clicked", lambda *_: self.launch(None))
            self.btn_shell = icon_button("utilities-terminal-symbolic", "Терминал", None,
                                         "Открыть оболочку bash внутри среды (Ctrl+T)")
            self.btn_shell.connect("clicked", lambda *_: self.launch(SHELL_COMMAND))
            self.btn_install = icon_button("system-software-install-symbolic", "Установить…", None,
                                           "Установить программы внутрь среды (без проекта и секретов)")
            self.btn_install.connect("clicked", self.on_install)
            self.btn_link = icon_button("insert-link-symbolic", "Ссылка…", None,
                                        "Передать ссылку приложению внутри среды: вход по ссылке, claude://… (Ctrl+Shift+L)")
            self.btn_link.connect("clicked", self.on_open_link)
            self.btn_stop = icon_button("media-playback-stop-symbolic", "Остановить", "destructive-action",
                                        "Остановить среду")
            self.btn_stop.connect("clicked", self.on_stop_current)

            root = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
            self.set_child(root)
            self.sidebar = self.build_sidebar()
            root.append(self.sidebar)
            root.append(Gtk.Separator(orientation=Gtk.Orientation.VERTICAL))
            right = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, hexpand=True, vexpand=True)
            right.set_overflow(Gtk.Overflow.HIDDEN)   # содержимое не раздувает окно
            root.append(right)

            self.toolbar = margins(Gtk.Box(spacing=8), 8)
            self.lbl_toolbar = Gtk.Label(xalign=0, hexpand=True, ellipsize=Pango.EllipsizeMode.END)
            self.lbl_toolbar.add_css_class("eb-h2")
            self.toolbar.append(self.lbl_toolbar)
            for b in (self.btn_run, self.btn_shell, self.btn_install, self.btn_link, self.btn_stop):
                self.toolbar.append(b)
            right.append(self.toolbar)
            right.append(Gtk.Separator())
            self.lbl_status = Gtk.Label(xalign=0, ellipsize=Pango.EllipsizeMode.END)
            self.lbl_status.add_css_class("eb-status")
            self.lbl_status.add_css_class("dim-label")

            self.nb = Gtk.Notebook()
            self.page_overview = self.build_overview_page()
            self.nb.append_page(self.page_overview, Gtk.Label(label="Обзор"))
            self.page_terminal = self.build_terminal_page()
            self.nb.append_page(self.page_terminal, Gtk.Label(label="Терминал"))
            self.page_browser = self.build_browser_page()
            self.nb.append_page(self.page_browser, Gtk.Label(label="Окно браузера"))
            self.page_profile = self.build_profile_page()
            self.nb.append_page(self.page_profile, Gtk.Label(label="Настройки"))
            self.nb.append_page(self.build_isolation_page(), Gtk.Label(label="Изоляция"))
            self.nb.append_page(self.build_net_page(), Gtk.Label(label="Журнал сети"))
            self.nb.connect("switch-page", self.on_switch_page)
            self.main_stack = Gtk.Stack()
            self.main_stack.add_named(self.build_welcome_page(), "welcome")
            self.main_stack.add_named(self.nb, "main")
            self.main_stack.set_vexpand(True)
            right.append(self.main_stack)
            right.append(Gtk.Separator())
            right.append(self.lbl_status)

            self.add_shortcuts()
            self.reload_profiles()
            self.refresh_sessions()
            GLib.timeout_add(1000, self.tick)
            GLib.timeout_add(500, self.check_width)
            self.connect("close-request", self.on_close)

        def install_css(self):
            prov = Gtk.CssProvider()
            try:
                if hasattr(prov, "load_from_string"):
                    prov.load_from_string(CSS)
                else:
                    prov.load_from_data(CSS.encode())
                Gtk.StyleContext.add_provider_for_display(
                    self.get_display(), prov, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
            except Exception as e:  # noqa: BLE001 — оформление не должно мешать работе
                sys.stderr.write(f"envbox-gui: оформление не применено: {e}\n")

        def status(self, message):
            self.lbl_status.set_text(message)
            self.status_token += 1
            token = self.status_token

            def clear():
                if token == self.status_token:
                    self.lbl_status.set_text("")
                return False

            GLib.timeout_add_seconds(STATUS_SECONDS, clear)

        def run_async(self, func, done):
            """func() в потоке, done(результат_или_исключение) в главном потоке."""
            def worker():
                try:
                    res = func()
                except Exception as e:  # noqa: BLE001 — показываем пользователю
                    res = e
                GLib.idle_add(lambda: (done(res), False)[1])

            threading.Thread(target=worker, daemon=True).start()

        def add_shortcuts(self):
            ctl = Gtk.ShortcutController()
            bindings = (("<Control>s", lambda: self.save_current(quiet=False)),
                        ("<Control>n", lambda: self.on_new()),
                        ("<Control>t", lambda: self.btn_shell.get_visible() and self.launch(SHELL_COMMAND)),
                        ("<Control><Shift>l", lambda: self.btn_link.get_visible() and self.on_open_link()),
                        ("<Control>r", lambda: self.launch(None)),
                        ("F5", lambda: self.refresh_all()))
            def make_handler(fn):
                return lambda *_: (fn(), True)[1]

            for accel, fn in bindings:
                action = Gtk.CallbackAction.new(make_handler(fn))
                ctl.add_shortcut(Gtk.Shortcut.new(Gtk.ShortcutTrigger.parse_string(accel), action))
            self.add_controller(ctl)

        def refresh_all(self):
            self.refresh_sessions()
            self.reload_profiles()
            self.status("Обновлено")

        def on_switch_page(self, _nb, page, _num):
            if page is self.page_overview and self.current:
                self.update_overview(self.collect())  # с учётом ещё не сохранённых правок

        def check_width(self):
            """Узкое окно: кнопки без подписей, боковая панель уже."""
            try:
                width = int(self.get_width())
            except (TypeError, ValueError):
                return True
            compact = 0 < width < 1000
            if compact != getattr(self, "compact", None):
                self.compact = compact
                for b in (self.btn_run, self.btn_shell, self.btn_install, self.btn_link, self.btn_stop):
                    b.lbl.set_visible(not compact)
                self.sidebar.set_size_request(190 if compact else 250, -1)
            return True

        def tick(self):
            self.procs = [t for t in self.procs if t.poll() is None]
            self.refresh_sessions_async()
            self.poll_net()
            if self.current and self.current.is_browser:
                self.update_cdp_label()
            return True

        def on_close(self, *_):
            if self.b_detached is not None:
                try:
                    self.b_detached.close()
                except Exception:  # noqa: BLE001
                    pass
            self.browser_disconnect()
            self.save_current(quiet=True)
            alive = [e for e in self.term_entries.values() if e["alive"] and e["pid"]]
            if alive and not getattr(self, "closing_confirmed", False):
                def done(idx):
                    if idx == 1:
                        self.closing_confirmed = True
                        for e in alive:
                            self.kill_group(e["pid"])
                        self.close()

                choose(self, "Закрыть окно?",
                       f"Открытых терминалов: {len(alive)}. Они будут завершены вместе со средами.",
                       ["Отмена", "Закрыть и завершить"], done)
                return True
            return False


    # ---- gui/app.py: Приложение GTK и точка входа gui_main.

    class App(Gtk.Application):
        def __init__(self):
            flags = getattr(Gio.ApplicationFlags, "DEFAULT_FLAGS", Gio.ApplicationFlags.FLAGS_NONE)
            super().__init__(application_id="io.github.envbox.Gui", flags=flags)

        def do_activate(self):
            win = self.props.active_window or EnvboxWindow(self)
            win.present()


    def gui_main():
        GLib.set_application_name("envbox")
        return App().run([sys.argv[0]])


    gui_main.window_class = EnvboxWindow

    return gui_main


if __name__ == "__main__":
    sys.exit(main())
