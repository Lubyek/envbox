"""Сетевой шлюз: мосты unix-сокет <-> localhost, канал ссылок (команды wrap, probe)."""

import os
import shlex
import stat
import sys
import time

from ..lazy import asyncio, re, signal, socket, threading
from .common import BUF, split_hostport, tune_socket
from .upstream import Upstream


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
