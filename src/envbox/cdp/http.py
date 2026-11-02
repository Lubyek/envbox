"""CDP: HTTP-запросы к DevTools через unix-сокет."""

import json
import os
import re
import socket
import stat

from ..core.browser import cdp_socket_path
from ..core.consts import CDP_PORT


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
