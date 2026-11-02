"""Сетевой шлюз: вышестоящий прокси (http / socks5 / socks5h)."""

import struct

from ..lazy import asyncio, base64, ipaddress, urllib_parse
from .common import CONNECT_TIMEOUT, tune_socket


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
