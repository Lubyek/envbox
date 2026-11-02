"""Сетевой шлюз: свой DNS-клиент и проверки имён/адресов."""

import os
import struct
import time

from ..lazy import asyncio, ipaddress, re, socket
from .common import CONNECT_TIMEOUT, is_public


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
