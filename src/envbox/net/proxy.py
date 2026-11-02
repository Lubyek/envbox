"""Сетевой шлюз: журналирующий прокси (команда proxy)."""

import itertools
import os
import sys
import time

from ..lazy import asyncio, ipaddress, json, signal, urllib_parse
from .common import (
    BUF,
    HEAD_LIMIT,
    HEAD_TIMEOUT,
    HEDGE_DELAY,
    IDLE_TIMEOUT,
    MAX_HEDGES,
    MAX_SETUPS,
    canon_host,
    is_public,
    now,
    split_hostport,
)
from .chain import PROBE_EVERY, Channel, Chain, parse_chain_spec, probe
from .connect import connect_race
from .dns import Resolver, is_ip_literal, is_private_name
from .upstream import Upstream
from .vpn import START_TIMEOUT, VpnClient


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


class PrivateAddress(Exception):
    """Имя ведёт на частный адрес: это решение политики (403), а не сбой канала."""

    def __init__(self, resolved):
        super().__init__("private address")
        self.resolved = resolved


class OpenFailed(OSError):
    """Не удалось открыть соединение: причина для журнала, текст для клиента и вышестоящий канал (если был)."""

    def __init__(self, reason, text, via=None):
        super().__init__(reason)
        self.reason, self.text, self.via = reason, text, via


class Proxy:
    def __init__(self, log_path, allow, allow_private, upstream=None, dns=None, direct=None,
                 idle=IDLE_TIMEOUT, hedge=HEDGE_DELAY, max_hedges=MAX_HEDGES, max_setups=MAX_SETUPS, chain=None):
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
        # каналы выхода по порядку; без явной цепочки это один вышестоящий прокси (или прямой выход, если его нет)
        self.chain = chain if chain is not None else Chain(
            [Channel("proxy", "proxy", upstream)] if upstream is not None else [])
        self.tasks = []
        # сайты, к которым прокси подключается сам, минуя вышестоящий прокси (некоторые сайты не пускают его адрес)
        self.direct = [a.lower().rstrip(".") for a in (direct or [])]
        self.dns = list(dns or [])
        self.ids = itertools.count(1)
        self.run_id = os.urandom(3).hex()   # у каждого запуска свои номера соединений
        # прокси на этом же компьютере или в локальной сети разрешает имена у себя: проверяем и здесь
        self.check_local = any(c.kind == "proxy" and is_private_name(c.upstream.host) for c in self.chain.channels)
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
        """Идёт ли соединение с хостом через цепочку каналов (сайты из списка «напрямую» идут мимо неё)."""
        return bool(self.chain) and not host_matches(self.direct, host)

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

    async def hedged_tunnel(self, up, host, port):
        """Туннель через вышестоящий прокси `up`. Если первая попытка не готова за `hedge` секунд, стартует вторая;
        берётся первая удавшаяся, остальные закрываются. Ошибка — только если не удалась ни одна."""
        first = asyncio.ensure_future(up.tunnel(host, port))
        done, _ = await asyncio.wait({first}, timeout=self.hedge)
        if done:
            return first.result()
        if self.hedging >= self.max_hedges:
            return await first          # прокси и так перегружен: вторую попытку не добавляем
        self.hedging += 1
        self.write({"event": "hedge", "host": host, "port": port, "reason": "upstream-slow"})
        pending = {first, asyncio.ensure_future(up.tunnel(host, port))}
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
        """Пересылка в обе стороны. Возвращает (отправлено, получено, кто_закончил, метки времени в мс):
        кто_закончил — «client», «upstream» или «idle»."""
        counts = {"up": len(first), "down": 0}
        started = last_t = time.monotonic()
        last = [last_t]
        stamps = {}       # моменты (от начала пересылки): последний байт от клиента, первый и последний байт ответа
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
                    now = last[0] = time.monotonic()
                    counts[key] += len(data)
                    if key == "up":
                        stamps["up_end"] = now
                    else:
                        stamps.setdefault("down_first", now)
                        stamps["down_last"] = now
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
        # по этим меткам видно, кто молчит у зависшего соединения: клиент не договорил запрос или сервер не ответил
        timing = {k: int((t - started) * 1000) for k, t in stamps.items()}
        return counts["up"], counts["down"], end, timing

    async def deny(self, writer, rec, code, reason, text, **extra):
        """Отказ: запись в журнал и быстрый ответ клиенту (с названием хоста: понятно, что именно закрыто)."""
        self.write({**rec, "event": "deny" if code == 403 else "error", "reason": reason, **extra})
        await self.reply(writer, code, f"{text}: {rec.get('host', '?')}")

    async def open_direct(self, host, port):
        """Соединение напрямую (с этого компьютера): имя разрешается у нас, адрес проверяется на частный."""
        try:
            addrs = await self.resolver.resolve(host)
        except (OSError, asyncio.TimeoutError) as e:
            raise OpenFailed(f"dns: {err_text(e)}", "DNS resolution failed") from None
        candidates = addrs if self.allow_private else [a for a in addrs if is_public(a)]
        if not candidates:
            raise PrivateAddress(addrs)
        try:  # подключаемся к уже проверенному IP (без повторного DNS), адреса пробуются «наперегонки»
            return await connect_race(candidates, port)
        except (OSError, asyncio.TimeoutError) as e:
            raise OpenFailed(f"connect: {err_text(e)}", "Upstream connection failed") from None

    async def channel_upstream(self, ch):
        """Вышестоящий прокси канала; у VPN сначала дожидаемся запуска клиента."""
        if ch.ready is not None and not ch.ready.is_set():
            await asyncio.wait_for(ch.ready.wait(), START_TIMEOUT + 5)
        if ch.upstream is None:
            raise OSError(ch.error or "VPN-клиент не запущен")
        return ch.upstream

    async def open_channel(self, ch, host, port, method, rec):
        """Соединение с host:port через канал ch -> (читатель, писатель, туннель?, Upstream, IP)."""
        if ch.kind == "direct":
            ip, ur, uw = await self.open_direct(host, port)
            return ur, uw, True, None, ip
        up = await self.channel_upstream(ch)
        if method == "CONNECT" or up.kind == "socks5":
            queued = time.monotonic()
            async with self.setups:
                waited = time.monotonic() - queued
                ur, uw = await self.hedged_tunnel(up, host, port)
            if waited > 0.2:
                rec["wait_ms"] = int(waited * 1000)   # всплеск соединений: ждали своей очереди
            return ur, uw, True, up, None
        ur, uw = await up.open()      # обычный HTTP: запрос в абсолютной форме самому прокси
        return ur, uw, False, up, None

    async def open_chain(self, host, port, method, rec):
        """Первый отозвавшийся канал цепочки. Упавшие пропускаются; смена канала пишется в журнал."""
        errors = []
        for ch in self.chain.order():
            try:
                ur, uw, tunnel, up, ip = await self.open_channel(ch, host, port, method, rec)
            except PrivateAddress:
                raise
            except (OSError, asyncio.TimeoutError) as e:
                why = e.reason if isinstance(e, OpenFailed) else f"upstream: {err_text(e)}"
                if self.chain.failed(ch, why):
                    nxt = next((c for c in self.chain.order() if c is not ch), None)
                    self.write({"event": "channel", "state": "down", "channel": ch.label, "reason": why,
                                **({"next": nxt.label} if nxt else {})})
                errors.append((ch, why, e))
                continue
            if self.chain.worked(ch):
                self.write({"event": "channel", "state": "up", "channel": ch.label})
            return ur, uw, tunnel, up, ip, ch
        ch, why, e = errors[-1]
        if len(errors) > 1:
            why = "chain: " + "; ".join(f"{c.label}: {w}" for c, w, _ in errors)
        text = e.text if isinstance(e, OpenFailed) else "Upstream proxy failed"
        via = ch.upstream.label if ch.upstream is not None and ch.kind == "proxy" else None
        raise OpenFailed(why, text, via)

    async def start_client(self, ch):
        try:
            await ch.client.start()
            ch.upstream = ch.client.upstream
            self.write({"event": "channel", "state": "started", "channel": ch.label})
        except OSError as e:
            ch.broken, ch.error = True, err_text(e)
            self.write({"event": "channel", "state": "broken", "channel": ch.label, "reason": ch.error})
        finally:
            ch.ready.set()

    async def probe_loop(self):
        """Упавшие каналы проверяются в фоне: как только отвечают, новые соединения возвращаются на них."""
        while True:
            await asyncio.sleep(PROBE_EVERY)
            for ch in self.chain.channels:
                if ch.down and not ch.broken and await probe(ch) and self.chain.worked(ch):
                    self.write({"event": "channel", "state": "up", "channel": ch.label})

    def begin(self):
        """Запустить VPN-клиенты и фоновую проверку каналов (вызывается внутри работающего цикла событий)."""
        for ch in self.chain.channels:
            if ch.kind == "vpn":
                ch.ready = asyncio.Event()
                self.tasks.append(asyncio.ensure_future(self.start_client(ch)))
        if len(self.chain.channels) > 1:
            self.tasks.append(asyncio.ensure_future(self.probe_loop()))

    def end(self):
        for t in self.tasks:
            t.cancel()
        for ch in self.chain.channels:
            if ch.client is not None:
                ch.client.stop()

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

            tunnel, used = True, None     # used — Upstream, через который идёт соединение (нужен для обычного HTTP)
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
                    ur, upstream, tunnel, used, ip, chan = await self.open_chain(host, port, method, rec)
                except PrivateAddress as e:
                    await self.deny(writer, rec, 403, "private-address",
                                    "Private address forbidden by envbox", resolved=e.resolved)
                    return
                except OpenFailed as e:
                    await self.deny(writer, rec, 502, e.reason, e.text, **({"via": e.via} if e.via else {}))
                    return
                if chan.kind == "direct":
                    rec["ip"], rec["direct"] = ip, True    # выход этого компьютера (или его системного VPN)
                else:
                    rec["via"] = chan.label
                if len(self.chain.channels) > 1:
                    rec["chan"] = chan.label
            else:
                try:
                    ip, ur, upstream = await self.open_direct(host, port)
                except PrivateAddress as e:
                    await self.deny(writer, rec, 403, "private-address",
                                    "Private address forbidden by envbox", resolved=e.resolved)
                    return
                except OpenFailed as e:
                    await self.deny(writer, rec, 502, e.reason, e.text)
                    return
                rec["ip"] = ip
                if self.chain:
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
                    if used is not None and used.auth:
                        headers.append(f"Proxy-Authorization: {used.basic()}")
                req = f"{method} {target_line} HTTP/1.1\r\n" + "".join(h + "\r\n" for h in headers)
                first = (req + ("" if websocket else "Connection: close\r\n") + "\r\n").encode("latin-1")
            up, down, end, timing = await self.pipe(reader, writer, ur, upstream, first)
            self.write({"id": cid, "event": "close", "host": host, "port": port,
                        "up": up, "down": down, "ms": int((time.monotonic() - t0) * 1000), "end": end,
                        **timing, **({"idle": True} if end == "idle" else {})})
        except Exception as e:  # журнал не должен ронять прокси
            self.write({**rec, "event": "error", "reason": f"internal: {e!r}"})
        finally:
            for w in (writer, upstream):
                if w is not None:
                    try:
                        w.close()
                    except Exception:
                        pass


def build_chain(specs, upstream, log_dir):
    """Цепочка каналов из --chain: proxy (это --upstream), direct, vpn:<вид>:<путь к конфигурации>."""
    channels = []
    for i, spec in enumerate(specs):
        try:
            kind, vkind, path = parse_chain_spec(spec)
        except ValueError as e:
            sys.exit(f"envbox-net: {e}")
        if kind == "proxy":
            if upstream is None:
                sys.exit("envbox-net: в --chain есть proxy, но не задан --upstream")
            channels.append(Channel("proxy", "proxy", upstream))
        elif kind == "direct":
            channels.append(Channel("direct", "direct"))
        else:
            stem = os.path.splitext(os.path.basename(path))[0]
            channels.append(Channel(f"vpn:{stem}", "vpn",
                                    client=VpnClient(vkind, path, os.path.join(log_dir, f"vpn-{i}.log"))))
    if upstream is not None and not any(c.kind == "proxy" for c in channels):
        sys.exit("envbox-net: задан --upstream, но в --chain нет proxy: прокси не будет использован")
    return Chain(channels)


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
    chain = build_chain(a.chain, upstream, os.path.dirname(os.path.abspath(a.log))) if a.chain else None
    proxy = Proxy(a.log, a.allow, a.allow_private, upstream, a.dns, a.direct, chain=chain)

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
                     "chain": proxy.chain.describe() if chain is not None else None,
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
        proxy.begin()
        await stop.wait()
        watcher.cancel()
        proxy.end()
        server.close()
        proxy.write({"event": "proxy-stop"})

    asyncio.run(main())
    # потоки DNS-запросов могли зависнуть на ответе сервера: ждать их при выходе незачем (журнал построчный)
    os._exit(0)
