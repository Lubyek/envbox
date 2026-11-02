"""Сетевой шлюз: прокси, DNS, подключение, проверка имён, разбор аргументов, Git, быстрый вход."""
import asyncio
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "src"))

import build  # noqa: E402
from envbox.net.common import canon_host, is_public  # noqa: E402
from envbox.net.connect import connect_race, interleave  # noqa: E402
from envbox.net.dns import Resolver, _dns_parse, is_ip_literal, is_private_name  # noqa: E402
from envbox.net.entry import net_parse  # noqa: E402
from envbox.net.proxy import Proxy  # noqa: E402
from envbox.net.report import fmt_event  # noqa: E402
from envbox.net.upstream import Upstream  # noqa: E402


class HostChecks(unittest.TestCase):
    def test_fake_ip_range_is_usable(self):
        # DNS VPN-клиентов в режиме fake-ip отдаёт 198.18.0.0/15: это не «частный адрес»
        self.assertTrue(is_public("198.18.0.5"))
        self.assertTrue(is_public("198.19.255.254"))
        for bad in ("10.1.2.3", "192.168.1.1", "127.0.0.1", "100.64.0.1", "169.254.1.1", "0.0.0.0", "::1",
                    "::ffff:127.0.0.1", "fe80::1"):
            self.assertFalse(is_public(bad), bad)
        self.assertTrue(is_public("8.8.8.8"))

    def test_idna_cannot_hide_a_private_address(self):
        # «1²7.0.0.1» после IDNA-кодирования — 127.0.0.1: проверять нужно каноничное имя
        name = canon_host("1²7.0.0.1")
        self.assertEqual(name, "127.0.0.1")
        self.assertTrue(is_private_name(name))
        self.assertTrue(is_ip_literal(name))

    def test_canon_host_rejects_junk(self):
        for bad in ("", "a b", "a\nb", "a\r\nX: y", "ex/ample.com", "a@b.com", "x" * 300, "a..b", "a%b", "evil\x1b[0m.com"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                canon_host(bad)
        self.assertEqual(canon_host("Example.COM"), "example.com")
        self.assertEqual(canon_host("2001:DB8::1"), "2001:db8::1")
        self.assertEqual(canon_host("пример.рф"), "xn--e1afmkfd.xn--p1ai")

    def test_dns_parse_survives_short_rdata(self):
        # ответ с rdlength=16, но обрезанными данными раньше ронял разбор ValueError
        head = b"\x12\x34\x81\x80\x00\x00\x00\x01\x00\x00\x00\x00"
        answer = b"\xc0\x0c\x00\x1c\x00\x01\x00\x00\x00\x3c\x00\x10" + b"\x20\x01"
        with self.assertRaises(OSError):
            _dns_parse(head + answer, 0x1234)


class Connect(unittest.IsolatedAsyncioTestCase):
    def test_interleave(self):
        self.assertEqual(interleave(["::1", "::2", "1.1.1.1", "2.2.2.2"]), ["::1", "1.1.1.1", "::2", "2.2.2.2"])
        self.assertEqual(interleave(["1.1.1.1", "::1"]), ["1.1.1.1", "::1"])

    async def test_falls_back_to_next_address(self):
        server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            # 127.0.0.2 на этом порту никто не слушает: отказ, затем подключение к рабочему адресу
            ip, _r, w = await connect_race(["127.0.0.2", "127.0.0.1"], port, timeout=5)
            self.assertEqual(ip, "127.0.0.1")
            w.close()
            with self.assertRaises(OSError):
                await connect_race(["127.0.0.2"], port, timeout=5)
        finally:
            server.close()


class ResolverTests(unittest.IsolatedAsyncioTestCase):
    async def test_cache_coalesces_and_remembers_failures(self):
        calls = []

        def fake(host, port, family, type_):
            calls.append(host)
            if host == "bad.example":
                raise socket.gaierror(-2, "Name or service not known")
            return [(2, 1, 6, "", ("93.184.216.34", 0)), (2, 1, 6, "", ("93.184.216.34", 0))]

        r = Resolver()
        with mock.patch("socket.getaddrinfo", fake):
            first = await asyncio.gather(*(r.resolve("ok.example") for _ in range(5)))
            self.assertTrue(all(x == ["93.184.216.34"] for x in first))
            await r.resolve("ok.example")
            self.assertEqual(calls.count("ok.example"), 1)          # один запрос на всех и потом из кэша
            for _ in range(3):
                with self.assertRaises(OSError):
                    await r.resolve("bad.example")
            self.assertEqual(calls.count("bad.example"), 1)         # отказ тоже помнится на короткое время
        self.assertEqual(await r.resolve("1.2.3.4"), ["1.2.3.4"])


async def start_proxy(tmp, **kw):
    sock_path = os.path.join(tmp, "p.sock")
    proxy = Proxy(os.path.join(tmp, "net.log"), kw.pop("allow", []), kw.pop("allow_private", True), **kw)
    server = await asyncio.start_unix_server(proxy.handle, path=sock_path, limit=64 * 1024)
    return proxy, server, sock_path


async def ask(sock_path, request, read=65536, close_write=False):
    r, w = await asyncio.open_unix_connection(sock_path)
    w.write(request)
    await w.drain()
    if close_write:
        w.write_eof()
    data = await asyncio.wait_for(r.read(read), 10)
    return data, r, w


class ProxyTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="eb")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    async def start(self, **kw):
        started = await start_proxy(self.tmp, **kw)
        self.addCleanup(lambda: started[0].log.close())
        return started

    async def echo_server(self):
        async def handle(r, w):
            w.write(b"hello:" + await r.read(100))
            await w.drain()
            w.close()
        srv = await asyncio.start_server(handle, "127.0.0.1", 0)
        return srv, srv.sockets[0].getsockname()[1]

    async def test_connect_tunnel_and_log(self):
        proxy, server, path = await self.start()
        echo, port = await self.echo_server()
        try:
            data, r, w = await ask(path, f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
            self.assertTrue(data.startswith(b"HTTP/1.1 200"), data)
            w.write(b"ping")
            await w.drain()
            self.assertEqual(await asyncio.wait_for(r.read(100), 10), b"hello:ping")
            w.close()
        finally:
            server.close()
            echo.close()
        await asyncio.sleep(0.1)
        with open(os.path.join(self.tmp, "net.log"), encoding="utf-8") as f:
            events = [json.loads(line) for line in f]
        self.assertIn("open", [e["event"] for e in events])
        self.assertIn("close", [e["event"] for e in events])

    async def test_private_address_denied_fast_and_names_the_host(self):
        proxy, server, path = await self.start(allow_private=False)
        try:
            data, _r, w = await ask(path, b"CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: x\r\n\r\n", read=-1)
            self.assertTrue(data.startswith(b"HTTP/1.1 403"), data)
            self.assertIn(b"127.0.0.1", data)
            w.close()
        finally:
            server.close()

    async def test_allowlist_wildcard_matches_platform_claude_com(self):
        proxy, server, path = await self.start(allow=["*.anthropic.com", "*.claude.ai", "*.claude.com"])
        try:
            self.assertTrue(proxy.allowed("platform.claude.com"))
            self.assertTrue(proxy.allowed("claude.ai"))
            self.assertTrue(proxy.allowed("api.anthropic.com"))
            self.assertFalse(proxy.allowed("evilclaude.com"))
            data, _r, w = await ask(path, b"CONNECT example.org:443 HTTP/1.1\r\nHost: x\r\n\r\n", read=-1)
            self.assertTrue(data.startswith(b"HTTP/1.1 403"), data)
            self.assertIn(b"example.org", data)
            w.close()
        finally:
            server.close()

    async def test_header_injection_in_host_is_rejected(self):
        proxy, server, path = await self.start()
        try:
            data, _r, w = await ask(path, b"CONNECT a\nX-Evil:443 HTTP/1.1\r\nHost: x\r\n\r\n", read=-1)
            self.assertTrue(data.startswith(b"HTTP/1.1 400"), data)
            w.close()
        finally:
            server.close()

    async def test_plain_http_is_forwarded(self):
        async def web(r, w):
            await r.readuntil(b"\r\n\r\n")
            w.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            await w.drain()
            w.close()
        srv = await asyncio.start_server(web, "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        proxy, server, path = await self.start()
        try:
            data, _r, w = await ask(path, f"GET http://127.0.0.1:{port}/x HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".encode(), read=-1)
            self.assertTrue(data.endswith(b"ok"), data)
            w.close()
        finally:
            server.close()
            srv.close()

    async def test_direct_sites_bypass_the_upstream_proxy(self):
        echo, port = await self.echo_server()
        dead = Upstream("http://127.0.0.1:1")                      # вышестоящий прокси, к которому не подключиться
        proxy, server, path = await self.start(upstream=dead, direct=["127.0.0.1"])
        try:
            data, _r, w = await ask(path, f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
            self.assertTrue(data.startswith(b"HTTP/1.1 200"), data)    # из списка: идёт мимо мёртвого прокси
            w.close()
            data, _r, w = await ask(path, f"CONNECT localhost:{port} HTTP/1.1\r\nHost: x\r\n\r\n".encode(), read=-1)
            self.assertTrue(data.startswith(b"HTTP/1.1 502"), data)    # не из списка: через вышестоящий прокси
            w.close()
        finally:
            server.close()
            echo.close()
        await asyncio.sleep(0.1)
        with open(os.path.join(self.tmp, "net.log"), encoding="utf-8") as f:
            events = [json.loads(line) for line in f]
        self.assertTrue(any(e.get("event") == "open" and e.get("direct") for e in events))

    async def test_direct_sites_still_obey_the_private_address_ban(self):
        dead = Upstream("http://127.0.0.1:1")
        proxy, server, path = await self.start(allow_private=False, upstream=dead, direct=["127.0.0.1"])
        try:
            data, _r, w = await ask(path, b"CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: x\r\n\r\n", read=-1)
            self.assertTrue(data.startswith(b"HTTP/1.1 403"), data)    # «напрямую» не открывает localhost
            w.close()
        finally:
            server.close()

    async def test_direct_sites_are_allowed_in_allowlist_mode(self):
        proxy, server, path = await self.start(allow=["example.com"], direct=["*.2gis.ru"])
        server.close()
        self.assertTrue(proxy.allowed("example.com"))
        self.assertTrue(proxy.allowed("maps.2gis.ru"))
        self.assertTrue(proxy.allowed("2gis.ru"))
        self.assertFalse(proxy.allowed("evil2gis.ru"))
        self.assertFalse(proxy.allowed("evil.com"))

    def read_log(self):
        with open(os.path.join(self.tmp, "net.log"), encoding="utf-8") as f:
            return [json.loads(line) for line in f]

    async def test_dead_tunnel_is_closed_after_idle_timeout(self):
        async def silent(r, w):          # принимает запрос и молчит: как туннель, по которому пропал ответ
            await r.read(100)
            await r.read()
            w.close()
        srv = await asyncio.start_server(silent, "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        proxy, server, path = await self.start(idle=0.4)
        try:
            data, r, w = await ask(path, f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
            self.assertTrue(data.startswith(b"HTTP/1.1 200"), data)
            w.write(b"request")
            await w.drain()
            # прокси сам обрывает мёртвый туннель: клиент получает конец потока, а не ждёт свой тайм-аут
            self.assertEqual(await asyncio.wait_for(r.read(100), 5), b"")
            w.close()
        finally:
            server.close()
            srv.close()
        await asyncio.sleep(0.3)
        self.assertTrue(any(e.get("event") == "close" and e.get("idle") for e in self.read_log()))

    async def test_active_stream_survives_the_idle_timeout(self):
        async def trickle(r, w):         # SSE-подобный поток: байты идут часто, но дольше, чем таймаут бездействия
            await r.read(100)
            for _ in range(6):
                w.write(b"x")
                await w.drain()
                await asyncio.sleep(0.2)
            w.close()
        srv = await asyncio.start_server(trickle, "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        proxy, server, path = await self.start(idle=0.5)
        try:
            data, r, w = await ask(path, f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
            self.assertTrue(data.startswith(b"HTTP/1.1 200"), data)
            w.write(b"go")
            await w.drain()
            got = b""
            while True:
                chunk = await asyncio.wait_for(r.read(100), 5)
                if not chunk:
                    break
                got += chunk
            self.assertEqual(got, b"xxxxxx")
            w.close()
        finally:
            server.close()
            srv.close()
        await asyncio.sleep(0.3)
        self.assertFalse(any(e.get("idle") for e in self.read_log()))

    async def test_slow_upstream_tunnel_is_hedged(self):
        conns = []

        async def fake_upstream(r, w):
            conns.append(1)
            first = len(conns) == 1
            await r.readuntil(b"\r\n\r\n")
            if first:
                await r.read()           # первый туннель «завис»: ответа нет, пока прокси сам его не закроет
                w.close()
                return
            w.write(b"HTTP/1.1 200 OK\r\n\r\n")
            await w.drain()
            w.write(b"hello:" + await r.read(100))
            await w.drain()
            w.close()
        srv = await asyncio.start_server(fake_upstream, "127.0.0.1", 0)
        uport = srv.sockets[0].getsockname()[1]
        proxy, server, path = await self.start(upstream=Upstream(f"http://127.0.0.1:{uport}"), hedge=0.2)
        try:
            data, r, w = await ask(path, b"CONNECT 93.184.216.34:443 HTTP/1.1\r\nHost: x\r\n\r\n")
            self.assertTrue(data.startswith(b"HTTP/1.1 200"), data)    # ответил второй туннель, а не завис первый
            w.write(b"ping")
            await w.drain()
            self.assertEqual(await asyncio.wait_for(r.read(100), 5), b"hello:ping")
            w.close()
        finally:
            server.close()
            srv.close()
        self.assertEqual(len(conns), 2)

    async def test_hedging_is_capped_when_the_upstream_is_overloaded(self):
        conns = []

        async def slow_upstream(r, w):
            conns.append(1)
            await r.readuntil(b"\r\n\r\n")
            await asyncio.sleep(0.5)     # медленно отвечает всем: второй туннель только добавил бы нагрузки
            w.write(b"HTTP/1.1 200 OK\r\n\r\n")
            await w.drain()
            w.close()
        srv = await asyncio.start_server(slow_upstream, "127.0.0.1", 0)
        uport = srv.sockets[0].getsockname()[1]
        proxy, server, path = await self.start(upstream=Upstream(f"http://127.0.0.1:{uport}"),
                                               hedge=0.1, max_hedges=0)
        try:
            data, _r, w = await ask(path, b"CONNECT 93.184.216.34:443 HTTP/1.1\r\nHost: x\r\n\r\n")
            self.assertTrue(data.startswith(b"HTTP/1.1 200"), data)
            w.close()
        finally:
            server.close()
            srv.close()
        self.assertEqual(len(conns), 1)
        self.assertEqual(proxy.hedging, 0)

    async def test_burst_of_connections_waits_in_line_for_the_upstream(self):
        active, peak, conns = [0], [0], []

        async def upstream_server(r, w):
            conns.append(1)
            await r.readuntil(b"\r\n\r\n")
            active[0] += 1
            peak[0] = max(peak[0], active[0])
            await asyncio.sleep(0.15)    # установка туннеля занимает время: одновременно их не должно быть больше лимита
            w.write(b"HTTP/1.1 200 OK\r\n\r\n")
            await w.drain()
            active[0] -= 1
            await r.read()
            w.close()
        srv = await asyncio.start_server(upstream_server, "127.0.0.1", 0)
        uport = srv.sockets[0].getsockname()[1]
        proxy, server, path = await self.start(upstream=Upstream(f"http://127.0.0.1:{uport}"),
                                               hedge=5, max_setups=2)
        try:
            async def one():
                data, _r, w = await ask(path, b"CONNECT 93.184.216.34:443 HTTP/1.1\r\nHost: x\r\n\r\n")
                w.close()
                return data

            results = await asyncio.gather(*(one() for _ in range(6)))
            self.assertTrue(all(d.startswith(b"HTTP/1.1 200") for d in results), results)
        finally:
            server.close()
            srv.close()
        self.assertEqual(len(conns), 6)
        self.assertLessEqual(peak[0], 2)
        await asyncio.sleep(0.3)
        log = self.read_log()
        self.assertTrue(any(e.get("wait_ms") for e in log if e.get("event") == "open"))   # очередь видна в журнале

    async def test_close_event_says_who_ended_the_connection(self):
        async def short(r, w):           # сервер сам закрывает после ответа
            await r.read(100)
            w.write(b"bye")
            await w.drain()
            w.close()
        srv = await asyncio.start_server(short, "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        proxy, server, path = await self.start()
        try:
            data, r, w = await ask(path, f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
            w.write(b"hi")
            await w.drain()
            self.assertEqual(await asyncio.wait_for(r.read(100), 5), b"bye")
            w.close()
        finally:
            server.close()
            srv.close()
        await asyncio.sleep(0.3)
        closes = [e for e in self.read_log() if e.get("event") == "close"]
        self.assertEqual(closes[-1].get("end"), "upstream")

    async def test_close_event_has_timing_marks_for_stuck_connections(self):
        # «запрос ушёл, а ответа нет»: по меткам видно, когда клиент договорил и пришёл ли хоть один байт ответа
        async def slow(r, w):
            await r.read(100)
            await asyncio.sleep(0.4)
            w.write(b"late")
            await w.drain()
            await asyncio.sleep(0.2)
            w.close()
        srv = await asyncio.start_server(slow, "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        proxy, server, path = await self.start()
        try:
            data, r, w = await ask(path, f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
            w.write(b"hi")
            await w.drain()
            await asyncio.wait_for(r.read(100), 5)
            w.close()
        finally:
            server.close()
            srv.close()
        await asyncio.sleep(0.3)
        close = [e for e in self.read_log() if e.get("event") == "close"][-1]
        self.assertLess(close["up_end"], 300)                        # клиент договорил сразу
        self.assertGreaterEqual(close["down_first"], 350)            # ответ пришёл только через 0.4 с
        self.assertGreaterEqual(close["down_last"], close["down_first"])

    async def test_hedging_reports_the_error_when_every_tunnel_fails(self):
        async def refuse(r, w):
            await r.readuntil(b"\r\n\r\n")
            w.write(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            await w.drain()
            w.close()
        srv = await asyncio.start_server(refuse, "127.0.0.1", 0)
        uport = srv.sockets[0].getsockname()[1]
        proxy, server, path = await self.start(upstream=Upstream(f"http://127.0.0.1:{uport}"), hedge=0.05)
        try:
            data, _r, w = await ask(path, b"CONNECT 93.184.216.34:443 HTTP/1.1\r\nHost: x\r\n\r\n", read=-1)
            self.assertTrue(data.startswith(b"HTTP/1.1 502"), data)
            w.close()
        finally:
            server.close()
            srv.close()

    async def test_log_rotates_while_running(self):
        proxy, server, path = await self.start()
        server.close()
        with mock.patch("envbox.net.proxy.LOG_LIMIT", 1000), mock.patch("envbox.net.proxy.LOG_CHECK_EVERY", 5):
            for i in range(60):
                proxy.write({"event": "open", "host": "example.com", "port": 443, "i": i})
        self.assertTrue(os.path.exists(os.path.join(self.tmp, "net.log.1")))


class ArgsAndReport(unittest.TestCase):
    def test_proxy_args(self):
        a = net_parse("proxy", ["--socket", "/s", "--log", "/l", "--allow", "a.com", "--allow", "*.b.com",
                                "--allow-private", "--parent-pid", "42", "--upstream", "socks5://h:1", "--dns", "1.1.1.1"])
        self.assertEqual((a.socket, a.log, a.allow, a.allow_private, a.parent_pid, a.upstream, a.dns),
                         ("/s", "/l", ["a.com", "*.b.com"], True, 42, "socks5://h:1", ["1.1.1.1"]))

    def test_wrap_args_keep_the_command_intact(self):
        a = net_parse("wrap", ["--map", "3128:/p", "--inbox-callback", "--", "claude", "--resume", "-x"])
        self.assertEqual((a.map, a.inbox_callback, a.cmd), (["3128:/p"], True, ["claude", "--resume", "-x"]))

    def test_gitcheck_and_errors(self):
        a = net_parse("gitcheck", ["verify", "/w", "/s"])
        self.assertEqual((a.action, a.workdir, a.snapshot), ("verify", "/w", "/s"))
        self.assertIsNone(net_parse("gitcheck", ["snapshot", "/w"]).snapshot)
        for mode, argv in (("proxy", ["--socket", "/s"]), ("seccomp", ["--bogus"]), ("gitcheck", ["bad", "/w"])):
            with self.assertRaises(SystemExit) as cm, mock.patch("sys.stderr"):
                net_parse(mode, argv)
            self.assertEqual(cm.exception.code, 2)

    def test_terminal_escape_sequences_are_removed(self):
        line = fmt_event({"event": "deny", "host": "evil\x1b]0;pwned\x07.com", "port": 443, "reason": "x\x1b[2J"})
        self.assertNotIn("\x1b", line)
        self.assertNotIn("\x07", line)


class GitCheck(unittest.TestCase):
    def run_gitcheck(self, *args):
        return subprocess.run([sys.executable, "-I", os.path.join(ROOT, "dist", "envbox.py"), "gitcheck", *args],
                              capture_output=True, text=True, timeout=60)

    def snapshot(self, work):
        snap = os.path.join(work, "snap.json")
        r = self.run_gitcheck("snapshot", work)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(snap, "w", encoding="utf-8") as f:
            f.write(r.stdout)
        return snap

    def test_commondir_and_new_git_are_noticed(self):
        work = tempfile.mkdtemp(prefix="eb")
        self.addCleanup(shutil.rmtree, work, True)
        # проект без .git: среда может создать его сама (хук, config)
        snap = self.snapshot(work)
        self.assertEqual(self.run_gitcheck("verify", work, snap).returncode, 0)
        os.makedirs(os.path.join(work, ".git", "hooks"))
        with open(os.path.join(work, ".git", "config"), "w") as f:
            f.write("[core]\n")
        r = self.run_gitcheck("verify", work, snap)
        self.assertEqual(r.returncode, 4)
        self.assertIn("создан", r.stderr)
        # репозиторий есть; .sample-хуки не шумят, а commondir — тревога
        snap = self.snapshot(work)
        with open(os.path.join(work, ".git", "hooks", "pre-commit.sample"), "w") as f:
            f.write("#!/bin/sh\n")
        self.assertEqual(self.run_gitcheck("verify", work, snap).returncode, 0)
        with open(os.path.join(work, ".git", "commondir"), "w") as f:
            f.write("../elsewhere\n")
        r = self.run_gitcheck("verify", work, snap)
        self.assertEqual(r.returncode, 4)
        self.assertIn("commondir", r.stderr)


class FastEntry(unittest.TestCase):
    def test_helper_commands_do_not_load_the_rest_of_the_program(self):
        """version/seccomp/gitcheck/wrap должны стартовать без asyncio, argparse, dataclasses и subprocess."""
        dist = os.path.join(ROOT, "dist", "envbox.py")
        for args in (["version"], ["seccomp"], ["wrap", "--", "true"]):
            r = subprocess.run([sys.executable, "-I", "-X", "importtime", dist, *args],
                               capture_output=True, timeout=60)      # seccomp пишет в stdout двоичные данные
            err = r.stderr.decode("utf-8", "replace")
            self.assertEqual(r.returncode, 0, err[-500:])
            loaded = {line.split("|")[-1].strip() for line in err.splitlines() if "|" in line}
            for heavy in ("asyncio", "argparse", "dataclasses", "subprocess", "shutil", "json"):
                self.assertNotIn(heavy, loaded, f"{args[0]}: загружен {heavy}")

    def test_fast_entry_precedes_the_rest_in_the_bundle(self):
        text = build.build_text()
        self.assertLess(text.index("sys.exit(net_main())"), text.index("\nimport subprocess\n"))
        self.assertLess(text.index("sys.exit(net_main())"), text.index("class Profile"))


class Gui(unittest.TestCase):
    def test_net_summary_is_incremental_and_matches_full_recount(self):
        from envbox.core.netlog import NetSummary, summarize
        events = [{"ts": f"2026-11-01T10:00:{i % 60:02d}", "event": ev, "host": f"h{i % 5}", "port": 443,
                   "ip": "1.1.1.1", "up": 10, "down": 20}
                  for i in range(100) for ev in ("open", "close", "deny")]
        inc = NetSummary()
        for i in range(0, len(events), 7):
            inc.add(events[i:i + 7])
        self.assertEqual(inc.rows(), summarize(events))
        row = next(r for r in inc.rows() if r["host"] == "h0")
        self.assertEqual((row["open"], row["deny"], row["up"], row["down"]), (20, 20, 200, 400))

    def test_session_scan_reads_only_bwrap_cmdlines(self):
        from envbox.core.sessions import list_sessions

        def proc(pid, comm, args, ppid=1):
            d = os.path.join(root, str(pid))
            os.makedirs(d)
            with open(os.path.join(d, "comm"), "w") as f:
                f.write(comm + "\n")
            with open(os.path.join(d, "cmdline"), "wb") as f:
                f.write(b"\0".join(a.encode() for a in args) + b"\0")
            with open(os.path.join(d, "stat"), "w") as f:
                f.write(f"{pid} ({comm}) S {ppid} " + " ".join(["0"] * 17) + " 500 " + " ".join(["0"] * 5))

        root = tempfile.mkdtemp(prefix="eb")
        self.addCleanup(shutil.rmtree, root, True)
        proc(100, "bwrap", ["bwrap", "--setenv", "ENVBOX_SESSION", "demo", "--", "claude"])
        proc(101, "bwrap", ["bwrap", "--setenv", "ENVBOX_SESSION", "demo", "--", "sleep"], ppid=100)   # внутренний
        proc(200, "bash", ["bash"])
        proc(300, "bwrap", ["bwrap", "--unshare-user", "--", "true"])                                  # не среда envbox
        with open(os.path.join(root, "uptime"), "w") as f:
            f.write("1000.00 0.0\n")
        found = list_sessions(root)
        self.assertEqual([(x.pid, x.name, x.command, x.inner) for x in found], [(100, "demo", "claude", (101,))])

    def test_cdp_socket_must_be_a_real_socket(self):
        from envbox.cdp.http import CdpError, _unix_connect
        d = tempfile.mkdtemp(prefix="eb")
        self.addCleanup(shutil.rmtree, d, True)
        real = os.path.join(d, "r.sock")
        ls = socket.socket(socket.AF_UNIX)
        self.addCleanup(ls.close)
        ls.bind(real)
        ls.listen(4)
        _unix_connect(real).close()
        os.symlink(real, os.path.join(d, "l.sock"))     # среда подложила ссылку на чужой сокет
        with self.assertRaises(CdpError):
            _unix_connect(os.path.join(d, "l.sock"))
        with self.assertRaises(CdpError):
            _unix_connect(os.path.join(d, "missing.sock"))


class Install(unittest.TestCase):
    def test_pyc_is_rebuilt_after_python_upgrade(self):
        from envbox import install
        d = tempfile.mkdtemp(prefix="eb")
        self.addCleanup(shutil.rmtree, d, True)
        py, pyc = os.path.join(d, "envbox.py"), os.path.join(d, "envbox.pyc")
        shutil.copy(os.path.join(ROOT, "dist", "envbox.py"), py)
        with mock.patch.multiple(install, INSTALLED_PY=py, INSTALLED_PYC=pyc, INSTALLED_PYC_TAG=pyc + ".python"):
            self.assertTrue(install.compile_installed())
            self.assertFalse(install.compile_installed())               # ничего не изменилось — не пересобираем
            with open(pyc + ".python", encoding="utf-8") as f:
                self.assertEqual(f.read(), os.path.realpath("/usr/bin/python3"))
            with open(pyc + ".python", "w", encoding="utf-8") as f:
                f.write("/usr/bin/python3.0")                           # система обновила Python
            self.assertTrue(install.compile_installed())
            os.unlink(pyc + ".python")
            self.assertTrue(install.compile_installed())


    def test_install_keeps_a_newer_copy_unless_forced(self):
        from envbox import install
        from envbox.version import ENVBOX_VERSION
        d = tempfile.mkdtemp(prefix="eb")
        self.addCleanup(shutil.rmtree, d, True)
        home, inst = os.path.join(d, "home"), os.path.join(d, "inst")
        os.makedirs(home)
        os.makedirs(inst)
        py, old = os.path.join(inst, "envbox.py"), os.path.join(d, "old.py")
        dist = os.path.join(ROOT, "dist", "envbox.py")
        shutil.copy(dist, py)
        with open(dist, encoding="utf-8") as f:
            text = f.read().replace(f'ENVBOX_VERSION = "{ENVBOX_VERSION}"', 'ENVBOX_VERSION = "2020.01.01.1"')
        with open(old, "w", encoding="utf-8") as f:
            f.write(text)
        with mock.patch.multiple(install, INSTALL_DIR=inst, INSTALLED_PY=py, INSTALLED_PYC=py + "c",
                                 INSTALLED_PYC_TAG=py + "c.python", ENVBOX_SH=os.path.join(inst, "envbox.sh"),
                                 bundle_path=lambda: old), \
                mock.patch.dict(os.environ, {"HOME": home, "ENVBOX_NO_REEXEC": "1"}):
            install.ensure_installed()
            self.assertEqual(install.file_version_text(py), ENVBOX_VERSION)    # старый запуск новую копию не затирает
            install.ensure_installed(force=True)
            self.assertEqual(install.file_version_text(py), "2020.01.01.1")    # --force затирает


class VersionLabel(unittest.TestCase):
    def test_version_is_shown_by_the_bundle_and_compared_with_installed(self):
        from envbox.install import file_version, file_version_text
        from envbox.version import ENVBOX_VERSION
        dist = os.path.join(ROOT, "dist", "envbox.py")
        out = subprocess.run([sys.executable, "-I", dist, "--version"], capture_output=True, text=True).stdout.strip()
        self.assertEqual(out, ENVBOX_VERSION)
        self.assertEqual(file_version_text(dist), ENVBOX_VERSION)           # с ведущими нулями, как в version.py
        self.assertEqual(file_version(dist), tuple(int(x) for x in ENVBOX_VERSION.split(".")))
        self.assertIsNone(file_version_text(os.path.join(ROOT, "нет-такого-файла")))


class Presets(unittest.TestCase):
    def test_claude_preset_covers_oauth_refresh(self):
        from envbox.core.profile import Profile
        p = Profile.claude_preset("c")
        self.assertIn("*.claude.com", p.allow_domains)       # platform.claude.com: обновление токена
        self.assertIn("*.anthropic.com", p.allow_domains)
        self.assertFalse(p.validate() and [e for e in p.validate() if "claude" in e.lower()])

    def test_old_preset_is_upgraded_on_load(self):
        from envbox.core.consts import OLD_CLAUDE_DOMAINS
        from envbox.core.profile import Profile
        p = Profile.from_dict({"name": "c", "net": "allowlist", "allow_domains": list(OLD_CLAUDE_DOMAINS)})
        self.assertIn("*.claude.com", p.allow_domains)
        custom = Profile.from_dict({"name": "c", "net": "allowlist", "allow_domains": ["example.com"]})
        self.assertEqual(custom.allow_domains, ["example.com"])    # чужие списки не трогаем

    def test_desktop_preset_allows_the_claude_bridge(self):
        # без bridge.claudeusercontent.com Claude Desktop повторяет попытку каждые секунды: «Connection problem»
        from envbox.core.consts import CLAUDE_DOMAINS, OLD_CLAUDE_DOMAINS
        from envbox.core.profile import Profile
        p = Profile.claude_desktop_preset("d")
        self.assertIn("bridge.claudeusercontent.com", p.allow_domains)
        self.assertNotIn("bridge.claudeusercontent.com", Profile.claude_preset("c").allow_domains)   # CLI он не нужен
        for old in (list(CLAUDE_DOMAINS), list(OLD_CLAUDE_DOMAINS)):
            q = Profile.from_dict({"name": "d", "net": "allowlist", "link_handler": "claude-desktop",
                                   "allow_domains": old})
            self.assertIn("bridge.claudeusercontent.com", q.allow_domains)
        custom = Profile.from_dict({"name": "d", "net": "allowlist", "link_handler": "claude-desktop",
                                    "allow_domains": ["example.com"]})
        self.assertEqual(custom.allow_domains, ["example.com"])      # свои списки не трогаем

    def test_desktop_preset_allows_the_login_captcha(self):
        # вход на claude.ai проверяется через hCaptcha; без js.hcaptcha.com: «Couldn't verify your browser»
        from envbox.core.consts import OLD_CLAUDE_DESKTOP_DOMAINS
        from envbox.core.profile import Profile
        from envbox.net.proxy import host_matches
        p = Profile.claude_desktop_preset("d")
        self.assertTrue(host_matches(p.allow_domains, "js.hcaptcha.com"))
        self.assertFalse(host_matches(Profile.claude_preset("c").allow_domains, "js.hcaptcha.com"))
        q = Profile.from_dict({"name": "d", "net": "allowlist", "link_handler": "claude-desktop",
                               "allow_domains": list(OLD_CLAUDE_DESKTOP_DOMAINS)})
        self.assertTrue(host_matches(q.allow_domains, "js.hcaptcha.com"))     # прежний пресет обновляется
        custom = Profile.from_dict({"name": "d", "net": "allowlist", "link_handler": "claude-desktop",
                                    "allow_domains": OLD_CLAUDE_DESKTOP_DOMAINS + ["example.com"]})
        self.assertNotIn("*.hcaptcha.com", custom.allow_domains)               # свои списки не трогаем

    def test_desktop_preset_allows_google_login_and_frames(self):
        # «Войти через Google» — окно внутри приложения; предпросмотр грузится с <случайное>.frame.claudeusercontent.com
        from envbox.core.consts import OLD_CLAUDE_DESKTOP_DOMAINS_V2
        from envbox.core.profile import Profile
        from envbox.net.proxy import host_matches
        p = Profile.claude_desktop_preset("d")
        for host in ("accounts.google.com", "www.google.com", "ssl.gstatic.com",
                     "a2f0cfb4-a34b-49df-8ef7-6c32556880c2.frame.claudeusercontent.com"):
            self.assertTrue(host_matches(p.allow_domains, host), host)
        for host in ("mail.google.com", "drive.google.com", "api.github.com", "o1.ingest.us.sentry.io"):
            self.assertFalse(host_matches(p.allow_domains, host), host)     # лишнего не открываем
        q = Profile.from_dict({"name": "d", "net": "allowlist", "link_handler": "claude-desktop",
                               "allow_domains": list(OLD_CLAUDE_DESKTOP_DOMAINS_V2)})
        self.assertTrue(host_matches(q.allow_domains, "accounts.google.com"))   # прежний пресет обновляется

    def test_timeout_errors_are_not_logged_with_an_empty_reason(self):
        from envbox.net.proxy import err_text
        self.assertEqual(err_text(asyncio.TimeoutError()), "TimeoutError")
        self.assertEqual(err_text(OSError("нет маршрута")), "нет маршрута")

    def test_direct_domains_are_passed_only_with_upstream(self):
        from envbox.core.profile import Profile
        p = Profile(name="t", no_workdir=True, direct_domains=["*.2gis.ru"])
        self.assertNotIn("--direct-domain", p.envbox_args())       # без своего прокси всё и так напрямую
        p.upstream = "socks5://127.0.0.1:1080"
        a = p.envbox_args()
        self.assertEqual(a[a.index("--direct-domain") + 1], "*.2gis.ru")
        self.assertEqual(p.validate(), [])
        p.direct_domains = ["bad domain"]
        self.assertTrue([e for e in p.validate() if "прямого" in e])


FAKE_WIREPROXY = r"""#!/usr/bin/env python3
import asyncio, re, sys
cfg = open(sys.argv[sys.argv.index("-c") + 1]).read()
assert "PostUp" not in cfg and "TCPServerTunnel" not in cfg, cfg
host, port = re.search(r"BindAddress\s*=\s*(\S+):(\d+)", cfg).groups()
user = re.search(r"Username\s*=\s*(\S+)", cfg).group(1)
pw = re.search(r"Password\s*=\s*(\S+)", cfg).group(1)
async def pipe(r, w):
    try:
        while (d := await r.read(4096)):
            w.write(d); await w.drain()
    finally:
        w.close()
async def handle(r, w):
    _ver, n = await r.readexactly(2)
    await r.readexactly(n)
    w.write(b"\x05\x02")
    await w.drain()
    await r.readexactly(1)
    u = await r.readexactly((await r.readexactly(1))[0])
    p = await r.readexactly((await r.readexactly(1))[0])
    ok = u.decode() == user and p.decode() == pw
    w.write(b"\x01" + (b"\x00" if ok else b"\x01"))
    await w.drain()
    if not ok:
        return w.close()
    head = await r.readexactly(4)
    if head[3] == 3:
        addr = (await r.readexactly((await r.readexactly(1))[0])).decode()
    else:
        addr = ".".join(str(b) for b in await r.readexactly(4))
    dport = int.from_bytes(await r.readexactly(2), "big")
    ur, uw = await asyncio.open_connection("127.0.0.1", dport)    # любое имя «внутри VPN» ведёт на локальный стенд
    w.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
    await w.drain()
    await asyncio.gather(pipe(r, uw), pipe(ur, w), return_exceptions=True)
async def main():
    srv = await asyncio.start_server(handle, host, int(port))
    await srv.serve_forever()
asyncio.run(main())
"""


class ChainTests(unittest.IsolatedAsyncioTestCase):
    """Цепочка каналов: прокси, VPN-клиент, прямой выход; переключение на запасной и возврат на основной."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="eb")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    async def start(self, channels, **kw):
        from envbox.net.chain import Chain
        proxy, server, path = await start_proxy(self.tmp, chain=Chain(channels), **kw)
        self.addCleanup(proxy.log.close)
        return proxy, server, path

    @staticmethod
    async def http_proxy(tag, port=0):
        """Подставной вышестоящий HTTP-прокси: принимает CONNECT и отвечает «<метка>:<данные>»."""
        async def handle(r, w):
            await r.readuntil(b"\r\n\r\n")
            w.write(b"HTTP/1.1 200 OK\r\n\r\n")
            await w.drain()
            w.write(tag + b":" + await r.read(100))
            await w.drain()
            w.close()
        srv = await asyncio.start_server(handle, "127.0.0.1", port)
        return srv, srv.sockets[0].getsockname()[1]

    @staticmethod
    def dead_port():
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        return port

    def read_log(self):
        with open(os.path.join(self.tmp, "net.log"), encoding="utf-8") as f:
            return [json.loads(line) for line in f]

    async def through(self, path, payload=b"ping"):
        data, r, w = await ask(path, b"CONNECT 93.184.216.34:443 HTTP/1.1\r\nHost: x\r\n\r\n")
        self.assertTrue(data.startswith(b"HTTP/1.1 200"), data)
        w.write(payload)
        await w.drain()
        answer = await asyncio.wait_for(r.read(100), 5)
        w.close()
        return answer

    async def test_failover_then_return_to_the_preferred_channel(self):
        import envbox.net.proxy as proxy_mod
        from envbox.net.chain import Channel
        dead = self.dead_port()
        b_srv, b_port = await self.http_proxy(b"B")
        a = Channel("a", "proxy", Upstream(f"http://127.0.0.1:{dead}"))
        b = Channel("b", "proxy", Upstream(f"http://127.0.0.1:{b_port}"))
        proxy, server, path = await self.start([a, b])
        old = proxy_mod.PROBE_EVERY
        proxy_mod.PROBE_EVERY = 0.1
        self.addCleanup(setattr, proxy_mod, "PROBE_EVERY", old)
        proxy.begin()
        a_srv = None
        try:
            self.assertEqual(await self.through(path), b"B:ping")                # первый не отвечает: идём через второй
            self.assertTrue(a.down)
            self.assertEqual(proxy.chain.order()[0], b)                          # упавший больше не пробуем первым
            self.assertEqual(await self.through(path), b"B:ping")
            a_srv, _ = await self.http_proxy(b"A", dead)                         # основной канал ожил
            for _ in range(40):
                if not a.down:
                    break
                await asyncio.sleep(0.1)
            self.assertFalse(a.down)
            self.assertEqual(await self.through(path), b"A:ping")                # новые соединения вернулись на него
        finally:
            proxy.end()
            server.close()
            b_srv.close()
            if a_srv:
                a_srv.close()
        await asyncio.sleep(0.2)
        states = [(e["state"], e["channel"]) for e in self.read_log() if e.get("event") == "channel"]
        self.assertIn(("down", a.label), states)
        self.assertIn(("up", a.label), states)
        opens = [e for e in self.read_log() if e.get("event") == "open"]
        self.assertEqual([e.get("chan") for e in opens][0], b.label)             # в журнале видно, через что шло

    async def test_direct_channel_is_the_last_resort(self):
        from envbox.net.chain import Channel
        async def answer(r, w):
            await r.read(100)
            w.write(b"direct:ok")
            await w.drain()
            w.close()
        echo = await asyncio.start_server(answer, "127.0.0.1", 0)
        port = echo.sockets[0].getsockname()[1]
        a = Channel("a", "proxy", Upstream(f"http://127.0.0.1:{self.dead_port()}"))
        proxy, server, path = await self.start([a, Channel("direct", "direct")], allow_private=True)
        try:
            data, r, w = await ask(path, f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
            self.assertTrue(data.startswith(b"HTTP/1.1 200"), data)
            w.write(b"hi")
            await w.drain()
            self.assertEqual(await asyncio.wait_for(r.read(100), 5), b"direct:ok")
            w.close()
        finally:
            server.close()
            echo.close()
        await asyncio.sleep(0.1)
        opened = [e for e in self.read_log() if e.get("event") == "open"][-1]
        self.assertTrue(opened.get("direct"))
        self.assertEqual(opened.get("chan"), "direct")

    async def test_vpn_only_fails_closed_and_never_goes_direct(self):
        # «только через VPN»: VPN не запустился/упал — отказ, а не тихий выход с настоящего адреса
        from envbox.net.chain import Channel
        hits = []

        async def secret_service(r, w):
            hits.append(1)
            w.close()
        echo = await asyncio.start_server(secret_service, "127.0.0.1", 0)
        port = echo.sockets[0].getsockname()[1]

        class Broken:
            async def start(self):
                raise OSError("не найдена программа wireproxy")

            def stop(self):
                pass
        vpn = Channel("vpn:x", "vpn", client=Broken())
        proxy, server, path = await self.start([vpn], allow_private=True)    # частные адреса разрешены: всё равно не напрямую
        proxy.begin()
        try:
            data, _r, w = await ask(path, f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: x\r\n\r\n".encode(), read=-1)
            self.assertTrue(data.startswith(b"HTTP/1.1 502"), data)
            w.close()
        finally:
            proxy.end()
            server.close()
            echo.close()
        await asyncio.sleep(0.1)
        self.assertEqual(hits, [])                                            # к цели никто не подключался
        self.assertFalse([e for e in self.read_log() if e.get("event") == "open"])
        reasons = [e["reason"] for e in self.read_log() if e.get("event") == "error"]
        self.assertTrue(any("wireproxy" in r for r in reasons), reasons)      # причина названа в журнале

    async def test_every_channel_failed_gives_one_clear_502(self):
        from envbox.net.chain import Channel
        a = Channel("a", "proxy", Upstream(f"http://127.0.0.1:{self.dead_port()}"))
        b = Channel("b", "proxy", Upstream(f"socks5://127.0.0.1:{self.dead_port()}"))
        proxy, server, path = await self.start([a, b])
        try:
            data, _r, w = await ask(path, b"CONNECT 93.184.216.34:443 HTTP/1.1\r\nHost: x\r\n\r\n", read=-1)
            self.assertTrue(data.startswith(b"HTTP/1.1 502"), data)
            w.close()
        finally:
            server.close()
        await asyncio.sleep(0.1)
        err = [e for e in self.read_log() if e.get("event") == "error"][-1]
        self.assertTrue(err["reason"].startswith("chain: "), err)
        self.assertIn(a.label, err["reason"])
        self.assertIn(b.label, err["reason"])

    async def test_vpn_client_that_cannot_start_is_skipped(self):
        from envbox.net.chain import Channel

        class Broken:
            async def start(self):
                raise OSError("не найдена программа wireproxy")

            def stop(self):
                pass
        b_srv, b_port = await self.http_proxy(b"B")
        vpn = Channel("vpn:x", "vpn", client=Broken())
        b = Channel("b", "proxy", Upstream(f"http://127.0.0.1:{b_port}"))
        proxy, server, path = await self.start([vpn, b])
        proxy.begin()
        try:
            self.assertEqual(await self.through(path), b"B:ping")
        finally:
            proxy.end()
            server.close()
            b_srv.close()
        self.assertTrue(vpn.broken)
        await asyncio.sleep(0.1)
        broken = [e for e in self.read_log() if e.get("state") == "broken"]
        self.assertIn("wireproxy", broken[0]["reason"])

    async def test_wireguard_client_process_end_to_end(self):
        # заглушка wireproxy читает НАШ сгенерированный конфиг (порт, логин, пароль) и ведёт себя как SOCKS5 с паролем
        from envbox.net.chain import Channel
        from envbox.net.vpn import VpnClient
        fake = os.path.join(self.tmp, "wireproxy")
        with open(fake, "w") as f:
            f.write(FAKE_WIREPROXY)
        os.chmod(fake, 0o755)
        src = os.path.join(self.tmp, "wg.conf")
        with open(src, "w") as f:
            f.write("[Interface]\nPrivateKey = k\nAddress = 10.0.0.2/32\nPostUp = touch /tmp/pwned\n"
                    "[Peer]\nPublicKey = p\nEndpoint = 1.2.3.4:51820\nAllowedIPs = 0.0.0.0/0\n"
                    "[TCPServerTunnel]\nListenPort = 22\nTarget = 127.0.0.1:22\n")
        async def answer(r, w):
            await r.read(100)
            w.write(b"via-vpn:ok")
            await w.drain()
            w.close()
        echo = await asyncio.start_server(answer, "127.0.0.1", 0)
        eport = echo.sockets[0].getsockname()[1]
        os.environ["ENVBOX_VPN_WIREPROXY"] = fake
        self.addCleanup(os.environ.pop, "ENVBOX_VPN_WIREPROXY", None)
        client = VpnClient("wireguard", src, os.path.join(self.tmp, "vpn.log"))
        chan = Channel("vpn:wg", "vpn", client=client)
        proxy, server, path = await self.start([chan])
        proxy.begin()
        try:
            data, r, w = await ask(path, f"CONNECT vpn.test:{eport} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
            self.assertTrue(data.startswith(b"HTTP/1.1 200"), data)
            w.write(b"hi")
            await w.drain()
            self.assertEqual(await asyncio.wait_for(r.read(100), 5), b"via-vpn:ok")
            w.close()
            self.assertIsNotNone(client.proc)
            tmpdir = client.dir
            self.assertTrue(os.path.isdir(tmpdir))
        finally:
            proxy.end()
            server.close()
            echo.close()
        self.assertIsNotNone(client.proc.wait(timeout=5))      # клиент остановлен вместе со шлюзом
        self.assertFalse(os.path.exists(tmpdir))              # временная конфигурация (с ключами) стёрта


class VpnConfigs(unittest.TestCase):
    WG = ("[Interface]\nPrivateKey = abc\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = def\n"
          "Endpoint = 1.2.3.4:51820\nAllowedIPs = 0.0.0.0/0\n")
    UUID = "12345678-1234-1234-1234-123456789abc"

    def test_kind_detection(self):
        from envbox.net.vpn import detect_kind
        self.assertEqual(detect_kind(self.WG), "wireguard")
        self.assertEqual(detect_kind(f"vless://{self.UUID}@h.example:443?security=tls#x"), "xray")
        self.assertEqual(detect_kind('{"outbounds":[{"protocol":"vless"}]}'), "xray")
        self.assertEqual(detect_kind('{"outbounds":[{"type":"vless"}]}'), "singbox")
        for bad in ("", "hello", "{", '{"a":1}', "[Interface]\nPrivateKey=x"):
            with self.assertRaises(ValueError):
                detect_kind(bad)

    def test_wireguard_is_checked_and_stripped(self):
        from envbox.net.vpn import wg_runtime, wg_validate
        self.assertEqual(wg_validate(self.WG), "1.2.3.4:51820")
        with self.assertRaises(ValueError):
            wg_validate(self.WG.replace("Endpoint = 1.2.3.4:51820\n", ""))
        text = wg_runtime(self.WG + "PostUp = rm -rf /\n[TCPClientTunnel]\nBindAddress=127.0.0.1:1\n", 1080, "u", "p")
        self.assertNotIn("PostUp", text)
        self.assertNotIn("TCPClientTunnel", text)
        self.assertIn("DNS = 1.1.1.1", text)                         # без DNS внутри туннеля имена утекли бы
        self.assertIn("BindAddress = 127.0.0.1:1080", text)         # только loopback
        self.assertIn("Username = u", text)

    def test_vless_link_becomes_an_xray_config_with_a_password_protected_socks_inbound(self):
        import json as _json
        from envbox.net.vpn import vpn_validate, xray_runtime
        link = (f"vless://{self.UUID}@h.example:443?type=ws&security=tls&sni=s.example&path=%2Fw&fp=firefox"
                "&flow=xtls-rprx-vision#name")
        self.assertEqual(vpn_validate("xray", link), "name (h.example:443)")   # имя из #name показывается
        cfg = _json.loads(xray_runtime(link, 1080, "u", "p"))
        inbound = cfg["inbounds"][0]
        self.assertEqual((inbound["listen"], inbound["port"], inbound["settings"]["auth"]), ("127.0.0.1", 1080, "password"))
        out = cfg["outbounds"][0]
        self.assertEqual(out["settings"]["vnext"][0]["users"][0]["flow"], "xtls-rprx-vision")
        self.assertEqual(out["streamSettings"]["wsSettings"]["path"], "/w")
        self.assertEqual(out["streamSettings"]["tlsSettings"]["serverName"], "s.example")
        with self.assertRaises(ValueError):
            xray_runtime(f"vless://not-a-uuid@h.example:443", 1, "u", "p")
        with self.assertRaises(ValueError):
            xray_runtime(f"vless://{self.UUID}@h.example:443?security=reality", 1, "u", "p")   # нет pbk

    def test_json_configs_get_our_inbound_and_lose_control_ports(self):
        import json as _json
        from envbox.net.vpn import singbox_runtime, xray_runtime
        x = _json.loads(xray_runtime('{"api":{"tag":"a"},"inbounds":[{"port":9,"protocol":"http"}],'
                                      '"outbounds":[{"protocol":"vless"}]}', 1081, "u", "p"))
        self.assertEqual([i["port"] for i in x["inbounds"]], [1081])
        self.assertNotIn("api", x)
        sb = _json.loads(singbox_runtime('{"experimental":{"clash_api":{"external_controller":"0.0.0.0:9090"}},'
                                          '"inbounds":[{"type":"mixed"}],"outbounds":[{"type":"vless"}]}', 1082, "u", "p"))
        self.assertEqual([(i["type"], i["listen"], i["listen_port"]) for i in sb["inbounds"]],
                         [("socks", "127.0.0.1", 1082)])
        self.assertNotIn("experimental", sb)

    def test_chain_spec(self):
        from envbox.net.chain import parse_chain_spec
        self.assertEqual(parse_chain_spec("proxy"), ("proxy", None, None))
        self.assertEqual(parse_chain_spec("vpn:wireguard:/a b/c.conf"), ("vpn", "wireguard", "/a b/c.conf"))
        for bad in ("vpn", "vpn:foo:/x", "vpn:xray:rel/path", "socks5://x", ""):
            with self.assertRaises(ValueError):
                parse_chain_spec(bad)


class ShareLinks(unittest.TestCase):
    UUID = VpnConfigs.UUID

    @staticmethod
    def b64(text, url=False, pad=True):
        import base64 as _b
        raw = (_b.urlsafe_b64encode if url else _b.b64encode)(text.encode())
        return (raw if pad else raw.rstrip(b"=")).decode()

    def test_vmess_base64_json_link(self):
        import json as _json
        from envbox.net.vpn import detect_kind, parse_share_link, vpn_validate
        d = {"v": "2", "ps": "Берлин", "add": "v.example", "port": "443", "id": self.UUID, "aid": "0", "scy": "auto",
             "net": "ws", "type": "none", "host": "cdn.example", "path": "/ws", "tls": "tls", "sni": "s.example"}
        link = "vmess://" + self.b64(_json.dumps(d, ensure_ascii=False))
        self.assertEqual(detect_kind(link), "xray")
        out, remark = parse_share_link(link)
        self.assertEqual((out["protocol"], remark), ("vmess", "Берлин"))
        self.assertEqual(out["settings"]["vnext"][0]["users"][0]["id"], self.UUID)
        st = out["streamSettings"]
        self.assertEqual((st["network"], st["security"], st["tlsSettings"]["serverName"]), ("ws", "tls", "s.example"))
        self.assertEqual(st["wsSettings"], {"path": "/ws", "headers": {"Host": "cdn.example"}})
        self.assertEqual(vpn_validate("xray", link), "Берлин (v.example:443)")
        for bad in ("vmess://!!!!", "vmess://" + self.b64("{}"), "vmess://" + self.b64(_json.dumps({**d, "id": "x"}))):
            with self.assertRaises(ValueError):
                parse_share_link(bad)

    def test_vmess_url_trojan_and_vless_links(self):
        from envbox.net.vpn import parse_share_link
        out, _ = parse_share_link(f"vmess://{self.UUID}@h.example:8443?type=grpc&serviceName=g&security=tls&sni=s#r")
        self.assertEqual((out["protocol"], out["streamSettings"]["grpcSettings"]), ("vmess", {"serviceName": "g"}))
        out, remark = parse_share_link("trojan://p%40ss:w%3Ard@t.example:443?sni=t.example&type=ws&path=%2Ft#%D0%A2")
        node = out["settings"]["servers"][0]
        self.assertEqual((node["password"], node["port"], remark), ("p@ss:w:rd", 443, "Т"))
        self.assertEqual(out["streamSettings"]["security"], "tls")                    # у trojan защита по умолчанию
        with self.assertRaises(ValueError):
            parse_share_link("trojan://t.example:443")                                  # нет пароля
        out, _ = parse_share_link(f"vless://{self.UUID}@h.example:443?type=h2&security=tls&host=a.example,b.example")
        self.assertEqual(out["streamSettings"]["network"], "http")
        self.assertEqual(out["streamSettings"]["httpSettings"]["host"], ["a.example", "b.example"])
        with self.assertRaises(ValueError):
            parse_share_link(f"vless://{self.UUID}@h.example:443?type=quic")           # незнакомый транспорт

    def test_shadowsocks_links(self):
        from envbox.net.vpn import parse_share_link
        # SIP002: метод:пароль в base64url
        out, remark = parse_share_link("ss://" + self.b64("aes-256-gcm:pa55", url=True, pad=False) + "@s.example:8388#S1")
        node = out["settings"]["servers"][0]
        self.assertEqual((node["method"], node["password"], node["address"], node["port"], remark),
                         ("aes-256-gcm", "pa55", "s.example", 8388, "S1"))
        # открытым текстом (новый вид) и старый «всё в base64»
        out, _ = parse_share_link("ss://chacha20-ietf-poly1305:pw@s.example:1")
        self.assertEqual(out["settings"]["servers"][0]["method"], "chacha20-ietf-poly1305")
        out, _ = parse_share_link("ss://" + self.b64("aes-128-gcm:pw@old.example:2000"))
        self.assertEqual(out["settings"]["servers"][0]["address"], "old.example")
        with self.assertRaises(ValueError):
            parse_share_link("ss://" + self.b64("aes-128-gcm:pw", url=True) + "@s.example:1/?plugin=obfs-local")
        with self.assertRaises(ValueError):
            parse_share_link("ss://@@@")

    def test_subscription_text_plain_and_base64(self):
        from envbox.net.vpn import split_links
        v = f"vless://{self.UUID}@a.example:443?security=tls"
        t = "trojan://pw@b.example:443"
        h = "hysteria2://pw@c.example:443"
        for text in (f"{v}\n{t}\n{h}\n", self.b64(f"{v}\n{t}\n{h}"), self.b64(f"{v}\r\n{t}\r\n{h}", url=True, pad=False),
                     "\n".join([self.b64(f"{v}\n{t}\n{h}")[:40], self.b64(f"{v}\n{t}\n{h}")[40:]])):    # переносы внутри base64
            links, other = split_links(text)
            self.assertEqual(links, [v, t], text[:30])
            self.assertEqual(other, ["hysteria2"])
        self.assertEqual(split_links("<html><body>Please open in app</body></html>"), ([], []))


class VpnSubscriptions(unittest.TestCase):
    UUID = VpnConfigs.UUID

    def setUp(self):
        import http.server
        import threading
        self.root = tempfile.mkdtemp(prefix="eb")
        self.addCleanup(shutil.rmtree, self.root, True)
        patcher = mock.patch("envbox.core.vpn.envbox_root", return_value=self.root)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.agents = []
        body = ShareLinks.b64(f"vless://{self.UUID}@a.example:443?security=tls#A\nhysteria2://x@h.example:1\n"
                              "trojan://pw@b.example:443#B\nss://bad\n")
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                outer.agents.append(self.headers.get("User-Agent"))
                if self.path == "/missing":
                    self.send_response(404)
                    self.end_headers()
                    return
                data = b"x" * (3 * 1024 * 1024) if self.path == "/huge" else body.encode()
                self.send_response(200)
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *a):
                pass
        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.shutdown)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def test_import_subscription_creates_one_vpn_per_server(self):
        from envbox.core.vpn import import_subscription, list_vpns
        done, skipped = import_subscription("prov", self.url + "/token")
        self.assertEqual([n for n, _k, _s in done], ["prov-1", "prov-2"])
        self.assertEqual([s for _n, _k, s in done], ["A (a.example:443)", "B (b.example:443)"])
        self.assertTrue(any("hysteria2" in x for x in skipped))                 # неподдерживаемое названо, а не молчком
        self.assertTrue(any("сервер 3" in x for x in skipped))                  # битая ссылка объяснена
        self.assertEqual(self.agents, ["Happ/2.5.0"])                           # первым пробуем Happ: ему отдают всё
        import_subscription("prov", self.url + "/token")                        # повторно: обновляет, а не падает
        self.assertEqual([v["name"] for v in list_vpns()], ["prov-1", "prov-2"])
        # имя можно не указывать: берётся из адреса
        from envbox.core.vpn import base_name_from_url
        self.assertEqual(base_name_from_url("https://www.toriispirits.com/tok"), "toriispirits-com")

    def test_download_errors_are_explained(self):
        from envbox.core.vpn import fetch_subscription
        for url, part in ((self.url + "/missing", "HTTP 404"), (self.url + "/huge", "слишком большой"),
                          ("ftp://x/y", "http://"), ("http://127.0.0.1:1/", "не удалось скачать"), ("https://a b", "пробелов")):
            with self.assertRaises(ValueError) as cm:
                fetch_subscription(url, timeout=3)
            self.assertIn(part, str(cm.exception))

    @staticmethod
    def connect_proxy(mapping, auth=None):
        """Подставной HTTP-прокси (CONNECT): имя из mapping ведёт на локальный порт, остальное не находится."""
        import socketserver
        import threading
        seen = []

        class H(socketserver.BaseRequestHandler):
            def handle(self):
                buf = b""
                while b"\r\n\r\n" not in buf:
                    chunk = self.request.recv(4096)
                    if not chunk:
                        return
                    buf += chunk
                head = buf.decode("latin-1")
                target = head.split()[1]
                seen.append(target)
                host, _, _port = target.rpartition(":")
                if host not in mapping:
                    self.request.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                    return
                up = socket.create_connection(("127.0.0.1", mapping[host]))
                self.request.sendall(b"HTTP/1.1 200 OK\r\n\r\n")

                def pump(a, b):
                    try:
                        while (d := a.recv(65536)):
                            b.sendall(d)
                    except OSError:
                        pass
                    try:
                        b.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                t = threading.Thread(target=pump, args=(up, self.request), daemon=True)
                t.start()
                pump(self.request, up)
                t.join(5)
                up.close()
        srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), H)
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv, seen

    def test_subscription_through_a_proxy_when_the_site_is_not_resolvable(self):
        # у вас: «[Errno -3] Temporary failure in name resolution» — имя сайта не находится по DNS компьютера
        from envbox.core.vpn import fetch_subscription, import_subscription
        port = self.srv.server_address[1]
        proxy, seen = self.connect_proxy({"sub.invalid": port})
        self.addCleanup(proxy.shutdown)
        purl = f"http://127.0.0.1:{proxy.server_address[1]}"
        with self.assertRaises(ValueError) as cm:                       # напрямую имя не находится: понятная подсказка
            fetch_subscription(f"http://sub.invalid:{port}/tok", timeout=3)
        self.assertIn("DNS", str(cm.exception))
        self.assertIn("прокси среды", str(cm.exception))
        done, _ = import_subscription("", f"http://sub.invalid:{port}/tok", proxy=purl)
        self.assertEqual(len(done), 2)
        self.assertEqual(seen, [f"sub.invalid:{port}"])                  # имя разрешал прокси, а не мы
        with self.assertRaises(ValueError) as cm:                       # прокси не знает сайт: ошибка названа
            fetch_subscription(f"http://other.invalid:{port}/tok", timeout=3, proxy=purl)
        self.assertIn("через прокси", str(cm.exception))

    def test_https_subscription_through_a_proxy_and_redirect(self):
        import http.server
        import ssl
        import threading
        from envbox.core.vpn import fetch_subscription
        scratch = os.path.join(self.root, "tls")
        os.makedirs(scratch)
        crt, key = os.path.join(scratch, "c.pem"), os.path.join(scratch, "k.pem")
        r = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt,
                            "-days", "2", "-subj", "/CN=sub.test", "-addext", "subjectAltName=DNS:sub.test"],
                           capture_output=True)
        if r.returncode:
            self.skipTest("нет openssl")

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/old":
                    self.send_response(302)
                    self.send_header("Location", "/new")
                    self.end_headers()
                    return
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"trojan://pw@b.example:443#B")

            def log_message(self, *a):
                pass
        tls = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(crt, key)
        tls.socket = ctx.wrap_socket(tls.socket, server_side=True)
        threading.Thread(target=tls.serve_forever, daemon=True).start()
        self.addCleanup(tls.shutdown)
        proxy, seen = self.connect_proxy({"sub.test": tls.server_address[1]})
        self.addCleanup(proxy.shutdown)
        client_ctx = ssl.create_default_context(cafile=crt)
        with mock.patch("ssl.create_default_context", return_value=client_ctx):
            text = fetch_subscription(f"https://sub.test:{tls.server_address[1]}/old", timeout=5,
                                      proxy=f"http://127.0.0.1:{proxy.server_address[1]}")
        self.assertEqual(text, "trojan://pw@b.example:443#B")                    # TLS поверх туннеля и переход /old → /new
        self.assertEqual(len(seen), 2)

    def test_stubs_are_not_imported_and_other_apps_are_tried(self):
        # volnasubs: «Приложение не поддерживается (0.0.0.0:1)» и «Используйте Happ» были импортированы как серверы
        from envbox.core.vpn import fetch_subscription_full, import_subscription, list_vpns
        real = f"vless://{self.UUID}@real.example:443?security=tls#Berlin"
        stub1 = f"vless://{self.UUID}@0.0.0.0:1?security=none#%D0%9F%D1%80%D0%B8%D0%BB%D0%BE%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5"
        stub2 = f"vless://{self.UUID}@0.0.0.0:1#Use-Happ"
        import http.server
        import threading
        seen = []

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append((self.headers.get("User-Agent"), self.headers.get("x-hwid")))
                if self.path == "/happ-only":
                    body = real if self.headers.get("User-Agent", "").startswith("v2rayN") else f"{stub1}\n{stub2}"
                elif self.path == "/never":
                    body = f"{stub1}\n{stub2}"
                else:
                    body = f"{stub1}\n{real}\n{stub2}"
                self.send_response(200)
                self.send_header("profile-title", "base64:" + ShareLinks.b64("Мой сервис"))
                self.send_header("subscription-userinfo", "upload=10; download=20; total=1000; expire=1893456000")
                self.send_header("profile-update-interval", "6")
                self.end_headers()
                self.wfile.write(body.encode())

            def log_message(self, *a):
                pass
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        base = f"http://127.0.0.1:{srv.server_address[1]}"
        # настоящий сервер среди заглушек: заглушки пропущены, а не добавлены
        done, skipped = import_subscription("svc", base + "/mixed")
        self.assertEqual([x[0] for x in done], ["svc"])
        self.assertTrue(any("заглушки" in x and "Use-Happ" in x for x in skipped), skipped)
        self.assertEqual([v["host"] for v in list_vpns()], ["real.example"])
        # провайдер отдаёт настоящее только другому приложению: перебираем
        seen.clear()
        done, _ = import_subscription("svc2", base + "/happ-only")
        self.assertEqual([a for a, _h in seen], ["Happ/2.5.0", "v2rayN/6.42"])
        self.assertEqual(len({h for _a, h in seen}), 1)                       # заголовок устройства один и тот же
        self.assertRegex(seen[0][1], r"^[0-9a-f]{32}$")
        self.assertEqual(len(done), 1)
        # только заглушки: понятная ошибка, ничего не добавлено
        before = len(list_vpns())
        with self.assertRaises(ValueError) as cm:
            import_subscription("svc3", base + "/never")
        self.assertIn("Use-Happ", str(cm.exception))
        self.assertIn("приложении провайдера", str(cm.exception))
        self.assertEqual(len(list_vpns()), before)
        text, headers = fetch_subscription_full(base + "/mixed")
        self.assertEqual(headers["profile-update-interval"], "6")

    def test_folders_are_services_with_traffic_and_refresh(self):
        from envbox.core.vpn import (delete_folder, import_subscription, list_folders, list_vpns, refresh_folder,
                                     set_folder, subscription_info)
        info = subscription_info({"profile-title": "base64:" + ShareLinks.b64("Мой сервис"),
                                  "subscription-userinfo": "upload=10; download=20; total=1000; expire=1893456000",
                                  "profile-update-interval": "6", "support-url": "https://t.me/support"})
        self.assertEqual((info["title"], info["used"], info["total"], info["expire"], info["interval"]),
                         ("Мой сервис", 30, 1000, 1893456000, 6))
        done, _ = import_subscription("prov", self.url + "/token")
        folders = list_folders()
        self.assertEqual(list(folders), ["prov"])                              # без заголовка название — из адреса
        self.assertEqual(folders["prov"]["url"], self.url + "/token")
        self.assertEqual({v["folder"] for v in list_vpns()}, {"prov"})
        meta_path = os.path.join(self.root, "_vpn", "meta.json")
        self.assertEqual(os.stat(meta_path).st_mode & 0o777, 0o600)            # в нём адрес с токеном
        # ручное перемещение и возврат
        import_many_ = __import__("envbox.core.vpn", fromlist=["import_many"]).import_many
        import_many_("mine", f"trojan://a@x.example:443")
        set_folder("mine", "Мои серверы")
        self.assertEqual(sorted(list_folders()), sorted(["Мои серверы", "prov"]))
        set_folder("mine", "")
        self.assertEqual(sorted(list_folders()), ["prov"])                     # пустая папка не висит
        # у папки без подписки обновлять нечего; у подписочной — обновляется
        set_folder("mine", "Ручные")
        with self.assertRaises(ValueError):
            refresh_folder("Ручные")
        again, _skipped, gone = refresh_folder("prov")
        self.assertEqual([n for n, _k, _s in again], ["prov-1", "prov-2"])
        self.assertEqual(gone, [])
        self.assertEqual(delete_folder("prov"), 2)
        self.assertEqual([v["name"] for v in list_vpns()], ["mine"])
        self.assertEqual(sorted(list_folders()), ["Ручные"])

    def test_search_and_ping(self):
        import socket as _socket
        from envbox.core.vpn import import_many, list_vpns, ping_vpns, search_vpns, tcp_ping
        listener = _socket.socket()
        listener.bind(("127.0.0.2", 0))
        listener.listen(5)
        self.addCleanup(listener.close)
        port = listener.getsockname()[1]
        closed = _socket.socket()
        closed.bind(("127.0.0.2", 0))
        dead = closed.getsockname()[1]
        closed.close()
        import_many("alive", f"trojan://a@127.0.0.2:{port}#Berlin-1", folder="Сервис А")
        import_many("dead", f"trojan://a@127.0.0.2:{dead}#Paris", folder="Сервис Б")
        import_many("wg", VpnConfigs.WG, folder="Сервис А")
        vpns = list_vpns()
        by = lambda q: sorted(v["name"] for v in search_vpns(vpns, q))      # noqa: E731
        self.assertEqual(by("berlin"), ["alive"])                           # по названию из ссылки
        self.assertEqual(by("127.0.0.2"), ["alive", "dead"])                # по адресу сервера
        self.assertEqual(by(str(dead)), ["dead"])                           # по порту
        self.assertEqual(by("сервис а"), ["alive", "wg"])                   # по папке, слова в любом месте
        self.assertEqual(by("сервис а berlin"), ["alive"])                  # все слова сразу
        self.assertEqual(by("wireguard"), ["wg"])                           # по виду
        self.assertEqual(by(""), ["alive", "dead", "wg"])
        self.assertEqual(by("нет такого"), [])
        self.assertIsNotNone(tcp_ping("127.0.0.2", port))
        self.assertIsNone(tcp_ping("127.0.0.2", dead, timeout=1))
        res = ping_vpns(vpns, timeout=1)
        self.assertIsInstance(res["alive"], int)
        self.assertIsNone(res["dead"])                                      # не ответил
        self.assertNotIn("wg", res)                                         # WireGuard — UDP, пингом не измеряется

    def test_json_array_subscription_is_split_into_servers(self):
        # «конфигурация слишком большая (больше 256 КБ)»: подписка отдала массив готовых конфигураций Xray
        import json as _json
        from envbox.core.vpn import import_many, list_vpns
        junk = [f"geosite:{i}-example.com" for i in range(4000)]               # правила маршрутизации «раздувают» конфиг

        def cfg(remark, host, port):
            out = {"protocol": "vless", "tag": "proxy", "settings": {"vnext": [{
                "address": host, "port": port, "users": [{"id": VpnConfigs.UUID, "encryption": "none"}]}]},
                "streamSettings": {"network": "tcp", "security": "none"}}
            return {"remarks": remark, "inbounds": [{"port": 10808, "protocol": "socks"}],
                    "outbounds": [{"protocol": "freedom", "tag": "direct"}, out],
                    "routing": {"rules": [{"type": "field", "domain": junk, "outboundTag": "direct"}]}}
        body = _json.dumps([cfg("Берлин", "a.example", 443), cfg("Приложение не поддерживается", "0.0.0.0", 1),
                            cfg("Париж", "b.example", 8443)], ensure_ascii=False)
        self.assertGreater(len(body.encode()), 256 * 1024)                      # весь ответ больше лимита одной конфигурации
        done, skipped = import_many("svc", body, folder="Сервис")
        self.assertEqual([n for n, _k, _s in done], ["svc-1", "svc-2"])
        self.assertTrue(any("заглушки" in x and "Приложение не поддерживается" in x for x in skipped), skipped)
        by = {v["name"]: v for v in list_vpns()}
        self.assertEqual((by["svc-1"]["title"], by["svc-1"]["host"], by["svc-1"]["port"], by["svc-1"]["folder"]),
                         ("Берлин", "a.example", 443, "Сервис"))                # название и сервер видны в списке и для пинга
        self.assertEqual(by["svc-2"]["title"], "Париж")

    def test_foreign_routing_cannot_bypass_the_vpn(self):
        # в подписках бывают правила «эти сайты напрямую»: при «только через VPN» это утечка настоящего адреса
        import json as _json
        from envbox.net.vpn import singbox_runtime, xray_runtime
        direct_first = {"outbounds": [{"protocol": "freedom", "tag": "direct"}, {"protocol": "blackhole"},
                                      {"protocol": "vless", "tag": "proxy"}],
                        "routing": {"rules": [{"domain": ["geosite:ru"], "outboundTag": "direct"}]},
                        "observatory": {"subjectSelector": ["proxy"]}}
        cfg = _json.loads(xray_runtime(_json.dumps(direct_first), 1081, "u", "p"))
        self.assertNotIn("routing", cfg)
        self.assertNotIn("observatory", cfg)
        self.assertEqual(cfg["outbounds"][0]["protocol"], "vless")              # по умолчанию берётся первый выход
        with self.assertRaises(ValueError):
            xray_runtime('{"outbounds":[{"protocol":"freedom"}]}', 1, "u", "p")  # без прокси-выхода VPN не VPN
        sb = _json.loads(singbox_runtime(_json.dumps({
            "outbounds": [{"type": "direct", "tag": "direct"}, {"type": "vless", "tag": "p"}],
            "route": {"final": "direct", "rules": [{"domain_suffix": [".ru"], "outbound": "direct"}]}}), 1082, "u", "p"))
        self.assertEqual(sb["route"], {"final": "p"})
        sb = _json.loads(singbox_runtime('{"outbounds":[{"type":"vless"}]}', 1082, "u", "p"))
        self.assertEqual(sb["route"], {"final": "envbox-out"})                  # без тега даём свой
        with self.assertRaises(ValueError):
            singbox_runtime('{"outbounds":[{"type":"direct","tag":"d"}]}', 1, "u", "p")

    def test_unrecognised_response_is_described_not_just_too_big(self):
        from envbox.core.vpn import import_many
        cases = (("<!DOCTYPE html><html>" + "x" * 300000 + "</html>", "веб-страница"),
                 ("proxies:\n  - name: a\n    type: vless\n", "Clash"),
                 ('[{"a":1},{"b":2}]', "массив из 2 элементов"),
                 ("просто текст без ссылок", "без ссылок"),
                 ("   ", "пустой"))
        for text, part in cases:
            with self.assertRaises(ValueError) as cm:
                import_many("x", text)
            self.assertIn("не похож на подписку", str(cm.exception))
            self.assertIn(part, str(cm.exception))

    def test_folder_summary_and_natural_order(self):
        from envbox.core.vpn import folder_summary, human_bytes, natural_key
        self.assertEqual(human_bytes(512), "512 Б")
        self.assertEqual(human_bytes(5 * 1024 ** 3), "5.0 ГБ")
        text = folder_summary({"used": 1024 ** 3, "total": 10 * 1024 ** 3, "expire": 1893456000, "support": "t.me/s"})
        for part in ("1.0 ГБ из 10.0 ГБ", "до 01.01.2030", "поддержка: t.me/s"):
            self.assertIn(part, text)
        self.assertEqual(folder_summary({}), "")
        self.assertEqual(sorted(["vpn-10", "vpn-2", "vpn-1"], key=natural_key), ["vpn-1", "vpn-2", "vpn-10"])

    def test_name_is_optional_and_forgiving(self):
        # «имя VPN: латинские буквы…» мешало добавить ссылку: имя пустое, с кириллицей или в него вставили ссылку
        from envbox.core.vpn import (free_name, import_many, is_subscription_url, list_vpns, looks_like_source,
                                     normalize_name)
        self.assertEqual(normalize_name("Мой VPN №1!"), "VPN-1")
        self.assertEqual(normalize_name("тест"), "vpn")
        self.assertEqual(normalize_name("  ok.name_1 "), "ok.name_1")
        self.assertEqual(len(normalize_name("a" * 100)), 40)
        link = f"vless://{self.UUID}@a.example:443"
        a, _ = import_many("", link)
        b, _ = import_many("   ", link)
        c, _ = import_many("Мой сервер", link)
        self.assertEqual([x[0][0] for x in (a, b, c)], ["vpn", "vpn-2", "vpn-3"])    # пустое имя ничего не затирает
        self.assertEqual(free_name("vpn"), "vpn-4")
        self.assertEqual(len(list_vpns()), 3)
        for text in ("https://x.example/tok", ' "https://x.example/tok" ', "<https://x.example/tok>"):
            self.assertTrue(is_subscription_url(text), text)
        for text in ("https://x.example/a b", "vless://u@h:1", "просто имя", ""):
            self.assertFalse(is_subscription_url(text), text)
        for text in ("https://x.example/t", "vmess://x", "trojan://x", "ss://x", "[Interface]\nA=1", "{ }"):
            self.assertTrue(looks_like_source(text), text)
        self.assertFalse(looks_like_source("vpn1"))

    def test_subscription_with_a_cyrillic_name_still_works(self):
        from envbox.core.vpn import import_subscription
        done, _ = import_subscription("Провайдер", self.url + "/token")
        self.assertEqual([n for n, _k, _s in done], ["vpn-1", "vpn-2"])               # имя заменено, а не отвергнуто
        done, _ = import_subscription("", ' "' + self.url + '/token" ')              # кавычки и пробелы вокруг ссылки
        self.assertEqual([n[:9] for n, _k, _s in done], ["127-0-0-1", "127-0-0-1"])

    def test_single_link_and_pasted_list(self):
        from envbox.core.vpn import import_many, list_vpns
        done, _ = import_many("one", f"vless://{self.UUID}@a.example:443")
        self.assertEqual([n for n, _k, _s in done], ["one"])                    # одна ссылка: имя как задано
        done, _ = import_many("many", f"trojan://a@x.example:443\ntrojan://b@y.example:8443")
        self.assertEqual([n for n, _k, _s in done], ["many-1", "many-2"])
        self.assertEqual(len(list_vpns()), 3)
        with self.assertRaises(ValueError) as cm:
            import_many("only", "hysteria2://x@h.example:1\ntuic://y@t.example:2")
        self.assertIn("hysteria2", str(cm.exception))
        with self.assertRaises(ValueError):
            import_many("html", "<html>login</html>")


class VpnStore(unittest.TestCase):
    WG = VpnConfigs.WG

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="eb")
        self.addCleanup(shutil.rmtree, self.root, True)
        patcher = mock.patch("envbox.core.vpn.envbox_root", return_value=self.root)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_import_list_replace_delete(self):
        from envbox.core.vpn import delete_vpn, import_vpn, list_vpns, vpn_source
        name, kind, server = import_vpn("wg0", self.WG)
        self.assertEqual((name, kind, server), ("wg0", "wireguard", "1.2.3.4:51820"))
        path = vpn_source("wg0")[1]
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)                 # в файле приватный ключ
        self.assertEqual(os.stat(os.path.dirname(path)).st_mode & 0o777, 0o700)
        with self.assertRaises(ValueError):
            import_vpn("wg0", self.WG)                                          # молча не затираем
        import_vpn("wg0", self.WG, replace=True)
        import_vpn("x", f"vless://{VpnConfigs.UUID}@h.example:443?security=tls")
        self.assertEqual([(v["name"], v["kind"]) for v in list_vpns()], [("wg0", "wireguard"), ("x", "xray")])
        import_vpn("x", '{"outbounds":[{"type":"vless"}]}', replace=True)      # тот же ключ, другой вид: старый файл уходит
        self.assertEqual([(v["name"], v["kind"]) for v in list_vpns()], [("wg0", "wireguard"), ("x", "singbox")])
        self.assertTrue(delete_vpn("wg0"))
        self.assertFalse(delete_vpn("wg0"))
        with self.assertRaises(ValueError):
            vpn_source("wg0")

    def test_vpn_check_from_the_gui_starts_the_client_and_opens_a_tunnel(self):
        # кнопка «Проверить» на вкладке VPN: клиент запускается, через него открывается туннель, клиент останавливается
        import threading
        from envbox.core.vpn import import_vpn, test_vpn
        fake = os.path.join(self.root, "wireproxy")
        with open(fake, "w") as f:
            f.write(FAKE_WIREPROXY)
        os.chmod(fake, 0o755)
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(5)
        port = srv.getsockname()[1]
        threading.Thread(target=lambda: [srv.accept()[0].close() for _ in range(3)], daemon=True).start()
        self.addCleanup(srv.close)
        import_vpn("wg0", self.WG)
        with mock.patch.dict(os.environ, {"ENVBOX_VPN_WIREPROXY": fake}):
            ok, msg = test_vpn("wg0", ("vpn.test", port))
        self.assertTrue(ok, msg)
        self.assertIn("работает", msg)
        with mock.patch.dict(os.environ, {"ENVBOX_VPN_WIREPROXY": "/нет/такой/программы"}):
            ok, msg = test_vpn("wg0")
        self.assertFalse(ok)
        self.assertIn("wireproxy", msg)                                      # понятно, что установить
        self.assertFalse(test_vpn("нет-такого")[0])

    def test_exit_modes_round_trip(self):
        from envbox.core.vpn import EXIT_MODES, exit_chain, exit_mode
        self.assertEqual(exit_chain("proxy", ""), [])
        self.assertEqual(exit_chain("vpn_only", "wg0"), ["vpn:wg0"])
        self.assertEqual(exit_chain("vpn_then_proxy", "wg0"), ["vpn:wg0", "proxy"])
        self.assertEqual(exit_chain("proxy_then_vpn", "wg0"), ["proxy", "vpn:wg0"])
        self.assertIsNone(exit_chain("custom", "wg0"))                      # свой список режим не переписывает
        for mode in ("proxy", "vpn_only", "vpn_then_proxy", "proxy_then_vpn"):
            self.assertEqual(exit_mode(exit_chain(mode, "wg0")), (mode, "wg0" if mode != "proxy" else ""))
        for odd in (["direct"], ["vpn:a", "vpn:b"], ["vpn:a", "direct"], ["proxy"], ["vpn:a", "proxy", "direct"]):
            self.assertEqual(exit_mode(odd)[0], "custom", odd)
        self.assertEqual(set(EXIT_MODES), {"proxy", "vpn_only", "vpn_then_proxy", "proxy_then_vpn", "custom"})

    def test_vpn_only_profile_needs_no_proxy_and_is_described_honestly(self):
        from envbox.core.describe import describe
        from envbox.core.profile import Profile
        from envbox.core.vpn import import_vpn
        import_vpn("wg0", self.WG)
        p = Profile(name="c", net="allowlist", allow_domains=["example.com"], no_workdir=True,
                    upstream_chain=["vpn:wg0"])
        self.assertEqual(p.validate(), [])                                  # прокси не нужен
        a = p.envbox_args()
        self.assertNotIn("--upstream", a)
        self.assertEqual([a[i + 1] for i, x in enumerate(a) if x == "--chain"][0].split(":")[:2], ["vpn", "wireguard"])
        text = " ".join(t for _lvl, t in describe(p))
        self.assertIn("только через VPN «wg0»", text)
        self.assertIn("отклоняться", text)
        self.assertNotIn("direct", text.replace("прямого", ""))
        leak = Profile(name="c", net="log", upstream_chain=["vpn:wg0", "direct"], direct_domains=["a.example"])
        warns = " ".join(t for lvl, t in describe(leak) if lvl == "warn")
        self.assertIn("напрямую с вашего настоящего адреса", warns)         # утечка через direct названа
        self.assertIn("a.example", warns)                                   # и сайты «напрямую» тоже

    def test_bad_input_is_rejected_with_a_reason(self):
        from envbox.core.vpn import import_vpn, list_vpns
        for name, text in (("a/b", self.WG), ("", self.WG), ("ok", "мусор"), ("ok", "[Interface]\nAddress=1\n[Peer]\n"),
                           ("ok", "x" * 300000)):
            with self.assertRaises(ValueError):
                import_vpn(name, text)
        self.assertEqual(list_vpns(), [])

    def test_profile_chain_validation_and_args(self):
        from envbox.core.profile import Profile
        from envbox.core.vpn import import_vpn, vpn_source
        import_vpn("wg0", self.WG)
        path = vpn_source("wg0")[1]
        p = Profile(name="c", net="log", upstream="http://127.0.0.1:9", upstream_auth=True,
                    upstream_chain=["proxy", "vpn:wg0", "direct"])
        self.assertEqual([e for e in p.validate() if "цепоч" in e], [])
        a = p.envbox_args()
        i = a.index("--upstream")
        self.assertEqual(a[i:i + 2], ["--upstream", "http://127.0.0.1:9"])
        chain = [a[j + 1] for j, x in enumerate(a) if x == "--chain"]
        self.assertEqual(chain, ["proxy", f"vpn:wireguard:{path}", "direct"])    # порядок сохранён
        self.assertIn("ENVBOX_UPSTREAM_AUTH", p.wrapper_secrets())
        # VPN первым, прокси исключён из цепочки: --upstream не передаётся и пароль прокси не нужен
        q = Profile(name="c", net="log", upstream="http://127.0.0.1:9", upstream_auth=True,
                    upstream_chain=["vpn:wg0", "direct"])
        a = q.envbox_args()
        self.assertNotIn("--upstream", a)
        self.assertNotIn("ENVBOX_UPSTREAM_AUTH", q.wrapper_secrets())
        # ошибки
        bad = Profile(name="c", net="log", upstream_chain=["proxy", "vpn:нет", "direct", "direct", "tor"])
        text = "\n".join(bad.validate())
        for part in ("«proxy», но свой прокси не задан", "не найден", "указан дважды", "неизвестный канал"):
            self.assertIn(part, text)
        self.assertTrue([e for e in Profile(name="c", net="off", upstream_chain=["direct"]).validate() if "цепоч" in e])
        self.assertTrue([e for e in Profile(name="c", net="log", dns=["1.1.1.1"],
                                            upstream_chain=["vpn:wg0"]).validate() if "DNS" in e])
        # без цепочки всё как раньше
        old = Profile(name="c", net="log", upstream="http://127.0.0.1:9").envbox_args()
        self.assertIn("--upstream", old)
        self.assertNotIn("--chain", old)
        self.assertEqual(Profile.from_dict(p.__dict__).upstream_chain, ["proxy", "vpn:wg0", "direct"])


class BrowserLogin(unittest.TestCase):
    def test_chrome_hides_the_automation_flag(self):
        # порт отладки делает navigator.webdriver истинным, и Google/Cloudflare отвечают «браузер не прошёл проверку»
        from envbox.core.browser import browser_command
        from envbox.core.profile import Profile
        argv = browser_command(Profile(name="b", kind="browser", browser_bin="/usr/bin/chromium"))
        self.assertIn("--disable-blink-features=AutomationControlled", argv)
        self.assertFalse([a for a in argv if a.startswith("--headless")])    # «HeadlessChrome» в User-Agent

    def test_viewer_closes_javascript_dialogs(self):
        # открытый диалог (после входа через Google) останавливает страницу и кадры: окно «зависает»
        from envbox.cdp.viewer import CdpViewer
        v = CdpViewer("/nonexistent.sock", lambda *_: None)
        other, sent = mock.Mock(), mock.Mock()
        v.client = sent
        for kind, accept in (("alert", True), ("beforeunload", True), ("confirm", False), ("prompt", False)):
            for c in (sent, other):                  # и в активной вкладке, и в фоновой
                c.reset_mock()
                v._page_event(c, "Page.javascriptDialogOpening", {"type": kind, "message": "x"})
                c.notify.assert_called_once_with("Page.handleJavaScriptDialog", {"accept": accept})


class BrowserViewer(unittest.TestCase):
    def test_external_scheme(self):
        from envbox.cdp.viewer import external_scheme
        self.assertEqual(external_scheme("claude://login?code=1"), "claude")
        self.assertEqual(external_scheme("MAILTO:a@b.c"), "mailto")
        for own in ("https://claude.ai/", "http://localhost:1/", "about:blank", "data:text/html,x", "blob:https://a/b",
                    "javascript:void(0)", "chrome-error://chromewebdata/", "view-source:https://a/", "", "no scheme"):
            self.assertEqual(external_scheme(own), "", own)

    def test_external_navigation_is_reported_and_stuck_tab_closed(self):
        # claude:// из страницы входа: Chrome без окна показывает запрос, и вкладка перестаёт принимать ввод
        import threading
        from envbox.cdp.viewer import CdpViewer
        got, done = [], threading.Event()
        v = CdpViewer("/nonexistent.sock", lambda *_: None, on_external=got.append)
        bg, fg = mock.Mock(), mock.Mock()
        v.clients = {"TAB1": fg, "TAB2": bg}
        v.client = fg
        closed = []
        v.close_tab = lambda tid: (closed.append(tid), done.set())
        v._page_event(bg, "Page.frameRequestedNavigation",
                      {"url": "claude://login?code=1", "frameId": "F", "reason": "scriptInitiated"})   # фоновая вкладка
        self.assertTrue(done.wait(5))
        self.assertEqual(got, ["claude://login?code=1"])
        self.assertEqual(closed, ["TAB2"])
        done.clear()
        v._page_event(fg, "Page.frameRequestedNavigation", {"url": "https://claude.ai/x", "frameId": "F"})
        self.assertFalse(done.wait(0.3))                       # обычные адреса не трогаем
        self.assertEqual((got, closed), (["claude://login?code=1"], ["TAB2"]))

    def test_login_callback_on_localhost_is_reported_and_tab_kept(self):
        # вход в Claude CLI: сайт ведёт браузер на http://127.0.0.1:порт/callback, который слушает программа в ДРУГОЙ среде
        import threading
        from envbox.cdp.viewer import CdpViewer, local_callback_url
        self.assertTrue(local_callback_url("http://127.0.0.1:46441/callback?code=a&state=b"))
        self.assertTrue(local_callback_url("http://localhost:3000/x"))
        for no in ("", "https://claude.ai/callback", "http://127.0.0.1/x", "http://example.com:8080/", "claude://x"):
            self.assertEqual(local_callback_url(no), no and "", no)
        got, done = [], threading.Event()
        v = CdpViewer("/nonexistent.sock", lambda *_: None, on_external=lambda u: (got.append(u), done.set()))
        tab = mock.Mock()
        v.clients, v.client = {"T": tab}, tab
        v.close_tab = mock.Mock()
        err = {"frame": {"url": "chrome-error://chromewebdata/",
                         "unreachableUrl": "http://127.0.0.1:46441/callback?code=a&state=b"}}
        v._page_event(tab, "Page.frameNavigated", err)
        self.assertTrue(done.wait(5))
        self.assertEqual(got, ["http://127.0.0.1:46441/callback?code=a&state=b"])
        v.close_tab.assert_not_called()                          # вкладку не закрываем: она не зависла
        done.clear()
        err["frame"]["parentId"] = "P"                           # ошибка во вложенном кадре — не вход
        v._page_event(tab, "Page.frameNavigated", err)
        self.assertFalse(done.wait(0.3))

    def test_page_sees_real_window_size_and_zoom(self):
        # безоконный Chrome отвечал странице «окно 500x87, экран 1x1» (страница подтверждения входа: «окно слишком
        # маленькое»); масштаб был CSS-хитростью, и страница его не видела
        from envbox.cdp.viewer import CdpViewer
        v = CdpViewer("/nonexistent.sock", lambda *_: None)
        page, browser = mock.Mock(closed=False), mock.Mock()
        browser.call.side_effect = lambda m, p=None: (
            {"windowId": 7, "bounds": {"width": 500, "height": 87}} if m == "Browser.getWindowForTarget" else {})
        v.browser.client = browser
        v.client, v.active, v.size = page, "T", (1200, 700)
        v.zoom["T"] = 0.8
        v._apply_metrics()
        args = page.call.call_args[0]
        self.assertEqual(args[0], "Emulation.setDeviceMetricsOverride")
        m = args[1]
        self.assertEqual((m["width"], m["height"], m["deviceScaleFactor"]), (1500, 875, 0.8))   # страница видит зум
        self.assertEqual((m["screenWidth"], m["screenHeight"]), (1500, 875))
        calls = [c[0] for c in browser.call.call_args_list]
        self.assertEqual(calls[-1][0], "Browser.setWindowBounds")
        self.assertEqual((calls[-1][1]["bounds"]["width"], calls[-1][1]["bounds"]["height"]), (1200, 700))
        browser.reset_mock()
        v._apply_metrics()
        self.assertEqual([c[0][0] for c in browser.call.call_args_list], [])                    # окно уже нужного размера


class AppImageBuild(unittest.TestCase):
    def test_existing_appimage_is_replaced_not_overwritten(self):
        # запущенный AppImage нельзя открыть на запись («Text file busy»): собираем рядом и подменяем
        from envbox.appimage import build_appimage
        d = tempfile.mkdtemp()
        stub = os.path.join(d, "tool.sh")
        with open(stub, "w") as f:
            f.write('#!/bin/sh\n[ -e "$2" ] && { echo "busy" >&2; exit 1; }\necho new > "$2"\n')
        os.chmod(stub, 0o755)
        arch = os.uname().machine
        out = os.path.join(d, f"envbox-{arch}.AppImage")
        with open(out, "w") as f:
            f.write("old")
        cwd = os.getcwd()
        os.chdir(d)
        try:
            with mock.patch.dict(os.environ, {"APPIMAGETOOL": stub}):
                self.assertEqual(build_appimage(None), 0)
        finally:
            os.chdir(cwd)
        with open(out) as f:
            self.assertEqual(f.read().strip(), "new")
        self.assertEqual(os.listdir(d).count(f"envbox-{arch}.AppImage.new"), 0)


if __name__ == "__main__":
    unittest.main()
