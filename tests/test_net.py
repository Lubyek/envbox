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


if __name__ == "__main__":
    unittest.main()
