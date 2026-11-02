"""CDP: клиент WebSocket DevTools."""

import base64
import hashlib
import itertools
import json
import os
import socket
import struct
import threading
import urllib.parse

from ..core.consts import CDP_PORT
from .http import CdpError, WS_GUID, _read_http_head, _unix_connect, cdp_pick_page


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
