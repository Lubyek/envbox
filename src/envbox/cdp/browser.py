"""CDP: управление страницей браузера (навигация, вкладки, скрипты)."""

import json
import threading

from .client import CdpClient
from .http import cdp_http


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
