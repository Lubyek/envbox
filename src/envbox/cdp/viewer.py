"""CDP: просмотр страницы в окне (кадры экрана, ввод)."""

import base64
import json
import threading

from ..core.consts import CDP_PORT
from .browser import CdpBrowser, ZOOM_STEPS, _JS_SELECTION, _js_hit_info
from .client import CdpClient
from .http import CdpError, cdp_pick_page
from .keys import cdp_key_events, normalize_url


class CdpViewer:
    """Просмотр браузера среды: вкладки, кадры (JPEG) в on_frame, ввод мышью и клавиатурой, масштаб.

    on_tabs(список вкладок, id активной) вызывается из потока чтения при любом изменении вкладок."""

    def __init__(self, sock_path, on_frame, on_url=None, on_close=None, on_tabs=None):
        self.sock_path = sock_path
        self.on_frame, self.on_url, self.on_close, self.on_tabs = on_frame, on_url, on_close, on_tabs
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
            self._apply_metrics()
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
                if self.cur_zoom != 1.0 and client.zoom_script is None:
                    self._apply_zoom()
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

    def _page(self):
        c = self.client
        if c is None or c.closed:
            raise CdpError("нет открытой вкладки")
        return c

    # ---- размер и масштаб
    @property
    def cur_zoom(self):
        return self.zoom.get(self.active, 1.0)

    def _apply_metrics(self):
        w, h = self.size
        c = self._page()
        c.call("Emulation.setDeviceMetricsOverride", {"width": w, "height": h, "deviceScaleFactor": 1, "mobile": False})
        c.applied_size = (w, h)

    def _apply_zoom(self):
        """Масштаб страницы как CSS zoom корневого элемента (в отличие от deviceScaleFactor кадр остаётся
        чётким 1:1, а координаты мыши не пересчитываются). Сценарий на новый документ сохраняет масштаб
        при переходах, пока вкладка показывается."""
        c = self._page()
        z = self.cur_zoom
        old = getattr(c, "zoom_script", None)
        if old:
            try:
                c.call("Page.removeScriptToEvaluateOnNewDocument", {"identifier": old})
            except CdpError:
                pass
            c.zoom_script = None
        value = "" if z == 1.0 else repr(z)
        if z != 1.0:
            src = ("(function(){var z=%s;function a(){var r=document.documentElement;if(r){r.style.zoom=String(z);}}"
                   "a();document.addEventListener('DOMContentLoaded',a);})();" % repr(z))
            c.zoom_script = c.call("Page.addScriptToEvaluateOnNewDocument", {"source": src}).get("identifier")
        self.evaluate("(function(){var r=document.documentElement;if(r){r.style.zoom=%s;}})()" % json.dumps(value))

    def set_size(self, width, height):
        width, height = max(200, int(width)), max(150, int(height))
        if (width, height) == self.size:
            return
        self.size = (width, height)
        if self.client is not None:
            self._apply_metrics()

    def set_zoom(self, value):
        value = round(min(5.0, max(0.25, float(value))), 2)
        self.zoom[self.active] = value
        self._apply_zoom()
        return value

    def zoom_step(self, direction):
        z = self.cur_zoom
        if direction > 0:
            nxt = next((x for x in ZOOM_STEPS if x > z + 1e-6), ZOOM_STEPS[-1])
        else:
            nxt = next((x for x in reversed(ZOOM_STEPS) if x < z - 1e-6), ZOOM_STEPS[0])
        return self.set_zoom(nxt)

    def _css(self, x, y):
        return x, y  # координаты кадра = координаты окна страницы (масштаб — CSS zoom, см. _apply_zoom)

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
