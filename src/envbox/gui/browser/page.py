"""Страница встроенного браузера: подключение, отключение, запуск."""

import threading

from ...cdp.http import cdp_listening
from ...cdp.viewer import CdpViewer
from ...core.browser import cdp_socket_path
from ...core.store import load_profile
from ..gtk import GLib, Gtk
from ..widgets import alert, hint


class BrowserPageMixin:
    """Страница встроенного браузера: подключение, отключение, запуск."""

    # ------------------------------------------------------- окно браузера (кадры по CDP)

    def build_browser_page(self):
        self.viewer = None
        self.viewer_env = None
        self.b_connecting = False
        self.b_manual_off = False
        self.b_frame = None
        self.b_frame_size = (0, 0)
        self.b_paint_pending = False
        self.b_ptr = (0.0, 0.0)
        self.b_buttons = 0
        self.b_last_move = 0.0
        self.b_wheel = None
        self.b_tabs = []
        self.b_active = None
        self.b_tabs_sig = None
        self.b_ctx = {}
        self.b_detached = None        # отдельное окно браузера (Gtk.Window) или None
        self.b_detached_env = ""
        self.b_want_url = ""          # ссылка, которую нужно открыть вкладкой сразу после подключения
        self.link_queue = []          # запросы на открытие ссылок из сред: (среда, адрес)
        self.link_dialog_open = False
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)

        # --- полоса вкладок
        strip = Gtk.Box(spacing=4, margin_top=4, margin_start=6, margin_end=6)
        self.b_tabs_box = Gtk.Box(spacing=2)
        scroller = Gtk.ScrolledWindow(hexpand=True)
        scroller.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.NEVER)
        scroller.set_child(self.b_tabs_box)
        strip.append(scroller)
        btn_new = Gtk.Button(icon_name="tab-new-symbolic", tooltip_text="Новая вкладка (Ctrl+T)")
        btn_new.add_css_class("flat")
        btn_new.connect("clicked", lambda *_a: self.browser_new_tab())
        strip.append(btn_new)
        outer.append(strip)

        # --- панель: назад, вперёд, обновить, адрес, масштаб, подключение
        bar = Gtk.Box(spacing=4, margin_top=4, margin_bottom=4, margin_start=6, margin_end=6)

        def tool(icon, tip, fn):
            btn = Gtk.Button(icon_name=icon, tooltip_text=tip)
            btn.add_css_class("flat")
            btn.connect("clicked", lambda *_a: fn())
            bar.append(btn)

        tool("go-previous-symbolic", "Назад (Alt+←)", lambda: self.browser_cmd(lambda v: v.history(-1)))
        tool("go-next-symbolic", "Вперёд (Alt+→)", lambda: self.browser_cmd(lambda v: v.history(1)))
        tool("view-refresh-symbolic", "Обновить (F5)", lambda: self.browser_cmd(lambda v: v.reload()))
        self.e_b_url = Gtk.Entry(hexpand=True, placeholder_text="Адрес: https://…  (Ctrl+L)")
        self.e_b_url.connect("activate", self.on_browser_go)
        bar.append(self.e_b_url)
        for text, tip, step in (("A−", "Мельче (Ctrl −)", -1), ("A+", "Крупнее (Ctrl +)", 1)):
            btn = Gtk.Button(label=text, tooltip_text=tip)
            btn.add_css_class("flat")
            btn.connect("clicked", lambda *_a, st=step: self.browser_zoom(st))
            bar.append(btn)
        self.btn_b_zoom = Gtk.Button(label="100%", tooltip_text="Масштаб страницы; клик — вернуть 100% (Ctrl 0)")
        self.btn_b_zoom.add_css_class("flat")
        self.btn_b_zoom.connect("clicked", lambda *_a: self.browser_zoom(0))
        bar.append(self.btn_b_zoom)
        self.btn_b_conn = Gtk.Button(label="Подключиться")
        self.btn_b_conn.connect("clicked", self.on_browser_toggle)
        bar.append(self.btn_b_conn)
        self.btn_b_detach = Gtk.Button(label="Отдельное окно",
                                       tooltip_text="Показать браузер в отдельном окне (можно держать рядом с другими)")
        self.btn_b_detach.connect("clicked", self.on_browser_detach_toggle)
        bar.append(self.btn_b_detach)
        outer.append(bar)

        # --- поиск по странице (Ctrl+F)
        self.b_find_bar = Gtk.Box(spacing=4, margin_start=6, margin_end=6, margin_bottom=4)
        self.e_b_find = Gtk.Entry(hexpand=True, placeholder_text="Найти на странице")
        self.e_b_find.connect("activate", lambda *_a: self.browser_find(False))
        self.b_find_bar.append(self.e_b_find)
        for text, back in (("Далее", False), ("Назад", True)):
            btn = Gtk.Button(label=text)
            btn.connect("clicked", lambda *_a, bk=back: self.browser_find(bk))
            self.b_find_bar.append(btn)
        btn_close = Gtk.Button(icon_name="window-close-symbolic", tooltip_text="Закрыть поиск")
        btn_close.add_css_class("flat")
        btn_close.connect("clicked", lambda *_a: self.browser_find_close())
        self.b_find_bar.append(btn_close)
        self.b_find_bar.set_visible(False)
        outer.append(self.b_find_bar)

        # --- страница
        self.b_picture = Gtk.Picture(hexpand=True, vexpand=True)
        try:
            self.b_picture.set_content_fit(Gtk.ContentFit.CONTAIN)
        except Exception:  # noqa: BLE001
            self.b_picture.set_keep_aspect_ratio(True)
        self.b_picture.set_can_shrink(True)
        self.b_picture.set_focusable(True)
        click = Gtk.GestureClick()
        click.set_button(0)
        click.connect("pressed", lambda g, n, x, y: self.on_b_mouse(g, "mousePressed", n, x, y))
        click.connect("released", lambda g, n, x, y: self.on_b_mouse(g, "mouseReleased", n, x, y))
        self.b_picture.add_controller(click)
        motion = Gtk.EventControllerMotion()
        motion.connect("motion", self.on_b_motion)
        self.b_picture.add_controller(motion)
        scroll = Gtk.EventControllerScroll.new(Gtk.EventControllerScrollFlags.BOTH_AXES)
        scroll.connect("scroll", self.on_b_scroll)
        self.b_picture.add_controller(scroll)
        keys = Gtk.EventControllerKey()
        keys.connect("key-pressed", lambda c, kv, kc, st: self.on_b_key(kv, kc, st, True))
        keys.connect("key-released", lambda c, kv, kc, st: self.on_b_key(kv, kc, st, False))
        self.b_picture.add_controller(keys)
        self.build_browser_menu()

        off = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, valign=Gtk.Align.CENTER, halign=Gtk.Align.CENTER)
        msg = Gtk.Label(wrap=True, justify=Gtk.Justification.CENTER, max_width_chars=60,
                        label="Здесь будет видна страница изолированного браузера.\n"
                              "Запустите его кнопкой «Запустить браузер» — вкладка подключится сама.\n"
                              "ИИ-среды управляют тем же браузером, поэтому вы увидите всё, что они делают.")
        msg.add_css_class("dim-label")
        off.append(msg)
        self.btn_b_start = Gtk.Button(label="Запустить браузер", halign=Gtk.Align.CENTER, margin_top=10)
        self.btn_b_start.add_css_class("suggested-action")
        self.btn_b_start.connect("clicked", self.on_browser_start)
        off.append(self.btn_b_start)
        self.b_stack = Gtk.Stack(vexpand=True, hexpand=True)
        self.b_stack.add_named(off, "off")
        self.b_stack.add_named(self.b_picture, "view")
        outer.append(self.b_stack)
        self.b_status = hint("")
        outer.append(self.b_status)
        GLib.timeout_add(1500, self.browser_tick)
        GLib.timeout_add(1500, self.poll_links)
        return outer

    # ---- служебное

    def bg(self, fn):
        """Вызов с ожиданием ответа браузера — не в потоке интерфейса."""
        def run():
            try:
                fn()
            except (OSError, ValueError, KeyError) as e:
                GLib.idle_add(self.browser_note, str(e))

        threading.Thread(target=run, daemon=True).start()

    def browser_note(self, text):
        self.b_status.set_text(text)
        return False

    def safe(self, fn):
        """Быстрая отправка ввода (без ожидания ответа) прямо из обработчика события."""
        try:
            fn()
        except OSError as e:
            self.browser_note(f"Связь с браузером потеряна: {e}")

    def browser_cmd(self, fn):
        v = self.viewer
        if v is None:
            self.browser_note("Браузер не подключён")
            return
        self.bg(lambda: fn(v))

    def set_clipboard(self, text):
        try:
            self.get_clipboard().set_text(text)
        except Exception:  # noqa: BLE001
            try:
                self.get_clipboard().set(text)
            except Exception:  # noqa: BLE001
                return False
        return True

    # ---- подключение

    def b_target(self):
        """Имя браузера, который показывается: в отдельном окне — его, иначе выбранная среда-браузер."""
        if self.b_detached is not None:
            return self.b_detached_env or None
        cur = self.current
        return cur.name if cur is not None and cur.is_browser else None

    def b_visible(self):
        if self.b_detached is not None:
            return True
        return self.nb.get_current_page() == self.nb.page_num(self.page_browser)

    def browser_tick(self):
        try:
            target = self.b_target()
            if self.viewer is not None:
                if target is None or target != self.viewer_env:
                    self.browser_disconnect()
                else:
                    w, h = int(self.b_picture.get_width()), int(self.b_picture.get_height())
                    vw, vh = self.viewer.size
                    if w > 200 and h > 150 and (abs(w - vw) > 8 or abs(h - vh) > 8):
                        v = self.viewer
                        self.bg(lambda: v.set_size(w, h))
            elif (target is not None and not self.b_connecting and not self.b_manual_off
                  and self.b_visible() and cdp_listening(target)):
                self.browser_connect(target)
        except Exception:  # noqa: BLE001
            pass
        return True

    def browser_connect(self, name=None):
        name = name or self.b_target()
        if self.viewer is not None or self.b_connecting or not name:
            return
        w = max(400, int(self.b_picture.get_width()) or 1000)
        h = max(300, int(self.b_picture.get_height()) or 700)
        self.b_connecting = True
        self.browser_note("Подключаюсь к браузеру…")
        holder = {}

        def work():
            v = None
            try:
                v = CdpViewer(cdp_socket_path(name), self.browser_on_frame, self.browser_on_url,
                                   lambda: GLib.idle_add(self.browser_closed, holder.get("v")),
                                   lambda tabs, active: GLib.idle_add(self.browser_set_tabs, tabs, active))
                holder["v"] = v
                v.connect(w, h)
                GLib.idle_add(self.browser_connected, v, name)
            except (OSError, ValueError, KeyError) as e:
                if v is not None:
                    v.close()
                GLib.idle_add(self.browser_failed, str(e))

        threading.Thread(target=work, daemon=True).start()

    def browser_connected(self, v, name):
        self.b_connecting = False
        if self.b_target() != name or self.viewer is not None:
            v.close()
            return False
        self.viewer, self.viewer_env = v, name
        self.b_buttons = 0
        self.b_stack.set_visible_child_name("view")
        self.btn_b_conn.set_label("Отключить")
        self.browser_note(f"Показан браузер «{name}». Клики, прокрутка и клавиши идут на страницу; ИИ работает "
                          "с теми же вкладками. Звука нет: у среды нет доступа к аудио. Правая кнопка — меню.")
        if self.b_want_url:  # ссылка из приложения среды: открыть новой вкладкой и показать
            url, self.b_want_url = self.b_want_url, ""
            self.bg(lambda: v.new_tab(url))
        return False

    def browser_failed(self, msg):
        self.b_connecting = False
        self.browser_note(f"Не удалось подключиться к браузеру: {msg}")
        return False

    def browser_closed(self, v):
        if v is not None and v is self.viewer:
            self.viewer = None
            self.viewer_env = None
            self.b_stack.set_visible_child_name("off")
            self.btn_b_conn.set_label("Подключиться")
            self.browser_set_tabs([], None)
            self.browser_note("Соединение с браузером закрыто (он остановлен?). Вкладка подключится снова сама.")
        return False

    def browser_disconnect(self):
        v, self.viewer, self.viewer_env = self.viewer, None, None
        self.b_buttons = 0
        self.b_stack.set_visible_child_name("off")
        self.btn_b_conn.set_label("Подключиться")
        self.browser_set_tabs([], None)
        if v is not None:
            try:
                v.close()
            except OSError:
                pass

    def browser_detach(self, name=None):
        """Показать браузер в отдельном окне (страница переезжает из вкладки envbox)."""
        name = name or self.b_target()
        if not name:
            self.browser_note("Выберите среду-браузер, чтобы открыть его в отдельном окне")
            return
        if self.b_detached is not None:
            if self.b_detached_env != name:
                self.b_detached_env = name
                self.b_detached.set_title(f"Браузер «{name}»")
                self.browser_disconnect()
            self.b_detached.present()
            return
        win = Gtk.Window(title=f"Браузер «{name}»")
        win.set_default_size(1180, 800)
        try:
            self.nb.detach_tab(self.page_browser)
        except Exception:  # noqa: BLE001
            n = self.nb.page_num(self.page_browser)
            if n >= 0:
                self.nb.remove_page(n)
        self.page_browser.set_visible(True)
        win.set_child(self.page_browser)
        win.connect("close-request", self.on_browser_window_close)
        self.b_detached, self.b_detached_env = win, name
        self.btn_b_detach.set_label("Вернуть в окно envbox")
        if self.viewer is not None and self.viewer_env != name:
            self.browser_disconnect()
        self.b_manual_off = False
        win.present()
        GLib.timeout_add(300, lambda: (self.browser_connect(name), False)[1])

    def on_browser_window_close(self, win):
        """Закрытие отдельного окна возвращает браузер во вкладку envbox."""
        if self.b_detached is not win:
            return False
        self.b_detached, self.b_detached_env = None, ""
        win.set_child(None)
        self.nb.insert_page(self.page_browser, Gtk.Label(label="Окно браузера"), 2)
        cur = self.current
        self.page_browser.set_visible(bool(cur is not None and cur.is_browser))
        self.btn_b_detach.set_label("Отдельное окно")
        return False

    def on_browser_detach_toggle(self, *_):
        if self.b_detached is not None:
            self.b_detached.close()
        else:
            self.browser_detach()

    def on_browser_start(self, *_):
        name = self.b_target()
        if not name:
            return
        if name in self.running:
            self.browser_note(f"Браузер «{name}» уже запущен; подождите подключения")
            return
        try:
            bp = load_profile(name)
        except (OSError, ValueError) as e:
            alert(self, "Не удалось прочитать среду", str(e))
            return
        errs = bp.validate()
        if errs:
            alert(self, f"Браузер «{name}» не готов к запуску", "\n".join(errs))
            return
        self.launch_browser(bp)

    def on_browser_toggle(self, *_):
        if self.viewer is not None:
            self.b_manual_off = True
            self.browser_disconnect()
            self.browser_note("Отключено. Нажмите «Подключиться», чтобы снова увидеть страницу.")
        else:
            self.b_manual_off = False
            self.browser_connect()
