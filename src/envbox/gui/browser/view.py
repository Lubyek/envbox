"""Встроенный браузер: вкладки, масштаб, поиск, меню, мышь и клавиатура."""

import re
import time

from ...cdp.http import CDP_MOD_ALT, CDP_MOD_CTRL, CDP_MOD_META, CDP_MOD_SHIFT
from ...cdp.keys import map_point, normalize_url
from ..gtk import GLib, Gdk, Gio, Gtk, Pango


class BrowserViewMixin:
    """Встроенный браузер: вкладки, масштаб, поиск, меню, мышь и клавиатура."""

    # ---- вкладки

    @staticmethod
    def b_tab_title(tab):
        title = (tab.get("title") or "").strip()
        if title and title != tab.get("url"):
            return title
        url = tab.get("url") or ""
        if not url or url == "about:blank":
            return "Новая вкладка"
        return re.sub(r"^https?://", "", url).split("/")[0] or url

    def browser_set_tabs(self, tabs, active):
        self.b_tabs, self.b_active = list(tabs), active
        sig = tuple((t["id"], self.b_tab_title(t), t["id"] == active) for t in tabs)
        if self.viewer is not None:
            self.btn_b_zoom.set_label(f"{round(self.viewer.cur_zoom * 100)}%")
        if sig == self.b_tabs_sig:
            return False
        self.b_tabs_sig = sig
        child = self.b_tabs_box.get_first_child()
        while child is not None:
            nxt = child.get_next_sibling()
            self.b_tabs_box.remove(child)
            child = nxt
        for t in tabs:
            tid = t["id"]
            cell = Gtk.Box(spacing=0)
            btn = Gtk.ToggleButton(label=self.b_tab_title(t), tooltip_text=f"{t.get('title') or ''}\n{t.get('url') or ''}")
            btn.set_active(tid == active)
            btn.add_css_class("flat")
            lbl = btn.get_child()
            try:
                lbl.set_ellipsize(Pango.EllipsizeMode.END)
                lbl.set_max_width_chars(18)
            except Exception:  # noqa: BLE001
                pass
            btn.connect("clicked", lambda *_a, i=tid, b=btn: (b.set_active(i == self.b_active),
                                                              self.browser_cmd(lambda v: v.switch_tab(i))))
            close = Gtk.Button(icon_name="window-close-symbolic", tooltip_text="Закрыть вкладку (Ctrl+W)")
            close.add_css_class("flat")
            close.connect("clicked", lambda *_a, i=tid: self.browser_cmd(lambda v: v.close_tab(i)))
            cell.append(btn)
            cell.append(close)
            self.b_tabs_box.append(cell)
        return False

    def browser_new_tab(self):
        self.browser_cmd(lambda v: v.new_tab("about:blank"))
        GLib.timeout_add(300, lambda: (self.e_b_url.grab_focus(), False)[1])

    def browser_cycle_tab(self, step):
        ids = [t["id"] for t in self.b_tabs]
        if len(ids) < 2 or self.b_active not in ids:
            return
        target = ids[(ids.index(self.b_active) + step) % len(ids)]
        self.browser_cmd(lambda v: v.switch_tab(target))

    # ---- адрес, масштаб, поиск, копирование

    def on_browser_go(self, *_):
        v = self.viewer
        if v is None:
            self.browser_note("Браузер не подключён: запустите его кнопкой «Запустить браузер»")
            return
        try:
            url = normalize_url(self.e_b_url.get_text())
        except ValueError as e:
            self.browser_note(str(e))
            return
        self.bg(lambda: v.navigate(url))
        self.b_picture.grab_focus()

    def browser_zoom(self, step):
        v = self.viewer
        if v is None:
            return

        def work():
            z = v.set_zoom(1.0) if step == 0 else v.zoom_step(step)
            GLib.idle_add(self.btn_b_zoom.set_label, f"{round(z * 100)}%")

        self.bg(work)

    def browser_find(self, back):
        text = self.e_b_find.get_text()
        v = self.viewer
        if v is None or not text:
            return

        def work():
            found = v.find(text, back)
            if not found:
                GLib.idle_add(self.browser_note, f"«{text}» на странице не найдено")

        self.bg(work)

    def browser_find_open(self):
        self.b_find_bar.set_visible(True)
        self.e_b_find.grab_focus()

    def browser_find_close(self):
        self.b_find_bar.set_visible(False)
        self.b_picture.grab_focus()

    def browser_copy_selection(self):
        v = self.viewer
        if v is None:
            return

        def work():
            text = v.selection_text()
            if text:
                GLib.idle_add(self.browser_copied, text)
            else:
                GLib.idle_add(self.browser_note, "Ничего не выделено")

        self.bg(work)

    def browser_copied(self, text):
        if self.set_clipboard(text):
            self.browser_note(f"Скопировано символов: {len(text)}")
        return False

    def paste_into_browser(self):
        def done(clip, res):
            try:
                text = clip.read_text_finish(res)
            except Exception:  # noqa: BLE001
                return
            v = self.viewer
            if text and v is not None:
                self.safe(lambda: v.insert_text(text))

        self.get_clipboard().read_text_async(None, done)

    # ---- меню правой кнопки

    def build_browser_menu(self):
        group = Gio.SimpleActionGroup()
        self.b_actions = {}

        def add(name, fn):
            act = Gio.SimpleAction.new(name, None)
            act.connect("activate", lambda *_a: fn())
            group.add_action(act)
            self.b_actions[name] = act

        def open_url(key):
            url = self.b_ctx.get(key) or ""
            if not re.match(r"^https?://", url, re.I):
                self.browser_note("Этот адрес нельзя открыть во вкладке (только http и https); его можно скопировать")
                return
            self.browser_cmd(lambda v: v.new_tab(url))

        def copy_url(key):
            url = self.b_ctx.get(key) or ""
            if url and self.set_clipboard(url):
                self.browser_note("Адрес скопирован")

        add("back", lambda: self.browser_cmd(lambda v: v.history(-1)))
        add("forward", lambda: self.browser_cmd(lambda v: v.history(1)))
        add("reload", lambda: self.browser_cmd(lambda v: v.reload()))
        add("copy", self.browser_copy_selection)
        add("paste", self.paste_into_browser)
        add("select-all", lambda: self.browser_cmd(lambda v: v.select_all()))
        add("open-link", lambda: open_url("link"))
        add("copy-link", lambda: copy_url("link"))
        add("open-image", lambda: open_url("image"))
        add("copy-image", lambda: copy_url("image"))
        add("open-video", lambda: open_url("video"))
        add("copy-video", lambda: copy_url("video"))
        add("zoom-in", lambda: self.browser_zoom(1))
        add("zoom-out", lambda: self.browser_zoom(-1))
        add("zoom-reset", lambda: self.browser_zoom(0))
        add("find", self.browser_find_open)
        self.b_picture.insert_action_group("web", group)
        self.b_popover = Gtk.PopoverMenu.new_from_model(Gio.Menu())
        self.b_popover.set_parent(self.b_picture)
        self.b_popover.set_has_arrow(False)

    def browser_show_menu(self, info, x, y):
        self.b_ctx = info
        menu = Gio.Menu()
        for key, items in (("link", (("Открыть ссылку в новой вкладке", "web.open-link"),
                                     ("Скопировать адрес ссылки", "web.copy-link"))),
                           ("image", (("Открыть картинку в новой вкладке", "web.open-image"),
                                      ("Скопировать адрес картинки", "web.copy-image"))),
                           ("video", (("Открыть видео в новой вкладке", "web.open-video"),
                                      ("Скопировать адрес видео", "web.copy-video")))):
            if info.get(key):
                sec = Gio.Menu()
                for label, act in items:
                    sec.append(label, act)
                menu.append_section(None, sec)
        edit = Gio.Menu()
        if info.get("selection"):
            edit.append("Копировать (Ctrl+C)", "web.copy")
        if info.get("editable"):
            edit.append("Вставить (Ctrl+V)", "web.paste")
        edit.append("Выделить всё (Ctrl+A)", "web.select-all")
        edit.append("Найти на странице… (Ctrl+F)", "web.find")
        menu.append_section(None, edit)
        nav = Gio.Menu()
        nav.append("Назад", "web.back")
        nav.append("Вперёд", "web.forward")
        nav.append("Обновить", "web.reload")
        menu.append_section(None, nav)
        view = Gio.Menu()
        view.append("Крупнее (Ctrl +)", "web.zoom-in")
        view.append("Мельче (Ctrl −)", "web.zoom-out")
        view.append("Масштаб 100% (Ctrl 0)", "web.zoom-reset")
        menu.append_section(None, view)
        self.b_popover.set_menu_model(menu)
        rect = Gdk.Rectangle()
        rect.x, rect.y, rect.width, rect.height = int(x), int(y), 1, 1
        self.b_popover.set_pointing_to(rect)
        self.b_popover.popup()
        return False

    # ---- кадры

    def browser_on_frame(self, data, meta):  # поток чтения: только запоминаем кадр
        self.b_frame = data
        if not self.b_paint_pending:
            self.b_paint_pending = True
            GLib.idle_add(self.browser_paint, priority=GLib.PRIORITY_DEFAULT)

    def browser_paint(self):
        self.b_paint_pending = False
        data = self.b_frame
        if data is None:
            return False
        try:
            tex = Gdk.Texture.new_from_bytes(GLib.Bytes.new(data))
        except Exception:  # noqa: BLE001
            return False
        self.b_frame_size = (tex.get_width(), tex.get_height())
        self.b_picture.set_paintable(tex)
        return False

    def browser_on_url(self, url):
        def apply():
            if not self.e_b_url.has_focus():
                self.e_b_url.set_text(url)
            return False

        GLib.idle_add(apply)

    # ---- ввод: мышь, колесо, клавиатура

    def b_point(self, x, y):
        fw, fh = getattr(self, "b_frame_size", (0, 0))
        return map_point(x, y, self.b_picture.get_width(), self.b_picture.get_height(), fw, fh)

    @staticmethod
    def b_mods(state):
        m = 0
        if state & Gdk.ModifierType.SHIFT_MASK:
            m |= CDP_MOD_SHIFT
        if state & Gdk.ModifierType.CONTROL_MASK:
            m |= CDP_MOD_CTRL
        if state & Gdk.ModifierType.ALT_MASK:
            m |= CDP_MOD_ALT
        if state & Gdk.ModifierType.SUPER_MASK:
            m |= CDP_MOD_META
        return m

    def on_b_mouse(self, gesture, kind, n, x, y):
        v = self.viewer
        if v is None:
            return
        if kind == "mousePressed":
            self.b_picture.grab_focus()
        pt = self.b_point(x, y)
        if pt is None:
            return
        num = gesture.get_current_button()
        if num == 3:  # правая кнопка — наше меню (содержимое под курсором узнаём у страницы)
            if kind == "mousePressed":
                def work():
                    info = v.hit_info(pt[0], pt[1])
                    GLib.idle_add(self.browser_show_menu, info, x, y)

                self.bg(work)
            return
        button = {1: "left", 2: "middle"}.get(num, "left")
        bit = {1: 1, 2: 4}.get(num, 1)
        self.b_buttons = (self.b_buttons | bit) if kind == "mousePressed" else (self.b_buttons & ~bit)
        mods = self.b_mods(gesture.get_current_event_state())
        self.safe(lambda: v.mouse(kind, pt[0], pt[1], button, max(1, n), mods, self.b_buttons))

    def on_b_motion(self, _ctrl, x, y):
        self.b_ptr = (x, y)
        v = self.viewer
        now = time.monotonic()
        if v is None or now - self.b_last_move < 0.04:
            return
        pt = self.b_point(x, y)
        if pt is None:
            return
        self.b_last_move = now
        button = "left" if self.b_buttons & 1 else "none"
        self.safe(lambda: v.mouse("mouseMoved", pt[0], pt[1], button, 0, 0, self.b_buttons))

    def on_b_scroll(self, ctrl, dx, dy):
        v = self.viewer
        if v is None:
            return False
        try:
            state = ctrl.get_current_event_state()
        except Exception:  # noqa: BLE001
            state = 0
        if state & Gdk.ModifierType.CONTROL_MASK and dy:  # Ctrl + колесо — масштаб, как в браузерах
            self.browser_zoom(-1 if dy > 0 else 1)
            return True
        pt = self.b_point(*self.b_ptr)
        if pt is None:
            return False
        # события колеса склеиваются: не чаще раза в кадр (≈60 Гц), иначе быстрая прокрутка тормозит
        if self.b_wheel is None:
            self.b_wheel = [0.0, 0.0, pt[0], pt[1]]
            GLib.timeout_add(16, self.flush_wheel)
        self.b_wheel[0] += dx * 100
        self.b_wheel[1] += dy * 100
        self.b_wheel[2], self.b_wheel[3] = pt
        return True

    def flush_wheel(self):
        w, self.b_wheel = self.b_wheel, None
        v = self.viewer
        if w is not None and v is not None and (w[0] or w[1]):
            self.safe(lambda: v.wheel(w[2], w[3], w[0], w[1]))
        return False

    # физические клавиши (evdev + 8): сочетания работают в любой раскладке, в том числе русской
    KC_A, KC_C, KC_F, KC_L, KC_R, KC_T, KC_V, KC_W = 38, 54, 41, 46, 27, 28, 55, 25

    def on_b_key(self, keyval, keycode, state, pressed):
        v = self.viewer
        if v is None:
            return False
        mods = self.b_mods(state)
        ctrl, alt = bool(mods & CDP_MOD_CTRL), bool(mods & CDP_MOD_ALT)
        name = Gdk.keyval_name(keyval) or ""
        if pressed:
            handled = True
            if ctrl and not alt:
                if keycode == self.KC_V:
                    self.paste_into_browser()
                elif keycode == self.KC_C:
                    self.browser_copy_selection()
                elif keycode == self.KC_A:
                    self.browser_cmd(lambda vv: vv.select_all())
                elif keycode == self.KC_T:
                    self.browser_new_tab()
                elif keycode == self.KC_W:
                    tid = self.b_active
                    self.browser_cmd(lambda vv: vv.close_tab(tid))
                elif keycode == self.KC_L:
                    self.e_b_url.grab_focus()
                    self.e_b_url.select_region(0, -1)
                elif keycode == self.KC_F:
                    self.browser_find_open()
                elif keycode == self.KC_R:
                    self.browser_cmd(lambda vv: vv.reload())
                elif name in ("plus", "equal", "KP_Add"):
                    self.browser_zoom(1)
                elif name in ("minus", "KP_Subtract"):
                    self.browser_zoom(-1)
                elif name in ("0", "KP_0"):
                    self.browser_zoom(0)
                elif name == "Tab":
                    self.browser_cycle_tab(1)
                elif name == "ISO_Left_Tab":
                    self.browser_cycle_tab(-1)
                else:
                    handled = False
            elif alt and not ctrl and name in ("Left", "Right"):
                self.browser_cmd(lambda vv: vv.history(-1 if name == "Left" else 1))
            elif name == "F5":
                self.browser_cmd(lambda vv: vv.reload())
            else:
                handled = False
            if handled:
                return True
        elif ctrl and keycode in (self.KC_V, self.KC_C, self.KC_A, self.KC_T, self.KC_W, self.KC_L, self.KC_F,
                                  self.KC_R) or name in ("F5",):
            return True  # отпускание уже обработанного сочетания странице не нужно
        uni = Gdk.keyval_to_unicode(keyval)
        char = chr(uni) if uni else ""
        self.safe(lambda: v.key(name, char, mods, pressed))
        return True
