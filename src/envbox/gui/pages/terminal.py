"""Встроенный терминал (VTE)."""

import os
import signal

from ...core.system import pkg_hint
from ...core.terminal import terminal_argv
from ..consts import HOME
from ..gtk import GLib, Gdk, Gio, Gtk, Pango, Vte


class TerminalMixin:
    """Встроенный терминал (VTE)."""

    def build_terminal_page(self):
        self.term_stack = Gtk.Stack()
        empty = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14,
                        valign=Gtk.Align.CENTER, halign=Gtk.Align.CENTER)
        msg = Gtk.Label(wrap=True, justify=Gtk.Justification.CENTER, max_width_chars=60,
                        label="Здесь откроются терминалы выбранной среды.\n"
                              "Нажмите «Терминал» наверху.")
        msg.add_css_class("dim-label")
        empty.append(msg)
        if Vte is None:
            warn = Gtk.Label(wrap=True, justify=Gtk.Justification.CENTER, max_width_chars=60,
                             label="Встроенный терминал недоступен: не найден VTE для GTK 4.\n"
                                   "Установка: " + pkg_hint("vte") + "\n"
                                   "Пока терминал откроется во внешнем окне.")
            warn.add_css_class("eb-warn")
            empty.append(warn)
        self.term_nb = Gtk.Notebook(scrollable=True, vexpand=True, hexpand=True)
        self.term_stack.add_named(empty, "empty")
        self.term_stack.add_named(self.term_nb, "tabs")

        # панель действий над текущим терминалом (то же, что меню по правой кнопке)
        bar = Gtk.Box(spacing=4, margin_top=4, margin_bottom=2, margin_start=6, margin_end=6)
        for text, action, tip in (("Копировать", "copy", "Скопировать выделенное (Ctrl+Shift+C)"),
                                  ("Вставить", "paste", "Вставить из буфера (Ctrl+Shift+V, Shift+Insert)"),
                                  ("Выделить всё", "select-all", "Выделить весь вывод (Ctrl+Shift+A)"),
                                  ("Очистить", "clear", "Очистить экран и историю"),
                                  ("A−", "zoom-out", "Мельче (Ctrl −)"),
                                  ("A+", "zoom-in", "Крупнее (Ctrl +)")):
            btn = Gtk.Button(label=text, tooltip_text=tip)
            btn.add_css_class("flat")
            btn.connect("clicked", lambda *_a, act=action: self.term_do(self.current_term(), act))
            bar.append(btn)
        bar.append(Gtk.Label(label="Выделение мышью копируется само; средняя кнопка вставляет",
                             hexpand=True, xalign=1, css_classes=["dim-label"]))
        bar.set_visible(False)
        self.term_stack.connect("notify::visible-child-name",
                                lambda st, *_a: bar.set_visible(st.get_visible_child_name() == "tabs"))
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        outer.append(bar)
        outer.append(self.term_stack)
        return outer

    def use_embedded(self):
        return Vte is not None and bool(self.settings.get("embedded", True))

    # ---- копирование, вставка, масштаб: сочетания клавиш, меню по правой кнопке, панель сверху

    def term_do(self, term, action):
        """Действие над терминалом: copy, paste, select-all, clear, zoom-in, zoom-out, zoom-reset."""
        if term is None:
            return
        try:
            if action == "copy":
                if term.get_has_selection():
                    term.copy_clipboard_format(Vte.Format.TEXT)
            elif action == "paste":
                term.paste_clipboard()
            elif action == "select-all":
                term.select_all()
            elif action == "clear":
                term.reset(True, True)
            elif action == "zoom-in":
                term.set_font_scale(min(4.0, term.get_font_scale() * 1.1))
            elif action == "zoom-out":
                term.set_font_scale(max(0.4, term.get_font_scale() / 1.1))
            elif action == "zoom-reset":
                term.set_font_scale(1.0)
        except Exception as e:  # noqa: BLE001
            self.status(f"Не удалось выполнить действие терминала: {e}")
        term.grab_focus()

    def current_term(self):
        page = self.term_nb.get_current_page()
        term = self.term_nb.get_nth_page(page) if page >= 0 else None
        return term if term in self.term_entries else None

    def attach_term_controls(self, term):
        """Сочетания клавиш и меню правой кнопки; возвращает popover (его нужно отсоединить при закрытии)."""
        keys = Gtk.ShortcutController()
        # CAPTURE: иначе клавиши сначала достанутся самому терминалу и уйдут в программу как ввод
        keys.set_propagation_phase(Gtk.PropagationPhase.CAPTURE)
        for accel, action in (("<Control><Shift>c", "copy"), ("<Control>Insert", "copy"),
                              ("<Control><Shift>v", "paste"), ("<Shift>Insert", "paste"),
                              ("<Control><Shift>a", "select-all"),
                              ("<Control>plus", "zoom-in"), ("<Control>equal", "zoom-in"),
                              ("<Control>KP_Add", "zoom-in"), ("<Control>minus", "zoom-out"),
                              ("<Control>KP_Subtract", "zoom-out"), ("<Control>0", "zoom-reset")):
            keys.add_shortcut(Gtk.Shortcut.new(
                Gtk.ShortcutTrigger.parse_string(accel),
                Gtk.CallbackAction.new(lambda *_a, act=action: (self.term_do(term, act), True)[1])))
        term.add_controller(keys)

        group = Gio.SimpleActionGroup()
        actions = {}
        for name in ("copy", "paste", "select-all", "clear", "zoom-in", "zoom-out", "zoom-reset"):
            act = Gio.SimpleAction.new(name, None)
            act.connect("activate", lambda *_a, n=name: self.term_do(term, n))
            group.add_action(act)
            actions[name] = act
        term.insert_action_group("term", group)
        link_state = {"url": ""}
        open_act = Gio.SimpleAction.new("open-link", None)
        open_act.connect("activate", lambda *_a: self.open_term_link(term, link_state["url"]))
        open_act.set_enabled(False)
        group.add_action(open_act)
        actions["open-link"] = open_act
        tag = None
        try:  # подсветка и распознавание ссылок: Vte.Regex (PCRE2_UTF | NO_UTF_CHECK | MULTILINE)
            regex = Vte.Regex.new_for_match(r"https?://[^\s<>\"'`]+[^\s<>\"'`.,;:!?)\]}]", -1, 0x40080400)
            tag = term.match_add_regex(regex, 0)
            term.match_set_cursor_name(tag, "pointer")
        except Exception:  # noqa: BLE001
            tag = None

        def link_at(x, y):
            if tag is None:
                return ""
            try:
                m = term.check_match_at(x, y)
            except Exception:  # noqa: BLE001
                return ""
            text = m[0] if isinstance(m, (tuple, list)) else m
            return text or ""

        lclick = Gtk.GestureClick()
        lclick.set_button(1)

        def on_lclick(g, _n, x, y):
            if g.get_current_event_state() & Gdk.ModifierType.CONTROL_MASK:
                url = link_at(x, y)
                if url:
                    self.open_term_link(term, url)

        lclick.connect("pressed", on_lclick)
        term.add_controller(lclick)
        menu = Gio.Menu()
        top = Gio.Menu()
        top.append("Копировать (Ctrl+Shift+C)", "term.copy")
        top.append("Вставить (Ctrl+Shift+V)", "term.paste")
        top.append("Выделить всё (Ctrl+Shift+A)", "term.select-all")
        top.append("Открыть ссылку в браузере (Ctrl+клик)", "term.open-link")
        menu.append_section(None, top)
        view = Gio.Menu()
        view.append("Очистить экран и историю", "term.clear")
        view.append("Крупнее (Ctrl +)", "term.zoom-in")
        view.append("Мельче (Ctrl −)", "term.zoom-out")
        view.append("Обычный размер (Ctrl 0)", "term.zoom-reset")
        menu.append_section(None, view)
        popover = Gtk.PopoverMenu.new_from_model(menu)
        popover.set_parent(term)
        popover.set_has_arrow(False)
        click = Gtk.GestureClick()
        click.set_button(3)

        def on_press(_gesture, _n, x, y):
            rect = Gdk.Rectangle()
            rect.x, rect.y, rect.width, rect.height = int(x), int(y), 1, 1
            popover.set_pointing_to(rect)
            actions["copy"].set_enabled(bool(term.get_has_selection()))
            link_state["url"] = link_at(x, y)
            actions["open-link"].set_enabled(bool(link_state["url"]))
            popover.popup()

        click.connect("pressed", on_press)
        term.add_controller(click)
        return popover

    def open_embedded(self, p, command, install=False, feed="", install_domains=None):
        """Терминал во вкладке: оболочка/команда внутри среды, секреты берутся из keyring.
            install — режим установки; feed — текст, набранный в терминале (Enter нажимаете вы)."""
        term = Vte.Terminal()
        term.set_hexpand(True)
        term.set_vexpand(True)
        term.set_scrollback_lines(20000)
        term.set_mouse_autohide(True)
        term.set_scroll_on_keystroke(True)
        popover = self.attach_term_controls(term)

        title = f"{p.name} · " + ("установка" if install else (command or p.command))
        label = Gtk.Label(label=title)
        label.set_ellipsize(Pango.EllipsizeMode.END)
        label.set_max_width_chars(30)
        close = Gtk.Button(icon_name="window-close-symbolic", tooltip_text="Закрыть и завершить")
        close.add_css_class("flat")
        head = Gtk.Box(spacing=6)
        head.append(label)
        head.append(close)
        entry = {"pid": None, "alive": True, "title": title, "label": label, "popover": popover, "env": p.name}
        self.term_entries[term] = entry
        self.term_nb.append_page(term, head)
        self.term_nb.set_current_page(self.term_nb.page_num(term))
        self.term_stack.set_visible_child_name("tabs")
        self.nb.set_current_page(self.nb.page_num(self.page_terminal))
        close.connect("clicked", lambda *_: self.close_embedded(term))
        term.connect("child-exited", lambda t, status, *_: self.on_term_exit(t))

        def spawned(_t, pid, error, *_rest):
            if error is not None:
                entry["alive"] = False
                term.feed(f"envbox: не удалось запустить: {error.message}\r\n".encode())
            else:
                entry["pid"] = pid

        env = [f"{k}={v}" for k, v in os.environ.items()] + ["ENVBOX_EMBEDDED=1"]
        argv = terminal_argv([], p, command, install=install, install_domains=install_domains)
        args = (Vte.PtyFlags.DEFAULT, HOME, argv, env, GLib.SpawnFlags.DEFAULT,
                None, None, -1, None, spawned)
        try:
            term.spawn_async(*args, None)
        except TypeError:  # другая версия привязок: без user_data
            term.spawn_async(*args)
        term.grab_focus()
        if feed:
            def type_command():
                try:
                    term.feed_child(feed.encode())
                except TypeError:
                    term.feed_child(feed)
                return False

            GLib.timeout_add(1200, type_command)
        self.status(f"Терминал «{p.name}» открыт во вкладке")
        GLib.timeout_add(1500, self.refresh_sessions_once)

    def on_term_exit(self, term):
        entry = self.term_entries.get(term)
        if entry:
            entry["alive"] = False
            entry["label"].set_text(entry["title"] + "  (завершён)")
        GLib.timeout_add(700, self.refresh_sessions_once)

    def kill_group(self, pid):
        """Завершает всю группу процессов терминала (обёртка, envbox, прокси, bwrap)."""
        try:
            os.killpg(pid, signal.SIGTERM)
        except OSError:
            return

        def hard():
            try:
                os.killpg(pid, signal.SIGKILL)
            except OSError:
                pass
            return False

        GLib.timeout_add(3000, hard)

    def close_embedded(self, term):
        entry = self.term_entries.pop(term, None)
        if entry and entry.get("popover") is not None:
            try:
                entry["popover"].unparent()
            except Exception:  # noqa: BLE001
                pass
        if entry and entry["alive"] and entry["pid"]:
            self.kill_group(entry["pid"])
        page = self.term_nb.page_num(term)
        if page >= 0:
            self.term_nb.remove_page(page)
        if self.term_nb.get_n_pages() == 0:
            self.term_stack.set_visible_child_name("empty")
        GLib.timeout_add(900, self.refresh_sessions_once)
