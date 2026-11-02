"""Вкладка «Сеть»: журнал, фильтр, разрешение доменов, сеансы."""

from ...core.consts import DOMAIN_RE, NET_LABELS, NET_MODES
from ...core.diagnose import diagnose_claude
from ...core.netlog import LogTail, NetSummary, clear_net_log, filter_net_log, format_event, human_size, net_log_path
from ...core.sessions import list_sessions
from ..gtk import Gtk
from ..tables import Row, Table
from ..widgets import alert, choose, get_lines, hint, margins, set_text, text_area, to_home


class NetPageMixin:
    """Вкладка «Сеть»: журнал, фильтр, разрешение доменов, сеансы."""

    def build_net_page(self):
        box = margins(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8))
        self.lbl_net = Gtk.Label(xalign=0, wrap=True)
        box.append(self.lbl_net)
        self.net_search = Gtk.SearchEntry(placeholder_text="Фильтр по хосту")
        self.net_search.connect("search-changed", self.on_net_filter)
        box.append(self.net_search)
        self.net_table = Table(["Куда (хост:порт)", "Соединений", "Запрещено", "Ошибок", "Отправлено",
                                "Получено", "Последнее", "Через / IP"],
                               empty_text="Пока ни одного обращения.\nЗапустите среду в режиме "
                                          "«через прокси с журналом» — здесь появится, куда она ходит.")
        buttons = Gtk.Box(spacing=8)
        b_all = Gtk.Button(label="Выбрать все")
        b_all.connect("clicked", lambda *_: self.net_table.select_all())
        b_none = Gtk.Button(label="Снять выбор")
        b_none.connect("clicked", lambda *_: self.net_table.unselect_all())
        b_allow = Gtk.Button(label="Разрешить выбранные домены")
        b_allow.connect("clicked", self.on_allow_domain)
        b_clear_sel = Gtk.Button(label="Убрать выбранные из журнала")
        b_clear_sel.connect("clicked", self.on_clear_selected)
        b_clear = Gtk.Button(label="Очистить весь журнал")
        b_clear.connect("clicked", self.on_clear_log)
        b_diag = Gtk.Button(label="Почему Claude зависает?")
        b_diag.connect("clicked", self.on_claude_diag)
        for b in (b_all, b_none, b_allow, b_clear_sel, b_clear, b_diag):
            buttons.append(b)
        self.tv_events, sw = text_area(editable=False, height=120)
        buf = self.tv_events.get_buffer()
        self.events_end = buf.create_mark("end", buf.get_end_iter(), False)
        upper = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        upper.append(self.net_table.widget)
        upper.append(buttons)
        lower = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        lower.append(hint("События в реальном времени:"))
        lower.append(sw)
        upper.set_vexpand(True)
        sw.set_vexpand(False)
        box.append(upper)
        box.append(lower)
        box.append(hint("Журнал пишет прокси на хосте, среда его не видит. Для HTTPS видны только "
                        "хост, порт, IP, объём и время; содержимое и пути не расшифровываются."))
        return box

    def on_net_filter(self, entry):
        self.net_filter = entry.get_text().strip().lower()
        self.render_summary()

    def reset_net_view(self):
        set_text(self.tv_events, "")
        self.net_summary = NetSummary()
        self.net_table.set_rows([])
        if not self.current:
            self.tail = None
            self.lbl_net.set_text("")
            return
        p = self.current
        self.tail = LogTail(net_log_path(p.name))
        mode = NET_LABELS[p.net]
        via = f", через {p.upstream}" if p.upstream and p.net in ("log", "allowlist") else ""
        if p.chain_on:
            via = ", каналы по порядку: " + " → ".join(p.upstream_chain)
        if p.net in ("log", "allowlist"):
            self.lbl_net.set_text(f"Режим сети: {mode}{via}. Журнал: {to_home(net_log_path(p.name))}")
        else:
            self.lbl_net.set_text(f"Режим сети: {mode}. Журнал ведётся только в режимах «Через журнал» "
                                  "— ниже показаны записи прошлых запусков, если они есть.")
        self.poll_net()

    def render_summary(self):
        rows = []
        for s in self.net_summary.rows():
            label = f"{s['host']}:{s['port']}"
            if self.net_filter and self.net_filter not in label.lower():
                continue
            rows.append(Row([label, str(s["open"]), str(s["deny"]), str(s["error"]),
                             human_size(s["up"]), human_size(s["down"]),
                             s["last"].replace("T", " ")[:19],
                             s["via"] or ", ".join(sorted(s["ips"]))],
                            key=(s["host"], s["port"]), data=s["host"]))
        self.net_table.set_rows(rows)

    def poll_net(self):
        if self.tail is None:
            return
        new = self.tail.read_new()
        if not new:
            return
        self.net_summary.add(new)
        buf = self.tv_events.get_buffer()
        buf.insert(buf.get_end_iter(), "\n".join(format_event(e) for e in new) + "\n")
        lines = buf.get_line_count()
        if lines > 3000:
            res = buf.get_iter_at_line(lines - 2000)
            it = res[1] if isinstance(res, tuple) else res
            buf.delete(buf.get_start_iter(), it)
        self.tv_events.scroll_mark_onscreen(self.events_end)
        self.render_summary()

    def selected_hosts(self):
        """Хосты выбранных строк таблицы без повторов (одна строка — хост:порт, хосты могут повторяться)."""
        return sorted({row.data for row in self.net_table.selected_rows() if row.data})

    def on_allow_domain(self, *_):
        hosts = self.selected_hosts()
        if not hosts or not self.current:
            alert(self, "Выберите строки в таблице", "Несколько строк: Ctrl или Shift + клик, рамка мышью или "
                                                     "«Выбрать все» (после фильтра по хосту — только найденные).")
            return
        valid = [h for h in hosts if DOMAIN_RE.match(h)]
        invalid = [h for h in hosts if h not in valid]
        if not valid:
            alert(self, "Эти строки нельзя добавить как домены", ", ".join(invalid[:8]) +
                  "\nПоддерживаются имена и IPv4-адреса.")
            return
        lines = get_lines(self.tv_domains)
        added = [h for h in valid if h not in lines]
        set_text(self.tv_domains, "\n".join(lines + added))
        self.dd_net.set_selected(NET_MODES.index("allowlist"))
        if self.save_current(quiet=True):
            more = f"\nНе добавлены (не домены): {', '.join(invalid[:8])}" if invalid else ""
            alert(self, f"Разрешено доменов: {len(valid)} (новых {len(added)})",
                  ", ".join(valid[:12]) + (" …" if len(valid) > 12 else "") + more +
                  "\n\nРежим сети переключён на «только разрешённые домены». "
                  "Изменение вступит в силу при следующем запуске среды.")

    def on_claude_diag(self, *_):
        """Разбор журнала шлюза и записей Claude за последние часы: обрывы, зависшие туннели, лимит жизни туннеля."""
        if not self.current:
            alert(self, "Выберите среду")
            return
        name = self.current.name
        self.status(f"Разбираю журнал среды «{name}»…")

        def done(res):
            if isinstance(res, Exception):
                alert(self, "Не удалось разобрать журнал", str(res))
                return
            self.status("Диагностика готова")
            self.show_report(f"Почему Claude зависает: «{name}»", res)

        self.run_async(lambda: diagnose_claude(name), done)

    def on_clear_selected(self, *_):
        hosts = self.selected_hosts()
        if not hosts or not self.current:
            alert(self, "Выберите строки в таблице")
            return
        name = self.current.name

        def done(idx):
            if idx == 1:
                try:
                    removed = filter_net_log(name, hosts)
                except OSError as e:
                    alert(self, "Не удалось изменить журнал", str(e))
                    return
                self.status(f"Из журнала убрано записей: {removed} (хостов: {len(hosts)})")
                self.reset_net_view()

        choose(self, f"Убрать из журнала записи по выбранным хостам ({len(hosts)})?",
               ", ".join(hosts[:10]) + (" …" if len(hosts) > 10 else ""), ["Отмена", "Убрать"], done)

    def on_clear_log(self, *_):
        if not self.current:
            return
        name = self.current.name

        def done(idx):
            if idx == 1:
                try:
                    clear_net_log(name)
                except OSError as e:
                    alert(self, "Не удалось очистить журнал", str(e))
                self.reset_net_view()

        choose(self, "Очистить весь сетевой журнал?", to_home(net_log_path(name)),
               ["Отмена", "Очистить"], done)

    def refresh_sessions_async(self):
        """Просмотр /proc не в потоке окна: на компьютере с тысячами процессов он занимает заметное время."""
        if getattr(self, "scanning", False):
            return
        self.scanning = True

        def done(res):
            self.scanning = False
            if not isinstance(res, Exception):
                self.apply_sessions(res)

        self.run_async(lambda: {s.name for s in list_sessions()}, done)

    def refresh_sessions(self):
        self.apply_sessions({s.name for s in list_sessions()})

    def apply_sessions(self, names):
        if names != self.running:
            self.running = names
            for name, dot in self.row_dots.items():
                dot.set_text("●" if name in names else "")
            self.update_buttons()
            if self.current:
                self.update_overview()

    def refresh_sessions_once(self):
        self.refresh_sessions()
        return False
