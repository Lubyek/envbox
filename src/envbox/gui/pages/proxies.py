"""Вкладка «Прокси»: список прокси по папкам (сервисам), поиск, пинг, проверка, проверка для Claude, выделение."""

from ...core.proxies import (
    check_proxy,
    clear_proxies,
    delete_proxies,
    delete_px_folder,
    import_proxies,
    import_proxy_url,
    is_proxy_list_url,
    list_proxies,
    list_px_folders,
    proxy_url_with_auth,
    refresh_px_folder,
    set_px_folder,
    test_proxy,
)
from ...core.keyring import secret_clear, secret_tool_available
from ...core.consts import UPSTREAM_AUTH_VAR
from ...core.vpn import folder_summary, natural_key, ping_vpns, search_vpns
from ...core.vpncheck import format_report
from ..gtk import GLib, Gtk
from ..widgets import alert, choose, clear_children, get_text, hint, margins, prompt, text_area


class ProxyPageMixin:
    """Прокси общие для всех сред; «В среду…» подставляет выбранный в настройки текущей среды."""

    def build_px_page(self):
        self.px_query = ""
        self.px_ping = {}           # имя -> миллисекунды или None (не ответил)
        self.px_open = {}           # папка -> раскрыта ли
        self.px_by_ping = False
        self.px_sel = set()         # имена выделенных галочками прокси
        self.px_note = {}           # имя -> короткая сводка последней проверки «для Claude»
        box = margins(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10), 16)
        title = Gtk.Label(label="Прокси", xalign=0)
        title.add_css_class("eb-h2")
        box.append(title)
        box.append(hint("Добавьте прокси (HTTP или SOCKS5): по одному в строке, форматы схема://логин:пароль@хост:порт, "
                        "хост:порт:логин:пароль или просто хост:порт, либо ссылку на список (https://…). Прокси из списка "
                        "складываются в папку-сервис. «В среду…» подставляет выбранный прокси в настройки текущей среды "
                        "(пароль уходит в keyring среды). «Для Claude» показывает страну, регион, город, провайдера, "
                        "репутацию адреса, утечку настоящего адреса и доступность claude.ai и api.anthropic.com. "
                        "Пароли хранятся в каталоге данных envbox (папка _proxy, права только владельцу)."))
        bar = Gtk.Box(spacing=8)
        for label, handler in (("Загрузить из файла…", self.on_px_file), ("Вставить прокси или ссылку…", self.on_px_paste)):
            bt = Gtk.Button(label=label)
            bt.connect("clicked", handler)
            bar.append(bt)
        box.append(bar)
        search = Gtk.Box(spacing=8)
        self.px_search = Gtk.SearchEntry(hexpand=True, placeholder_text="Поиск: название, адрес, порт, папка, HTTP/SOCKS5")
        self.px_search.connect("search-changed", self.on_px_search)
        search.append(self.px_search)
        ping_all = Gtk.Button(label="Измерить пинг")
        ping_all.connect("clicked", lambda *_: self.on_px_ping(None))
        search.append(ping_all)
        by_ping = Gtk.CheckButton(label="Сначала быстрые")
        by_ping.connect("toggled", self.on_px_sort)
        search.append(by_ping)
        box.append(search)
        bulk = Gtk.Box(spacing=8)
        for label, handler in (("Выбрать все", self.on_px_select_all), ("Снять выбор", self.on_px_unselect)):
            bt = Gtk.Button(label=label)
            bt.connect("clicked", handler)
            bulk.append(bt)
        self.btn_px_del = Gtk.Button(label="Удалить выбранные (0)")
        self.btn_px_del.connect("clicked", self.on_px_delete_selected)
        bulk.append(self.btn_px_del)
        clear_all = Gtk.Button(label="Очистить всё")
        clear_all.add_css_class("destructive-action")
        clear_all.connect("clicked", self.on_px_clear_all)
        bulk.append(clear_all)
        box.append(bulk)
        self.px_list = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        scroll = Gtk.ScrolledWindow(vexpand=True)
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.set_child(self.px_list)
        box.append(scroll)
        box.append(hint("Пинг — время TCP-подключения к прокси с вашего компьютера. «Проверить» открывает через прокси "
                        "туннель до example.com."))
        self.refresh_px_list()
        return box

    # ---- список: папки, поиск, пинг

    def on_px_search(self, entry):
        self.px_query = entry.get_text().strip()
        self.refresh_px_list()

    def on_px_sort(self, button):
        self.px_by_ping = button.get_active()
        self.refresh_px_list()

    def px_ping_text(self, p):
        if p["name"] not in self.px_ping:
            return "—"
        ms = self.px_ping[p["name"]]
        return f"{ms} мс" if ms is not None else "нет ответа"

    def px_sort_key(self, p):
        if self.px_by_ping:
            ms = self.px_ping.get(p["name"])
            return (ms is None, ms or 0, natural_key(p["name"]))
        return natural_key(p["name"])

    def refresh_px_list(self):
        clear_children(self.px_list)
        everything = list_proxies()
        self.px_sel &= {p["name"] for p in everything}
        self.update_px_sel()
        shown = search_vpns(everything, self.px_query)
        if not everything:
            self.px_list.append(hint("Пока нет ни одного прокси."))
        elif not shown:
            self.px_list.append(hint(f"По запросу «{self.px_query}» ничего не найдено."))
        groups = {}
        for p in shown:
            groups.setdefault(p["folder"], []).append(p)
        folders = list_px_folders()
        for folder in sorted(f for f in groups if f) + ([""] if "" in groups else []):
            self.px_list.append(self.px_folder(folder, sorted(groups[folder], key=self.px_sort_key),
                                               folders.get(folder, {}),
                                               sum(1 for p in everything if p["folder"] == folder)))

    def px_folder(self, folder, items, info, total):
        exp = Gtk.Expander()
        exp.set_expanded(self.px_open.get(folder, True) or bool(self.px_query))
        exp.connect("notify::expanded", lambda e, _p, f=folder: self.px_open.__setitem__(f, e.get_expanded()))
        head = Gtk.Box(spacing=8, hexpand=True)
        text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2, hexpand=True)
        count = f"{len(items)} из {total}" if len(items) != total else str(total)
        name = Gtk.Label(label=f"{folder or 'Без папки'} · {count}", xalign=0)
        name.add_css_class("eb-h2")
        text.append(name)
        summary = folder_summary(info)
        if summary:
            text.append(hint(summary))
        head.append(text)
        names = [p["name"] for p in items]
        pick = Gtk.Button(label="Выбрать")
        pick.connect("clicked", lambda _b, n=names: self.on_px_select_names(n))
        head.append(pick)
        ping = Gtk.Button(label="Пинг")
        ping.connect("clicked", lambda _b, n=names: self.on_px_ping(n))
        head.append(ping)
        if info.get("url"):
            upd = Gtk.Button(label="Обновить")
            upd.connect("clicked", lambda _b, f=folder: self.on_px_folder_update(f))
            head.append(upd)
        if folder:
            drop = Gtk.Button(label="Удалить папку")
            drop.connect("clicked", lambda _b, f=folder, n=total: self.on_px_folder_delete(f, n))
            head.append(drop)
        exp.set_label_widget(head)
        rows = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        for p in items:
            rows.append(self.px_row(p))
        exp.set_child(margins(rows, 6))
        return exp

    def px_row(self, p):
        row = Gtk.Box(spacing=8)
        chk = Gtk.CheckButton(active=p["name"] in self.px_sel)
        chk.connect("toggled", lambda b, n=p["name"]: self.on_px_toggle(n, b.get_active()))
        row.append(chk)
        text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2, hexpand=True)
        name = Gtk.Label(label=p["title"] or p["name"], xalign=0)
        name.add_css_class("eb-h2")
        text.append(name)
        if p["error"]:
            info = f"{p['name']} · {p['error']}"
        else:
            info = f"{p['name']} · {p['label']} · {p['host']}:{p['port']} · " + ("с логином" if p["has_auth"] else "без логина")
            if self.px_note.get(p["name"]):
                info += "\n" + self.px_note[p["name"]]
        text.append(hint(info))
        row.append(text)
        ping = Gtk.Label(label=self.px_ping_text(p), width_chars=10)
        ping.add_css_class("dim-label")
        row.append(ping)
        for label, handler in (("Проверить", lambda _b, n=p["name"]: self.on_px_test(n)),
                               ("Для Claude", lambda _b, n=p["name"]: self.on_px_check(n)),
                               ("В среду…", lambda _b, n=p["name"]: self.on_px_apply(n)),
                               ("В папку…", lambda _b, n=p["name"], f=p["folder"]: self.on_px_move(n, f)),
                               ("Удалить", lambda _b, n=p["name"]: self.on_px_delete(n))):
            bt = Gtk.Button(label=label)
            bt.connect("clicked", handler)
            row.append(bt)
        card = margins(row, 8)
        card.add_css_class("frame")
        return card

    # ---- выделение и массовые действия

    def update_px_sel(self):
        n = len(self.px_sel)
        self.btn_px_del.set_label(f"Удалить выбранные ({n})")
        self.btn_px_del.set_sensitive(n > 0)

    def on_px_toggle(self, name, on):
        (self.px_sel.add if on else self.px_sel.discard)(name)
        self.update_px_sel()

    def on_px_select_names(self, names):
        self.px_sel |= set(names)
        self.refresh_px_list()

    def on_px_select_all(self, *_):
        """Выбрать все показанные (после поиска — только найденные)."""
        self.on_px_select_names([p["name"] for p in search_vpns(list_proxies(), self.px_query)])

    def on_px_unselect(self, *_):
        self.px_sel.clear()
        self.refresh_px_list()

    def on_px_delete_selected(self, *_):
        names = sorted(self.px_sel)
        if not names:
            return

        def go(idx):
            if idx == 1:
                n = delete_proxies(names)
                for x in names:
                    self.px_ping.pop(x, None)
                    self.px_note.pop(x, None)
                self.px_sel.clear()
                self.refresh_px_list()
                self.status(f"Удалено прокси: {n}")

        choose(self, f"Удалить выбранные прокси ({len(names)})?",
               ", ".join(names[:8]) + (" …" if len(names) > 8 else "") + "\n\nЛогины и пароли будут стёрты.",
               ["Отмена", "Удалить"], go)

    def on_px_clear_all(self, *_):
        total = len(list_proxies())
        if not total:
            self.status("Список прокси уже пуст")
            return

        def go(idx):
            if idx == 1:
                n = clear_proxies()
                self.px_ping.clear()
                self.px_note.clear()
                self.px_sel.clear()
                self.refresh_px_list()
                self.status(f"Список прокси очищен: удалено {n}")

        choose(self, "Очистить весь список прокси?",
               f"Будут удалены все прокси ({total}) и папки вместе с логинами и паролями. Прокси, уже подставленные в "
               "настройки сред, не меняются. Это нельзя отменить.", ["Отмена", "Очистить всё"], go)

    # ---- пинг, проверка, перенос, удаление

    def on_px_ping(self, names):
        proxies = list_proxies()
        proxies = search_vpns(proxies, self.px_query) if names is None else [p for p in proxies if p["name"] in names]
        self.status(f"Измеряю пинг: прокси {len(proxies)}…")

        def done(res):
            if isinstance(res, Exception):
                alert(self, "Не удалось измерить пинг", str(res))
                return
            self.px_ping.update(res)
            ok = sum(1 for ms in res.values() if ms is not None)
            self.status(f"Пинг измерен: ответили {ok} из {len(res)}")
            self.refresh_px_list()

        self.run_async(lambda: ping_vpns(proxies), done)

    def on_px_test(self, name):
        self.status(f"Проверяю прокси «{name}»…")

        def done(res):
            if isinstance(res, Exception):
                alert(self, "Проверка не удалась", str(res))
                return
            ok, msg = res
            self.status(msg if ok else f"Прокси «{name}» не работает")
            alert(self, "Прокси работает" if ok else "Прокси не работает", msg)

        self.run_async(lambda: test_proxy(name), done)

    def on_px_check(self, name):
        """Проверка выхода для Claude: адрес, страна, репутация, утечка, claude.ai и api.anthropic.com, канал до прокси."""
        self.status(f"Проверяю прокси «{name}» для Claude…")
        tz = self.e_tz.get_text().strip() if hasattr(self, "e_tz") and self.current else ""

        def done(res):
            if isinstance(res, Exception):
                alert(self, "Проверка не удалась", str(res))
                return
            verdict = {"ok": "подходит", "warn": "есть риски", "bad": "не подходит"}[res["verdict"]]
            e = res.get("exit") or {}
            self.px_note[name] = f"Claude: {verdict}" + (f" · {e.get('code', '')} {e.get('city', '')} · {e['ip']}"
                                                         if e.get("ip") else "")
            self.status(f"Для Claude: {verdict} (прокси «{name}»)")
            self.refresh_px_list()
            self.show_report(f"Прокси «{name}» для Claude", format_report(res, f"Прокси «{name}»"))

        self.run_async(lambda: check_proxy(name, env_tz=tz), done)

    def on_px_apply(self, name):
        """Подставить прокси в настройки текущей среды; логин и пароль профиль сам перенесёт в keyring."""
        if not self.current:
            alert(self, "Выберите среду", "Слева выберите среду, для которой нужен этот прокси.")
            return
        env = self.current.name

        def go(idx):
            if idx != 1:
                return
            try:
                self.e_upstream.set_text(proxy_url_with_auth(name))
            except ValueError as e:
                alert(self, "Не удалось подставить прокси", str(e))
                return
            if "@" not in self.e_upstream.get_text() and secret_tool_available():
                try:
                    secret_clear(env, UPSTREAM_AUTH_VAR)       # прежний пароль от другого прокси не нужен
                except OSError:
                    pass
                self.current.upstream_auth = False
            self.save_current(quiet=False)
            self.update_upstream_status()
            self.status(f"Прокси «{name}» подставлен в среду «{env}»; изменение вступит в силу при её запуске")

        choose(self, f"Сделать прокси «{name}» прокси среды «{env}»?",
               "Прежний прокси этой среды будет заменён. Логин и пароль уйдут в keyring среды (нужен secret-tool).",
               ["Отмена", "Подставить"], go)

    def on_px_move(self, name, folder):
        def got(value):
            try:
                set_px_folder(name, value)
            except ValueError as e:
                alert(self, "Не удалось переместить", str(e))
                return
            self.refresh_px_list()

        prompt(self, "Папка", "Название папки (сервиса). Пусто — вынуть из папки.", got, initial=folder)

    def on_px_delete(self, name):
        def go(idx):
            if idx == 1:
                delete_proxies([name])
                self.px_ping.pop(name, None)
                self.px_note.pop(name, None)
                self.px_sel.discard(name)
                self.refresh_px_list()
                self.status(f"Прокси «{name}» удалён")

        choose(self, f"Удалить прокси «{name}»?", "Логин и пароль будут стёрты.", ["Отмена", "Удалить"], go)

    def on_px_folder_delete(self, folder, total):
        def go(idx):
            if idx == 1:
                delete_px_folder(folder)
                self.refresh_px_list()
                self.status(f"Папка «{folder}» удалена вместе с прокси ({total})")

        choose(self, f"Удалить папку «{folder}»?", f"Будут удалены все прокси в ней ({total}).", ["Отмена", "Удалить"], go)

    def on_px_folder_update(self, folder):
        self.status(f"Обновляю список «{folder}»…")

        def work():
            via = (list_px_folders().get(folder) or {}).get("via", "")
            proxy, auth = self.env_proxy(via) if via else ("", "")
            return refresh_px_folder(folder, proxy=proxy, auth=auth)

        def done(res):
            if isinstance(res, Exception):
                alert(self, "Не удалось обновить список", str(res))
                return
            added, skipped, gone = res
            self.refresh_px_list()
            self.status(f"Список «{folder}» обновлён: прокси {len(added)}" + (f", убрано пропавших: {len(gone)}" if gone else ""))
            if skipped:
                alert(self, "Часть строк пропущена", "\n".join(skipped[:10]))

        self.run_async(work, done)

    # ---- добавление

    def on_px_file(self, *_):
        dlg = Gtk.FileDialog(title="Файл со списком прокси")

        def done(d, res):
            try:
                f = d.open_finish(res)
            except GLib.Error:
                return
            try:
                with open(f.get_path(), encoding="utf-8", errors="replace") as fh:
                    text = fh.read(2 * 1024 * 1024)
            except OSError as e:
                alert(self, "Не удалось прочитать файл", str(e))
                return
            self.add_px("", text)

        dlg.open(self, None, done)

    def on_px_paste(self, *_):
        win = Gtk.Window(title="Добавить прокси", transient_for=self, modal=True)
        win.set_default_size(660, -1)
        box = margins(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10), 16)
        box.append(hint("По одному прокси в строке или ссылка на список (https://…). Форматы: "
                        "схема://логин:пароль@хост:порт, хост:порт:логин:пароль, хост:порт; после # — пометка. "
                        "Без схемы берётся тип из списка ниже. Повторы пропускаются."))
        name = Gtk.Entry(hexpand=True, placeholder_text="имя, например proxy (можно не указывать)")
        box.append(name)
        folder = Gtk.Entry(hexpand=True, placeholder_text="папка (сервис), необязательно")
        box.append(folder)
        scheme = Gtk.DropDown.new_from_strings(["Строки без схемы — HTTP", "Строки без схемы — SOCKS5"])
        box.append(scheme)
        view, sw = text_area(height=160)
        box.append(sw)
        envs = self.proxy_envs()
        via = Gtk.DropDown.new_from_strings(["Список по ссылке: напрямую с этого компьютера"]
                                            + [f"Список по ссылке: через прокси среды «{n}»" for n in envs])
        if envs:
            box.append(via)
        buttons = Gtk.Box(spacing=8, halign=Gtk.Align.END)
        cancel = Gtk.Button(label="Отмена")
        ok = Gtk.Button(label="Добавить")
        ok.add_css_class("suggested-action")
        buttons.append(cancel)
        buttons.append(ok)
        box.append(buttons)

        def go(*_a):
            text, n, fld = get_text(view), name.get_text().strip(), folder.get_text().strip()
            sch = "socks5" if scheme.get_selected() == 1 else "http"
            idx = via.get_selected() if envs else 0
            win.destroy()
            self.add_px(n, text, sch, fld, envs[idx - 1] if idx > 0 else None)

        cancel.connect("clicked", lambda *_a: win.destroy())
        ok.connect("clicked", go)
        win.set_child(box)
        win.present()
        name.grab_focus()

    def add_px(self, name, text, scheme="http", folder="", via=None):
        text = (text or "").strip()
        if is_proxy_list_url(text):
            self.status("Скачиваю список прокси" + (f" через прокси среды «{via}»" if via else "") + "…")

            def work():
                proxy, auth = self.env_proxy(via) if via else ("", "")
                return import_proxy_url(name, text, scheme, folder=folder or None, proxy=proxy, auth=auth, via=via or "")

            def done(res):
                if isinstance(res, Exception):
                    alert(self, "Не удалось загрузить список", str(res))
                    return
                self.px_imported(*res)

            self.run_async(work, done)
            return
        try:
            imported, skipped = import_proxies(name, text, scheme, folder=folder or None)
        except ValueError as e:
            alert(self, "Не удалось добавить прокси", str(e))
            return
        self.px_imported(imported, skipped)

    def px_imported(self, imported, skipped):
        self.refresh_px_list()
        self.status(f"Добавлено прокси: {len(imported)}. «Для Claude» покажет, подходит ли каждый")
        if skipped:
            alert(self, "Часть строк пропущена", "\n".join(skipped[:10]))
