"""Вкладка «VPN»: серверы по папкам (сервисам), поиск, пинг, загрузка, проверка и удаление."""

import subprocess

from ...core.consts import UPSTREAM_AUTH_VAR
from ...core.keyring import secret_lookup, secret_tool_available
from ...core.store import list_profiles, load_profile
from ...core.upstream import split_proxy_url
from ...core.vpn import (
    VPN_MAX_BYTES,
    clear_vpns,
    delete_folder,
    delete_vpns,
    delete_vpn,
    folder_summary,
    import_many,
    import_subscription,
    is_subscription_url,
    list_folders,
    list_vpns,
    looks_like_source,
    natural_key,
    ping_vpns,
    refresh_folder,
    search_vpns,
    set_folder,
    test_vpn,
    vpn_binary_problem,
    vpn_name_from_file,
)
from ...core.vpncheck import check_vpn, format_report
from ..gtk import GLib, Gtk
from ..widgets import alert, choose, clear_children, get_text, hint, margins, prompt, set_text, text_area


class VpnPageMixin:
    """VPN-конфигурации общие для всех сред; в настройках среды они ставятся в «Выход в интернет»."""

    def build_vpn_page(self):
        self.vpn_query = ""
        self.vpn_ping = {}          # имя -> миллисекунды или None (не ответил); у не измеренных нет записи
        self.vpn_open = {}          # папка -> раскрыта ли
        self.vpn_by_ping = False
        self.vpn_sel = set()        # имена выделенных галочками VPN
        box = margins(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10), 16)
        title = Gtk.Label(label="VPN", xalign=0)
        title.add_css_class("eb-h2")
        box.append(title)
        box.append(hint("Загрузите конфигурацию WireGuard (.conf), ссылку на сервер (vless://, vmess://, trojan://, ss://), "
                        "ссылку-подписку от провайдера (https://…: серверы сложатся в папку-сервис) или JSON для Xray / "
                        "sing-box. envbox сам запускает VPN-клиент вместе со средой и останавливает вместе с ней, без "
                        "root: клиент слушает только 127.0.0.1 с одноразовым паролем, а среда по-прежнему выходит "
                        "только через прокси envbox. Нужна программа клиента: wireproxy для WireGuard, xray или "
                        "sing-box для остальных. Затем выберите VPN в «Выход в интернет» на вкладке «Настройки» среды. "
                        "Если VPN уже запущен на самом компьютере, используйте в порядке выхода «direct»."))
        bar = Gtk.Box(spacing=8)
        for label, handler in (("Загрузить из файла…", self.on_vpn_file), ("Вставить ссылку или текст…", self.on_vpn_paste)):
            bt = Gtk.Button(label=label)
            bt.connect("clicked", handler)
            bar.append(bt)
        box.append(bar)
        search = Gtk.Box(spacing=8)
        self.vpn_search = Gtk.SearchEntry(hexpand=True, placeholder_text="Поиск: название, сервер, адрес, порт, папка")
        self.vpn_search.connect("search-changed", self.on_vpn_search)
        search.append(self.vpn_search)
        ping_all = Gtk.Button(label="Измерить пинг")
        ping_all.connect("clicked", lambda *_: self.on_vpn_ping(None))
        search.append(ping_all)
        by_ping = Gtk.CheckButton(label="Сначала быстрые")
        by_ping.connect("toggled", self.on_vpn_sort)
        search.append(by_ping)
        box.append(search)
        bulk = Gtk.Box(spacing=8)
        for label, handler in (("Выбрать все", self.on_vpn_select_all), ("Снять выбор", self.on_vpn_unselect)):
            bt = Gtk.Button(label=label)
            bt.connect("clicked", handler)
            bulk.append(bt)
        self.btn_vpn_del = Gtk.Button(label="Удалить выбранные (0)")
        self.btn_vpn_del.connect("clicked", self.on_vpn_delete_selected)
        bulk.append(self.btn_vpn_del)
        clear_all = Gtk.Button(label="Очистить всё")
        clear_all.add_css_class("destructive-action")
        clear_all.connect("clicked", self.on_vpn_clear_all)
        bulk.append(clear_all)
        box.append(bulk)
        self.vpn_list = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        scroll = Gtk.ScrolledWindow(vexpand=True)
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.set_child(self.vpn_list)
        box.append(scroll)
        box.append(hint("Пинг — время TCP-подключения к серверу с вашего компьютера; у WireGuard (UDP) он не измеряется. "
                        "Конфигурации лежат в каталоге данных envbox (папка _vpn, права только владельцу): в них "
                        "приватные ключи и адреса подписок. Сценарии wg-quick (PostUp и подобные) и лишние туннели "
                        "wireproxy при запуске вырезаются."))
        self.refresh_vpn_list()
        return box

    # ---- список: папки, поиск, пинг

    def on_vpn_search(self, entry):
        self.vpn_query = entry.get_text().strip()
        self.refresh_vpn_list()

    def on_vpn_sort(self, button):
        self.vpn_by_ping = button.get_active()
        self.refresh_vpn_list()

    def vpn_ping_text(self, v):
        if v["udp"]:
            return "UDP"
        if v["name"] not in self.vpn_ping:
            return "—"
        ms = self.vpn_ping[v["name"]]
        return f"{ms} мс" if ms is not None else "нет ответа"

    def vpn_sort_key(self, v):
        if self.vpn_by_ping:
            ms = self.vpn_ping.get(v["name"])
            return (ms is None, ms or 0, natural_key(v["name"]))
        return natural_key(v["name"])

    def refresh_vpn_list(self):
        clear_children(self.vpn_list)
        everything = list_vpns()
        self.vpn_sel &= {v["name"] for v in everything}
        self.update_vpn_sel()
        shown = search_vpns(everything, self.vpn_query)
        if not everything:
            self.vpn_list.append(hint("Пока нет ни одного VPN."))
        elif not shown:
            self.vpn_list.append(hint(f"По запросу «{self.vpn_query}» ничего не найдено."))
        groups = {}
        for v in shown:
            groups.setdefault(v["folder"], []).append(v)
        folders = list_folders()
        for folder in sorted(f for f in groups if f) + ([""] if "" in groups else []):
            self.vpn_list.append(self.vpn_folder(folder, sorted(groups[folder], key=self.vpn_sort_key),
                                                 folders.get(folder, {}),
                                                 sum(1 for v in everything if v["folder"] == folder)))
        if hasattr(self, "refresh_vpn_choices"):
            self.refresh_vpn_choices()

    def vpn_folder(self, folder, items, info, total):
        exp = Gtk.Expander()
        exp.set_expanded(self.vpn_open.get(folder, True) or bool(self.vpn_query))
        exp.connect("notify::expanded", lambda e, _p, f=folder: self.vpn_open.__setitem__(f, e.get_expanded()))
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
        names = [v["name"] for v in items]
        pick = Gtk.Button(label="Выбрать")
        pick.connect("clicked", lambda _b, n=names: self.on_vpn_select_names(n))
        head.append(pick)
        ping = Gtk.Button(label="Пинг")
        ping.connect("clicked", lambda _b, n=names: self.on_vpn_ping(n))
        head.append(ping)
        if info.get("url"):
            upd = Gtk.Button(label="Обновить")
            upd.connect("clicked", lambda _b, f=folder: self.on_vpn_folder_update(f))
            head.append(upd)
        if folder:
            drop = Gtk.Button(label="Удалить папку")
            drop.connect("clicked", lambda _b, f=folder, n=total: self.on_vpn_folder_delete(f, n))
            head.append(drop)
        exp.set_label_widget(head)
        rows = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        for v in items:
            rows.append(self.vpn_row(v))
        exp.set_child(margins(rows, 6))
        return exp

    def vpn_row(self, v):
        row = Gtk.Box(spacing=8)
        chk = Gtk.CheckButton(active=v["name"] in self.vpn_sel)
        chk.connect("toggled", lambda b, n=v["name"]: self.on_vpn_toggle(n, b.get_active()))
        row.append(chk)
        text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2, hexpand=True)
        name = Gtk.Label(label=v["title"] or v["name"], xalign=0)
        name.add_css_class("eb-h2")
        text.append(name)
        if v["error"]:
            info = f"{v['name']} · конфигурация не читается: {v['error']}"
        else:
            where = f" · {v['host']}:{v['port']}" if v["host"] else ""
            info = f"{v['name']} · {v['label']}{where}"
            problem = vpn_binary_problem(v["kind"])
            if problem:
                info += f"\n⚠ {problem}"
        text.append(hint(info))
        row.append(text)
        ping = Gtk.Label(label=self.vpn_ping_text(v), width_chars=10)
        ping.add_css_class("dim-label")
        row.append(ping)
        for label, handler in (("Проверить", lambda _b, n=v["name"]: self.on_vpn_test(n)),
                               ("Для Claude", lambda _b, n=v["name"]: self.on_vpn_check(n)),
                               ("В папку…", lambda _b, n=v["name"], f=v["folder"]: self.on_vpn_move(n, f)),
                               ("Удалить", lambda _b, n=v["name"]: self.on_vpn_delete(n))):
            bt = Gtk.Button(label=label)
            bt.connect("clicked", handler)
            row.append(bt)
        card = margins(row, 8)
        card.add_css_class("frame")
        return card

    # ---- выделение и массовые действия

    def update_vpn_sel(self):
        n = len(self.vpn_sel)
        self.btn_vpn_del.set_label(f"Удалить выбранные ({n})")
        self.btn_vpn_del.set_sensitive(n > 0)

    def on_vpn_toggle(self, name, on):
        (self.vpn_sel.add if on else self.vpn_sel.discard)(name)
        self.update_vpn_sel()

    def on_vpn_select_names(self, names):
        self.vpn_sel |= set(names)
        self.refresh_vpn_list()

    def on_vpn_select_all(self, *_):
        """Выбрать все показанные (после поиска — только найденные)."""
        self.on_vpn_select_names([v["name"] for v in search_vpns(list_vpns(), self.vpn_query)])

    def on_vpn_unselect(self, *_):
        self.vpn_sel.clear()
        self.refresh_vpn_list()

    def on_vpn_delete_selected(self, *_):
        names = sorted(self.vpn_sel)
        if not names:
            return

        def go(idx):
            if idx == 1:
                n = delete_vpns(names)
                for x in names:
                    self.vpn_ping.pop(x, None)
                self.vpn_sel.clear()
                self.refresh_vpn_list()
                self.status(f"Удалено VPN: {n}")

        choose(self, f"Удалить выбранные VPN ({len(names)})?",
               ", ".join(names[:8]) + (" …" if len(names) > 8 else "") +
               "\n\nКонфигурации (с ключами) будут стёрты. Среды, где они выбраны в «Выход в интернет», не запустятся, "
               "пока вы не выберете другой выход.", ["Отмена", "Удалить"], go)

    def on_vpn_clear_all(self, *_):
        total = len(list_vpns())
        if not total:
            self.status("Список VPN уже пуст")
            return

        def go(idx):
            if idx == 1:
                n = clear_vpns()
                self.vpn_ping.clear()
                self.vpn_sel.clear()
                self.refresh_vpn_list()
                self.status(f"Список VPN очищен: удалено {n}")

        choose(self, "Очистить весь список VPN?",
               f"Будут удалены все VPN ({total}) и все папки вместе с ключами и адресами подписок. Это нельзя отменить.",
               ["Отмена", "Очистить всё"], go)

    def on_vpn_ping(self, names):
        """Измерить пинг: names — какие VPN (None — все, подходящие под поиск)."""
        vpns = list_vpns()
        vpns = search_vpns(vpns, self.vpn_query) if names is None else [v for v in vpns if v["name"] in names]
        self.status(f"Измеряю пинг: серверов {len(vpns)}…")

        def done(res):
            if isinstance(res, Exception):
                alert(self, "Не удалось измерить пинг", str(res))
                return
            self.vpn_ping.update(res)
            ok = sum(1 for ms in res.values() if ms is not None)
            self.status(f"Пинг измерен: ответили {ok} из {len(res)}")
            self.refresh_vpn_list()

        self.run_async(lambda: ping_vpns(vpns), done)

    def on_vpn_move(self, name, folder):
        def got(value):
            set_folder(name, value)
            self.refresh_vpn_list()
            self.status(f"VPN «{name}»: папка «{value.strip()}»" if value.strip() else f"VPN «{name}» вынут из папки")

        prompt(self, "Папка", "Название папки (сервиса). Пусто — вынуть из папки.", got, initial=folder)

    def on_vpn_folder_update(self, folder):
        self.status(f"Обновляю подписку «{folder}»…")

        def work():
            via = (list_folders().get(folder) or {}).get("via", "")
            proxy, auth = self.env_proxy(via) if via else ("", "")
            return refresh_folder(folder, proxy=proxy, auth=auth)

        def done(res):
            if isinstance(res, Exception):
                alert(self, "Не удалось обновить подписку", str(res))
                return
            imported, skipped, gone = res
            self.refresh_vpn_list()
            self.status(f"Подписка «{folder}» обновлена: серверов {len(imported)}"
                        + (f", убрано пропавших: {len(gone)}" if gone else ""))
            if skipped:
                alert(self, "Часть серверов пропущена", "\n".join(skipped[:10]))

        self.run_async(work, done)

    def on_vpn_folder_delete(self, folder, total):
        def go(idx):
            if idx == 1:
                delete_folder(folder)
                self.refresh_vpn_list()
                self.status(f"Папка «{folder}» удалена вместе с серверами ({total})")

        choose(self, f"Удалить папку «{folder}»?",
               f"Будут удалены все серверы в ней ({total}) вместе с ключами. Среды, где они выбраны в «Выход в интернет», "
               "не запустятся, пока вы не выберете другой выход.", ["Отмена", "Удалить"], go)

    # ---- добавление

    def on_vpn_file(self, *_):
        dlg = Gtk.FileDialog(title="Файл конфигурации VPN")

        def done(d, res):
            try:
                f = d.open_finish(res)
            except GLib.Error:
                return
            path = f.get_path()
            try:
                with open(path, encoding="utf-8") as fh:
                    text = fh.read(VPN_MAX_BYTES + 1)
            except (OSError, UnicodeDecodeError) as e:
                alert(self, "Не удалось прочитать файл", str(e))
                return
            prompt(self, "Имя VPN", "Как назвать этот VPN (латиница, цифры, точка, дефис):",
                   lambda name: self.add_vpn(name, text), initial=vpn_name_from_file(path))

        dlg.open(self, None, done)

    def on_vpn_paste(self, *_):
        win = Gtk.Window(title="Добавить VPN", transient_for=self, modal=True)
        win.set_default_size(640, -1)
        box = margins(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10), 16)
        box.append(hint("Вставьте ссылку на сервер (vless://, vmess://, trojan://, ss://), список таких ссылок, "
                        "конфигурацию WireGuard, JSON Xray / sing-box или ссылку-подписку https://… Вид определяется "
                        "сам. Подписка скачивается как приложение-клиент (Happ, v2rayN…) с заголовком устройства; "
                        "серверы сложатся в папку с названием сервиса, а настоящих серверов вместо заглушек "
                        "(«Используйте Happ») мы не добавляем. Clash-подписки в формате YAML не поддерживаются."))
        name = Gtk.Entry(hexpand=True, placeholder_text="имя, например vpn1 (для подписки можно не указывать)")
        box.append(name)
        folder = Gtk.Entry(hexpand=True, placeholder_text="папка (сервис), необязательно")
        box.append(folder)
        view, sw = text_area(height=160)
        box.append(sw)
        envs = self.proxy_envs()
        via = Gtk.DropDown.new_from_strings(["Скачать подписку напрямую с этого компьютера"]
                                            + [f"Скачать подписку через прокси среды «{n}»" for n in envs])
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
            idx = via.get_selected() if envs else 0
            win.destroy()
            self.add_vpn(n, text, via=envs[idx - 1] if idx > 0 else None, folder=fld)

        cancel.connect("clicked", lambda *_a: win.destroy())
        ok.connect("clicked", go)
        win.set_child(box)
        win.present()
        name.grab_focus()

    def add_vpn(self, name, text, replace=False, via=None, folder=""):
        text = (text or "").strip()
        if not text and looks_like_source(name):
            name, text = "", name.strip()      # ссылку вставили в поле имени: это не имя, а источник
        if is_subscription_url(text):          # ссылка-подписка: серверы скачиваются, а не вставлены
            self.add_subscription((name or "").strip(), text, via, folder)
            return
        try:
            imported, skipped = import_many(name, text, replace=replace, folder=folder or None)
        except ValueError as e:
            if "уже есть" in str(e) and not replace:
                choose(self, f"VPN «{name}» уже есть", "Заменить его новой конфигурацией?", ["Отмена", "Заменить"],
                       lambda idx: self.add_vpn(name, text, True, via, folder) if idx == 1 else None)
                return
            alert(self, "Не удалось добавить VPN", str(e))
            return
        self.vpn_imported(imported, skipped)

    def proxy_envs(self):
        """Среды со своим прокси: через него можно скачать подписку, если сайт не открывается напрямую."""
        out = []
        for n in list_profiles():
            try:
                if load_profile(n).upstream:
                    out.append(n)
            except (OSError, ValueError):
                continue
        return out

    @staticmethod
    def env_proxy(env):
        """(адрес, логин:пароль) прокси среды; пароль из keyring (вызывается в потоке)."""
        p = load_profile(env)
        url, auth = split_proxy_url(p.upstream)
        if not auth and p.upstream_auth and secret_tool_available():
            try:
                auth = secret_lookup(env, UPSTREAM_AUTH_VAR)
            except (OSError, subprocess.SubprocessError):
                auth = ""
        return url, auth

    def add_subscription(self, name, url, via=None, folder=""):
        self.status("Скачиваю подписку" + (f" через прокси среды «{via}»" if via else "") + "…")

        def work():
            proxy, auth = self.env_proxy(via) if via else ("", "")
            return import_subscription(name, url, proxy=proxy, auth=auth, via=via or "", folder=folder or None)

        def done(res):
            if isinstance(res, Exception):
                alert(self, "Не удалось загрузить подписку", str(res))
                return
            self.vpn_imported(*res)

        self.run_async(work, done)

    def vpn_imported(self, imported, skipped):
        self.refresh_vpn_list()
        names = ", ".join(n for n, _k, _s in imported[:6]) + (" …" if len(imported) > 6 else "")
        self.status(f"Добавлено VPN: {len(imported)} ({names}). Выберите нужный в «Выход в интернет» в настройках среды")
        if skipped:
            alert(self, "Часть серверов пропущена", "\n".join(skipped[:10]))

    # ---- проверка и удаление

    def on_vpn_test(self, name):
        self.status(f"Проверяю VPN «{name}»: запускаю клиент и открываю туннель…")

        def done(res):
            if isinstance(res, Exception):
                alert(self, "Проверка не удалась", str(res))
                return
            ok, msg = res
            self.status(msg if ok else f"VPN «{name}» не работает")
            alert(self, "VPN работает" if ok else "VPN не работает", msg)

        self.run_async(lambda: test_vpn(name), done)

    def on_vpn_check(self, name):
        """Проверка выхода для Claude: адрес, страна, репутация, утечка, claude.ai и api.anthropic.com, транспорт."""
        self.status(f"Проверяю VPN «{name}» для Claude: запускаю клиент и опрашиваю сервисы…")

        def done(res):
            if isinstance(res, Exception):
                alert(self, "Проверка не удалась", str(res))
                return
            self.status({"ok": "Для Claude подходит", "warn": "Для Claude: есть риски", "bad": "Для Claude не подходит"}
                        [res["verdict"]] + f" (VPN «{name}»)")
            self.show_report(f"VPN «{name}» для Claude", format_report(res, f"VPN «{name}»"))

        self.run_async(lambda: check_vpn(name), done)

    def show_report(self, title, text):
        """Окно с текстовым отчётом и кнопкой «Копировать»."""
        win = Gtk.Window(title=title, transient_for=self, modal=False)
        win.set_default_size(780, 560)
        box = margins(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10), 16)
        view, sw = text_area(editable=False, height=420)
        set_text(view, text)
        sw.set_vexpand(True)
        box.append(sw)
        bar = Gtk.Box(spacing=8, halign=Gtk.Align.END)
        copy = Gtk.Button(label="Копировать")
        copy.connect("clicked", lambda *_: (self.get_clipboard().set_text(text), self.status("Отчёт скопирован")))
        close = Gtk.Button(label="Закрыть")
        close.connect("clicked", lambda *_: win.destroy())
        bar.append(copy)
        bar.append(close)
        box.append(bar)
        win.set_child(box)
        win.present()

    def on_vpn_delete(self, name):
        def go(idx):
            if idx == 1:
                delete_vpn(name)
                self.vpn_ping.pop(name, None)
                self.vpn_sel.discard(name)
                self.refresh_vpn_list()
                self.status(f"VPN «{name}» удалён. Среды, где он выбран, не запустятся, пока вы не выберете другой выход")

        choose(self, f"Удалить VPN «{name}»?", "Конфигурация (с ключами) будет стёрта.", ["Отмена", "Удалить"], go)
