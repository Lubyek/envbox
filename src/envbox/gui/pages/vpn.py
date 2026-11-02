"""Вкладка «VPN»: загрузка конфигураций (WireGuard, VLESS/Xray, sing-box), проверка и удаление."""

import re

from ...core.vpn import (
    VPN_MAX_BYTES,
    delete_vpn,
    import_many,
    import_subscription,
    list_vpns,
    test_vpn,
    vpn_binary_problem,
    vpn_name_from_file,
)
from ..gtk import GLib, Gtk
from ..widgets import alert, choose, clear_children, get_text, hint, margins, prompt, text_area


class VpnPageMixin:
    """VPN-конфигурации общие для всех сред; в настройках среды они ставятся в «Порядок выхода»."""

    def build_vpn_page(self):
        box = margins(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10), 16)
        title = Gtk.Label(label="VPN", xalign=0)
        title.add_css_class("eb-h2")
        box.append(title)
        box.append(hint("Загрузите конфигурацию WireGuard (.conf), ссылку на сервер (vless://, vmess://, trojan://, ss://), "
                        "ссылку-подписку от провайдера (https://…: из неё добавятся все серверы) или JSON для Xray / "
                        "sing-box. "
                        "envbox сам запускает VPN-клиент вместе со средой и останавливает его вместе с ней, без root: "
                        "клиент слушает только 127.0.0.1 с одноразовым паролем, а среда по-прежнему выходит только "
                        "через прокси envbox. Нужна программа клиента: wireproxy для WireGuard, xray или sing-box "
                        "для остальных. Затем добавьте VPN в «Порядок выхода» на вкладке «Настройки» среды. "
                        "Если VPN уже запущен на самом компьютере, используйте в порядке выхода «direct»."))
        bar = Gtk.Box(spacing=8)
        for label, handler in (("Загрузить из файла…", self.on_vpn_file), ("Вставить ссылку или текст…", self.on_vpn_paste),
                               ("Обновить список", lambda *_: self.refresh_vpn_list())):
            bt = Gtk.Button(label=label)
            bt.connect("clicked", handler)
            bar.append(bt)
        box.append(bar)
        self.vpn_list = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        scroll = Gtk.ScrolledWindow(vexpand=True)
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.set_child(self.vpn_list)
        box.append(scroll)
        box.append(hint("Конфигурации лежат в каталоге данных envbox (папка _vpn, права только владельцу): в них "
                        "приватные ключи. Сценарии wg-quick (PostUp и подобные) и лишние туннели wireproxy при "
                        "запуске вырезаются."))
        self.refresh_vpn_list()
        return box

    def refresh_vpn_list(self):
        clear_children(self.vpn_list)
        vpns = list_vpns()
        if not vpns:
            self.vpn_list.append(hint("Пока нет ни одного VPN."))
        for v in vpns:
            row = Gtk.Box(spacing=8)
            text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2, hexpand=True)
            name = Gtk.Label(label=v["name"], xalign=0)
            name.add_css_class("eb-h2")
            text.append(name)
            if v["error"]:
                info = f"{v['label']}: конфигурация не читается: {v['error']}"
            else:
                info = f"{v['label']} · {v['server']}"
                problem = vpn_binary_problem(v["kind"])
                if problem:
                    info += f"\n⚠ {problem}"
            text.append(hint(info))
            row.append(text)
            check = Gtk.Button(label="Проверить")
            check.connect("clicked", lambda _b, n=v["name"]: self.on_vpn_test(n))
            row.append(check)
            drop = Gtk.Button(label="Удалить")
            drop.connect("clicked", lambda _b, n=v["name"]: self.on_vpn_delete(n))
            row.append(drop)
            card = margins(row, 8)
            card.add_css_class("frame")
            self.vpn_list.append(card)
        if hasattr(self, "refresh_vpn_choices"):
            self.refresh_vpn_choices()

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
                        "сам. Подписка скачивается с вашего компьютера напрямую: её сервер увидит ваш настоящий "
                        "адрес. Каждый сервер подписки сохраняется отдельным VPN (имя-1, имя-2…); Clash-подписки "
                        "в формате YAML не поддерживаются."))
        name = Gtk.Entry(hexpand=True, placeholder_text="имя, например vpn1 (для подписки можно не указывать)")
        box.append(name)
        view, sw = text_area(height=160)
        box.append(sw)
        buttons = Gtk.Box(spacing=8, halign=Gtk.Align.END)
        cancel = Gtk.Button(label="Отмена")
        ok = Gtk.Button(label="Добавить")
        ok.add_css_class("suggested-action")
        buttons.append(cancel)
        buttons.append(ok)
        box.append(buttons)

        def go(*_a):
            text, n = get_text(view), name.get_text().strip()
            win.destroy()
            self.add_vpn(n, text)

        cancel.connect("clicked", lambda *_a: win.destroy())
        ok.connect("clicked", go)
        win.set_child(box)
        win.present()
        name.grab_focus()

    def add_vpn(self, name, text, replace=False):
        text = (text or "").strip()
        if re.match(r"^https?://\S+$", text):   # ссылка-подписка: серверы скачиваются, а не вставлены
            self.add_subscription((name or "").strip(), text)
            return
        try:
            imported, skipped = import_many(name, text, replace=replace)
        except ValueError as e:
            if "уже есть" in str(e) and not replace:
                choose(self, f"VPN «{name}» уже есть", "Заменить его новой конфигурацией?", ["Отмена", "Заменить"],
                       lambda idx: self.add_vpn(name, text, True) if idx == 1 else None)
                return
            alert(self, "Не удалось добавить VPN", str(e))
            return
        self.vpn_imported(imported, skipped)

    def add_subscription(self, name, url):
        self.status("Скачиваю подписку…")

        def done(res):
            if isinstance(res, Exception):
                alert(self, "Не удалось загрузить подписку", str(res))
                return
            self.vpn_imported(*res)

        self.run_async(lambda: import_subscription(name, url), done)

    def vpn_imported(self, imported, skipped):
        self.refresh_vpn_list()
        names = ", ".join(n for n, _k, _s in imported[:6]) + (" …" if len(imported) > 6 else "")
        self.status(f"Добавлено VPN: {len(imported)} ({names}). Добавьте нужный в «Порядок выхода» в настройках среды")
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

    def on_vpn_delete(self, name):
        def go(idx):
            if idx == 1:
                delete_vpn(name)
                self.refresh_vpn_list()
                self.status(f"VPN «{name}» удалён. Среды, где он стоял в порядке выхода, не запустятся, пока вы его не уберёте")

        choose(self, f"Удалить VPN «{name}»?", "Конфигурация (с ключами) будет стёрта.", ["Отмена", "Удалить"], go)
