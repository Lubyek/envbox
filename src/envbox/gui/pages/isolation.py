"""Вкладка «Изоляция»."""

from ...core.consts import LANG_RE
from ...core.isolation import ISO_OPTIONS, ISO_PRESETS
from ...core.profile import locale_available, timezone_exists
from ...core.root import ISO_GROUPS, envbox_root
from ..gtk import GLib, Gtk
from ..widgets import Rows, card, choose, get_lines, hint, margins, set_text, text_area, to_home


class IsolationMixin:
    """Вкладка «Изоляция»."""

    def build_isolation_page(self):
        """Каждая защита — отдельный переключатель с названием, объяснением и последствием отключения."""
        self.iso_lock = False
        self.iso_switches = {}
        self.iso_risks = {}
        page = margins(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16), 16)

        box = card()
        title = Gtk.Label(label="Уровень изоляции", xalign=0)
        title.add_css_class("eb-h2")
        box.append(title)
        box.append(hint("Каждую защиту ниже можно включать и выключать отдельно. Набор — быстрый способ "
                        "выставить их все сразу; при ручных правках он станет «Свой набор»."))
        self.dd_preset = Gtk.DropDown.new_from_strings([pr[1] for pr in ISO_PRESETS] + ["Свой набор"])
        self.dd_preset.connect("notify::selected", self.on_preset_changed)
        box.append(self.dd_preset)
        self.lbl_preset = hint("")
        box.append(self.lbl_preset)
        page.append(box)

        for group in ISO_GROUPS:
            box = card()
            title = Gtk.Label(label=group, xalign=0)
            title.add_css_class("eb-h2")
            box.append(title)
            if group == "Файлы":
                box.append(self.build_files_choices())
            for opt in ISO_OPTIONS:
                if opt["group"] == group:
                    row = self.iso_row(opt)
                    box.append(row)
                    if opt.get("app_only"):
                        self.app_only.append(row)
            if group == "Сеть":
                box.append(hint("Режим сети, список сайтов, DNS и свой прокси настраиваются на вкладке «Настройки»."))
                box.append(self.build_direct_sites())
            page.append(box)

        scroll = Gtk.ScrolledWindow(vexpand=True)
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)  # по ширине окна, без растягивания
        scroll.set_child(page)
        return scroll

    def build_files_choices(self):
        grid = Gtk.Grid(column_spacing=12, row_spacing=8)
        rows = Rows(grid)
        self.dd_host = Gtk.DropDown.new_from_strings([
            "Только нужное (рекомендуется)",
            "Весь компьютер, писать только в проект",
            "Весь компьютер, писать везде"])
        self.dd_host.connect("notify::selected", self.on_host_changed)
        rows.add("Какие файлы видит программа", self.dd_host,
                 "По умолчанию: свой домашний каталог, проект и системные программы только на чтение. "
                 "Два других варианта открывают ваши настоящие файлы; сеть, язык, пояс и DNS остаются "
                 "заданными. Не проверено на вашей системе.")
        self.dd_home = Gtk.DropDown.new_from_strings([
            "Свой, отдельный (рекомендуется)",
            "Настоящий домашний каталог (опасно)"])
        self.dd_home.connect("notify::selected", self.on_home_changed)
        rows.add("Домашний каталог", self.dd_home,
                 f"Свой — отдельная папка {to_home(envbox_root())}/<имя>/home. Настоящий открывает ключи SSH, профили "
                 "браузеров и все личные файлы.")
        return grid

    def build_direct_sites(self):
        """Сайты, к которым прокси envbox подключается сам, минуя свой прокси (upstream)."""
        col = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        title = Gtk.Label(xalign=0, wrap=True)
        title.set_markup("<b>Сайты напрямую, мимо своего прокси</b>")
        col.append(title)
        col.append(hint("Для сайтов, которые не открываются через ваш прокси или VPN (например, не пускают его адрес). "
                        "По одному в строке: example.com — только он, *.example.com — он и все поддомены. "
                        "Программа в среде по-прежнему выходит только через прокси envbox и ваш настоящий адрес не "
                        "видит; его увидят только эти сайты. Работает, когда задан «Свой прокси»; в режиме «только "
                        "разрешённые домены» такие сайты разрешены автоматически."))
        self.tv_direct, sw = text_area(height=56)
        col.append(sw)
        warn = Gtk.Label(label="⚠ Эти сайты узнают ваш настоящий IP-адрес и обходят защиту вашего VPN.",
                         xalign=0, wrap=True)
        warn.add_css_class("eb-warn")
        col.append(warn)
        return col

    def iso_row(self, opt):
        line = Gtk.Box(spacing=12)
        text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2, hexpand=True)
        title = Gtk.Label(xalign=0, wrap=True)
        title.set_markup("<b>" + GLib.markup_escape_text(opt["title"]) + "</b>")
        text.append(title)
        text.append(hint(opt["text"]))
        risk = Gtk.Label(label="⚠ Если выключить: " + opt["risk"], xalign=0, wrap=True)
        risk.add_css_class("eb-warn")
        risk.set_visible(False)
        text.append(risk)
        sw = Gtk.Switch(valign=Gtk.Align.CENTER)
        sw.connect("notify::active", lambda *_: self.on_iso_toggled())
        line.append(text)
        line.append(sw)
        self.iso_switches[opt["key"]] = sw
        self.iso_risks[opt["key"]] = (risk, opt)
        return line

    def on_iso_toggled(self):
        if self.loading or self.iso_lock:
            return
        self.update_iso_views()

    def on_preset_changed(self, *_):
        if self.loading or self.iso_lock:
            return
        idx = self.dd_preset.get_selected()
        if idx >= len(ISO_PRESETS):
            return
        preset = ISO_PRESETS[idx][3]
        self.iso_lock = True
        for opt in ISO_OPTIONS:
            if opt.get("presets", True):
                self.iso_switches[opt["key"]].set_active(preset.get(opt["key"], True))
        self.iso_lock = False
        self.update_iso_views()

    def update_iso_views(self):
        """Показывает последствия выключенных защит и определяет, какому набору соответствует состояние."""
        state = {key: sw.get_active() for key, sw in self.iso_switches.items()}
        for key, (risk, opt) in self.iso_risks.items():
            risk.set_visible(bool(opt["warn_off"]) and not state[key])
        names = [pr[0] for pr in ISO_PRESETS] + ["custom"]
        found = "custom"
        for pname, _title, _text, preset in ISO_PRESETS:
            if all(state[o["key"]] == preset.get(o["key"], True)
                   for o in ISO_OPTIONS if o.get("presets", True)):
                found = pname
                break
        self.iso_lock = True
        self.dd_preset.set_selected(names.index(found))
        self.iso_lock = False
        if found == "custom":
            off = sum(1 for o in ISO_OPTIONS if o["warn_off"] and not state[o["key"]])
            self.lbl_preset.set_text(f"Свой набор. Выключено защит: {off}. Последствия показаны под каждой.")
        else:
            self.lbl_preset.set_text(next(pr[2] for pr in ISO_PRESETS if pr[0] == found))

    def show_isolation(self, p):
        self.iso_lock = True
        for key, sw in self.iso_switches.items():
            sw.set_active(p.iso_on(key))
        self.dd_host.set_selected({"": 0, "ro": 1, "rw": 2}.get(p.host_files, 0))
        self.dd_home.set_selected(1 if p.iso_on("home_real") else 0)
        set_text(self.tv_direct, "\n".join(p.direct_domains))
        self.iso_lock = False
        self.update_iso_views()

    def read_isolation(self, prof):
        for key, sw in self.iso_switches.items():
            prof.iso_set(key, sw.get_active())
        prof.host_files = ("", "ro", "rw")[self.dd_host.get_selected()]
        prof.iso_set("home_real", self.dd_home.get_selected() == 1)
        prof.direct_domains = get_lines(self.tv_direct)
        prof.host_confirmed = bool((prof.host_files or prof.iso_on("home_real"))
                                   and self.current is not None and self.current.host_confirmed)

    def confirm_host_access(self, widget, text, ok_message):
        """Подтверждение опасного доступа к файлам; при отказе возвращает переключатель назад."""
        def done(choice):
            if choice == 1:
                self.current.host_confirmed = True
                self.status(ok_message)
            else:
                self.loading = True
                widget.set_selected(0)
                self.loading = False

        choose(self, "Открыть среде ваши настоящие файлы?", text,
               ["Отмена", "Подтверждаю: дать доступ"], done)

    def on_host_changed(self, *_):
        if self.loading or not self.current:
            return
        idx = self.dd_host.get_selected()
        if idx == 0:
            if self.dd_home.get_selected() == 0:
                self.current.host_confirmed = False
            return
        self.confirm_host_access(
            self.dd_host,
            "Программа внутри сможет читать " + ("и изменять " if idx == 2 else "") +
            "все ваши настоящие файлы, включая ключи SSH и профили браузеров. Сеть останется только через прокси.",
            "Доступ к файлам компьютера включён после сохранения")

    def on_home_changed(self, *_):
        if self.loading or not self.current:
            return
        if self.dd_home.get_selected() == 0:
            if self.dd_host.get_selected() == 0:
                self.current.host_confirmed = False
            return
        self.confirm_host_access(
            self.dd_home,
            "Программа внутри будет работать с вашим настоящим домашним каталогом: личные файлы, ключи SSH, "
            "профили браузеров. Сеть останется только через прокси.",
            "Настоящий домашний каталог включён после сохранения")

    def update_system_hints(self):
        lang = self.e_lang.get_text().strip()
        if not lang:
            self.lbl_lang.set_text("Пусто — язык как на компьютере.")
        elif not LANG_RE.match(lang):
            self.lbl_lang.set_text("✖ Неверный формат. Пример: ru_RU.UTF-8")
        else:
            ok = locale_available(lang)
            self.lbl_lang.set_text("✔ Локаль есть в системе." if ok else
                                   "⚠ Такой локали нет на компьютере (locale -a): программы вернутся к "
                                   "английскому. Сгенерируйте её (Arch: /etc/locale.gen и sudo locale-gen)."
                                   if ok is False else "Не удалось проверить локаль.")
        tz = self.e_tz.get_text().strip()
        if not tz:
            self.lbl_tz.set_text("Пусто — пояс как на компьютере. Это часовой пояс, а не подмена часов.")
        elif timezone_exists(tz):
            self.lbl_tz.set_text("✔ Пояс найден. Это часовой пояс, а не подмена часов.")
        else:
            self.lbl_tz.set_text("✖ Не найден в /usr/share/zoneinfo. Пример: Europe/Moscow")
