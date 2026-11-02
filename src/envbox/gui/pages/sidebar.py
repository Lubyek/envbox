"""Боковая панель: список сред, создание, копирование, удаление."""

import os

from ...core.consts import KIND_LABELS, NAME_RE
from ...core.profile import new_profile
from ...core.root import box_dir, envbox_root
from ...core.store import (
    copy_profile,
    delete_profile,
    list_profiles,
    load_profile,
    profile_path,
    save_profile,
)
from ..consts import KIND_ICONS
from ..gtk import Gtk, Pango
from ..widgets import alert, choose, hint, icon_button, margins, prompt, to_home


class SidebarMixin:
    """Боковая панель: список сред, создание, копирование, удаление."""

    # ------------------------------------------------------------ боковая панель

    def build_sidebar(self):
        box = margins(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10), 12)
        box.add_css_class("eb-sidebar")
        box.set_hexpand(False)
        box.set_size_request(250, -1)
        title = Gtk.Label(label="Мои среды", xalign=0)
        title.add_css_class("eb-h2")
        box.append(title)
        self.plist = Gtk.ListBox(selection_mode=Gtk.SelectionMode.SINGLE)
        self.plist.add_css_class("navigation-sidebar")
        self.plist.connect("row-selected", self.on_profile_selected)
        scroll = Gtk.ScrolledWindow(vexpand=True)
        scroll.set_child(self.plist)
        box.append(scroll)
        b_new = icon_button("list-add-symbolic", "Новая среда", "suggested-action", "Ctrl+N")
        b_new.connect("clicked", self.on_new)
        box.append(b_new)
        small = Gtk.Box(spacing=6, homogeneous=True)
        b_copy = icon_button("edit-copy-symbolic", "Копия")
        b_copy.connect("clicked", self.on_copy)
        b_del = icon_button("user-trash-symbolic", "Удалить")
        b_del.connect("clicked", self.on_delete)
        small.append(b_copy)
        small.append(b_del)
        box.append(small)
        b_folders = icon_button("folder-symbolic", "Папки и каталог данных", None,
                                "Где лежат данные envbox и глобальные папки")
        b_folders.connect("clicked", self.on_folders)
        box.append(b_folders)
        tools = Gtk.Box(spacing=6, homogeneous=True)
        b_diag = icon_button("dialog-information-symbolic", "Проверка", None, "Проверка системы")
        b_diag.connect("clicked", self.on_diag)
        b_term = icon_button("preferences-system-symbolic", "Терминал", None, "Настройки терминала")
        b_term.connect("clicked", self.on_settings)
        tools.append(b_diag)
        tools.append(b_term)
        box.append(tools)
        box.append(hint("● — среда сейчас запущена"))
        return box

    def reload_profiles(self, select=None):
        self.loading = True
        while (row := self.plist.get_row_at_index(0)) is not None:
            self.plist.remove(row)
        self.row_dots = {}
        target = None
        for name in list_profiles():
            try:
                kind = load_profile(name).kind
            except (OSError, ValueError):
                kind = "app"
            row = Gtk.ListBoxRow()
            row.envname = name
            line = margins(Gtk.Box(spacing=10), 6)
            line.append(Gtk.Image.new_from_icon_name(KIND_ICONS.get(kind, KIND_ICONS["app"])))
            lbl = Gtk.Label(label=name, xalign=0, hexpand=True)
            lbl.set_ellipsize(Pango.EllipsizeMode.END)
            dot = Gtk.Label(label="")
            dot.add_css_class("eb-dot")
            line.append(lbl)
            line.append(dot)
            row.set_child(line)
            self.row_dots[name] = dot
            dot.set_text("●" if name in self.running else "")
            self.plist.append(row)
            if name == select or (select is None and self.current and self.current.name == name):
                target = row
        self.loading = False
        if target is None:
            target = self.plist.get_row_at_index(0)
        if target is not None:
            self.plist.select_row(target)
        else:
            self.show_profile(None)

    def on_profile_selected(self, _lb, row):
        if self.loading or row is None:
            return
        name = row.envname
        if self.current and self.current.name == name:
            return
        self.save_current(quiet=True)
        try:
            self.show_profile(load_profile(name))
        except (OSError, ValueError) as e:
            alert(self, f"Не удалось прочитать профиль {name}", str(e))

    def on_new(self, _btn=None, kind="app"):
        win = Gtk.Window(title="Новая среда", transient_for=self, modal=True)
        win.set_default_size(460, -1)
        box = margins(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10))
        box.append(Gtk.Label(label=f"Имя среды (каталог {to_home(envbox_root())}/<имя>):", xalign=0))
        entry = Gtk.Entry(hexpand=True)
        box.append(entry)
        box.append(Gtk.Label(label="Тип:", xalign=0))
        kinds = ("claude", "claude-desktop", "codex", "service", "app", "browser")
        kind_labels = {"claude": "Claude CLI — жёсткий шаблон (рекомендуется для ИИ)",
                       "claude-desktop": "Claude Desktop — окно через Wayland, сеть только к Claude",
                       "codex": "Codex или другой ИИ-агент — сеть с журналом, ключ как секрет",
                       "service": "Приложение-сервис для ИИ (Blender и т. п.) — без сети",
                       "app": KIND_LABELS["app"], "browser": KIND_LABELS["browser"]}
        kind_dd = Gtk.DropDown.new_from_strings([kind_labels[k] for k in kinds])
        kind_dd.set_selected(kinds.index(kind))
        box.append(kind_dd)
        box.append(hint("Claude CLI: сеть только к доменам Anthropic, без телеметрии и автообновления. "
                        "Codex и другие агенты: сеть с журналом — после первого запуска сузьте список по журналу. "
                        "Claude Desktop: Electron-приложение в песочнице; ставится через «Установить…» («Claude Desktop»), "
                        "окно показывается через Wayland (это слегка ослабляет изоляцию). "
                        "Приложение-сервис: программа без сети, порты открываются только подключённым ИИ-средам; "
                        "ставится через «Установить…». Браузер: Chromium без окна, к которому ИИ подключается по CDP."))
        buttons = Gtk.Box(spacing=8, halign=Gtk.Align.END)
        cancel = Gtk.Button(label="Отмена")
        ok = Gtk.Button(label="Создать")
        ok.add_css_class("suggested-action")
        buttons.append(cancel)
        buttons.append(ok)
        box.append(buttons)

        def create(*_):
            name = entry.get_text().strip()
            chosen = kinds[kind_dd.get_selected()]
            if not NAME_RE.match(name):
                alert(win, "Недопустимое имя",
                      "Латиница, цифры, '.', '_', '-'; первый символ — буква или цифра; до 48 символов.")
                return
            if os.path.exists(box_dir(name)) or os.path.exists(profile_path(name)):
                alert(win, f"Среда «{name}» уже существует")
                return
            win.destroy()
            self.save_current(quiet=True)
            p = new_profile(chosen, name)
            try:
                save_profile(p)
            except OSError as e:
                alert(self, "Не удалось создать среду", str(e))
                return
            self.reload_profiles(select=name)

        ok.connect("clicked", create)
        entry.connect("activate", create)
        cancel.connect("clicked", lambda *_: win.destroy())
        win.set_child(box)
        win.present()
        entry.grab_focus()

    def on_copy(self, *_):
        if not self.current:
            return
        self.save_current(quiet=True)
        src = self.current.name

        def do_copy(name):
            try:
                copy_profile(src, name.strip())
            except (OSError, ValueError) as e:
                alert(self, "Не удалось скопировать", str(e))
                return
            self.reload_profiles(select=name.strip())

        prompt(self, "Копия среды",
               f"Имя новой среды. Скопируются настройки «{src}»; домашний каталог, профиль браузера "
               "и пароль прокси из keyring не копируются:",
               do_copy, initial=f"{src}-copy")

    def on_delete(self, *_):
        if not self.current:
            return
        name = self.current.name

        def done(idx):
            if idx == 0:
                return
            try:
                delete_profile(name, with_home=(idx == 2))
            except (OSError, ValueError) as e:
                alert(self, "Не удалось удалить", str(e))
                return
            self.current = None
            self.reload_profiles()
            self.status(f"Среда «{name}» удалена")

        choose(self, f"Удалить среду «{name}»?",
               f"Домашний каталог среды: {to_home(box_dir(name))}/home\n"
               "Там лежат данные приложения (и профиль браузера, если это браузер).\n"
               "Рабочий каталог проекта, папки с записью и глобальные папки не затрагиваются "
               "в любом случае.",
               ["Отмена", "Удалить только профиль", "Удалить вместе с домашним каталогом"], done)
