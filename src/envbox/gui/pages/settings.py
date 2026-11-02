"""Настройки приложения, диагностика, ярлык."""

import subprocess

from ...core.consts import INSTALLED_PY
from ...core.desktop import install_desktop_entry
from ...core.diagnostics import diagnostics
from ...core.store import save_settings
from ...core.terminal import detect_terminal
from ...install import file_version, file_version_text
from ...version import ENVBOX_VERSION
from ..gtk import Gtk, Vte
from ..widgets import alert, hint, margins, set_text, text_area, to_home, toggle


def version_line():
    """Строка проверки: версия запущенного envbox и установленной копии (из неё работают шлюз и запущенные среды)."""
    installed = file_version_text(INSTALLED_PY)
    if installed is None:
        return f"⚠ версия envbox {ENVBOX_VERSION}: установленной копии нет (выполните python3 envbox.py install)"
    if file_version(INSTALLED_PY) == tuple(int(x) for x in ENVBOX_VERSION.split(".")):
        return f"✔ версия envbox {ENVBOX_VERSION}: запущенная совпадает с установленной"
    return (f"⚠ версия envbox: запущена {ENVBOX_VERSION}, установлена {installed}. Шлюз и среды работают из "
            "установленной копии: выполните python3 envbox.py install и перезапустите среды")


class SettingsMixin:
    """Настройки приложения, диагностика, ярлык."""

    def on_settings(self, *_):
        win = Gtk.Window(title="Настройки терминала", transient_for=self, modal=True)
        win.set_default_size(560, -1)
        box = margins(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12), 16)
        line, sw = toggle("Открывать терминал во вкладке внутри окна",
                          "Отдельный эмулятор терминала не нужен." if Vte is not None else
                          "Недоступно: не найден VTE. Arch: sudo pacman -S vte4")
        sw.set_active(self.use_embedded())
        sw.set_sensitive(Vte is not None)
        box.append(line)
        box.append(Gtk.Label(label="Внешний терминал (если не во вкладке):", xalign=0))
        entry = Gtk.Entry(text=self.settings.get("terminal", ""), hexpand=True,
                          placeholder_text="пусто — определить автоматически")
        box.append(entry)
        auto = detect_terminal({"terminal": ""})
        box.append(hint("Сейчас определён: " + (" ".join(auto) if auto else "не найден") +
                        ". Команда среды добавляется в конец. Примеры: «kitty», «alacritty -e», "
                        "«foot», «ghostty -e», «konsole -e», «gnome-terminal --»."))
        buttons = Gtk.Box(spacing=8, halign=Gtk.Align.END)
        cancel = Gtk.Button(label="Отмена")
        ok = Gtk.Button(label="Сохранить")
        ok.add_css_class("suggested-action")
        buttons.append(cancel)
        buttons.append(ok)
        box.append(buttons)

        def save(*_):
            self.settings["terminal"] = entry.get_text().strip()
            self.settings["embedded"] = sw.get_active()
            try:
                save_settings(self.settings)
            except OSError as e:
                alert(win, "Не удалось сохранить настройки", str(e))
                return
            win.destroy()
            self.status("Настройки терминала сохранены")

        ok.connect("clicked", save)
        cancel.connect("clicked", lambda *_: win.destroy())
        win.set_child(box)
        win.present()

    def on_diag(self, *_):
        win = Gtk.Window(title="Проверка системы", transient_for=self)
        win.set_default_size(760, 520)
        win.set_child(self.build_diag_page())
        self.run_diagnostics()
        win.present()

    def build_diag_page(self):
        box = margins(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8))
        buttons = Gtk.Box(spacing=8)
        b_check = Gtk.Button(label="Проверить снова")
        b_check.connect("clicked", lambda *_: self.run_diagnostics())
        b_desktop = Gtk.Button(label="Добавить в меню приложений")
        b_desktop.connect("clicked", self.on_install_desktop)
        buttons.append(b_check)
        buttons.append(b_desktop)
        box.append(buttons)
        self.tv_diag, sw = text_area(editable=False, height=300)
        sw.set_vexpand(True)
        box.append(sw)
        return box

    def run_diagnostics(self):
        icons = {"ok": "✔", "warn": "⚠", "fail": "✖"}
        out = [version_line()]
        try:
            for st, title, detail in diagnostics(self.settings):
                out.append(f"{icons.get(st, '?')} {title}")
                for line in detail.splitlines():
                    out.append(f"      {line}")
        except (OSError, subprocess.SubprocessError) as e:
            out.append(f"✖ ошибка диагностики: {e}")
        out.append(("✔ " if Vte is not None else "⚠ ") + "встроенный терминал (VTE): " +
                   ("есть" if Vte is not None else "нет — Arch: sudo pacman -S vte4"))
        set_text(self.tv_diag, "\n".join(out))

    def on_install_desktop(self, *_):
        try:
            path = install_desktop_entry()
        except OSError as e:
            alert(self, "Не удалось создать ярлык", str(e))
            return
        alert(self, "Ярлык создан", to_home(path))
