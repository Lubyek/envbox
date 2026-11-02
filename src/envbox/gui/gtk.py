"""Импорт GTK 4 (с перезапуском под системным Python и понятной ошибкой)."""
import os
import sys

from ..selfpath import SELF


def _load_gtk():
    """Импорт GTK; при неудаче перезапуск под системным Python или понятная ошибка."""
    try:
        import gi
        gi.require_version("Gtk", "4.0")
        gi.require_version("Gdk", "4.0")
        from gi.repository import Gdk, Gio, GLib, GObject, Gtk, Pango
        try:  # встроенный терминал; без него терминал открывается во внешнем окне
            gi.require_version("Vte", "3.91")
            from gi.repository import Vte
        except (ImportError, ValueError):
            Vte = None
        return Gdk, Gio, GLib, GObject, Gtk, Pango, Vte
    except (ImportError, ValueError) as exc:
        # GTK-привязки ставятся для системного Python; если скрипт запущен другим
        # интерпретатором (pyenv, mise, conda, uv, linuxbrew), перезапускаемся под системным.
        system_py = "/usr/bin/python3"
        try:
            same = os.path.samefile(sys.executable, system_py)
        except OSError:
            same = True
        if not same and os.access(system_py, os.X_OK) and not os.environ.get("ENVBOX_GUI_REEXEC"):
            os.environ["ENVBOX_GUI_REEXEC"] = "1"
            os.execv(system_py, [system_py, SELF, *sys.argv[1:]])
        sys.stderr.write("envbox: нужен GTK 4 для Python (системный /usr/bin/python3):\n"
                         "  Arch:          sudo pacman -S python-gobject gtk4\n"
                         "  Debian/Ubuntu: sudo apt install python3-gi gir1.2-gtk-4.0\n"
                         "  Fedora:        sudo dnf install python3-gobject gtk4\n"
                         f"(интерпретатор: {sys.executable}; ошибка: {exc})\n")
        sys.exit(1)


Gdk, Gio, GLib, GObject, Gtk, Pango, Vte = _load_gtk()
if Gtk.get_major_version() != 4 or Gtk.get_minor_version() < 10:
    sys.stderr.write("envbox: нужен GTK >= 4.10 (Ubuntu 24.04 и новее)\n")
    sys.exit(1)
