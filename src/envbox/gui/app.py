"""Приложение GTK и точка входа gui_main."""

import sys

from .gtk import GLib, Gio, Gtk
from .window import EnvboxWindow


class App(Gtk.Application):
    def __init__(self):
        flags = getattr(Gio.ApplicationFlags, "DEFAULT_FLAGS", Gio.ApplicationFlags.FLAGS_NONE)
        super().__init__(application_id="io.github.envbox.Gui", flags=flags)

    def do_activate(self):
        win = self.props.active_window or EnvboxWindow(self)
        win.present()


def gui_main():
    GLib.set_application_name("envbox")
    return App().run([sys.argv[0]])


gui_main.window_class = EnvboxWindow
