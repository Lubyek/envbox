"""Главное окно: собирается из миксинов страниц (gui/pages/*, gui/browser/*)."""

import sys
import threading

from ..core.netlog import NetSummary
from ..core.store import load_settings
from ..version import ENVBOX_VERSION
from .browser.page import BrowserPageMixin
from .browser.view import BrowserViewMixin
from .consts import CSS, SHELL_COMMAND, STATUS_SECONDS
from .gtk import GLib, Gtk, Pango
from .pages.folders import FoldersMixin
from .pages.isolation import IsolationMixin
from .pages.launch import LaunchMixin
from .pages.links import LinksMixin
from .pages.net_page import NetPageMixin
from .pages.overview import OverviewMixin
from .pages.profile_net import ProfileNetMixin
from .pages.profile_page import ProfilePageMixin
from .pages.settings import SettingsMixin
from .pages.sidebar import SidebarMixin
from .pages.terminal import TerminalMixin
from .pages.vpn import VpnPageMixin
from .widgets import choose, icon_button, margins


class EnvboxWindow(
    SidebarMixin,
    OverviewMixin,
    ProfilePageMixin,
    IsolationMixin,
    FoldersMixin,
    ProfileNetMixin,
    LaunchMixin,
    BrowserPageMixin,
    BrowserViewMixin,
    LinksMixin,
    TerminalMixin,
    SettingsMixin,
    NetPageMixin,
    VpnPageMixin,
    Gtk.ApplicationWindow,
):
    """Главное окно."""

    def __init__(self, app):
        super().__init__(application=app, title=f"envbox {ENVBOX_VERSION}")
        self.set_default_size(1180, 800)
        self.settings = load_settings()
        self.current = None          # загруженный Profile
        self.loading = False         # подавляет обработчики при заполнении
        self.procs = []              # Popen терминалов и браузеров
        self.pending = {}            # имя среды -> (Popen, путь к launch.log) для проверки старта
        self.running = set()         # имена сред с запущенным bwrap
        self.tail = None
        self.net_summary = NetSummary()
        self.net_filter = ""
        self.term_entries = {}       # виджет терминала -> {"pid", "alive", "title", "label"}
        self.row_dots = {}
        self.status_token = 0
        self.attach_snippet_cache = {}

        self.install_css()
        # Кнопки запуска — внутри окна: в тайловых оконных менеджерах заголовок окна не рисуется
        self.btn_run = icon_button("media-playback-start-symbolic", "Запустить", "suggested-action",
                                   "Запустить команду среды (Ctrl+R)")
        self.btn_run.connect("clicked", lambda *_: self.launch(None))
        self.btn_shell = icon_button("utilities-terminal-symbolic", "Терминал", None,
                                     "Открыть оболочку bash внутри среды (Ctrl+T)")
        self.btn_shell.connect("clicked", lambda *_: self.launch(SHELL_COMMAND))
        self.btn_install = icon_button("system-software-install-symbolic", "Установить…", None,
                                       "Установить программы внутрь среды (без проекта и секретов)")
        self.btn_install.connect("clicked", self.on_install)
        self.btn_link = icon_button("insert-link-symbolic", "Ссылка…", None,
                                    "Передать ссылку приложению внутри среды: вход по ссылке, claude://… (Ctrl+Shift+L)")
        self.btn_link.connect("clicked", self.on_open_link)
        self.btn_stop = icon_button("media-playback-stop-symbolic", "Остановить", "destructive-action",
                                    "Остановить среду")
        self.btn_stop.connect("clicked", self.on_stop_current)

        root = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        self.set_child(root)
        self.sidebar = self.build_sidebar()
        root.append(self.sidebar)
        root.append(Gtk.Separator(orientation=Gtk.Orientation.VERTICAL))
        right = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, hexpand=True, vexpand=True)
        right.set_overflow(Gtk.Overflow.HIDDEN)   # содержимое не раздувает окно
        root.append(right)

        self.toolbar = margins(Gtk.Box(spacing=8), 8)
        self.lbl_toolbar = Gtk.Label(xalign=0, hexpand=True, ellipsize=Pango.EllipsizeMode.END)
        self.lbl_toolbar.add_css_class("eb-h2")
        self.toolbar.append(self.lbl_toolbar)
        for b in (self.btn_run, self.btn_shell, self.btn_install, self.btn_link, self.btn_stop):
            self.toolbar.append(b)
        right.append(self.toolbar)
        right.append(Gtk.Separator())
        self.lbl_status = Gtk.Label(xalign=0, ellipsize=Pango.EllipsizeMode.END)
        self.lbl_status.add_css_class("eb-status")
        self.lbl_status.add_css_class("dim-label")

        self.nb = Gtk.Notebook()
        self.page_overview = self.build_overview_page()
        self.nb.append_page(self.page_overview, Gtk.Label(label="Обзор"))
        self.page_terminal = self.build_terminal_page()
        self.nb.append_page(self.page_terminal, Gtk.Label(label="Терминал"))
        self.page_browser = self.build_browser_page()
        self.nb.append_page(self.page_browser, Gtk.Label(label="Окно браузера"))
        self.page_profile = self.build_profile_page()
        self.nb.append_page(self.page_profile, Gtk.Label(label="Настройки"))
        self.nb.append_page(self.build_isolation_page(), Gtk.Label(label="Изоляция"))
        self.nb.append_page(self.build_vpn_page(), Gtk.Label(label="VPN"))
        self.nb.append_page(self.build_net_page(), Gtk.Label(label="Журнал сети"))
        self.nb.connect("switch-page", self.on_switch_page)
        self.main_stack = Gtk.Stack()
        self.main_stack.add_named(self.build_welcome_page(), "welcome")
        self.main_stack.add_named(self.nb, "main")
        self.main_stack.set_vexpand(True)
        right.append(self.main_stack)
        right.append(Gtk.Separator())
        right.append(self.lbl_status)

        self.add_shortcuts()
        self.reload_profiles()
        self.refresh_sessions()
        GLib.timeout_add(1000, self.tick)
        GLib.timeout_add(500, self.check_width)
        self.connect("close-request", self.on_close)

    def install_css(self):
        prov = Gtk.CssProvider()
        try:
            if hasattr(prov, "load_from_string"):
                prov.load_from_string(CSS)
            else:
                prov.load_from_data(CSS.encode())
            Gtk.StyleContext.add_provider_for_display(
                self.get_display(), prov, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
        except Exception as e:  # noqa: BLE001 — оформление не должно мешать работе
            sys.stderr.write(f"envbox-gui: оформление не применено: {e}\n")

    def status(self, message):
        self.lbl_status.set_text(message)
        self.status_token += 1
        token = self.status_token

        def clear():
            if token == self.status_token:
                self.lbl_status.set_text("")
            return False

        GLib.timeout_add_seconds(STATUS_SECONDS, clear)

    def run_async(self, func, done):
        """func() в потоке, done(результат_или_исключение) в главном потоке."""
        def worker():
            try:
                res = func()
            except Exception as e:  # noqa: BLE001 — показываем пользователю
                res = e
            GLib.idle_add(lambda: (done(res), False)[1])

        threading.Thread(target=worker, daemon=True).start()

    def add_shortcuts(self):
        ctl = Gtk.ShortcutController()
        bindings = (("<Control>s", lambda: self.save_current(quiet=False)),
                    ("<Control>n", lambda: self.on_new()),
                    ("<Control>t", lambda: self.btn_shell.get_visible() and self.launch(SHELL_COMMAND)),
                    ("<Control><Shift>l", lambda: self.btn_link.get_visible() and self.on_open_link()),
                    ("<Control>r", lambda: self.launch(None)),
                    ("F5", lambda: self.refresh_all()))
        def make_handler(fn):
            return lambda *_: (fn(), True)[1]

        for accel, fn in bindings:
            action = Gtk.CallbackAction.new(make_handler(fn))
            ctl.add_shortcut(Gtk.Shortcut.new(Gtk.ShortcutTrigger.parse_string(accel), action))
        self.add_controller(ctl)

    def refresh_all(self):
        self.refresh_sessions()
        self.reload_profiles()
        self.status("Обновлено")

    def on_switch_page(self, _nb, page, _num):
        if page is self.page_overview and self.current:
            self.update_overview(self.collect())  # с учётом ещё не сохранённых правок

    def check_width(self):
        """Узкое окно: кнопки без подписей, боковая панель уже."""
        try:
            width = int(self.get_width())
        except (TypeError, ValueError):
            return True
        compact = 0 < width < 1000
        if compact != getattr(self, "compact", None):
            self.compact = compact
            for b in (self.btn_run, self.btn_shell, self.btn_install, self.btn_link, self.btn_stop):
                b.lbl.set_visible(not compact)
            self.sidebar.set_size_request(190 if compact else 250, -1)
        return True

    def tick(self):
        self.procs = [t for t in self.procs if t.poll() is None]
        self.refresh_sessions_async()
        self.poll_net()
        if self.current and self.current.is_browser:
            self.update_cdp_label()
        return True

    def on_close(self, *_):
        if self.b_detached is not None:
            try:
                self.b_detached.close()
            except Exception:  # noqa: BLE001
                pass
        self.browser_disconnect()
        self.save_current(quiet=True)
        alive = [e for e in self.term_entries.values() if e["alive"] and e["pid"]]
        if alive and not getattr(self, "closing_confirmed", False):
            def done(idx):
                if idx == 1:
                    self.closing_confirmed = True
                    for e in alive:
                        self.kill_group(e["pid"])
                    self.close()

            choose(self, "Закрыть окно?",
                   f"Открытых терминалов: {len(alive)}. Они будут завершены вместе со средами.",
                   ["Отмена", "Закрыть и завершить"], done)
            return True
        return False
