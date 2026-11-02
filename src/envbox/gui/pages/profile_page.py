"""Страница настроек среды: сбор формы, сохранение."""

import shutil
import subprocess

from ...core.browser import find_browser
from ...core.consts import NET_LABELS, NET_MODES, SHELLS, UPSTREAM_AUTH_VAR
from ...core.keyring import secret_store, secret_tool_available
from ...core.profile import Profile
from ...core.root import envbox_root
from ...core.store import browser_profiles, save_profile
from ...core.system import installed_shells, pkg_hint
from ...core.upstream import split_proxy_url
from ...core.vpn import EXIT_LABELS, EXIT_MODES
from ..gtk import GLib, Gtk
from ..widgets import (
    Rows,
    alert,
    expander_section,
    get_lines,
    get_text,
    hint,
    icon_button,
    margins,
    section,
    set_text,
    show_all,
    text_area,
    to_home,
    toggle,
)


class ProfilePageMixin:
    """Страница настроек среды: сбор формы, сохранение."""

    def build_profile_page(self):
        page = margins(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16), 16)
        self.app_only = []       # виджеты, видимые только у сред-приложений
        self.browser_only = []   # виджеты, видимые только у сред-браузеров
        adv = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16, margin_top=12)
        adv_exp = Gtk.Expander()
        adv_exp.set_label_widget(Gtk.Label(label="Дополнительные настройки: прокси, язык и DNS, браузер для ИИ, "
                                                 "переменные", wrap=True, xalign=0))
        adv_exp.set_child(adv)

        # --- Что запускать
        box, grid = section("Что запускать")
        rows = Rows(grid)
        self.e_workdir = Gtk.Entry(hexpand=True, placeholder_text="~/projects/app")
        b = Gtk.Button(label="Выбрать…")
        b.connect("clicked", lambda *_: self.choose_folder(
            lambda p: self.e_workdir.set_text(to_home(p))))
        wbox = Gtk.Box(spacing=6)
        wbox.append(self.e_workdir)
        wbox.append(b)
        self.app_only += rows.add("Каталог проекта", wbox,
                                  "Единственное место на компьютере, куда программа сможет записывать.")
        self.e_command = Gtk.Entry(hexpand=True, placeholder_text="claude")
        self.app_only += rows.add("Команда", self.e_command,
                                  "Запускается кнопкой «Запустить». «Терминал» открывает оболочку (её можно выбрать ниже).")

        self.shell_choices = ["bash"]
        self.dd_shell = Gtk.DropDown.new_from_strings(["bash"])
        others = [x for x in SHELLS if x != "bash" and not shutil.which(x)]
        self.app_only += rows.add(
            "Оболочка", self.dd_shell,
            "Что открывает кнопка «Терминал». bash есть всегда. fish удобнее: подсказки из истории и "
            "подсветка работают сразу; zsh — привычный. Оболочка берётся с компьютера"
            + (": не найдены — " + ", ".join(f"{x} ({pkg_hint(x)})" for x in others) if others else "")
            + ".")

        self.e_start_url = Gtk.Entry(hexpand=True, placeholder_text="about:blank")
        self.browser_only += rows.add("Стартовая страница", self.e_start_url)
        self.e_browser_bin = Gtk.Entry(hexpand=True, placeholder_text="найти автоматически")
        found = find_browser()
        self.browser_only += rows.add("Путь к браузеру", self.e_browser_bin,
                                      f"Найден: {found}" if found else
                                      "Chrome/Chromium не найден: sudo pacman -S chromium "
                                      "или: " + pkg_hint("chromium"))
        line, self.cb_visible = toggle(
            "Показывать окно браузера",
            "Обычно не нужно: ИИ управляет браузером без окна, а вы видите страницу на вкладке "
            "«Окно браузера» внутри приложения. Отдельное окно требует доступа к Wayland "
            "и ослабляет изоляцию.")
        self.browser_only += rows.add(None, line)
        line, self.cb_chrome_sandbox = toggle(
            "Встроенная защита Chrome (sandbox)",
            "Нужны вложенные user namespaces. Если браузер сразу закрывается — выключите "
            f"(причина будет в {to_home(envbox_root())}/<имя>/launch.log).")
        self.browser_only += rows.add(None, line)
        page.append(box)

        # --- Папки: доступ к дополнительным каталогам и глобальные папки
        self.global_rows = {}
        box, grid = section("Папки", "Что ещё среда может видеть на компьютере. Свой домашний каталог "
                                     "и проект подключены всегда.")
        rows = Rows(grid)
        self.tv_rw, sw = text_area(height=50)
        b_rw = Gtk.Button(label="Добавить…", valign=Gtk.Align.START)
        b_rw.connect("clicked", lambda *_: self.choose_folder(self.add_rw_path))
        rwbox = Gtk.Box(spacing=6)
        rwbox.append(sw)
        rwbox.append(b_rw)
        rows.add("Папки с записью", rwbox,
                 "Каталоги компьютера, куда программа сможет записывать, кроме проекта: например папка "
                 "для загрузок браузера или общий каталог с данными. По одному в строке. "
                 "Только для чтения — в «Переменные и файлы».")
        line, self.cb_global = toggle(
            "Глобальные папки",
            "Папки внутри каталога данных envbox, которые не принадлежат ни одной среде: при удалении "
            "среды они остаются на месте. Удобно хранить там код, чтобы случайно не потерять его вместе "
            "с профилем. По умолчанию выключено.")
        self.cb_global.connect("notify::active", lambda *_: self.update_global_visibility())
        rows.add(None, line)
        self.global_list = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        gbtns = Gtk.Box(spacing=6)
        b_gnew = Gtk.Button(label="Создать папку…")
        b_gnew.connect("clicked", lambda *_: self.on_global_create())
        b_gmanage = Gtk.Button(label="Управление папками…")
        b_gmanage.connect("clicked", self.on_folders)
        gbtns.append(b_gnew)
        gbtns.append(b_gmanage)
        gcol = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        gcol.append(self.global_list)
        gcol.append(gbtns)
        self.global_widgets = rows.add(
            "Подключить", gcol,
            "Отметьте папки и выберите режим для каждой. Папка подключается по своему настоящему пути. "
            "«Сделать проектом» ставит её каталогом проекта (работа с кодом внутри неё).")
        page.append(box)

        # --- Сеть
        box, grid = section("Сеть")
        rows = Rows(grid)
        self.dd_net = Gtk.DropDown.new_from_strings([NET_LABELS[m] for m in NET_MODES])
        self.dd_net.connect("notify::selected", lambda *_: self.update_net_sensitivity())
        rows.add("Режим", self.dd_net,
                 "Рекомендуется «через прокси с журналом»: программа не видит ваш localhost, "
                 "а все обращения записываются.")
        self.tv_domains, sw = text_area(height=56)
        self.domain_widgets = rows.add("Разрешённые сайты", sw,
                                       "По одному в строке: example.com — только он, *.example.com — "
                                       "он и все его поддомены. Удобно добавлять из «Журнала сети».")
        line, self.cb_private = toggle(
            "Пускать на частные адреса",
            "Открывает среде localhost и локальную сеть через прокси. Обычно не нужно.")
        self.private_widgets = rows.add(None, line)
        page.append(box)

        box, grid = section("Свой прокси",
                            "Необязательно: весь трафик среды пойдёт через ваш прокси (HTTP или SOCKS5).")
        rows = Rows(grid)
        self.e_upstream = Gtk.Entry(hexpand=True,
                                    placeholder_text="socks5://хост:порт или http://хост:порт")
        up_box = Gtk.Box(spacing=6)
        up_box.append(self.e_upstream)
        for label, handler in (("Из файла…", self.on_proxy_file), ("Проверить", self.on_proxy_test),
                               ("Для Claude…", self.on_proxy_check), ("Логин и пароль…", self.on_proxy_auth)):
            bt = Gtk.Button(label=label)
            bt.connect("clicked", handler)
            up_box.append(bt)
        self.up_widgets = rows.add("Свой прокси", up_box)
        self.lbl_up = hint("")
        rows.grid.attach(self.lbl_up, 1, rows.r, 1, 1)
        rows.r += 1
        self.e_upstream.connect("changed", lambda *_: self.update_net_sensitivity())
        # режим выхода: готовые порядки каналов; «только через VPN» — без прокси и прямого выхода
        self.exit_sync = False
        self.exit_vpns = []
        exit_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self.dd_exit = Gtk.DropDown.new_from_strings([EXIT_LABELS[m] for m in EXIT_MODES])
        self.dd_exit.connect("notify::selected", self.on_exit_changed)
        exit_box.append(self.dd_exit)
        self.dd_exit_vpn = Gtk.DropDown.new_from_strings(["—"])
        self.dd_exit_vpn.connect("notify::selected", self.on_exit_changed)
        exit_box.append(self.dd_exit_vpn)
        self.lbl_exit = hint("")
        exit_box.append(self.lbl_exit)
        self.up_widgets += rows.add("Выход в интернет", exit_box,
                                    "VPN загружаются на вкладке «VPN». «Только через VPN»: весь трафик идёт через "
                                    "выбранный VPN, а если он не запустился или оборвался, соединения отклоняются "
                                    "(настоящий адрес не раскрывается).")
        # порядок выхода: прокси, VPN, выход этого компьютера; первый рабочий принимает новые соединения
        self.tv_chain, sw = text_area(height=56)
        chain_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        chain_box.append(sw)
        chain_bar = Gtk.Box(spacing=6)
        for label, item in (("+ proxy", "proxy"), ("+ direct", "direct")):
            bt = Gtk.Button(label=label)
            bt.connect("clicked", lambda _b, i=item: self.on_chain_add(i))
            chain_bar.append(bt)
        self.dd_vpns = Gtk.DropDown.new_from_strings(["—"])
        chain_bar.append(self.dd_vpns)
        bt = Gtk.Button(label="+ VPN")
        bt.connect("clicked", self.on_chain_add_vpn)
        chain_bar.append(bt)
        chain_box.append(chain_bar)
        self.chain_widgets = rows.add(
            "Порядок выхода", chain_box,
            "Необязательно. По одному каналу в строке: proxy (свой прокси выше), vpn:имя (вкладка «VPN»), "
            "direct (выход этого компьютера, в том числе через его системный VPN). Первый рабочий принимает все "
            "новые соединения; если он не отвечает, берётся следующий, а когда первый вернётся, соединения снова "
            "идут через него. Пусто: как раньше, один прокси или прямой выход.")
        self.up_widgets += self.chain_widgets
        self.tv_chain.get_buffer().connect("changed", lambda *_: (self.sync_exit_from_chain(),
                                                                  self.update_net_sensitivity()))
        adv.append(box)


        # --- Система внутри среды
        box, grid = section("Система внутри среды",
                            "Язык, часовой пояс и DNS, которые увидит программа внутри среды.")
        rows = Rows(grid)
        self.e_lang = Gtk.Entry(hexpand=True, placeholder_text="как на компьютере; например ru_RU.UTF-8")
        self.e_lang.connect("changed", lambda *_: self.update_system_hints())
        rows.add("Язык", self.e_lang)
        self.lbl_lang = hint("")
        rows.grid.attach(self.lbl_lang, 1, rows.r, 1, 1)
        rows.r += 1
        self.e_tz = Gtk.Entry(hexpand=True, placeholder_text="как на компьютере; например Europe/Moscow")
        self.e_tz.connect("changed", lambda *_: self.update_system_hints())
        rows.add("Часовой пояс", self.e_tz)
        self.lbl_tz = hint("")
        rows.grid.attach(self.lbl_tz, 1, rows.r, 1, 1)
        rows.r += 1
        self.tv_dns, sw = text_area(height=44)
        self.dns_widgets = rows.add("DNS-серверы", sw,
                                    "По одному IP в строке, например адрес вашего роутера. Пусто — системные.")
        self.lbl_dns = hint("")
        rows.grid.attach(self.lbl_dns, 1, rows.r, 1, 1)
        rows.r += 1
        self.dns_widgets.append(self.lbl_dns)
        adv.append(box)

        # --- Браузер для ИИ (приложения)
        box, grid = section("Браузер для ИИ",
                            "Дайте программе внутри среды управляемый изолированный браузер.")
        rows = Rows(grid)
        self.tv_attach, sw = text_area(height=40)
        self.dd_browsers = Gtk.DropDown.new_from_strings(["—"])
        b_add = Gtk.Button(label="Добавить")
        b_add.connect("clicked", self.on_attach_add)
        b_help = Gtk.Button(label="Как подключить ИИ…")
        b_help.connect("clicked", self.on_attach_help)
        pick = Gtk.Box(spacing=6)
        pick.append(self.dd_browsers)
        pick.append(b_add)
        pick.append(b_help)
        rows.add("Подключено", sw,
                 "Внутри этой среды браузер виден как http://127.0.0.1:9222. Ни компьютеру, ни другим "
                 "средам он недоступен. Формат строки: среда[:порт[:локальный порт]].")
        rows.add("Среда-браузер", pick)
        self.app_only.append(box)
        adv.append(box)

        # --- Приложение как сервис и установка (приложения)
        box, grid = section("Приложение как сервис и установка",
                            "Запуск программ внутри среды, к которым ИИ-среды подключаются по закрытому сокету.")
        rows = Rows(grid)
        self.tv_expose, sw = text_area(height=40)
        rows.add("Открыть порты для других сред", sw,
                 "Номера портов, по одному в строке (например 9876 для Blender MCP). Порт виден внутри "
                 "среды на 127.0.0.1 и доступен только тем средам, которые вы подключили к ней в блоке "
                 "«Браузер для ИИ». Среда должна быть без сети или через прокси.")
        line, self.cb_nowd = toggle("Без каталога проекта",
                                    "Среда видит только свой домашний каталог: удобно для сервисов и установки.")
        rows.add(None, line)
        line, self.cb_gui = toggle("Показывать окно приложения (Wayland)",
                                   "Нужно приложениям с окном (Blender и т. п.). Ослабляет изоляцию: "
                                   "доступ к сокету Wayland. Графического ускорения в среде нет.")
        rows.add(None, line)
        self.tv_install_domains, sw = text_area(height=40)
        rows.add("Сайты для установки", sw,
                 "Пусто — при установке открыты любые публичные сайты с журналом. Иначе — только эти домены.")
        self.e_link_handler = Gtk.Entry(hexpand=True, placeholder_text="claude-desktop")
        rows.add("Команда открытия ссылок", self.e_link_handler,
                 "Что запустить внутри среды, чтобы приложение открыло ссылку (получит её последним аргументом). "
                 "Если приложение уже запущено, оно примет ссылку у себя. Пусто — приём ссылок выключен.")
        self.e_link_schemes = Gtk.Entry(hexpand=True, placeholder_text="claude")
        rows.add("Схемы ссылок приложения", self.e_link_schemes,
                 "Через пробел, например: claude (ссылки claude://…). Ссылки http и https разрешены всегда.")
        line, self.cb_link_cb = toggle("Принимать вход по ссылке localhost",
                                       "Для Claude CLI: адрес вида http://localhost:порт/… выполняется внутри среды, "
                                       "потому что браузер на компьютере не может достучаться до порта среды.")
        rows.add(None, line)
        line, self.cb_link_auto = toggle("Открывать ссылки из этой среды в браузере без вопроса",
                                         "Программа внутри среды просит открыть сайт (вход, документация) — envbox открывает "
                                         "его в изолированном браузере сразу. Выключено: сначала покажет адрес и спросит. "
                                         "Включайте только для сред, которым доверяете: через ссылку можно отправить данные "
                                         "на любой сайт, доступный браузеру.")
        rows.add(None, line)
        self.btn_bind = Gtk.Button(label="Открывать ссылки из браузера в этой среде", halign=Gtk.Align.START)
        self.btn_bind.connect("clicked", self.on_bind_scheme)
        rows.add(None, self.btn_bind)
        self.lbl_bind = hint("")
        rows.add(None, self.lbl_bind)
        self.app_only.append(box)
        adv.append(box)

        # --- Доступ ИИ (браузер)
        box, grid = section("Доступ ИИ к этому браузеру")
        rows = Rows(grid)
        self.lbl_cdp = Gtk.Label(xalign=0, wrap=True, selectable=True)
        rows.add("Сокет CDP", self.lbl_cdp)
        b_snip = Gtk.Button(label="Строки подключения…", halign=Gtk.Align.START)
        b_snip.connect("clicked", self.on_browser_help)
        rows.add(None, b_snip,
                 "ИИ получает полный контроль над браузером, включая cookies и сеансы в его профиле. "
                 "Не входите в личные аккаунты в этой среде.")
        self.browser_only.append(box)
        adv.append(box)

        # --- Для опытных: окружение и файлы
        box, grid = expander_section("Переменные и файлы",
                                     "Для опытных: что ещё передать в среду и что разрешить читать.")
        rows = Rows(grid)
        self.tv_env, sw = text_area(height=50)
        rows.add("Переменные", sw,
                 "VAR — взять значение у компьютера; VAR=значение — задать явно "
                 "(хранится в профиле открытым текстом, не для паролей).")
        self.tv_secrets, sw = text_area(height=40)
        b_secret = Gtk.Button(label="Задать значение…", valign=Gtk.Align.START)
        b_secret.connect("clicked", self.on_set_secret)
        sbox = Gtk.Box(spacing=6)
        sbox.append(sw)
        sbox.append(b_secret)
        rows.add("Секреты", sbox)
        self.lbl_secrets = hint("")
        rows.grid.attach(self.lbl_secrets, 1, rows.r, 1, 1)
        rows.r += 1
        self.tv_ro, sw = text_area(height=50)
        b_ro = Gtk.Button(label="Добавить…", valign=Gtk.Align.START)
        b_ro.connect("clicked", lambda *_: self.choose_folder(self.add_ro_path))
        rbox = Gtk.Box(spacing=6)
        rbox.append(sw)
        rbox.append(b_ro)
        rows.add("Читать (без записи)", rbox, "Пути, видимые в среде только на чтение, например ~/.nvm.")
        self.tv_path, sw = text_area(height=40)
        rows.add("Каталоги PATH", sw, "Добавляются в начало PATH внутри среды.")
        adv.append(box)

        # --- Для опытных: защита
        page.append(adv_exp)

        scroll = Gtk.ScrolledWindow(vexpand=True)
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)  # по ширине окна, без растягивания
        scroll.set_child(page)

        wrapper = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        wrapper.append(scroll)
        wrapper.append(Gtk.Separator())
        bar = margins(Gtk.Box(spacing=10), 10)
        b_save = icon_button("document-save-symbolic", "Сохранить", "suggested-action", "Ctrl+S")
        b_save.connect("clicked", lambda *_: self.save_current(quiet=False))
        bar.append(b_save)
        bar.append(hint("Настройки применятся при следующем запуске среды."))
        wrapper.append(bar)
        return wrapper

    def update_net_sensitivity(self):
        mode = NET_MODES[self.dd_net.get_selected()]
        show_all(self.domain_widgets, mode == "allowlist")
        show_all(self.private_widgets, mode in ("log", "allowlist"))
        show_all(self.up_widgets + [self.lbl_up], mode in ("log", "allowlist"))
        chain_items = get_lines(self.tv_chain) if hasattr(self, "tv_chain") else []
        via_upstream = mode in ("log", "allowlist") and (
            bool(self.e_upstream.get_text().strip()) or any(c.startswith("vpn:") for c in chain_items))
        if hasattr(self, "dd_exit"):
            self.update_exit_ui(mode in ("log", "allowlist"))
        show_all(self.dns_widgets, mode in ("log", "allowlist", "host") and not via_upstream)
        if mode == "host":
            self.lbl_dns.set_text("Серверы запишутся в /etc/resolv.conf среды.")
        else:
            self.lbl_dns.set_text("Имена сайтов разрешает прокси на компьютере через эти серверы. "
                                  "Обычный DNS не шифруется: запросы видит сеть и владелец сервера.")

    def show_profile(self, p):
        self.loading = True
        self.current = p
        if p is None:
            self.main_stack.set_visible_child_name("welcome")
            self.loading = False
            self.update_buttons()
            self.reset_net_view()
            if self.b_detached is None:
                self.browser_disconnect()
            return
        self.main_stack.set_visible_child_name("main")
        is_browser = p.is_browser
        detached = self.b_detached is not None
        self.page_browser.set_visible(is_browser or detached)
        if self.viewer is not None and not detached and (not is_browser or self.viewer_env != p.name):
            self.browser_disconnect()
        if not detached:
            self.b_manual_off = False
        show_all(self.app_only, not is_browser)
        show_all(self.browser_only, is_browser)
        self.e_workdir.set_text(p.workdir)
        self.e_command.set_text(p.command)
        self.shell_choices = installed_shells()
        if p.shell_cmd not in self.shell_choices:
            self.shell_choices.append(p.shell_cmd)
        self.dd_shell.set_model(Gtk.StringList.new(
            [x if x in installed_shells() else f"{x} (не установлена)" for x in self.shell_choices]))
        self.dd_shell.set_selected(self.shell_choices.index(p.shell_cmd))
        self.e_start_url.set_text(p.browser_start_url)
        self.e_browser_bin.set_text(p.browser_bin)
        self.cb_visible.set_active(p.browser_visible)
        self.cb_chrome_sandbox.set_active(p.browser_chrome_sandbox)
        self.dd_net.set_selected(NET_MODES.index(p.net))
        set_text(self.tv_domains, "\n".join(p.allow_domains))
        self.cb_private.set_active(p.net_allow_private)
        self.e_upstream.set_text(p.upstream)
        set_text(self.tv_chain, "\n".join(p.upstream_chain))
        self.refresh_vpn_choices()
        self.e_lang.set_text(p.lang)
        self.e_tz.set_text(p.timezone)
        set_text(self.tv_dns, "\n".join(p.dns))
        set_text(self.tv_attach, "\n".join(p.attach))
        set_text(self.tv_expose, "\n".join(p.expose_ports))
        set_text(self.tv_install_domains, "\n".join(p.install_domains))
        self.e_link_handler.set_text(p.link_handler)
        self.e_link_schemes.set_text(" ".join(p.link_schemes))
        self.cb_link_cb.set_active(p.link_callback)
        self.cb_link_auto.set_active(p.link_out_auto)
        self.cb_nowd.set_active(p.no_workdir)
        self.cb_gui.set_active(p.gui_wayland)
        self.update_bind_status()
        set_text(self.tv_env, "\n".join(p.env))
        set_text(self.tv_secrets, "\n".join(p.secrets))
        set_text(self.tv_ro, "\n".join(p.ro))
        set_text(self.tv_rw, "\n".join(p.rw))
        self.cb_global.set_active(p.global_on)
        self.refresh_global_rows(p.global_folders)
        self.update_global_visibility()
        set_text(self.tv_path, "\n".join(p.path))
        self.show_isolation(p)
        set_text(self.tv_preview, "")
        names = [n for n in browser_profiles() if n != p.name] or ["—"]
        self.dd_browsers.set_model(Gtk.StringList.new(names))
        self.update_net_sensitivity()
        self.update_system_hints()
        self.loading = False
        self.update_secret_status()
        self.update_upstream_status()
        self.update_cdp_label()
        self.update_buttons()
        self.update_overview(p)
        self.reset_net_view()

    def selected_shell(self):
        i = self.dd_shell.get_selected()
        choices = getattr(self, "shell_choices", ["bash"])
        sh = choices[i] if 0 <= i < len(choices) else "bash"
        return "" if sh == "bash" else sh

    def collect(self):
        prof = Profile(
            name=self.current.name,
            kind=self.current.kind,
            workdir=self.e_workdir.get_text().strip(),
            command=self.e_command.get_text().strip(),
            net=NET_MODES[self.dd_net.get_selected()],
            allow_domains=get_lines(self.tv_domains),
            net_allow_private=self.cb_private.get_active(),
            upstream=self.e_upstream.get_text().strip(),
            upstream_auth=self.current.upstream_auth,
            upstream_chain=get_lines(self.tv_chain),
            attach=get_lines(self.tv_attach),
            expose_ports=get_text(self.tv_expose).replace(",", " ").split(),
            install_domains=get_lines(self.tv_install_domains),
            link_handler=self.e_link_handler.get_text().strip(),
            link_schemes=self.e_link_schemes.get_text().replace(",", " ").split(),
            link_callback=self.cb_link_cb.get_active(),
            link_out_auto=self.cb_link_auto.get_active(),
            link_browser=self.current.link_browser,
            no_workdir=self.cb_nowd.get_active(),
            gui_wayland=self.cb_gui.get_active(),
            shell=self.selected_shell(),
            env=get_lines(self.tv_env),
            secrets=get_lines(self.tv_secrets),
            ro=get_lines(self.tv_ro),
            rw=get_lines(self.tv_rw),
            global_on=self.cb_global.get_active(),
            global_folders=self.collect_global(),
            path=get_lines(self.tv_path),
            browser_bin=self.e_browser_bin.get_text().strip(),
            browser_start_url=self.e_start_url.get_text().strip() or "about:blank",
            browser_visible=self.cb_visible.get_active(),
            browser_chrome_sandbox=self.cb_chrome_sandbox.get_active(),
            lang=self.e_lang.get_text().strip(),
            timezone=self.e_tz.get_text().strip(),
            dns=get_text(self.tv_dns).replace(",", " ").split(),
        )
        self.read_isolation(prof)
        return prof

    def commit_upstream(self):
        """Если в поле прокси указан логин:пароль, переносим их в keyring, а поле очищаем."""
        text = self.e_upstream.get_text().strip()
        if "@" not in text:
            return None
        try:
            url, auth = split_proxy_url(text)
        except ValueError as e:
            return (f"Адрес прокси неверен ({e}). Поле очищено, чтобы логин и пароль "
                    "не попали в файл профиля.")
        if not auth:
            return None
        if not secret_tool_available():
            return "Для хранения пароля прокси нужен secret-tool: " + pkg_hint("secret-tool")
        try:
            secret_store(self.current.name, UPSTREAM_AUTH_VAR, auth)
        except (OSError, RuntimeError, subprocess.SubprocessError) as e:
            return f"Не удалось сохранить пароль прокси в keyring: {e}"
        self.current.upstream_auth = True
        self.e_upstream.set_text(url)
        return None

    def save_current(self, quiet):
        if not self.current:
            return None
        err = self.commit_upstream()
        if err:
            if not quiet:
                alert(self, "Пароль прокси не сохранён", err)
            self.e_upstream.set_text("")
        p = self.collect()
        try:
            save_profile(p)
        except (OSError, ValueError) as e:
            if not quiet:
                alert(self, "Не удалось сохранить профиль", str(e))
            return None
        self.current = p
        self.update_upstream_status()
        self.update_overview(p)
        if not quiet:
            errs = p.validate()
            if errs:
                alert(self, "Профиль сохранён, но пока не готов к запуску", "\n".join(errs))
            else:
                self.status("Сохранено")
        return p

    def choose_folder(self, callback):
        dlg = Gtk.FileDialog(title="Выберите каталог")

        def done(d, res):
            try:
                f = d.select_folder_finish(res)
            except GLib.Error:
                return
            if f is not None and f.get_path():
                callback(f.get_path())

        dlg.select_folder(self, None, done)

    def add_ro_path(self, path):
        lines = get_lines(self.tv_ro)
        if to_home(path) not in lines:
            lines.append(to_home(path))
        set_text(self.tv_ro, "\n".join(lines))

    def add_rw_path(self, path):
        lines = get_lines(self.tv_rw)
        if to_home(path) not in lines:
            lines.append(to_home(path))
        set_text(self.tv_rw, "\n".join(lines))
