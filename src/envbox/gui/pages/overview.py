"""Страницы «Добро пожаловать» и «Обзор»."""

from ...core.consts import KIND_LABELS, NET_SHORT
from ...core.describe import describe
from ...core.root import box_dir
from ..consts import KIND_ICONS, LEVEL_ICONS
from ..gtk import Gtk
from ..widgets import badge, card, clear_children, hint, icon_button, margins, text_area, to_home


class OverviewMixin:
    """Страницы «Добро пожаловать» и «Обзор»."""

    # ------------------------------------------------------- приветствие и обзор

    def build_welcome_page(self):
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, valign=Gtk.Align.CENTER,
                        halign=Gtk.Align.CENTER, spacing=16)
        outer.set_margin_start(40)
        outer.set_margin_end(40)
        title = Gtk.Label(label="Изолированные среды для программ и ИИ")
        title.add_css_class("eb-welcome-title")
        title.set_wrap(True)
        outer.append(title)
        intro = Gtk.Label(wrap=True, justify=Gtk.Justification.CENTER, max_width_chars=64,
                          label="Программа запускается в «песочнице»: она не видит ваши личные файлы, "
                                "записывает только в выбранный проект, а выход в сеть можно выключить "
                                "или записывать в журнал.")
        intro.add_css_class("dim-label")
        outer.append(intro)
        steps = card()
        for text in ("1.  Создайте среду — для программы (например claude) или для браузера.",
                     "2.  Выберите рабочий каталог и режим сети.",
                     "3.  Нажмите «Терминал» — всё внутри будет изолировано."):
            steps.append(Gtk.Label(label=text, xalign=0))
        outer.append(steps)
        buttons = Gtk.Box(spacing=10, halign=Gtk.Align.CENTER)
        b_claude = icon_button("utilities-terminal-symbolic", "Claude CLI (жёсткая изоляция)",
                               "suggested-action")
        b_claude.connect("clicked", lambda *_: self.on_new(kind="claude"))
        b_app = icon_button("utilities-terminal-symbolic", "Среда для другой программы")
        b_app.connect("clicked", lambda *_: self.on_new(kind="app"))
        b_browser = icon_button("web-browser-symbolic", "Среда-браузер")
        b_browser.connect("clicked", lambda *_: self.on_new(kind="browser"))
        buttons.append(b_claude)
        buttons.append(b_app)
        buttons.append(b_browser)
        outer.append(buttons)
        return outer

    def build_overview_page(self):
        page = margins(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16), 16)

        banner = card()
        top = Gtk.Box(spacing=16)
        self.img_kind = Gtk.Image.new_from_icon_name(KIND_ICONS["app"])
        self.img_kind.set_pixel_size(40)
        top.append(self.img_kind)
        info = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6, hexpand=True)
        self.lbl_title = Gtk.Label(xalign=0)
        self.lbl_title.add_css_class("eb-title")
        info.append(self.lbl_title)
        self.lbl_where = hint("")
        info.append(self.lbl_where)
        row = Gtk.Box(spacing=8)
        self.badge_kind = badge()
        self.badge_state = badge()
        self.badge_net = badge()
        self.badge_strict = badge()
        for b in (self.badge_kind, self.badge_state, self.badge_net, self.badge_strict):
            row.append(b)
        info.append(row)
        top.append(info)
        banner.append(top)
        self.lbl_next = Gtk.Label(xalign=0, wrap=True)
        banner.append(self.lbl_next)
        page.append(banner)

        self.problems_card = card("eb-card-warn")
        title = Gtk.Label(label="Что нужно исправить, чтобы запустить", xalign=0)
        title.add_css_class("eb-h2")
        self.problems_card.append(title)
        self.problems_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self.problems_card.append(self.problems_box)
        page.append(self.problems_card)

        summary = card()
        title = Gtk.Label(label="Что получает эта среда", xalign=0)
        title.add_css_class("eb-h2")
        summary.append(title)
        summary.append(hint("Описание по текущим настройкам, включая ещё не сохранённые."))
        self.summary_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        summary.append(self.summary_box)
        page.append(summary)

        exp = Gtk.Expander(label="Показать итоговую команду bwrap")
        inner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8, margin_top=8)
        b_preview = Gtk.Button(label="Собрать команду", halign=Gtk.Align.START)
        b_preview.connect("clicked", self.on_preview)
        inner.append(b_preview)
        self.tv_preview, sw = text_area(editable=False, height=150)
        inner.append(sw)
        exp.set_child(inner)
        page.append(exp)

        scroll = Gtk.ScrolledWindow(vexpand=True)
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)  # по ширине окна, без растягивания
        scroll.set_child(page)
        return scroll

    def update_overview(self, p=None):
        p = p or self.current
        if p is None:
            return
        self.img_kind.set_from_icon_name(KIND_ICONS.get(p.kind, KIND_ICONS["app"]))
        self.lbl_title.set_text(p.name)
        self.lbl_where.set_text(f"Данные среды: {to_home(box_dir(p.name))}")
        self.badge_kind.set_text(KIND_LABELS[p.kind])
        running = p.name in self.running
        self.badge_state.set_text("● запущена" if running else "остановлена")
        if running:
            self.badge_state.add_css_class("eb-badge-run")
        else:
            self.badge_state.remove_css_class("eb-badge-run")
        text, warn = p.isolation_summary()
        self.badge_strict.set_text(text)
        if warn:
            self.badge_strict.add_css_class("eb-badge-warn")
        else:
            self.badge_strict.remove_css_class("eb-badge-warn")
        self.badge_net.set_text("сеть: " + NET_SHORT[p.net])
        if p.net == "host":
            self.badge_net.add_css_class("eb-badge-warn")
        else:
            self.badge_net.remove_css_class("eb-badge-warn")
        if p.is_browser:
            self.lbl_next.set_text("Нажмите «Запустить браузер». Затем подключите его к ИИ-среде: в её "
                                   "настройках, раздел «Браузер для ИИ». Страница появится на вкладке «Окно браузера».")
        elif p.gui_wayland and p.command == "claude-desktop":
            self.lbl_next.set_text("Первый раз: «Установить…» → «Claude Desktop». Затем «Запустить»: окно появится на "
                                   "рабочем столе через Wayland. Вход: войдите в обычном браузере, а полученную "
                                   "ссылку claude://… вставьте через «Ссылка…» (или свяжите её с этой средой в "
                                   "«Настройках», тогда браузер сам передаст её сюда). Если что-то блокируется, "
                                   "смотрите «Журнал сети».")
        else:
            self.lbl_next.set_text("Нажмите «Терминал», чтобы получить оболочку внутри среды, или "
                                   "«Запустить», чтобы сразу выполнить: " + (p.command or "—"))
        clear_children(self.problems_box)
        errs = p.validate()
        for e in errs:
            lbl = Gtk.Label(label="✖  " + e, xalign=0, wrap=True)
            self.problems_box.append(lbl)
        self.problems_card.set_visible(bool(errs))
        clear_children(self.summary_box)
        for level, text in describe(p):
            mark, css = LEVEL_ICONS[level]
            line = Gtk.Box(spacing=10)
            m = Gtk.Label(label=mark, valign=Gtk.Align.START)
            m.add_css_class(css)
            line.append(m)
            line.append(Gtk.Label(label=text, xalign=0, wrap=True, hexpand=True))
            self.summary_box.append(line)
