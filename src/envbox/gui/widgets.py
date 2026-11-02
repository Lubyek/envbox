"""Мелкие виджеты и диалоги GTK: кнопки, карточки, переключатели, alert/choose/prompt."""

from .consts import HOME
from .gtk import GLib, Gtk


def to_home(path):
    if path == HOME:
        return "~"
    if path.startswith(HOME + "/"):
        return "~" + path[len(HOME):]
    return path


def margins(widget, m=12):
    widget.set_margin_top(m)
    widget.set_margin_bottom(m)
    widget.set_margin_start(m)
    widget.set_margin_end(m)
    return widget


def text_area(editable=True, height=60):
    view = Gtk.TextView(monospace=True, editable=editable, wrap_mode=Gtk.WrapMode.WORD_CHAR)
    view.set_left_margin(6)
    view.set_right_margin(6)
    view.set_top_margin(4)
    view.set_bottom_margin(4)
    scroll = Gtk.ScrolledWindow(hexpand=True)
    scroll.set_min_content_height(height)
    scroll.set_child(view)
    scroll.add_css_class("frame")
    return view, scroll


def get_text(view):
    buf = view.get_buffer()
    return buf.get_text(buf.get_start_iter(), buf.get_end_iter(), False)


def get_lines(view):
    return [line.strip() for line in get_text(view).splitlines() if line.strip()]


def set_text(view, text):
    view.get_buffer().set_text(text)


def hint(text):
    lbl = Gtk.Label(label=text, xalign=0, wrap=True)
    lbl.set_max_width_chars(72)
    lbl.add_css_class("dim-label")
    return lbl


def alert(parent, message, detail=""):
    dlg = Gtk.AlertDialog()
    dlg.set_message(message)
    dlg.set_detail(detail)
    dlg.show(parent)


def choose(parent, message, detail, buttons, callback):
    """Диалог выбора; callback(индекс кнопки). Кнопка 0 — отмена."""
    dlg = Gtk.AlertDialog()
    dlg.set_message(message)
    dlg.set_detail(detail)
    dlg.set_buttons(buttons)
    dlg.set_cancel_button(0)
    dlg.set_default_button(0)

    def done(d, res):
        try:
            idx = d.choose_finish(res)
        except GLib.Error:
            idx = 0
        callback(idx)

    dlg.choose(parent, None, done)


def prompt(parent, title, label, callback, initial="", secret=False):
    """Окно ввода строки; callback(значение) вызывается только по OK."""
    win = Gtk.Window(title=title, transient_for=parent, modal=True)
    win.set_default_size(480, -1)
    box = margins(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10))
    box.append(Gtk.Label(label=label, xalign=0, wrap=True))
    entry = Gtk.PasswordEntry(show_peek_icon=True) if secret else Gtk.Entry(text=initial)
    entry.set_hexpand(True)
    box.append(entry)
    buttons = Gtk.Box(spacing=8, halign=Gtk.Align.END)
    cancel = Gtk.Button(label="Отмена")
    ok = Gtk.Button(label="OK")
    ok.add_css_class("suggested-action")
    buttons.append(cancel)
    buttons.append(ok)
    box.append(buttons)

    def finish(*_):
        value = entry.get_text()
        win.destroy()
        callback(value)

    ok.connect("clicked", finish)
    entry.connect("activate", finish)
    cancel.connect("clicked", lambda *_: win.destroy())
    win.set_child(box)
    win.present()
    entry.grab_focus()


def icon_button(icon, text, css=None, tooltip=None):
    """Кнопка «значок + подпись»; подпись меняется через set_button_text."""
    btn = Gtk.Button()
    line = Gtk.Box(spacing=6)
    line.append(Gtk.Image.new_from_icon_name(icon))
    btn.lbl = Gtk.Label(label=text)
    line.append(btn.lbl)
    btn.set_child(line)
    if css:
        btn.add_css_class(css)
    if tooltip:
        btn.set_tooltip_text(tooltip)
    return btn


def set_button_text(btn, text):
    btn.lbl.set_text(text)


def badge(text="", css=None):
    lbl = Gtk.Label(label=text)
    lbl.add_css_class("eb-badge")
    if css:
        lbl.add_css_class(css)
    return lbl


def card(css="eb-card", spacing=10):
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=spacing)
    box.add_css_class(css)
    return box


def toggle(title, subtitle=None):
    """Переключатель с подписью: (строка, Gtk.Switch)."""
    line = Gtk.Box(spacing=12)
    text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2, hexpand=True)
    text.append(Gtk.Label(label=title, xalign=0, wrap=True))
    if subtitle:
        text.append(hint(subtitle))
    sw = Gtk.Switch(valign=Gtk.Align.CENTER)
    line.append(text)
    line.append(sw)
    return line, sw


def section(title, subtitle=None):
    """Карточка раздела: (карточка, сетка внутри)."""
    box = card()
    lbl = Gtk.Label(label=title, xalign=0)
    lbl.add_css_class("eb-h2")
    box.append(lbl)
    if subtitle:
        box.append(hint(subtitle))
    grid = Gtk.Grid(column_spacing=12, row_spacing=8)
    box.append(grid)
    return box, grid


def expander_section(title, subtitle):
    """Свёрнутый по умолчанию раздел «для опытных»: (карточка, сетка внутри)."""
    box = card()
    exp = Gtk.Expander()
    head = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
    t = Gtk.Label(label=title, xalign=0)
    t.add_css_class("eb-h2")
    head.append(t)
    head.append(hint(subtitle))
    exp.set_label_widget(head)
    grid = Gtk.Grid(column_spacing=12, row_spacing=8, margin_top=12)
    exp.set_child(grid)
    box.append(exp)
    return box, grid


class Rows:
    """Добавление строк «подпись — виджет — подсказка» в сетку."""

    def __init__(self, grid):
        self.grid = grid
        self.r = 0

    def add(self, label, widget, note=None):
        made = []
        if label is not None:
            lbl = Gtk.Label(label=label, xalign=1, valign=Gtk.Align.START, margin_top=6, wrap=True)
            lbl.set_max_width_chars(24)
            self.grid.attach(lbl, 0, self.r, 1, 1)
            made.append(lbl)
        self.grid.attach(widget, 1, self.r, 1, 1)
        made.append(widget)
        self.r += 1
        if note:
            h = hint(note)
            self.grid.attach(h, 1, self.r, 1, 1)
            made.append(h)
            self.r += 1
        return made


def clear_children(box):
    child = box.get_first_child()
    while child is not None:
        nxt = child.get_next_sibling()
        box.remove(child)
        child = nxt


def show_all(widgets, visible):
    for w in widgets:
        w.set_visible(visible)
