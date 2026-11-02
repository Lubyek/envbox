"""Таблицы и строки списков GUI."""

from .gtk import GObject, Gio, Gtk, Pango


class Row(GObject.Object):
    def __init__(self, cells, key=None, data=None):
        super().__init__()
        self.cells = cells
        self.key = key
        self.data = data


class Table:
    """ColumnView из строковых ячеек с выбором нескольких строк (Ctrl/Shift-клик, рамка); при обновлении
    сохраняет выбор по ключу."""

    def __init__(self, titles, expand_col=0, empty_text="Пока пусто"):
        self.store = Gio.ListStore(item_type=Row)
        self.sel = Gtk.MultiSelection(model=self.store)
        self.view = Gtk.ColumnView(model=self.sel, show_row_separators=True, enable_rubberband=True)
        for i, title in enumerate(titles):
            factory = Gtk.SignalListItemFactory()
            factory.connect("setup", self._setup)
            factory.connect("bind", self._bind, i)
            col = Gtk.ColumnViewColumn(title=title, factory=factory)
            col.set_expand(i == expand_col)
            col.set_resizable(True)
            self.view.append_column(col)
        scroll = Gtk.ScrolledWindow(vexpand=True, hexpand=True)
        scroll.set_child(self.view)
        scroll.add_css_class("frame")
        empty = Gtk.Label(label=empty_text, wrap=True, justify=Gtk.Justification.CENTER)
        empty.add_css_class("dim-label")
        self.stack = Gtk.Stack(vexpand=True, hexpand=True)
        self.stack.add_named(scroll, "table")
        self.stack.add_named(empty, "empty")
        self.widget = self.stack

    @staticmethod
    def _setup(_factory, item):
        lbl = Gtk.Label(xalign=0)
        lbl.set_ellipsize(Pango.EllipsizeMode.END)
        item.set_child(lbl)

    @staticmethod
    def _bind(_factory, item, i):
        item.get_child().set_text(item.get_item().cells[i])

    def selected_rows(self):
        """Все выбранные строки."""
        bits = self.sel.get_selection()
        return [self.sel.get_item(bits.get_nth(i)) for i in range(bits.get_size())]

    def selected(self):
        """Первая из выбранных строк или None."""
        rows = self.selected_rows()
        return rows[0] if rows else None

    def select_all(self):
        self.sel.select_all()

    def unselect_all(self):
        self.sel.unselect_all()

    def set_rows(self, rows):
        keys = {r.key for r in self.selected_rows() if r.key is not None}
        self.store.splice(0, self.store.get_n_items(), rows)
        self.stack.set_visible_child_name("table" if rows else "empty")
        self.sel.unselect_all()
        for n, r in enumerate(rows):
            if r.key is not None and r.key in keys:
                self.sel.select_item(n, False)
