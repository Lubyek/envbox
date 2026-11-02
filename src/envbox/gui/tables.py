"""Таблицы и строки списков GUI."""

from .gtk import GObject, Gio, Gtk, Pango


class Row(GObject.Object):
    def __init__(self, cells, key=None, data=None):
        super().__init__()
        self.cells = cells
        self.key = key
        self.data = data


class Table:
    """ColumnView из строковых ячеек; при обновлении сохраняет выбор по ключу."""

    def __init__(self, titles, expand_col=0, empty_text="Пока пусто"):
        self.store = Gio.ListStore(item_type=Row)
        self.sel = Gtk.SingleSelection(model=self.store, autoselect=False, can_unselect=True)
        self.view = Gtk.ColumnView(model=self.sel, show_row_separators=True)
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

    def selected(self):
        return self.sel.get_selected_item()

    def set_rows(self, rows):
        cur = self.selected()
        key = cur.key if cur is not None else None
        self.store.splice(0, self.store.get_n_items(), rows)
        self.stack.set_visible_child_name("table" if rows else "empty")
        pos = Gtk.INVALID_LIST_POSITION
        for n, r in enumerate(rows):
            if key is not None and r.key == key:
                pos = n
                break
        self.sel.set_selected(pos)
