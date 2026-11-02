"""Глобальные папки и каталог данных."""

import os

from ...core.links import open_in_file_manager
from ...core.root import (
    GLOBAL_ENTRY_RE,
    create_global_folder,
    default_root,
    envbox_root,
    global_path,
    global_root,
    list_global_folders,
    reset_root_cache,
    root_error,
    set_root,
)
from ...core.rootops import delete_global_folder, global_folder_users, move_root
from ...core.sessions import list_sessions
from ...core.store import load_settings
from ..gtk import Gtk
from ..widgets import alert, card, choose, clear_children, hint, margins, prompt, show_all, to_home, toggle


class FoldersMixin:
    """Глобальные папки и каталог данных."""

    # ---- глобальные папки (на странице профиля)

    def update_global_visibility(self):
        show_all(self.global_widgets, self.cb_global.get_active())

    def refresh_global_rows(self, entries):
        """Список глобальных папок с отметками; entries — записи профиля «имя:режим»."""
        chosen = {}
        for g in entries:
            m = GLOBAL_ENTRY_RE.match(g)
            if m:
                chosen[m.group(1)] = m.group(2)
        clear_children(self.global_list)
        self.global_rows = {}
        names = list_global_folders()
        missing = [n for n in chosen if n not in names]
        if not names and not missing:
            self.global_list.append(hint("Глобальных папок пока нет: создайте первую кнопкой ниже."))
            return
        is_browser = bool(self.current and self.current.is_browser)
        for name in names + missing:
            line = Gtk.Box(spacing=8)
            chk = Gtk.CheckButton(label=name if name in names else f"{name} (папка не найдена)", hexpand=True)
            chk.set_active(name in chosen)
            dd = Gtk.DropDown.new_from_strings(["чтение и запись", "только чтение"])
            dd.set_selected(1 if chosen.get(name) == "ro" else 0)
            line.append(chk)
            line.append(dd)
            if name in names and not is_browser:
                b = Gtk.Button(label="Сделать проектом")
                b.connect("clicked", lambda _b, n=name: self.set_workdir_global(n))
                line.append(b)
            self.global_list.append(line)
            self.global_rows[name] = (chk, dd)

    def collect_global(self):
        out = []
        for name, (chk, dd) in self.global_rows.items():
            if chk.get_active():
                out.append(f"{name}:{'ro' if dd.get_selected() == 1 else 'rw'}")
        return out

    def set_workdir_global(self, name):
        self.e_workdir.set_text(to_home(global_path(name)))
        self.cb_nowd.set_active(False)
        self.cb_global.set_active(True)   # путь в глобальной папке требует включённых глобальных папок
        self.status(f"Каталог проекта: глобальная папка «{name}». Нажмите «Сохранить».")

    def on_global_create(self):
        def got(name):
            try:
                create_global_folder(name)
            except (OSError, ValueError) as e:
                alert(self, "Не удалось создать папку", str(e))
                return
            self.refresh_global_rows(self.collect_global())
            self.status(f"Глобальная папка «{name.strip()}» создана")

        prompt(self, "Новая глобальная папка", "Имя папки (латиница, цифры, «.», «_», «-»):", got)

    # ---- окно «Папки и каталог данных»

    def on_folders(self, *_):
        win = Gtk.Window(title="Папки и каталог данных", transient_for=self, modal=True)
        win.set_default_size(660, 600)
        outer = margins(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14), 16)

        root_box = card()
        t = Gtk.Label(label="Каталог данных", xalign=0)
        t.add_css_class("eb-h2")
        root_box.append(t)
        root_box.append(hint("Здесь лежат домашние каталоги сред, профили, журналы сети и глобальные папки."))
        lbl_root = Gtk.Label(xalign=0, wrap=True, selectable=True)
        root_box.append(lbl_root)
        lbl_note = hint("")
        root_box.append(lbl_note)
        move_line, move_sw = toggle(
            "Перенести существующие данные",
            "Среды, профили и глобальные папки переедут на новое место. Если выключить, на новом месте "
            "envbox начнёт с чистого листа, а старые данные останутся нетронутыми.")
        move_sw.set_active(True)
        root_box.append(move_line)
        rbtns = Gtk.Box(spacing=8)
        b_change = Gtk.Button(label="Изменить…")
        b_reset = Gtk.Button(label="Вернуть стандартный")
        b_open_root = Gtk.Button(label="Открыть")
        for b in (b_change, b_reset, b_open_root):
            rbtns.append(b)
        root_box.append(rbtns)
        outer.append(root_box)

        glob_box = card()
        t = Gtk.Label(label="Глобальные папки", xalign=0)
        t.add_css_class("eb-h2")
        glob_box.append(t)
        glob_box.append(hint(
            "Папки, которые не принадлежат ни одной среде. Удаление среды их не затрагивает, поэтому "
            "там удобно хранить код. Среде они доступны, только если включить «Глобальные папки» "
            "на вкладке «Настройки» и отметить нужные."))
        glist = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        gscroll = Gtk.ScrolledWindow(vexpand=True, min_content_height=160)
        gscroll.set_child(glist)
        glob_box.append(gscroll)
        gbtns = Gtk.Box(spacing=8)
        b_new = Gtk.Button(label="Создать папку…")
        b_open_glob = Gtk.Button(label="Открыть каталог глобальных папок")
        gbtns.append(b_new)
        gbtns.append(b_open_glob)
        glob_box.append(gbtns)
        outer.append(glob_box)

        close = Gtk.Button(label="Закрыть", halign=Gtk.Align.END)
        close.connect("clicked", lambda *_: win.destroy())
        outer.append(close)

        def refresh():
            root = envbox_root()
            lbl_root.set_text(to_home(root))
            env = os.environ.get("ENVBOX_ROOT", "").strip()
            if env:
                lbl_note.set_text("Задан переменной окружения ENVBOX_ROOT: пока она есть, выбор здесь не "
                                  "действует.")
            elif root == os.path.realpath(default_root()):
                lbl_note.set_text("Стандартное место.")
            else:
                lbl_note.set_text(f"Выбрано вами. Стандартное место: {to_home(default_root())}.")
            b_change.set_sensitive(not env)
            b_reset.set_sensitive(not env and root != os.path.realpath(default_root()))
            clear_children(glist)
            names = list_global_folders()
            if not names:
                glist.append(hint("Глобальных папок пока нет."))
            for name in names:
                users = global_folder_users(name)
                row = Gtk.Box(spacing=8)
                text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2, hexpand=True)
                text.append(Gtk.Label(label=name, xalign=0))
                text.append(hint("Использует: " + ", ".join(users) if users else "Пока никем не используется"))
                b_o = Gtk.Button(label="Открыть")
                b_o.connect("clicked", lambda _b, n=name: self.open_folder_path(global_path(n)))
                b_d = Gtk.Button(label="Удалить…")
                b_d.add_css_class("destructive-action")
                b_d.connect("clicked", lambda _b, n=name, u=users: delete_global(n, u))
                row.append(text)
                row.append(b_o)
                row.append(b_d)
                glist.append(row)

        def delete_global(name, users):
            def done(idx):
                if idx != 1:
                    return
                try:
                    delete_global_folder(name)
                except (OSError, ValueError) as e:
                    alert(win, "Не удалось удалить папку", str(e))
                    return
                refresh()
                self.refresh_global_rows(self.collect_global())
                self.status(f"Глобальная папка «{name}» удалена")

            extra = ("\nЕё используют среды: " + ", ".join(users) + ". Они потеряют эту папку." if users else "")
            choose(win, f"Удалить глобальную папку «{name}»?",
                   f"Всё содержимое {to_home(global_path(name))} будет удалено без возможности "
                   "восстановления." + extra, ["Отмена", "Удалить навсегда"], done)

        def create():
            def got(name):
                try:
                    create_global_folder(name)
                except (OSError, ValueError) as e:
                    alert(win, "Не удалось создать папку", str(e))
                    return
                refresh()
                self.refresh_global_rows(self.collect_global())

            prompt(win, "Новая глобальная папка", "Имя папки (латиница, цифры, «.», «_», «-»):", got)

        def pick_root():
            self.choose_folder(lambda path: self.apply_new_root(path, move_sw.get_active(), refresh))

        b_change.connect("clicked", lambda *_: pick_root())
        b_reset.connect("clicked", lambda *_: self.apply_new_root("", move_sw.get_active(), refresh))
        b_open_root.connect("clicked", lambda *_: self.open_folder_path(envbox_root()))
        b_new.connect("clicked", lambda *_: create())
        b_open_glob.connect("clicked", lambda *_: self.open_folder_path(global_root(), create=True))
        refresh()
        win.set_child(outer)
        win.present()

    def open_folder_path(self, path, create=False):
        try:
            if create:
                os.makedirs(path, mode=0o700, exist_ok=True)
            open_in_file_manager(path)
        except OSError as e:
            alert(self, "Не удалось открыть папку", str(e))

    def apply_new_root(self, new, move, after=None):
        """Сменить каталог данных (new пусто — стандартный); move — перенести существующие данные."""
        if os.environ.get("ENVBOX_ROOT", "").strip():
            alert(self, "Каталог задан переменной ENVBOX_ROOT",
                  "Пока переменная задана, выбор в приложении не действует: уберите её и перезапустите envbox.")
            return
        old = envbox_root()
        target = os.path.realpath(os.path.expanduser(new)) if new else os.path.realpath(default_root())
        if target == old:
            self.status("Каталог данных уже там")
            return
        err = root_error(target)
        if err:
            alert(self, "Этот каталог не подходит", f"{to_home(target)}: {err}")
            return
        if any(True for _ in list_sessions()):
            alert(self, "Есть запущенные среды", "Остановите все среды и повторите.")
            return
        if move and os.path.isdir(target) and os.listdir(target):
            alert(self, "Каталог не пуст", f"{to_home(target)}: для переноса нужен пустой или новый каталог. "
                                           "Выберите другой или выключите «Перенести существующие данные».")
            return
        what = (f"Данные будут перенесены из {to_home(old)} в {to_home(target)}." if move else
                f"envbox начнёт работать в {to_home(target)} с чистого листа; данные в {to_home(old)} "
                "останутся нетронутыми, среды из них не будут видны.")

        def go(idx):
            if idx != 1:
                return
            self.save_current(quiet=True)
            if hasattr(self, "browser_disconnect"):
                try:
                    self.browser_disconnect()
                except Exception:  # noqa: BLE001 — просмотр браузера не должен мешать смене каталога
                    pass

            def work():
                if move:
                    move_root(old, target)
                set_root("" if target == os.path.realpath(default_root()) else target)

            def done(res):
                reset_root_cache()
                if isinstance(res, Exception):
                    alert(self, "Не удалось сменить каталог данных", str(res))
                    return
                self.settings = load_settings()
                self.current = None
                self.reload_profiles()
                self.refresh_sessions()
                if after:
                    after()
                self.status(f"Каталог данных: {to_home(envbox_root())}")

            self.status("Меняю каталог данных…")
            self.run_async(work, done)

        choose(self, "Сменить каталог данных?", what + "\nЗапущенных сред быть не должно.",
               ["Отмена", "Сменить"], go)
