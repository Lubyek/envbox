"""Запуск среды: терминал, браузер, установка программ, остановка."""

import subprocess

from ...core.consts import CDP_PORT
from ...core.isolation import INSTALL_RECIPES, recipe_placeholders, recipe_warning
from ...core.sessions import list_sessions, stop_session
from ...core.terminal import detect_terminal, launch_background, read_tail, terminal_argv
from ..consts import SHELL_COMMAND
from ..gtk import GLib, Gtk
from ..widgets import alert, choose, hint, margins, set_button_text, to_home, toggle


class LaunchMixin:
    """Запуск среды: терминал, браузер, установка программ, остановка."""

    def update_buttons(self):
        p = self.current
        has = p is not None
        is_browser = has and p.is_browser
        is_running = has and p.name in self.running
        self.lbl_toolbar.set_text(p.name if has else "")
        self.btn_shell.set_visible(has and not is_browser)
        self.btn_shell.set_sensitive(has)
        if has and not is_browser:
            set_button_text(self.btn_shell, f"Терминал ({p.shell_cmd})")
            self.btn_shell.set_tooltip_text(f"Оболочка внутри среды: {p.shell_cmd} (Ctrl+T)")
        self.btn_install.set_visible(has and not is_browser)
        self.btn_link.set_visible(has and not is_browser)
        set_button_text(self.btn_run, "Запустить браузер" if is_browser else "Запустить")
        if has:
            self.btn_run.set_tooltip_text(
                "Запустить браузер без окна (Ctrl+R)" if is_browser
                else f"Запустить в терминале: {p.command or '—'} (Ctrl+R)")
        self.btn_run.set_visible(has)
        self.btn_run.set_sensitive(has and not (is_browser and is_running))
        self.btn_stop.set_visible(has and is_running)

    def preflight(self):
        """Сохраняет и проверяет профиль; возвращает Profile или None."""
        p = self.save_current(quiet=True)
        if p is None:
            return None
        errs = p.validate()
        if errs:
            alert(self, "Профиль не готов к запуску", "\n".join(errs))
            return None
        return p

    def launch(self, command):
        if not self.current:
            return
        p = self.preflight()
        if p is None:
            return
        if command == SHELL_COMMAND:
            command = p.shell_cmd
        # Пробный запуск (dry-run) здесь не нужен: проверка профиля уже пройдена, а ошибки envbox
        # показывает прямо в терминале (для браузера — в окне после запуска). Это экономит ~0,2 с.
        if p.is_browser:
            self.launch_browser(p)
            return
        if self.use_embedded():
            self.open_embedded(p, command)
            return
        term = detect_terminal(self.settings)
        if not term:
            alert(self, "Не найден эмулятор терминала",
                  "Установите встроенный терминал (Arch: sudo pacman -S vte4) или укажите команду "
                  "внешнего терминала в настройках (кнопка с шестерёнкой).")
            return
        try:
            proc = subprocess.Popen(terminal_argv(term, p, command),
                                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, start_new_session=True)
        except OSError as e:
            alert(self, "Не удалось запустить терминал", f"{term[0]}: {e}")
            return
        self.procs.append(proc)
        self.status(f"Терминал для «{p.name}» запущен")
        GLib.timeout_add(1500, self.refresh_sessions_once)

    def on_install(self, *_):
        """Установка программ внутрь среды: отдельный терминал без проекта и секретов."""
        if not self.current or self.current.is_browser:
            return
        p = self.save_current(quiet=True)
        if p is None:
            return
        recipes = INSTALL_RECIPES
        win = Gtk.Window(title="Установка внутрь среды", transient_for=self, modal=True)
        win.set_default_size(680, -1)
        box = margins(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10), 16)
        box.append(hint("Откроется отдельный терминал этой среды. В нём нет вашего проекта и секретов, "
                        "а сеть открыта только на время установки. Программы ставятся в домашний каталог "
                        "среды и не могут выбраться за её пределы."))
        box.append(Gtk.Label(label="Что установить:", xalign=0))
        dd = Gtk.DropDown.new_from_strings([r["title"] for r in recipes])
        box.append(dd)
        note = hint("")
        box.append(note)
        box.append(Gtk.Label(label="Команда (можно поправить; Enter нажмёте в терминале):", xalign=0))
        entry = Gtk.Entry(hexpand=True)
        box.append(entry)
        line, only = toggle("Ограничить сеть сайтами рецепта",
                            "Выключено — сеть открыта на любые публичные сайты с журналом.")
        box.append(line)

        def refresh(*_):
            r = recipes[dd.get_selected()]
            entry.set_text(r["command"])
            sites = ", ".join(r["domains"]) if r["domains"] else "заранее неизвестны"
            warning = recipe_warning(r, p.name)
            note.set_text(r["note"] + "  Сайты: " + sites + "." + (("\n" + warning) if warning else ""))
            only.set_active(bool(r["domains"]))
            only.set_sensitive(bool(r["domains"]))

        dd.connect("notify::selected", refresh)
        refresh()
        buttons = Gtk.Box(spacing=8, halign=Gtk.Align.END)
        cancel = Gtk.Button(label="Отмена")
        ok = Gtk.Button(label="Открыть установочный терминал")
        ok.add_css_class("suggested-action")
        buttons.append(cancel)
        buttons.append(ok)
        box.append(buttons)

        def start(*_):
            r = recipes[dd.get_selected()]
            domains = list(r["domains"]) if (only.get_active() and r["domains"]) else []
            text = entry.get_text().strip()
            holes = recipe_placeholders(text)
            if holes:
                alert(win, "Заполните команду", "В ней остались места для подстановки: " + ", ".join(holes))
                return
            win.destroy()
            errs = p.install_view(domains).validate()
            if errs:
                alert(self, "Профиль не готов к установке", "\n".join(errs))
                return
            if self.use_embedded():
                self.open_embedded(p, "bash", install=True, feed=text, install_domains=domains)
                where = "только " + ", ".join(domains) if domains else "любые публичные сайты (с журналом)"
                self.status(f"Режим установки: нет проекта и секретов; сеть: {where}")
            else:
                term = detect_terminal(self.settings)
                if not term:
                    alert(self, "Не найден эмулятор терминала", "Установите vte4 или задайте терминал в настройках.")
                    return
                subprocess.Popen(terminal_argv(term, p, "bash", install=True, install_domains=domains),
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, start_new_session=True)
                try:
                    self.get_clipboard().set_text(text)
                except Exception:  # noqa: BLE001
                    pass
                self.status("Установочный терминал открыт; команда скопирована, вставьте её и нажмите Enter")

        ok.connect("clicked", start)
        cancel.connect("clicked", lambda *_: win.destroy())
        win.set_child(box)
        win.present()

    def launch_browser(self, p):
        if p.name in self.running:
            self.status(f"Браузер «{p.name}» уже запущен")
            return
        try:
            proc, log_path = launch_background(p)
        except (OSError, subprocess.SubprocessError) as e:
            alert(self, "Не удалось запустить браузер", str(e))
            return
        self.procs.append(proc)
        self.pending[p.name] = (proc, log_path)
        self.status(f"Браузер «{p.name}» запускается; CDP внутри ИИ-сред: http://127.0.0.1:{CDP_PORT}")
        self.b_manual_off = False
        if self.b_detached is None:
            try:
                self.nb.set_current_page(self.nb.page_num(self.page_browser))
            except Exception:  # noqa: BLE001
                pass
        GLib.timeout_add(2500, lambda: self.check_launch(p.name))
        GLib.timeout_add(1500, self.refresh_sessions_once)

    def check_launch(self, name):
        entry = self.pending.pop(name, None)
        if entry is None:
            return False
        proc, log_path = entry
        if proc.poll() is not None:
            tail = read_tail(log_path)
            alert(self, f"Браузер «{name}» завершился сразу после запуска",
                  (tail or "вывода нет") + f"\n\nЖурнал: {to_home(log_path)}\n"
                  "Частые причины: встроенная защита Chrome (sandbox) не запускается — снимите флажок "
                  "«Встроенная защита Chrome (sandbox)» на вкладке «Настройки»; или фильтр "
                  "системных вызовов мешает — см. «Изоляция». Если ваш Chrome не поддерживает режим "
                  "без окна на платформе ozone «headless», запустите envbox с переменной "
                  "ENVBOX_BROWSER_HEADLESS=new (прежний режим; сайты вроде Gmail его не принимают).")
        return False

    def on_stop_current(self, *_):
        if not self.current:
            return
        name = self.current.name
        sessions = [s for s in list_sessions() if s.name == name]
        if not sessions:
            self.status("Среда не запущена")
            return

        def done(idx):
            if idx != 1:
                return
            for s in sessions:
                try:
                    stop_session(s)
                except ProcessLookupError:
                    pass
                except OSError as e:
                    alert(self, "Не удалось остановить", str(e))
            GLib.timeout_add(700, self.refresh_sessions_once)
            self.status(f"Среда «{name}» остановлена")

        choose(self, f"Остановить среду «{name}»?",
               "Все процессы внутри среды будут завершены.", ["Отмена", "Остановить"], done)
