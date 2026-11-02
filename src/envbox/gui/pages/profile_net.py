"""Настройки сети среды: секрет, прокси, подключение приложений, CDP."""

import subprocess

from ...cdp.http import cdp_listening
from ...core.browser import attach_snippets, cdp_socket_path
from ...core.consts import RESERVED_VARS, UPSTREAM_AUTH_VAR, VAR_RE
from ...core.keyring import secret_clear, secret_exists, secret_lookup, secret_store, secret_tool_available
from ...core.system import pkg_hint
from ...core.terminal import dry_run
from ...core.upstream import probe_upstream, read_proxy_file, split_proxy_url
from ..gtk import GLib, Gtk
from ..widgets import alert, get_lines, hint, margins, prompt, set_text, to_home


class ProfileNetMixin:
    """Настройки сети среды: секрет, прокси, подключение приложений, CDP."""

    # ---- секреты

    def update_secret_status(self):
        if not self.current or not self.current.secrets:
            self.lbl_secrets.set_text("Имена переменных, значения которых хранятся в системном keyring "
                                      "и передаются в среду при запуске.")
            return
        if not secret_tool_available():
            self.lbl_secrets.set_text("secret-tool не найден: " + pkg_hint("secret-tool"))
            return
        parts = []
        for s in self.current.secrets:
            try:
                ok = secret_exists(self.current.name, s)
            except (OSError, subprocess.SubprocessError):
                ok = False
            parts.append(f"{s}: {'в keyring ✔' if ok else 'не задан ✖'}")
        self.lbl_secrets.set_text("   ".join(parts))

    def on_set_secret(self, *_):
        if not self.current:
            return
        if not secret_tool_available():
            alert(self, "Нужен secret-tool", pkg_hint("secret-tool"))
            return
        names = get_lines(self.tv_secrets)
        name = self.current.name

        def got_var(var):
            var = var.strip()
            if (not VAR_RE.match(var) or var in RESERVED_VARS
                    or var.startswith("ENVBOX_")):
                alert(self, f"Недопустимое имя переменной: {var}")
                return

            def got_value(value):
                if not value:
                    return
                try:
                    secret_store(name, var, value)
                except (OSError, RuntimeError, subprocess.SubprocessError) as e:
                    alert(self, "Не удалось сохранить секрет", str(e))
                    return
                lines = get_lines(self.tv_secrets)
                if var not in lines:
                    lines.append(var)
                    set_text(self.tv_secrets, "\n".join(lines))
                self.save_current(quiet=True)
                self.update_secret_status()
                self.status(f"Секрет {var} сохранён в keyring")

            prompt(self, "Значение секрета",
                   f"Значение {var} для среды «{name}». Оно сохранится в системном keyring "
                   "и не попадёт ни в профиль, ни в командную строку.", got_value, secret=True)

        prompt(self, "Секрет", "Имя переменной окружения:", got_var,
               initial=names[0] if names else "ANTHROPIC_API_KEY")

    # ---- прокси

    def update_upstream_status(self):
        if not self.current:
            return
        if not self.current.upstream:
            self.lbl_up.set_text("Весь трафик идёт напрямую с этого компьютера. Один прокси на среду; "
                                 "списки и ротация не поддерживаются.")
        elif self.current.upstream_auth:
            self.lbl_up.set_text("Логин и пароль прокси хранятся в keyring. Имена сайтов разрешает сам "
                                 "прокси, а не этот компьютер.")
        else:
            self.lbl_up.set_text("Без логина. Имена сайтов разрешает сам прокси, а не этот компьютер.")

    def on_proxy_file(self, *_):
        dlg = Gtk.FileDialog(title="Файл с адресом прокси")

        def done(d, res):
            try:
                f = d.open_finish(res)
            except GLib.Error:
                return
            try:
                text = read_proxy_file(f.get_path())
                split_proxy_url(text)  # проверка формата
            except (OSError, ValueError) as e:
                alert(self, "Не удалось загрузить прокси", str(e))
                return
            self.e_upstream.set_text(text)
            self.status("Прокси загружен из файла; нажмите «Сохранить»")

        dlg.open(self, None, done)

    def on_proxy_test(self, *_):
        if not self.current:
            return
        try:
            url, auth = split_proxy_url(self.e_upstream.get_text())
        except ValueError as e:
            alert(self, "Адрес прокси неверен", str(e))
            return
        name = self.current.name
        if not auth and self.current.upstream_auth and secret_tool_available():
            try:
                auth = secret_lookup(name, UPSTREAM_AUTH_VAR)
            except (OSError, subprocess.SubprocessError):
                auth = ""
        self.status("Проверяю прокси…")

        def done(res):
            if isinstance(res, Exception):
                alert(self, "Проверка не удалась", str(res))
                return
            ok, msg = res
            self.status(msg if ok else "Прокси не работает")
            alert(self, "Прокси работает" if ok else "Прокси не работает", msg)

        self.run_async(lambda: probe_upstream(url, auth), done)

    def on_proxy_auth(self, *_):
        if not self.current:
            return
        if not secret_tool_available():
            alert(self, "Нужен secret-tool", pkg_hint("secret-tool"))
            return
        name = self.current.name

        def got(value):
            value = value.strip()
            try:
                if value:
                    if ":" not in value:
                        alert(self, "Нужен формат логин:пароль")
                        return
                    secret_store(name, UPSTREAM_AUTH_VAR, value)
                    self.current.upstream_auth = True
                else:
                    secret_clear(name, UPSTREAM_AUTH_VAR)
                    self.current.upstream_auth = False
            except (OSError, RuntimeError, subprocess.SubprocessError) as e:
                alert(self, "Не удалось обновить keyring", str(e))
                return
            self.save_current(quiet=True)
            self.update_upstream_status()
            self.status("Логин и пароль прокси сохранены в keyring" if value else "Логин и пароль прокси удалены")

        prompt(self, "Логин и пароль прокси",
               "В формате логин:пароль. Они хранятся в системном keyring, не в профиле и не в командной "
               "строке. Пустое значение удаляет сохранённые данные.", got, secret=True)

    # ---- браузер для ИИ

    def on_attach_add(self, *_):
        item = self.dd_browsers.get_selected_item()
        name = item.get_string() if item is not None else "—"
        if name == "—":
            alert(self, "Нет сред-браузеров",
                  "Создайте среду типа «Браузер» кнопкой «Новая», затем вернитесь сюда.")
            return
        lines = get_lines(self.tv_attach)
        if not any(l.split(":")[0] == name for l in lines):
            lines.append(name)
        set_text(self.tv_attach, "\n".join(lines))

    def show_snippets(self, spec, title):
        win = Gtk.Window(title=title, transient_for=self, modal=False)
        win.set_default_size(820, 420)
        box = margins(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10))
        box.append(hint("Команды выполняются внутри ИИ-среды (Claude Code хранит настройки MCP в её "
                        "домашнем каталоге). Для npx нужен доступ к registry.npmjs.org в списке сети. "
                        "Параметры MCP-серверов проверьте по их документации."))
        for label, text in attach_snippets(spec):
            box.append(Gtk.Label(label=label, xalign=0))
            line = Gtk.Box(spacing=6)
            entry = Gtk.Entry(text=text, editable=False, hexpand=True)
            copy = Gtk.Button(label="Копировать")

            def do_copy(_b, t=text):
                try:
                    self.get_clipboard().set_text(t)
                    self.status("Скопировано")
                except Exception as e:  # noqa: BLE001
                    alert(self, "Не удалось скопировать", str(e))

            copy.connect("clicked", do_copy)
            line.append(entry)
            line.append(copy)
            box.append(line)
        win.set_child(box)
        win.present()

    def on_attach_help(self, *_):
        lines = get_lines(self.tv_attach)
        if not lines:
            alert(self, "Сначала добавьте среду-браузер")
            return
        self.show_snippets(lines[0], f"Подключение ИИ к {lines[0].split(':')[0]}")

    def on_browser_help(self, *_):
        if self.current:
            self.show_snippets(self.current.name, f"Подключение ИИ к {self.current.name}")

    def update_cdp_label(self):
        if not self.current or not self.current.is_browser:
            return
        state = "слушает" if cdp_listening(self.current.name) else "браузер не запущен"
        self.lbl_cdp.set_text(f"{to_home(cdp_socket_path(self.current.name))}  —  {state}")

    def on_preview(self, *_):
        p = self.save_current(quiet=True)
        if p is None:
            return
        errs = p.validate()
        if errs:
            set_text(self.tv_preview, "Профиль не готов:\n" + "\n".join(errs))
            return
        try:
            rc, out = dry_run(p)
        except (OSError, subprocess.SubprocessError) as e:
            rc, out = 1, str(e)
        set_text(self.tv_preview, out if rc == 0 else f"[код {rc}]\n{out}")
