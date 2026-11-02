"""Ссылки: очередь запросов, выбор браузера, привязка схем."""

import re
import subprocess
import threading
import urllib.parse

from ...cdp.http import cdp_listening
from ...core.link_handler import install_link_handler, link_handler_installed, remove_link_handler
from ...core.links import (
    browser_profiles_names,
    cdp_open_url,
    link_spool_pending,
    log_link_event,
    open_in_host_browser,
    open_link_in_env,
    parse_link,
    read_link_spool,
    safe_link_label,
)
from ...core.profile import Profile
from ...core.store import list_profiles, load_profile, save_profile
from ..gtk import GLib, Gtk, Pango
from ..widgets import alert, choose, hint, margins


class LinksMixin:
    """Ссылки: очередь запросов, выбор браузера, привязка схем."""

    # ------------------------------------- ссылки из приложений среды -> изолированный браузер

    def pick_link_browser(self, p):
        """Браузер для ссылок среды: выбранный ранее или единственный; иначе None (спросим)."""
        names = browser_profiles_names()
        if p is not None and p.link_browser in names:
            return p.link_browser
        return names[0] if len(names) == 1 else None

    def poll_links(self):
        try:
            for name in list_profiles():
                if not link_spool_pending(name):
                    continue
                try:
                    q = load_profile(name)
                except (OSError, ValueError):
                    continue
                reqs = read_link_spool(name)   # читает и очищает канал в любом случае
                if q.is_browser:
                    continue
                for url, err in reqs:
                    if err:
                        self.status(f"Среда «{name}» просила открыть ссылку, но она отклонена: {err}")
                    else:
                        self.link_queue.append((name, url))
            self.process_link_queue()
        except Exception:  # noqa: BLE001
            pass
        return True

    def process_link_queue(self):
        """Автоматические ссылки открываются сразу; вопросы показываются по одному, остальные ждут своей очереди."""
        waiting = []
        for name, url in self.link_queue:
            try:
                q = load_profile(name)
            except (OSError, ValueError):
                continue
            browser = self.pick_link_browser(q)
            if q.link_out_auto and browser:
                self.open_url_in_browser(browser, url)
                self.status(f"Среда «{name}» открыла ссылку в браузере «{browser}»")
                continue
            waiting.append((name, url, q))
        self.link_queue = [(n, u) for n, u, _q in waiting]
        if waiting and not self.link_dialog_open:
            name, url, q = waiting[0]
            self.link_queue = self.link_queue[1:]
            self.show_link_request(name, url, q)

    def remember_link_choice(self, name, browser, auto):
        """Запомнить браузер (и «не спрашивать») для среды; для выбранной среды — через её профиль в окне."""
        if self.current is not None and self.current.name == name:
            self.current.link_browser = browser or self.current.link_browser
            if auto:
                self.cb_link_auto.set_active(True)
            self.save_current(quiet=True)
            return
        try:
            q = load_profile(name)
            q.link_browser = browser or q.link_browser
            q.link_out_auto = q.link_out_auto or auto
            save_profile(q)
        except (OSError, ValueError):
            pass

    def show_link_request(self, name, url, q):
        self.link_dialog_open = True
        browsers = browser_profiles_names()
        host = urllib.parse.urlsplit(url).hostname or "?"
        win = Gtk.Window(title=f"Среда «{name}» просит открыть ссылку", transient_for=self, modal=True)
        win.set_default_size(640, -1)
        box = margins(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10), 16)
        title = Gtk.Label(label=f"Сайт: {host}", xalign=0)
        title.add_css_class("eb-h2")
        box.append(title)
        full = Gtk.Label(label=url, xalign=0, wrap=True, selectable=True)
        full.set_wrap_mode(Pango.WrapMode.CHAR)
        full.set_max_width_chars(80)
        full.add_css_class("monospace")
        box.append(full)
        box.append(hint("Ссылка придёт из программы внутри песочницы. Прочитайте адрес: подставные сайты "
                        "выглядят правдоподобно. Откроется в изолированном браузере, у которого своя сеть."))
        dd = None
        if browsers:
            box.append(Gtk.Label(label="В каком браузере открыть:", xalign=0))
            dd = Gtk.DropDown.new_from_strings(browsers)
            pre = q.link_browser if q.link_browser in browsers else browsers[0]
            dd.set_selected(browsers.index(pre))
            box.append(dd)
        else:
            box.append(hint("Нет среды-браузера: создайте её («Новая среда» → «Браузер») или скопируйте ссылку."))
        auto_cb = Gtk.CheckButton(label="Всегда открывать ссылки из этой среды без вопроса")
        if browsers:
            box.append(auto_cb)
        buttons = Gtk.Box(spacing=8, halign=Gtk.Align.END)
        reject = Gtk.Button(label="Отклонить")
        copy_btn = Gtk.Button(label="Копировать")
        open_btn = Gtk.Button(label="Открыть в браузере")
        open_btn.add_css_class("suggested-action")
        open_btn.set_sensitive(bool(browsers))
        buttons.append(reject)
        buttons.append(copy_btn)
        buttons.append(open_btn)
        box.append(buttons)
        state = {"done": False}

        def finish():
            if state["done"]:
                return
            state["done"] = True
            self.link_dialog_open = False
            GLib.idle_add(self.process_link_queue)

        def do_open(*_):
            browser = browsers[dd.get_selected()] if dd is not None and browsers else None
            if not browser:
                return
            self.remember_link_choice(name, browser, auto_cb.get_active())
            win.destroy()
            self.open_url_in_browser(browser, url)
            self.status(f"Ссылка из среды «{name}» открыта в браузере «{browser}»")
            finish()

        def do_copy(*_):
            self.set_clipboard(url)
            self.status("Ссылка скопирована")
            win.destroy()
            finish()

        def do_reject(*_):
            self.status(f"Ссылка из среды «{name}» отклонена")
            win.destroy()
            finish()

        open_btn.connect("clicked", do_open)
        copy_btn.connect("clicked", do_copy)
        reject.connect("clicked", do_reject)
        win.connect("close-request", lambda *_a: (finish(), False)[1])
        win.set_child(box)
        win.present()

    def open_url_in_browser(self, browser, url):
        """Открыть ссылку новой вкладкой в браузере-среде; запустить его, если не запущен; показать его окно."""
        try:
            url = parse_link(url)
        except ValueError as e:
            alert(self, "Ссылку нельзя открыть", str(e))
            return
        self.browser_show(browser)
        if cdp_listening(browser):
            self.finish_open_url(browser, url)
            return
        try:
            bp = load_profile(browser)
        except (OSError, ValueError) as e:
            alert(self, "Не удалось прочитать среду-браузер", str(e))
            return
        errs = bp.validate()
        if errs:
            alert(self, f"Браузер «{browser}» не готов к запуску", "\n".join(errs))
            return
        if browser not in self.running:
            self.launch_browser(bp)
        tries = {"n": 0}

        def wait_ready():
            tries["n"] += 1
            if cdp_listening(browser):
                self.finish_open_url(browser, url)
                return False
            if tries["n"] > 60:
                alert(self, "Браузер не запустился", f"«{browser}» не отозвался за 30 секунд. Смотрите launch.log среды.")
                return False
            return True

        GLib.timeout_add(500, wait_ready)

    def finish_open_url(self, browser, url):
        v = self.viewer
        if v is not None and self.viewer_env == browser:
            self.bg(lambda: v.new_tab(url))
        else:
            self.b_want_url = url            # откроется сразу после подключения окна к браузеру
            self.browser_connect(browser)
            if self.b_connecting is False and self.viewer is None:
                self.bg(lambda: cdp_open_url(browser, url))   # окно не подключилось: хотя бы открыть вкладку
                self.b_want_url = ""

    def browser_show(self, name):
        """Сделать браузер видимым: во вкладке, если она открыта, иначе в отдельном окне."""
        if self.b_detached is not None:
            if self.b_detached_env != name:
                self.browser_detach(name)
            else:
                self.b_detached.present()
            return
        cur = self.current
        if cur is not None and cur.is_browser and cur.name == name:
            try:
                self.nb.set_current_page(self.nb.page_num(self.page_browser))
            except Exception:  # noqa: BLE001
                pass
            return
        self.browser_detach(name)   # другая среда выбрана: не трогаем её, открываем браузер отдельным окном

    def open_term_link(self, term, text):
        """Ctrl+клик по ссылке в терминале: открыть в браузере (явное действие, без вопроса)."""
        try:
            url = parse_link(text)
        except ValueError as e:
            self.status(f"Ссылка не открыта: {e}")
            return
        env = self.term_entries.get(term, {}).get("env")
        try:
            q = load_profile(env) if env else None
        except (OSError, ValueError):
            q = None
        browser = self.pick_link_browser(q)
        if browser:
            self.open_url_in_browser(browser, url)
            self.status(f"Ссылка открыта в браузере «{browser}»")
        else:
            self.show_link_request(env or "терминал", url, q or Profile(name="x"))

    # ---------------------------------------------- ссылки в приложение внутри среды

    def link_envs(self):
        """Среды, принимающие ссылки (не браузеры)."""
        out = []
        for n in list_profiles():
            try:
                q = load_profile(n)
            except (OSError, ValueError):
                continue
            if not q.is_browser and (q.link_handler or q.link_callback):
                out.append(n)
        return out

    def on_open_link(self, *_):
        if self.current and not self.current.is_browser:
            self.save_current(quiet=True)
        envs = self.link_envs()
        if not envs:
            alert(self, "Нет среды, принимающей ссылки",
                  "Откройте «Настройки» среды-приложения и задайте «Команду открытия ссылок» "
                  "(для Claude Desktop она уже задана в шаблоне). Для входа в Claude CLI включите «Принимать вход "
                  "по ссылке localhost».")
            return
        win = Gtk.Window(title="Ссылка", transient_for=self, modal=True)
        win.set_default_size(660, -1)
        box = margins(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10), 16)
        box.append(hint("Вход в Claude Desktop по ссылке из письма (https://claude.ai/magic-link…): нажмите «В браузере "
                        "envbox». Страница предложит открыть приложение, envbox спросит и передаст ссылку Claude Desktop "
                        "внутри песочницы. Ссылки claude://… и http://localhost:…/ передавайте кнопкой «Передать "
                        "приложению»: обычную https-ссылку приложение само не понимает."))
        entry = Gtk.Entry(hexpand=True, placeholder_text="https://claude.ai/magic-link…   claude://…   http://localhost:…")
        box.append(entry)
        box.append(Gtk.Label(label="Среда с приложением:", xalign=0))
        labels = ["Подобрать по ссылке"] + envs
        dd = Gtk.DropDown.new_from_strings(labels)
        if self.current and self.current.name in envs:
            dd.set_selected(1 + envs.index(self.current.name))
        box.append(dd)
        note = hint("")
        box.append(note)
        buttons = Gtk.Box(spacing=8, halign=Gtk.Align.END)
        cancel = Gtk.Button(label="Отмена")
        send_btn = Gtk.Button(label="Передать приложению в среде")
        web_btn = Gtk.Button(label="В браузере компьютера")
        eb_browsers = browser_profiles_names()
        eb_btn = Gtk.Button(label="В браузере envbox")
        buttons.append(cancel)
        buttons.append(send_btn)
        buttons.append(web_btn)
        if eb_browsers:
            buttons.append(eb_btn)
        box.append(buttons)

        def selected_env():
            idx = dd.get_selected()
            return None if idx <= 0 else envs[idx - 1]

        def classify(text):
            t = text.strip()
            if not re.match(r"^https?://", t, re.I):
                return "app"
            host = (urllib.parse.urlsplit(t).hostname or "").lower() if len(t) < 2100 else ""
            return "app" if host in ("localhost", "127.0.0.1", "::1") else "web"

        def refresh(*_):
            kind = classify(entry.get_text())
            web_btn.set_visible(True)
            for btn, primary in ((eb_btn, kind == "web" and bool(eb_browsers)),
                                 (web_btn, kind == "web" and not eb_browsers), (send_btn, kind != "web")):
                if primary:
                    btn.add_css_class("suggested-action")
                else:
                    btn.remove_css_class("suggested-action")
            if kind == "web":
                note.set_text("Обычная веб-ссылка: откройте её в браузере. После входа он предложит открыть приложение "
                              "(claude://…), и envbox передаст это в песочницу. Если среда не запущена, она запустится сама. "
                              + ("Надёжнее всего — «В браузере envbox»: ссылку перехватывает сам envbox."
                                 if eb_browsers else "Среды-браузера нет: создайте её («Новая среда» → «Браузер»)."))
            else:
                note.set_text("Ссылка будет передана приложению внутри песочницы. Если среда не запущена, запустится "
                              "её приложение с этой ссылкой.")

        def prefill(clip, res):
            try:
                text = (clip.read_text_finish(res) or "").strip()
            except Exception:  # noqa: BLE001
                return
            if not entry.get_text() and 0 < len(text) <= 2048 and re.match(r"^[a-z][a-z0-9+.-]*://\S+$", text, re.I):
                entry.set_text(text)

        try:
            self.get_clipboard().read_text_async(None, prefill)
        except Exception:  # noqa: BLE001
            pass

        def to_env(*_):
            url = entry.get_text().strip()
            env = selected_env()
            win.destroy()
            self.send_link_to_env(url, env)

        def to_browser(*_):
            url = entry.get_text().strip()
            env = selected_env()
            win.destroy()
            self.open_link_in_browser(url, env)

        def to_envbox_browser(*_):
            raw = entry.get_text().strip()
            env = selected_env()
            try:
                url = parse_link(raw)
            except ValueError as e:
                alert(self, "Ссылку нельзя открыть", str(e))
                return
            try:
                q = load_profile(env) if env else None
            except (OSError, ValueError):
                q = None
            browser = self.pick_link_browser(q) or eb_browsers[0]
            win.destroy()
            self.open_url_in_browser(browser, url)
            log_link_event(safe_link_label(url), f"открыта в браузере envbox «{browser}»")
            self.status(f"Ссылка открыта в браузере envbox «{browser}»: страница предложит открыть приложение")

        entry.connect("changed", refresh)
        send_btn.connect("clicked", to_env)
        web_btn.connect("clicked", to_browser)
        eb_btn.connect("clicked", to_envbox_browser)
        entry.connect("activate", lambda *_a: ((to_envbox_browser() if eb_browsers else to_browser())
                                               if classify(entry.get_text()) == "web" else to_env()))
        cancel.connect("clicked", lambda *_a: win.destroy())
        refresh()
        win.set_child(box)
        win.present()
        entry.grab_focus()

    def send_link_to_env(self, url, env):
        """Передать ссылку приложению внутри среды (в потоке: ждёт ответа до 8 секунд)."""
        self.status("Передаю ссылку в среду…")

        def work():
            try:
                name, msg = open_link_in_env(url, env, True)
            except (ValueError, OSError, subprocess.SubprocessError) as e:
                GLib.idle_add(self.link_done, None, str(e))
            else:
                GLib.idle_add(self.link_done, name, msg)

        threading.Thread(target=work, daemon=True).start()

    def open_link_in_browser(self, url, env):
        """Открыть веб-ссылку в обычном браузере; перед этим убедиться, что ссылки claude:// из браузера дойдут до среды."""
        try:
            url = parse_link(url)
        except ValueError as e:
            alert(self, "Ссылку нельзя открыть", str(e))
            return
        unbound = []
        for n in ([env] if env else self.link_envs()):
            try:
                q = load_profile(n)
            except (OSError, ValueError):
                continue
            for sc in q.link_schemes:
                if sc not in unbound and not link_handler_installed(sc):
                    unbound.append(sc)

        def do_open(bind):
            if bind:
                try:
                    for sc in unbound:
                        install_link_handler(sc)
                except (ValueError, OSError, subprocess.SubprocessError) as e:
                    alert(self, "Не удалось связать ссылки со средой", str(e))
                    return
            try:
                tool = open_in_host_browser(url)
            except OSError as e:
                alert(self, "Не удалось открыть браузер", str(e))
                return
            log_link_event(safe_link_label(url), f"открыта в браузере ({tool})")
            self.status("Ссылка открыта в браузере. Подтвердите там открытие приложения: вход завершится в песочнице")
            try:
                self.update_bind_status()
            except Exception:  # noqa: BLE001
                pass

        if unbound:
            choose(self, "Ссылки claude:// пока не идут в песочницу",
                   "После входа браузер попробует открыть приложение по ссылке " +
                   ", ".join(f"{x}://" for x in unbound) +
                   ", но сейчас она не связана с envbox, и вход не завершится (одноразовый код пропадёт).\n\n"
                   "«Связать и открыть» меняет ассоциации вашего рабочего стола для этой схемы (отключается в «Настройках»).",
                   ["Отмена", "Открыть без привязки", "Связать и открыть"],
                   lambda idx: do_open(idx == 2) if idx in (1, 2) else None)
        else:
            do_open(False)

    def link_done(self, name, msg):
        if name is None:
            alert(self, "Не удалось передать ссылку", msg)
            self.status("Ссылка не передана")
        else:
            self.status(f"Среда «{name}»: {msg}")
            GLib.timeout_add(1500, self.refresh_sessions_once)
        return False

    def update_bind_status(self):
        schemes = self.e_link_schemes.get_text().replace(",", " ").split()
        self.btn_bind.set_visible(bool(schemes))
        if not schemes:
            self.lbl_bind.set_text("")
            return
        installed = [x for x in schemes if link_handler_installed(x)]
        if installed:
            self.btn_bind.set_label("Больше не открывать эти ссылки из браузера через envbox")
            self.lbl_bind.set_text("Сейчас ссылки " + ", ".join(f"{x}://" for x in installed) +
                                   " из браузера передаются envbox, а он отдаёт их среде с такой схемой "
                                   "(запущенной в первую очередь).")
        else:
            self.btn_bind.set_label("Открывать ссылки из браузера в этой среде")
            self.lbl_bind.set_text("Меняет ассоциации вашего рабочего стола: ссылки " +
                                   ", ".join(f"{x}://" for x in schemes) + " из браузера будут идти в envbox "
                                   "и дальше в приложение внутри среды. Можно отключить здесь же.")

    def on_bind_scheme(self, *_):
        schemes = self.e_link_schemes.get_text().replace(",", " ").split()
        if not schemes:
            return
        self.save_current(quiet=True)
        try:
            if all(link_handler_installed(x) for x in schemes):
                for x in schemes:
                    remove_link_handler(x)
                self.status("Обработчик ссылок отключён")
            else:
                notes = []
                for x in schemes:
                    _path, note = install_link_handler(x)
                    if note:
                        notes.append(note)
                self.status("Обработчик ссылок включён" + ((": " + " ".join(notes)) if notes else ""))
        except (ValueError, OSError, subprocess.SubprocessError) as e:
            alert(self, "Не удалось изменить обработчик ссылок", str(e))
        self.update_bind_status()
