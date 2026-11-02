"""Профиль среды (dataclass Profile) и его проверка."""

import ipaddress
import os
import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field, fields

from .browser import browser_command, browser_mounts, find_browser, host_program_in_home
from .consts import (
    ATTACH_RE,
    CDP_PORT,
    CLAUDE_DESKTOP_DOMAINS,
    CLAUDE_DOMAINS,
    DOMAIN_RE,
    KINDS,
    LANG_RE,
    NAME_RE,
    NET_MODES,
    OLD_CLAUDE_DESKTOP_DOMAINS,
    OLD_CLAUDE_DESKTOP_DOMAINS_V2,
    OLD_CLAUDE_DOMAINS,
    RESERVED_VARS,
    SCHEME_RE,
    SHELLS,
    TZ_RE,
    UPSTREAM_AUTH_VAR,
    VAR_RE,
)
from .fsutil import _is_under
from .isolation import ISO_KEYS, ISO_OPTIONS, ISO_PRESETS, ISO_RISKY_DEFAULT
from .root import GLOBAL_ENTRY_RE, box_dir, envbox_root, global_path, global_root
from .system import pkg_hint
from .upstream import split_proxy_url
from .vpn import vpn_source


@dataclass
class Profile:
    name: str
    workdir: str = ""
    command: str = "bash"
    net: str = "log"
    allow_domains: list = field(default_factory=list)
    net_allow_private: bool = False
    direct_domains: list = field(default_factory=list)  # сайты, к которым прокси envbox идёт напрямую, мимо upstream
    env: list = field(default_factory=lambda: ["LANG", "COLORTERM"])
    secrets: list = field(default_factory=list)
    ro: list = field(default_factory=list)
    rw: list = field(default_factory=list)              # дополнительные папки компьютера с записью (для любой среды)
    global_on: bool = False                             # глобальные папки разрешены этой среде (по умолчанию выкл.)
    global_folders: list = field(default_factory=list)  # подключаемые глобальные папки: «имя:ro» или «имя:rw»
    path: list = field(default_factory=list)
    ephemeral: bool = False
    protect_git: bool = True
    allow_userns: bool = False
    kind: str = "app"
    upstream: str = ""
    upstream_auth: bool = False
    # Каналы выхода по порядку: «proxy» (поле upstream), «vpn:<имя>» (вкладка VPN), «direct» (выход этого компьютера,
    # в том числе через его системный VPN). Пусто — как раньше: один прокси или прямой выход.
    upstream_chain: list = field(default_factory=list)
    attach: list = field(default_factory=list)
    browser_bin: str = ""
    browser_start_url: str = "about:blank"
    browser_visible: bool = False
    browser_chrome_sandbox: bool = True
    lang: str = ""
    timezone: str = ""
    dns: list = field(default_factory=list)
    isolation: dict = field(default_factory=dict)
    host_files: str = ""
    host_confirmed: bool = False
    no_workdir: bool = False
    expose_ports: list = field(default_factory=list)
    install_domains: list = field(default_factory=list)
    gui_wayland: bool = False
    shell: str = ""
    link_handler: str = ""            # команда внутри среды, которой передаётся ссылка (например claude-desktop)
    link_schemes: list = field(default_factory=list)   # схемы ссылок приложения, например claude (claude://…)
    link_callback: bool = False       # принимать http://localhost:порт/… и выполнять запрос внутри среды (вход в CLI)
    link_browser: str = ""            # браузер (среда), в котором открываются ссылки из этой среды
    link_out_auto: bool = False       # открывать ссылки из этой среды в браузере без вопроса

    @classmethod
    def codex_preset(cls, name):
        """Шаблон для Codex и других ИИ-агентов: сеть через прокси с журналом, ключ — секрет."""
        return cls(name=name, command="codex", net="log", env=["LANG", "COLORTERM"],
                   secrets=["OPENAI_API_KEY"])

    @classmethod
    def claude_desktop_preset(cls, name):
        """Claude Desktop (Electron) в песочнице: окно через Wayland, сеть только к доменам Claude, без проекта."""
        return cls(name=name, command="claude-desktop", net="allowlist",
                   allow_domains=list(CLAUDE_DESKTOP_DOMAINS),
                   no_workdir=True, gui_wayland=True, protect_git=False, env=["LANG", "COLORTERM"],
                   link_handler="claude-desktop", link_schemes=["claude"])

    @classmethod
    def service_preset(cls, name):
        """Приложение-сервис для ИИ (например Blender): без сети; порты открываются только подключённым средам."""
        return cls(name=name, command="bash", net="off")

    def install_view(self, domains=None):
        """Профиль на время установки: без проекта, секретов, браузеров и открытых портов.
        Сеть: только перечисленные сайты, а если список пуст — любые публичные адреса с журналом."""
        import copy
        q = copy.deepcopy(self)
        q.no_workdir = True
        q.secrets, q.attach, q.expose_ports = [], [], []
        q.rw, q.global_on = [], False   # на время установки чужие папки не нужны
        q.gui_wayland = False
        q.link_handler, q.link_schemes, q.link_callback = "", [], False
        q.env = [e for e in self.env if e.split("=", 1)[0] in ("LANG", "COLORTERM")]
        q.net_allow_private = False
        q.command = "bash"
        sites = list(self.install_domains if domains is None else domains)
        if sites:
            q.net, q.allow_domains = "allowlist", sites
        else:
            q.net, q.allow_domains = "log", []
        return q

    @classmethod
    def claude_preset(cls, name):
        """Шаблон «Claude CLI, жёсткая изоляция»: только домены Anthropic, без лишнего трафика."""
        return cls(name=name, command="claude", net="allowlist",
                   allow_domains=list(CLAUDE_DOMAINS),
                   env=["LANG", "COLORTERM", "DISABLE_TELEMETRY=1", "DISABLE_AUTOUPDATER=1",
                        "DISABLE_ERROR_REPORTING=1", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1"],
                   link_callback=True)

    @classmethod
    def from_dict(cls, d):
        p = cls(name=str(d.get("name", "")))
        for f in fields(cls):
            if f.name == "name" or f.name not in d:
                continue
            v, default = d[f.name], getattr(p, f.name)
            if isinstance(default, bool):
                setattr(p, f.name, bool(v))
            elif isinstance(default, list):
                setattr(p, f.name, [str(x) for x in v] if isinstance(v, list) else default)
            elif isinstance(default, dict):
                setattr(p, f.name, {str(k): bool(x) for k, x in v.items() if str(k) in ISO_KEYS}
                        if isinstance(v, dict) else {})
            else:
                setattr(p, f.name, str(v))
        if d.get("strict") is False and "isolation" not in d:  # профиль старой версии: «мягкий режим»
            p.isolation = {"host_net_forbidden": False, "seccomp": False, "neutral_dns": False}
        if p.net not in NET_MODES:
            p.net = "log"
        if p.net == "allowlist" and p.allow_domains == OLD_CLAUDE_DOMAINS:
            p.allow_domains = list(CLAUDE_DOMAINS)   # старый пресет не пускал обновление токена на claude.com
        if (p.net == "allowlist" and p.link_handler == "claude-desktop"
                and p.allow_domains in (list(CLAUDE_DOMAINS), OLD_CLAUDE_DOMAINS, OLD_CLAUDE_DESKTOP_DOMAINS,
                                        OLD_CLAUDE_DESKTOP_DOMAINS_V2)):
            p.allow_domains = list(CLAUDE_DESKTOP_DOMAINS)   # пресет Claude Desktop без bridge, hCaptcha, Google
        if p.kind not in KINDS:
            p.kind = "app"
        return p

    def iso_on(self, key):
        """True, если защита `key` включена (для home_real: True — настоящий домашний каталог)."""
        opt = next((o for o in ISO_OPTIONS if o["key"] == key), None)
        if opt is None:
            return bool(self.isolation.get(key, ISO_RISKY_DEFAULT.get(key, True)))
        if opt["store"] == "iso":
            return bool(self.isolation.get(key, True))
        value = bool(getattr(self, opt["store"]))
        return (not value) if opt.get("invert") else value

    def iso_set(self, key, on):
        opt = next((o for o in ISO_OPTIONS if o["key"] == key), None)
        if opt is None or opt["store"] == "iso":
            default = ISO_RISKY_DEFAULT.get(key, True)
            if bool(on) == default:
                self.isolation.pop(key, None)
            else:
                self.isolation[key] = bool(on)
            return
        setattr(self, opt["store"], (not on) if opt.get("invert") else bool(on))

    def apply_iso_preset(self, name):
        preset = next(pr for pr in ISO_PRESETS if pr[0] == name)[3]
        for opt in ISO_OPTIONS:
            if opt.get("presets", True):
                self.iso_set(opt["key"], preset.get(opt["key"], True))

    def detect_iso_preset(self):
        """Имя набора, если защиты совпадают с ним, иначе 'custom'."""
        for name, _title, _text, preset in ISO_PRESETS:
            if all(self.iso_on(o["key"]) == preset.get(o["key"], True)
                   for o in ISO_OPTIONS if o.get("presets", True)):
                return name
        return "custom"

    def isolation_summary(self):
        """(короткий текст, предупреждение?) для метки в обзоре."""
        if self.host_files or self.iso_on("home_real"):
            return "⚠ доступ к компьютеру", True
        off = [o for o in ISO_OPTIONS if o["warn_off"] and not self.iso_on(o["key"])
               and not (self.is_browser and (o.get("app_only")
                                             or (o["key"] == "no_userns" and self.browser_chrome_sandbox)))]
        if not off:
            return "максимальная изоляция", False
        return f"изоляция: выключено защит — {len(off)}", True

    @property
    def is_browser(self):
        return self.kind == "browser"

    @property
    def shell_cmd(self):
        """Оболочка для кнопки «Терминал»."""
        return self.shell if self.shell in SHELLS else "bash"

    def wrapper_secrets(self):
        """Переменные, которые обёртка достаёт из keyring для envbox.sh (не все уходят в среду)."""
        return list(self.secrets) + ([UPSTREAM_AUTH_VAR] if self.upstream_auth and self.uses_proxy else [])

    @property
    def chain_on(self):
        """Цепочка каналов действует (задана и сеть идёт через прокси envbox)."""
        return bool(self.upstream_chain) and self.net in ("log", "allowlist")

    @property
    def uses_proxy(self):
        """Свой прокси участвует в выходе: задан и не исключён из цепочки."""
        return bool(self.upstream) and (not self.chain_on or "proxy" in self.upstream_chain)

    @property
    def has_remote(self):
        """Есть канал, за которым имена разрешает не этот компьютер (прокси или VPN)."""
        return self.uses_proxy or (self.chain_on and any(c.startswith("vpn:") for c in self.upstream_chain))

    def chain_specs(self):
        """Каналы для шлюза: proxy, direct, vpn:<вид>:<путь>. ValueError, если VPN не найден."""
        out = []
        for item in self.upstream_chain:
            if item.startswith("vpn:"):
                kind, path = vpn_source(item[4:])
                out.append(f"vpn:{kind}:{path}")
            else:
                out.append(item)
        return out

    def validate(self):
        """Список ошибок на русском; пустой список — профиль готов к запуску."""
        err = []
        if not NAME_RE.match(self.name):
            err.append(f"недопустимое имя профиля: '{self.name}'")
        if self.is_browser:
            if self.net == "host":
                err.append("браузер нельзя запускать с сетью хоста: выберите режим через журнал или «Выключена»")
            if self.browser_bin:
                if not os.path.isabs(self.browser_bin) or not os.access(self.browser_bin, os.X_OK):
                    err.append(f"браузер не найден или не исполняемый: {self.browser_bin}")
            elif not find_browser():
                err.append("не найден Chrome/Chromium (google-chrome-stable, chromium…): "
                           "установите его или укажите путь в профиле")
            real = os.path.realpath(self.browser_bin or find_browser() or "/")
            if real.startswith(("/snap/", "/var/lib/flatpak/")):
                err.append("snap- и flatpak-версии браузера не подходят: у них свой sandbox; "
                           "установите пакет из репозитория или с сайта Google")
            if (not self.browser_start_url.strip() or any(c.isspace() for c in self.browser_start_url)
                    or self.browser_start_url.strip().startswith("-")):
                err.append("стартовая страница должна быть одним адресом без пробелов и не начинаться с «-»")
        else:
            if self.shell and self.shell not in SHELLS:
                err.append(f"оболочка '{self.shell}' не поддерживается (bash, fish, zsh)")
            elif self.shell_cmd != "bash" and not shutil.which(self.shell_cmd):
                err.append(f"оболочка {self.shell_cmd} не установлена на компьютере: {pkg_hint(self.shell_cmd)}")
            wd = os.path.expanduser(self.workdir)
            if self.no_workdir:
                pass
            elif not self.workdir:
                err.append("не выбран рабочий каталог (или включите «Без каталога проекта»)")
            elif not os.path.isdir(wd):
                err.append(f"рабочий каталог не существует: {self.workdir}")
            try:
                if not shlex.split(self.command):
                    err.append("не задана команда")
            except ValueError as e:
                err.append(f"ошибка в команде: {e}")
        if self.iso_on("host_net_forbidden") and self.net == "host":
            err.append("сеть компьютера запрещена защитой «Запретить сеть компьютера»: выберите режим через "
                       "прокси или выключите эту защиту на вкладке «Изоляция»")
        if self.iso_on("home_real") and not self.host_confirmed:
            err.append("настоящий домашний каталог не подтверждён")
        if self.host_files:
            if self.host_files not in ("ro", "rw"):
                err.append(f"доступ к компьютеру: недопустимое значение '{self.host_files}'")
            elif not self.host_confirmed:
                err.append("доступ к файлам компьютера не подтверждён")
            if self.net == "host":
                err.append("доступ к файлам компьютера несовместим с сетью компьютера")
        for port in self.expose_ports:
            if not (port.isdigit() and 0 < int(port) < 65536):
                err.append(f"порт для других сред '{port}': нужно число от 1 до 65535")
        if self.expose_ports and self.net == "host":
            err.append("открывать порты другим средам можно только при сети через прокси или без сети")
        for d in self.install_domains:
            if not DOMAIN_RE.match(d):
                err.append(f"сайт для установки: недопустимый домен '{d}'")
        if self.lang and not LANG_RE.match(self.lang):
            err.append(f"язык: недопустимая локаль '{self.lang}' (пример: ru_RU.UTF-8)")
        if self.timezone and not timezone_exists(self.timezone):
            err.append(f"часовой пояс '{self.timezone}' не найден в /usr/share/zoneinfo (пример: Europe/Moscow)")
        for d in self.dns:
            try:
                ipaddress.ip_address(d)
            except ValueError:
                err.append(f"DNS: '{d}' — не IP-адрес")
        if self.dns:
            if self.net == "off":
                err.append("DNS не нужен без сети: уберите серверы или включите сеть")
            elif self.has_remote and self.net in ("log", "allowlist"):
                err.append("DNS-серверы несовместимы с вышестоящим прокси и VPN: имена разрешает он")
        if self.upstream:
            try:
                split_proxy_url(self.upstream, allow_auth=False)
            except ValueError as e:
                err.append(f"прокси: {e}")
            if self.net not in ("log", "allowlist"):
                err.append("вышестоящий прокси работает только в режимах сети «через журнал»")
        if self.upstream_chain:
            if self.net not in ("log", "allowlist"):
                err.append("цепочка выхода работает только в режимах сети «через журнал»")
            seen = set()
            for item in self.upstream_chain:
                if item in seen:
                    err.append(f"цепочка выхода: «{item}» указан дважды")
                seen.add(item)
                if item == "proxy":
                    if not self.upstream:
                        err.append("цепочка выхода: есть «proxy», но свой прокси не задан")
                elif item == "direct":
                    pass
                elif item.startswith("vpn:"):
                    try:
                        vpn_source(item[4:])
                    except ValueError as e:
                        err.append(f"цепочка выхода: {e}")
                else:
                    err.append(f"цепочка выхода: неизвестный канал '{item}' (proxy, direct или vpn:имя)")
        for spec in self.attach:
            m = ATTACH_RE.match(spec)
            if not m:
                err.append(f"подключение браузера: недопустимый формат '{spec}' (среда[:порт[:локальный порт]])")
                continue
            if m.group(1) == self.name:
                err.append("среда не может подключаться к самой себе")
            elif not os.path.isdir(box_dir(m.group(1))):
                err.append(f"подключение браузера: среда '{m.group(1)}' не найдена")
            for g in (m.group(2), m.group(3)):
                if g and not 0 < int(g) < 65536:
                    err.append(f"подключение браузера: недопустимый порт в '{spec}'")
        for sc in self.link_schemes:
            if not SCHEME_RE.match(sc) or sc in ("http", "https", "file", "ftp", "mailto"):
                err.append(f"схема ссылок «{sc}» не подходит (строчные латинские буквы и цифры; не http, https, file, ftp, mailto)")
        if self.link_schemes and not self.link_handler:
            err.append("схемы ссылок заданы, а команды открытия ссылок нет: приложению нечем их открыть")
        if self.link_handler:
            try:
                if not shlex.split(self.link_handler):
                    err.append("пустая команда открытия ссылок")
            except ValueError:
                err.append("команда открытия ссылок: незакрытые кавычки")
        if (self.attach or self.is_browser) and self.net == "host":
            err.append("подключение браузера требует режим сети не «общая с хостом»")
        if self.net == "allowlist" and not self.allow_domains:
            err.append("режим «только разрешённые домены», но список доменов пуст")
        for d in self.allow_domains:
            if not DOMAIN_RE.match(d):
                err.append(f"недопустимый домен: '{d}'")
        for d in self.direct_domains:
            if not DOMAIN_RE.match(d):
                err.append(f"сайт для прямого доступа: недопустимый домен '{d}'")
        for e in self.env:
            key = e.split("=", 1)[0]
            if not VAR_RE.match(key) or key in RESERVED_VARS or key.startswith("ENVBOX_"):
                err.append(f"недопустимая переменная окружения: '{e}'")
        for s in self.secrets:
            if not VAR_RE.match(s) or s in RESERVED_VARS or s.startswith("ENVBOX_"):
                err.append(f"недопустимое имя секрета: '{s}'")
        env_keys = {e.split("=", 1)[0] for e in self.env}
        for s in self.secrets:
            if s in env_keys:
                err.append(f"{s} указан и в переменных, и в секретах")
        for r in self.ro:
            if not os.path.exists(os.path.expanduser(r)):
                err.append(f"путь только для чтения не существует: {r}")
        for r in self.rw:
            if not os.path.isdir(os.path.expanduser(r)):
                err.append(f"папка с записью не существует или не каталог: {r}")
        seen_global = set()
        for g in self.global_folders:
            m = GLOBAL_ENTRY_RE.match(g)
            if not m:
                err.append(f"глобальная папка: недопустимая запись '{g}' (нужно имя:ro или имя:rw)")
            elif m.group(1) in seen_global:
                err.append(f"глобальная папка «{m.group(1)}» указана дважды")
            else:
                seen_global.add(m.group(1))
                if self.global_on and not os.path.isdir(global_path(m.group(1))):
                    err.append(f"глобальная папка «{m.group(1)}» не найдена: {global_path(m.group(1))}")
        # пути в каталоге данных: свои среды недоступны никогда, глобальные папки — только если включены
        groot = os.path.normpath(global_root())
        data = os.path.normpath(envbox_root())
        checked = [("рабочий каталог", self.workdir)] if not (self.is_browser or self.no_workdir) else []
        checked += [("путь только для чтения", x) for x in self.ro] + [("папка с записью", x) for x in self.rw]
        for label, v in checked:
            if not v:
                continue
            full = os.path.normpath(os.path.expanduser(v))
            in_global = full.startswith(groot + os.sep)
            if in_global and not self.global_on:
                err.append(f"{label} «{v}» лежит среди глобальных папок: включите «Глобальные папки» для этой среды")
            elif not in_global and (_is_under(full, data) or _is_under(data, full)):
                err.append(f"{label} «{v}» пересекается с каталогом данных envbox ({data}): "
                           "для общих данных используйте глобальные папки")
        for p in self.path:
            if not os.path.expanduser(p).startswith("/") or ":" in p:
                err.append(f"каталог PATH должен быть абсолютным и без ':': {p}")
        return err

    def envbox_args(self, command=None):
        """Аргументы для envbox.sh (без самого скрипта)."""
        a = ["-n", self.name, "--root", envbox_root()]
        if self.is_browser or self.no_workdir:
            a.append("--no-workdir")
        else:
            a += ["-w", os.path.expanduser(self.workdir)]
        if self.net == "off":
            a.append("--no-net")
        elif self.net == "log":
            a.append("--net-log")
        elif self.net == "allowlist":
            for d in self.allow_domains:
                a += ["--allow-domain", d]
        if self.uses_proxy and self.net in ("log", "allowlist"):
            a += ["--upstream", self.upstream]
        if self.chain_on:
            for spec in self.chain_specs():
                a += ["--chain", spec]
        if self.has_remote and self.net in ("log", "allowlist"):
            for d in self.direct_domains:
                a += ["--direct-domain", d]
        if self.lang:
            a += ["--lang", self.lang]
        if self.timezone:
            a += ["--timezone", self.timezone]
        for d in self.dns:
            a += ["--dns", d]
        if self.net_allow_private and self.net in ("log", "allowlist"):
            a.append("--net-allow-private")
        for e in self.env + self.secrets:
            a += ["--env", e]
        ro = [os.path.expanduser(r) for r in self.ro]
        if self.is_browser:
            for d in browser_mounts(self.browser_bin or find_browser()):
                if d not in ro:
                    ro.append(d)
            a += ["--expose-port", str(CDP_PORT)]
            if self.browser_visible:
                a.append("--wayland")
        else:
            for port in self.expose_ports:
                a += ["--expose-port", str(int(port))]
            if self.gui_wayland:
                a.append("--wayland")
        for r in ro:
            a += ["--ro", r]
        for r in self.rw:
            a += ["--rw", os.path.expanduser(r)]
        if self.global_on:
            for g in self.global_folders:
                if GLOBAL_ENTRY_RE.match(g):
                    a += ["--global", g]
        for p in self.path:
            a += ["--path", os.path.expanduser(p)]
        for spec in self.attach:
            a += ["--attach", spec]
        if self.ephemeral:
            a.append("--ephemeral")
        if not self.protect_git:
            a.append("--no-protect-git")
        if self.allow_userns or (self.is_browser and self.browser_chrome_sandbox):
            a.append("--allow-userns")
        if not self.is_browser:
            if self.link_handler:
                a += ["--inbox-cmd", self.link_handler]
                for sc in self.link_schemes:
                    a += ["--inbox-scheme", sc]
            if self.link_callback:
                a.append("--inbox-callback")
        for opt in ISO_OPTIONS:
            if opt["store"] == "iso" and not self.iso_on(opt["key"]):
                a += ["--iso", f"{opt['key']}=off"]
        if self.iso_on("home_real"):
            a += ["--iso", "home_real=on"]
        if self.host_files:
            a += ["--host-files", self.host_files]
        if (self.host_files or self.iso_on("home_real")) and self.host_confirmed:
            a.append("--confirm-host-access")
        a.append("--")
        if self.is_browser:
            a += browser_command(self)
        else:
            argv = shlex.split(command if command is not None else self.command)
            hp = host_program_in_home(argv[0]) if argv else None
            extra = []
            found = shutil.which(argv[0]) if argv and "/" not in argv[0] else (argv[0] if argv else "")
            for d in browser_mounts(found) if found else []:
                if d.startswith("/opt/"):  # пакеты из AUR и сторонние установщики лежат в /opt
                    if d not in ro and ["--ro", d] != extra[-2:]:
                        extra += ["--ro", d]
                    real_opt = os.path.realpath(found)
                    if real_opt.startswith("/opt/") and argv[0] != real_opt:
                        argv[0] = real_opt  # в PATH среды /opt нет: запускаем по полному пути
            if hp and not self.iso_on("home_real") and not self.host_files:
                real, mount = hp
                if mount not in ro:
                    extra += ["--ro", mount]
                argv[0] = real
            if argv and os.path.basename(argv[0]) in ("fish", "zsh"):
                extra += ["--shell", os.path.basename(argv[0])]
            if extra:
                a[a.index("--"):a.index("--")] = extra
            a += argv
        return a


_LOCALES = None


def locale_available(lang):
    """True/False — есть ли локаль на компьютере; None — проверить не удалось."""
    global _LOCALES
    if re.fullmatch(r"C|POSIX|C\..*", lang):
        return True
    if _LOCALES is None:
        try:
            out = subprocess.run(["locale", "-a"], capture_output=True, text=True, timeout=10).stdout
        except (OSError, subprocess.SubprocessError):
            return None
        _LOCALES = {l.strip().lower().replace("utf-8", "utf8") for l in out.splitlines() if l.strip()}
    return lang.lower().replace("utf-8", "utf8") in _LOCALES


def timezone_exists(tz):
    return bool(TZ_RE.match(tz)) and os.path.isfile("/usr/share/zoneinfo/" + tz)


def new_profile(kind_key, name):
    """Профиль по типу из диалога «Новая среда»: claude, claude-desktop, codex, service, app, browser."""
    if kind_key == "claude":
        return Profile.claude_preset(name)
    if kind_key == "codex":
        return Profile.codex_preset(name)
    if kind_key == "claude-desktop":
        return Profile.claude_desktop_preset(name)
    if kind_key == "service":
        return Profile.service_preset(name)
    p = Profile(name=name, kind="browser" if kind_key == "browser" else "app")
    if kind_key == "browser":
        p.env = ["LANG"]
        p.protect_git = False
    return p
