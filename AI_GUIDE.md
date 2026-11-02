# AI_GUIDE — путеводитель по envbox для ИИ-агента

Читайте этот файл вместо чтения всего кода. Он отвечает на три вопроса: **где что лежит**, **что менять**
под конкретную задачу и **что проверять** после правки. Правила сборки коротко — в `CLAUDE.md`, список модулей
с именами функций (генерируется) — в `MAP.md`. Если файл разошёлся с кодом, прав код: поправьте файл.

Общаться с пользователем по-русски. Не коммитить и не пушить без явной просьбы. `dist/envbox.py` руками не править.

---

## 0. За 60 секунд

- **Что это.** Изолированные среды на bubblewrap (`bwrap`): консольная утилита `envbox` (bash-скрипт
  `resources/envbox.sh`), сетевой шлюз (Python: прокси с журналом, DNS, мосты), ядро (профили, запуск,
  секреты, ссылки), GUI на GTK 4, управление Chrome через CDP, сборка AppImage.
- **Как поставляется.** Исходники — пакет `src/envbox/`, но пользователю уходит **один файл** `dist/envbox.py`
  (его собирает `build.py`). Установка копирует его в `~/.local/share/envbox/`, и уже ЭТА копия работает как
  сетевой шлюз при каждом запуске среды.
- **Главный контекст.** Пользователь запускает Claude Code ВНУТРИ среды envbox. Прокси и `envbox.sh` работают на
  хосте из установленной копии. Ваши правки в `src/` НЕ действуют на уже запущенные среды, пока на хосте не
  выполнено `python3 dist/envbox.py install` и среда не перезапущена.
- **Чего нельзя в песочнице Claude.** Запустить `bwrap` (вложенные user namespace → `ENOSPC`), открыть окно GUI на
  экране пользователя. Реальный запуск среды проверяет только пользователь на хосте. Что можно: тесты, сборка,
  `envbox.sh` с заглушкой bwrap, GUI без экрана через `gtk4-broadwayd`, прокси как отдельный процесс (см. §11).
- **После любой правки**: `python3 build.py && python3 -m unittest discover -s tests` (36+ тестов, ~3 с).
- **Версия.** Менялось поведение установленных файлов (`envbox.sh`, шлюз) → поднять `ENVBOX_VERSION` в
  `src/envbox/version.py` (формат строки не менять; ведущие нули допустимы, `file_version()` сравнивает числа).
  Версию видно в заголовке окна GUI, по `envbox.py --version` (у AppImage — `./envbox-x86_64.AppImage --version`), в
  «Проверке системы» (запущенная против установленной; `gui/pages/settings.py version_line`) и в `X-AppImage-Version`.
  Менялось что-то, что пользователь должен отличить в сборке, — поднимайте версию, иначе «обновилось ли» не понять.

---

## 1. Команды

```bash
python3 dev.py [команда…]        # запуск из исходников без сборки (GUI по умолчанию)
python3 build.py                 # собрать dist/envbox.py
python3 build.py --check         # проверить сборку, ничего не писать
python3 build.py map             # обновить MAP.md
python3 -m unittest discover -s tests                 # все тесты
python3 -m unittest tests.test_net                    # только сеть/шлюз/GUI-логика
python3 -W error::ResourceWarning -m unittest discover -s tests   # строже: не должно быть утечек файлов
bash -n src/envbox/resources/envbox.sh               # синтаксис скрипта (есть и в тестах)
```

Подкоманды `envbox.py` (разбор — `cli.py`; для net-команд — `net/entry.py`):

| Команда | Где обрабатывается | Кто вызывает |
|---|---|---|
| (пусто) / `gui` | `cli.main` → `ensure_installed()` → `gui.app.gui_main` | пользователь, ярлык |
| `install` | `install.ensure_installed` | пользователь |
| `--version`, `-V` | `cli.main` (печатает `ENVBOX_VERSION`; работает и у AppImage) | пользователь |
| `run ARGS…` | `ensure_installed()` + `execv(envbox.sh)` | пользователь |
| `root [ПУТЬ\|--reset] [--move]` | `cli.cmd_root` | пользователь |
| `global [list\|create\|delete]` | `cli.cmd_global` | пользователь |
| `open-link [--env ИМЯ] [--no-start] ССЫЛКА` | `core.link_handler.cmd_open_link` | `.desktop` обработчик схемы |
| `--install-desktop` | `core.desktop.install_desktop_entry` | пользователь |
| `build-appimage` | `appimage.build_appimage` (качает appimagetool!) | пользователь |
| `proxy`, `wrap`, `probe`, `report`, `seccomp`, `gitcheck`, `version` | `net.entry.net_main` (быстрый вход) | `envbox.sh`, песочница |

---

## 2. Как устроено: потоки

### 2.1. Запуск среды (от кнопки до bwrap)

```
GUI (gui/pages/launch.py: launch → preflight → Profile.validate)
  ├─ встроенный терминал (VTE):  gui/pages/terminal.py open_embedded → terminal_argv([], …)   + ENVBOX_EMBEDDED=1
  ├─ внешний терминал:           core/terminal.py detect_terminal + terminal_argv(prefix, …)
  └─ браузер без окна:           core/terminal.py launch_background → пишет <среда>/launch.log
        │
        ▼  argv = env ENVBOX_PKG_HINT=… bash -c TERMINAL_WRAPPER envbox-term <envbox.sh> <имя> <секреты…> -- <envbox_args>
resources/terminal_wrapper.sh   (на хосте)
  достаёт секреты из keyring (secret-tool lookup service envbox profile <имя> var <VAR>), экспортирует
        │
        ▼
~/.local/share/envbox/envbox.sh   (= resources/envbox.sh с подставленным путём к envbox.py)
  1. разбор и проверка аргументов, каталог данных, проверка путей
  2. (--net-log) СРАЗУ запускает прокси в фоне:  python3 -I envbox.py[c] proxy --socket run/proxy.sock …
  3. параллельно: снимки Git (gitcheck snapshot), seccomp-фильтр (кэш seccomp.bpf/.key), запись etc/*, rc-файлов
  4. собирает массив args для bwrap; самопроверка (bwrap с теми же аргументами и `true`)
  5. ждёт сокет прокси; exec bwrap … -- python3 -I /run/envbox/net.py wrap … -- <команда>
  6. после выхода: gitcheck verify (предупреждение, код 4), trap cleanup → kill прокси, rm сокета
        │
        ▼
bwrap → в песочнице:  python3 -I /run/envbox/net.py wrap --map 3128:/run/envbox/proxy.sock … -- <команда>
  wrap: слушает 127.0.0.1:3128 → пересылает в unix-сокет прокси; inbox-наблюдатель; затем execvp(команда)
```

`envbox_args()` (`core/profile.py`) превращает профиль в флаги `envbox.sh` — таблица в §5.2.

### 2.2. Сеть: что видит программа в среде

| Режим профиля `net` | Флаги | Что получает среда |
|---|---|---|
| `off` | `--no-net` | пустой netns, только loopback |
| `log` | `--net-log` | netns без сети; выход только через прокси хоста; любые публичные адреса |
| `allowlist` | `--allow-domain X` (повтор.) | то же, но только перечисленные домены |
| `host` | (ничего) | сеть хоста. Запрещена защитой `host_net_forbidden` (включена по умолчанию → `envbox.sh` сам превращает в `--net-log`) |

Дополнительно: `--upstream URL` (вышестоящий http/socks5/socks5h прокси, пароль только через
`ENVBOX_UPSTREAM_AUTH`), `--dns IP` (свои DNS прокси), `--net-allow-private` (разрешить частные адреса),
`--direct-domain ДОМЕН` (с `--upstream`: прокси envbox идёт к этому сайту сам, мимо вышестоящего; сайт виден с
настоящего адреса, среда по-прежнему видит только прокси envbox; в allowlist такой сайт разрешён автоматически, проверка
частных адресов действует как обычно; без `--upstream` флаг игнорируется с предупреждением).

Цепочка байтов: `приложение → HTTP_PROXY=127.0.0.1:3128 (внутри среды) → net.py wrap (поток на соединение) →
unix-сокет run/proxy.sock → net/proxy.py Proxy.handle (на хосте) → [Upstream.tunnel | connect_race] → интернет`.
Приложения, которые игнорируют `HTTP(S)_PROXY` (ssh, сырой TCP, UDP/QUIC), сети не получат — это ограничение
дизайна, а не баг. Внутри среды заданы: `HTTP_PROXY/http_proxy/HTTPS_PROXY/https_proxy`, `NODE_USE_ENV_PROXY=1`,
`NO_PROXY=localhost,127.0.0.1,::1`, `BROWSER=/run/envbox/bin/open-url`, `ENVBOX_SESSION=<имя>`.

Ответы прокси клиенту (все быстрые, с `Connection: close`):

| Код | Когда | Журнал (`event`/`reason`) |
|---|---|---|
| 200 | CONNECT удался | `open` |
| 400 | кривой запрос, недопустимое имя хоста (`canon_host`) | `error`/`unsupported-request` (для HTTP) |
| 403 | не из allowlist; частный адрес | `deny`/`not-in-allowlist`, `deny`/`private-address` |
| 502 | DNS не разрешил; не подключились; сбой вышестоящего прокси | `error`/`dns: …`, `connect: …`, `upstream: …` |

Тело ответа называет хост: `Forbidden by envbox allowlist: host`.

Формат `net.log` (JSON по строке): `ts`, `run` (id запуска прокси), `id` (номер соединения), `event`
(`open|close|deny|error|proxy-start|proxy-stop`), `kind` (`CONNECT|HTTP`), `host`, `port`, `method`, `url`
(без userinfo), `ip`, `via`, `reason`, `resolved`, при `close`: `up`, `down`, `ms`, метки от начала пересылки в мс `up_end` (клиент договорил запрос), `down_first` и `down_last` (первый и последний байт ответа; нет `down_first` — ответа не было вовсе: у зависшего соединения это сразу показывает, молчит сервер или клиент не дослал запрос). Хранится в
`<корень>/<имя>/net.log`, ротация >20 МБ → `net.log.1` (и при старте, и по ходу работы).

### 2.3. Ссылки из среды наружу и обратно

- **Наружу** (`xdg-open`, `$BROWSER`): шим `run/bin/open-url` пишет файл в `run/links/` → GUI (`gui/pages/links.py
  poll_links` каждые 1.5 с) читает `core/links.py read_link_spool` (каталог недоверенный: O_NOFOLLOW, только обычные
  файлы, лимиты) → проверка `parse_link` (только http/https, без логина в адресе) → вопрос пользователю/авто-открытие
  в браузере-среде (`cdp_open_url`) или в браузере хоста (`open_in_host_browser`).
- **Внутрь** (`claude://…`, колбэк входа `http://localhost:порт`): `.desktop` → `envbox.py open-link` →
  `core/links.py send_link` кладёт файл в `run/inbox/` → внутри среды `net/bridge.py inbox_loop` забирает, проверяет
  (`inbox_handle`), запускает `--inbox-cmd` или выполняет GET на loopback → пишет `<файл>.result`.

### 2.4. Браузеры и CDP

Среда-браузер (`kind="browser"`): `core/browser.py browser_command` запускает Chrome с
`--remote-debugging-port=9222`; порт публикуется как unix-сокет `run/expose/9222.sock` (`--expose-port`). Другие
среды подключаются `--attach` (внутри слушают 127.0.0.1:9222). GUI смотрит страницу по тому же сокету:
`cdp/http.py` (HTTP /json) → `cdp/client.py` (WebSocket) → `cdp/viewer.py` (кадры JPEG, ввод) → `gui/browser/*`.
Сокет лежит в каталоге, подконтрольном среде ⇒ **недоверенный**: `_unix_connect` открывает его `O_PATH|O_NOFOLLOW`
и проверяет `S_ISSOCK`.

---

## 3. Что где лежит (карта «хочу изменить X»)

### 3.1. Задача → файл → что проверить

| Хочу… | Править | Проверить / тест |
|---|---|---|
| Аргументы bwrap, монтирования, изоляцию | `resources/envbox.sh` (секции в §6) | `bash -n`; прогон с заглушкой bwrap (§11.2); `--dry-run` на хосте; поднять `ENVBOX_VERSION` |
| Новое поле профиля | `core/profile.py` (dataclass + `validate` + `envbox_args`) → `gui/pages/profile_page.py` (`show_profile`, `collect`) → `core/describe.py` | §5.3 чек-лист |
| Новую защиту (iso-ключ) | `core/isolation.py` `ISO_OPTIONS`/`ISO_PRESETS` + `envbox.sh` (`set_iso`, `iso_*`) | §5.4 |
| Домены пресета Claude | `core/consts.py` `CLAUDE_DOMAINS` (миграция старых — `OLD_CLAUDE_DOMAINS`, `Profile.from_dict`) | `tests/test_net.py::Presets` |
| Правила allowlist / отказы прокси | `net/proxy.py` `Proxy.allowed`, `Proxy.handle`, `Proxy.deny` | `ProxyTests` |
| Проверку «частный адрес», fake-ip | `net/common.py` `is_public`, `FAKE_IP_PREFIX`; `net/dns.py` `is_private_name` | `HostChecks` |
| Проверку имён хостов | `net/common.py` `canon_host` | `test_canon_host_rejects_junk`, `test_idna_cannot_hide_a_private_address` |
| DNS: кэш, свои серверы | `net/dns.py` `Resolver`, `dns_lookup`, `_dns_query` | `ResolverTests`, `test_dns_parse_survives_short_rdata` |
| Подключение к хосту (IPv6/IPv4) | `net/connect.py` `connect_race`, `interleave` | `Connect` |
| Вышестоящий прокси (socks5/http) | `net/upstream.py` `Upstream`; профильная часть — `core/upstream.py` | `probe` (`net/bridge.py cmd_probe`) |
| Мост внутри среды, порты, inbox | `net/bridge.py` (`pump`, `cmd_wrap`, `inbox_*`) | рисковый код: форк + потоки |
| Таймауты/буферы/keepalive сокетов | `net/common.py` (`HEAD_TIMEOUT`, `CONNECT_TIMEOUT`, `BUF`, `tune_socket`) | бенчмарки §11.4 |
| Проверку Git после работы | `net/gitcheck.py` + вызовы в `envbox.sh` (`gitcheck snapshot/verify`) | `GitCheck` |
| Защиту `.git` внутри среды | `envbox.sh` `protect_git_dir`, `add_git_dir` | вручную на хосте |
| seccomp-список вызовов | `net/seccomp.py` `SECCOMP_DENY_X86_64` | `test_seccomp_program_is_whole_instructions`; ключ кэша — mtime+size `net_py` |
| Вывод журнала (терминал/GUI) | `net/report.py` (`fmt_event`, `clean`) | `test_terminal_escape_sequences_are_removed` |
| Разбор аргументов шлюза | `net/entry.py` (`NET_OPTIONS`…, `net_parse`) | `ArgsAndReport` |
| Хранение профилей/настроек | `core/store.py` (`<корень>/<имя>/profile.json`, `<корень>/gui.json`) | — |
| Каталог данных, глобальные папки | `core/root.py`, `core/rootops.py`, `cli.cmd_root/cmd_global` | `envbox.sh` дублирует логику выбора корня |
| Запуск терминала/браузера | `core/terminal.py`, `resources/terminal_wrapper.sh` | — |
| Секреты (keyring) | `core/keyring.py` (`secret-tool`, атрибуты `service envbox profile <имя> var <VAR>`) | — |
| Список запущенных сред | `core/sessions.py` (`/proc`, `comm == bwrap`, метка `ENVBOX_SESSION`) | `test_session_scan_reads_only_bwrap_cmdlines` |
| Ссылки, очередь, браузер для ссылок | `core/links.py`, `core/link_handler.py`, `gui/pages/links.py` | — |
| Рецепты установки программ | `core/isolation.py` `INSTALL_RECIPES` | правило `domains=[]` = любая публичная сеть |
| Описание среды («Обзор») | `core/describe.py` | — |
| Диагностику | `core/diagnostics.py`, `gui/pages/settings.py` | — |
| Вкладку/страницу GUI | `gui/pages/*` (миксин) + база в `gui/window.py` | §5.5, импорт GUI-модулей (§11.3) |
| Тексты, CSS, `--help`, значки | `resources/` (файлы, не строки в коде) | пересборка |
| Установку, `.pyc`, метку Python | `install.py` (`ensure_installed`, `compile_installed`), `envbox.sh` (выбор `net_py`) | `Install` |
| Сборщик | `build.py` | `BuildTests`, `FastEntry` |
| AppImage | `appimage.py`, `resources/AppRun.sh`, `envbox.desktop` | требует сеть (appimagetool) |

### 3.2. Дерево

```
build.py  dev.py  CLAUDE.md  AI_GUIDE.md  MAP.md  README.md
dist/envbox.py                собранный единый файл (генерируется; актуальность проверяет test_dist_is_up_to_date)
legacy/envbox-2026.10.31.18.py  старый единый файл — эталон для сравнений и бенчмарков «до/после»
envbox-x86_64.AppImage        собранный раньше AppImage (устаревает; пересобирать build-appimage)
tests/test_structure.py       сборка, версия, импорты без GTK, синтаксис envbox.sh
tests/test_net.py             шлюз, прокси, DNS, Git, быстрый вход, GUI-логика, установка, пресеты
src/envbox/
  version.py lazy.py resources.py selfpath.py        самые нижние модули
  net/        common dns connect upstream proxy bridge gitcheck report seccomp entry   (шлюз, БЫСТРЫЙ ВХОД)
  core/       consts fsutil isolation root rootops store profile sessions keyring system browser
              upstream terminal netlog describe diagnostics desktop links link_handler
  cdp/        http client keys browser viewer
  gui/        gtk consts widgets tables app window ; pages/ (11 миксинов) ; browser/ (page, view)
  install.py  cli.py  appimage.py
  resources/  envbox.sh terminal_wrapper.sh help.txt gui.css icon.svg icon.png.b64 AppRun.sh envbox.desktop
```

Зависимости направлены строго вниз (циклы собирать нельзя — `build.py` ругается):
`version/lazy/resources/selfpath` ← `net` ← `core` ← `cdp` ← `core.links` ← `install`/`cli`; `gui/*` подключаются
только из `cli`. Актуальный граф: `python3 -c "import build"`-скриптом по `build.module_files()` (см. §11.5).

---

## 4. Модули по одному (что внутри, что важно)

Формат: **файл** — назначение; ключевые имена; инварианты. Имена функций проверяйте по `MAP.md` (там актуальный список).

### 4.1. Нижний слой

- **`version.py`** — `ENVBOX_VERSION = "ГГГГ.ММ.ДД.N"`. Строку читает регулярка `^ENVBOX_VERSION = "([0-9.]+)"` из
  `install.file_version` (не менять формат, не добавлять пробелов/кавычек иначе). Поднимать при изменении `envbox.sh`/шлюза.
- **`lazy.py`** — `_LazyModule` и готовые ленивые `asyncio, base64, datetime, ipaddress, json, re, signal, socket,
  threading, urllib_parse`. Импортируйте их в `net/*` так: `from ..lazy import json, re` (БЕЗ `as`!).
- **`resources.py`** — `resource_text(имя)`: читает файл из `resources/`; в сборке файлы вшиты словарём.
- **`selfpath.py`** — `SELF` (что перезапускать/откуда читать версию), `bundle_path()` (единый файл для установки и
  AppImage; из исходников — свежая сборка через `build.build_if_stale()`). `BUNDLED = False` — сборщик меняет на `True`.

### 4.2. `net/` — сетевой шлюз (БЫСТРЫЙ ВХОД, см. §8.2)

- **`common.py`** — `HEAD_LIMIT/HEAD_TIMEOUT(30)/CONNECT_TIMEOUT(15)/BUF(64К)`, `FAKE_IP_PREFIX` (198.18.0.0/15),
  `now()`, `split_hostport()`, `is_public()` (глобальные адреса + fake-ip; ipv4-mapped раскрывается),
  `canon_host()` (IDNA→ASCII, нижний регистр, отказ на управляющие символы/разделители), `tune_socket()`
  (NODELAY + keepalive 60/15/4 для TCP-сокетов).
- **`dns.py`** — собственный DNS-клиент (`_dns_query`, UDP с повтором по TCP, `_dns_parse` устойчив к обрезанным
  ответам), `dns_lookup`, `dns_resolve_blocking`; `Resolver` (кэш 60 с, отказ 2 с, объединение одинаковых запросов, свой
  пул потоков, A+AAAA параллельно; системный `getaddrinfo`, если `--dns` не задан); `is_private_name`
  (127.1, 2130706433, 0x7f000001, localhost), `is_ip_literal`.
- **`connect.py`** — `connect_race(ips, port)` (Happy Eyeballs: интерливинг семейств, старт следующего адреса через
  0.25 с, отмена проигравших), `interleave`.
- **`upstream.py`** — `Upstream(url, auth)`: http (CONNECT) / socks5 / socks5h; `tunnel(host, port)`, `open()`,
  `basic()`; `UpstreamError`. Хост в SOCKS кодируется IDNA → вызывающий обязан передать уже `canon_host`.
- **`proxy.py`** — `Proxy` (логика одного соединения в `handle`), `cmd_proxy`. Порядок в `handle`: разбор строки запроса →
  `canon_host` → allowlist (`Proxy.allowed`, учитывает `direct`) → (`Proxy.via_upstream(host)` — хосты из `direct`
  идут по ветке «без upstream»; через upstream: `is_private_name`, при `check_local` — локальный DNS-страж через
  `local_resolver`; иначе: `resolver.resolve` → фильтр `is_public` → `connect_race`) → `open` в журнал → туннель
  `pipe`. Туннель к upstream строит `hedged_tunnel` (через `HEDGE_DELAY` стартует второй, побеждает первый готовый);
  `pipe` закрывает соединение, если `IDLE_TIMEOUT` секунд не было байтов ни в одну сторону (событие `close` с `idle`).
  Для обычного HTTP: переписывает запрос (убирает `Proxy-*`, `Connection`, `Keep-Alive`; при `Upgrade:` —
  сохраняет соединение). `cmd_proxy` снимает `ENVBOX_UPSTREAM_AUTH` из окружения, заканчивает `os._exit(0)`.
  Следит за родителем (`--parent-pid`) раз в секунду, SIGTERM — штатная остановка.
- **`bridge.py`** — работает ВНУТРИ песочницы: `cmd_wrap` (листенеры `--map порт:сокет`, `--serve сокет:порт`,
  форк-наблюдатель с `PR_SET_PDEATHSIG`, затем `execvp` команды), `pump` (поток на направление), `inbox_loop`
  (опрос каталога раз в 0.4 с), `inbox_handle`; `cmd_probe` (проверка вышестоящего прокси).
- **`gitcheck.py`** — `git_state()` / `cmd_gitcheck()`: снимок `.git` (тип, inode, `config`, `hooks/` без `*.sample`,
  `commondir`, `config.worktree`, `modules/*/{config,hooks}`, `core.hooksPath`). Код выхода `verify` при различиях — **4**.
- **`seccomp.py`** — BPF-программа (deny-список вызовов x86_64 → EPERM; чужая архитектура/x32 → KILL), `--allow имя` снимает запрет.
- **`report.py`** — `fmt_event`, `clean` (замена управляющих символов), `cmd_report` (сводка/`--raw`/`--follow`).
- **`entry.py`** — самодельный разбор аргументов (`NET_OPTIONS`, `NET_REQUIRED`, `NET_POSITIONAL`, `net_parse`),
  `net_main`, `NET_COMMANDS`. argparse сюда возвращать нельзя (+18 мс на каждый вызов).

### 4.3. `core/` — ядро (без GTK)

- **`consts.py`** — регулярки (`NAME_RE`, `DOMAIN_RE`, `VAR_RE`, `LANG_RE`, `TZ_RE`, `ATTACH_RE`, `SCHEME_RE`),
  `NET_MODES/NET_LABELS/NET_SHORT`, `CLAUDE_DOMAINS`, `RESERVED_VARS`, `CDP_PORT=9222`, пути установки
  (`INSTALL_DIR`, `INSTALLED_PY/PYC/PYC_TAG`, `ENVBOX_SH`), `ENVBOX_SH_TEXT` (шаблон скрипта с `__ENVBOX_PY__`).
- **`profile.py`** — `Profile` (dataclass, все поля — §5.1), пресеты (`claude_preset`, `claude_desktop_preset`,
  `codex_preset`, `service_preset`, `new_profile(kind_key, name)`), `from_dict` (мягкая загрузка + миграции),
  `iso_on/iso_set/apply_iso_preset/detect_iso_preset`, `install_view` (профиль на время установки программ),
  `validate()` (список ошибок по-русски), `envbox_args()` (профиль → флаги `envbox.sh`).
- **`isolation.py`** — `ISO_OPTIONS` (список защит: key, group, store, invert, warn_off, title/text/risk),
  `ISO_PRESETS` (`max`, `compat`, `min`), `INSTALL_RECIPES` (id, title, domains, command, note, needs),
  `recipe_warning`, `env_has_tool`.
- **`root.py` / `rootops.py`** — каталог данных (ENVBOX_ROOT → `~/.config/envbox/root` → `~/.envbox`), `box_dir(имя)`,
  глобальные папки `_global/<имя>`; перенос корня (`move_root` перепривязывает пути в профилях), удаление, «кто использует».
- **`store.py`** — `list/load/save/copy/delete_profile`, `load/save_settings` (`gui.json`: `terminal`, `embedded`).
  `save_profile` отвергает логин в адресе прокси. Профиль — JSON `asdict(Profile)`, права 0600.
- **`sessions.py`** — `list_sessions(proc="/proc")`: сначала `comm == bwrap` (дёшево), потом `cmdline`/`stat`;
  внутренний bwrap (pid 1 ns) сворачивается в `inner`; имя среды — из `--setenv ENVBOX_SESSION`. `stop_session` → SIGTERM.
- **`terminal.py`** — список терминалов, `terminal_argv`, `dry_run` (`envbox.sh --dry-run`), `launch_background` (+`launch.log`).
- **`keyring.py`** — обёртка над `secret-tool` (значения не попадают в argv).
- **`browser.py`** — поиск Chrome, `browser_mounts` (что смонтировать из /opt), `browser_command`, `cdp_socket_path`,
  `host_program_in_home`, `attach_snippets`.
- **`links.py`**, **`link_handler.py`** — поток ссылок (§2.3); `parse_link` — единственная проверка недоверенных адресов.
- **`netlog.py`** — `LogTail` (чтение с хвоста, переживает очистку), `NetSummary` (инкрементальная сводка), `summarize`.
- **`describe.py`**, **`diagnostics.py`**, **`system.py`**, **`upstream.py`** (разбор URL прокси профиля), **`desktop.py`**, **`fsutil.py`** — вспомогательные.

### 4.4. `cdp/` — Chrome DevTools Protocol

- `http.py` (`_unix_connect`, `cdp_http`, `cdp_pick_page`, `cdp_listening`), `client.py` (`CdpClient`: свой WebSocket,
  лимит сообщения 64 МБ), `keys.py` (`normalize_url`: только http/https/about:blank; перевод координат/клавиш),
  `browser.py` (`CdpBrowser`: вкладки), `viewer.py` (`CdpViewer`: кадры, ввод, масштаб, поиск). Данные от браузера — недоверенные.
  `CdpViewer._apply_metrics`: размер страницы, экрана (`screenWidth/Height`) и окна (`Browser.setWindowBounds`, только
  в сторону увеличения) и масштаб как настоящий `deviceScaleFactor` (страница видит `innerWidth = ширина / масштаб`).
  Кадры идут в CSS-пикселях страницы, поэтому координаты мыши пересчитывать не нужно; масштаб ограничен 50–300%.
  `Page.frameRequestedNavigation` на внешнюю схему (`external_scheme`: claude://, mailto:…) → `on_external(адрес)` и
  закрытие вкладки: безоконный Chrome показывает запрос «открыть программу?», который нельзя закрыть, и вкладка
  перестаёт принимать ввод (reload, навигация, Escape не помогают, помогает только закрытие). GUI спрашивает
  пользователя и передаёт ссылку в среду (`gui/browser/page.py browser_ask_external` → `send_link_to_env`).
  Вход в Claude CLI: сайт ведёт на `http://127.0.0.1:порт/callback…`, порт слушает CLI в ДРУГОЙ среде, у браузера-среды свой
  localhost. По `Page.frameNavigated` с `unreachableUrl` (`local_callback_url`) адрес уходит туда же (`on_external`, вкладка
  остаётся); среда выбирается `find_env_for_url` (нужен `link_callback`), запрос делает внутри неё `net/bridge.py inbox_handle`.

### 4.5. `gui/` — GTK 4

- `gtk.py` — единственное место импорта GTK (может перезапустить процесс под `/usr/bin/python3`). Остальные берут
  `from ..gtk import Gtk, GLib…`. `window.py` — `EnvboxWindow` = склейка миксинов страниц; состояние окна в `__init__`
  (`current`, `running`, `procs`, `pending`, `tail`, `net_summary`, `term_entries`…). `app.py` — `gui_main`.
- Страницы (`gui/pages/`): `sidebar` (список сред), `profile_page` (форма: `show_profile` ↔ `collect` ↔ `save_current`),
  `profile_net` (секреты, прокси, подключение браузера), `isolation`, `folders`, `launch` (запуск/остановка/установка),
  `terminal` (VTE), `net_page` (журнал; `refresh_sessions_async`), `links`, `overview`, `settings`. Браузер: `gui/browser/page.py`, `view.py`.
- Правила GUI: тяжёлое — через `self.run_async(func, done)` (поток → `done` в главном потоке); таймеры `tick` 1 с,
  `poll_links` 1.5 с, `browser_tick` 1.5 с — **не класть в них блокирующую работу**.

---

## 5. Профиль среды

### 5.1. Поля `Profile` (`core/profile.py`) → где используются

| Группа | Поля |
|---|---|
| Основное | `name` (= имя каталога), `kind` (`app`/`browser`), `workdir`, `no_workdir`, `command`, `shell` (`bash`/`fish`/`zsh`) |
| Сеть | `net` (`off`/`log`/`allowlist`/`host`), `allow_domains`, `net_allow_private`, `upstream`, `upstream_auth` (пароль в keyring), `dns`, `direct_domains` (вкладка «Изоляция», блок «Сеть») |
| Окружение | `env` (`VAR` или `VAR=значение`), `secrets` (имена; значения из keyring), `path`, `lang`, `timezone` |
| Файлы | `ro`, `rw`, `global_on`, `global_folders` (`имя:ro|rw`), `ephemeral`, `host_files` (`ro`/`rw`), `host_confirmed` |
| Изоляция | `isolation` (dict `ключ→bool`, хранятся только отличия от умолчания), `protect_git`, `allow_userns` |
| Связь сред | `expose_ports`, `attach` (`среда[:порт[:локальный]]`), `gui_wayland` |
| Браузер | `browser_bin`, `browser_start_url`, `browser_visible`, `browser_chrome_sandbox` |
| Ссылки | `link_handler`, `link_schemes`, `link_callback`, `link_browser`, `link_out_auto` |
| Установка | `install_domains` |

Чтение профиля с диска мягкое (`from_dict` приводит типы, неизвестные поля игнорирует, чинит `net`/`kind`).
**Миграции старых профилей делаются в `from_dict`** (пример: список доменов Claude).

### 5.2. Профиль → флаги `envbox.sh` (`Profile.envbox_args`)

| Поле | Флаг |
|---|---|
| `name` | `-n имя`; всегда `--root <каталог данных>` |
| `workdir` / `no_workdir` / браузер | `-w путь` / `--no-workdir` |
| `net` | `--no-net` / `--net-log` / `--allow-domain д` (каждый) / — |
| `upstream` (только log/allowlist), `dns`, `net_allow_private` | `--upstream`, `--dns`, `--net-allow-private` |
| `direct_domains` (только при `upstream`) | `--direct-domain` (каждый) |
| `lang`, `timezone` | `--lang`, `--timezone` |
| `env` + `secrets` | `--env X` (значения секретов приходят в окружении от `terminal_wrapper.sh`/`launch_background`) |
| `ro` (+ каталоги браузера/`/opt`/программы из `~`) | `--ro путь` |
| `rw`, `global_folders` (если `global_on`), `path` | `--rw`, `--global имя:режим`, `--path` |
| `attach`, `expose_ports` (у браузера всегда CDP_PORT) | `--attach`, `--expose-port` |
| `browser_visible` / `gui_wayland` | `--wayland` |
| `ephemeral`, `protect_git=False`, `allow_userns` (или браузер с chrome-sandbox) | `--ephemeral`, `--no-protect-git`, `--allow-userns` |
| `link_handler`, `link_schemes`, `link_callback` (не для браузера) | `--inbox-cmd`, `--inbox-scheme`, `--inbox-callback` |
| `isolation[k]=False` | `--iso k=off`; `home_real=True` → `--iso home_real=on` |
| `host_files`, `host_confirmed` | `--host-files`, `--confirm-host-access` |
| `shell` fish/zsh (или команда fish/zsh) | `--shell` |
| `command` (браузер: `browser_command(p)`) | после `--` |

Валидацию дублируют двое: `Profile.validate()` (GUI, сообщения пользователю) и `envbox.sh` (`die`, это граница
доверия — ей нельзя доверять профилю). **Любое ограничение добавляйте в обе.**

### 5.3. Чек-лист: новое поле профиля

1. `Profile` (значение по умолчанию) → `from_dict` подхватит само (тип берётся из значения по умолчанию).
2. `validate()` — проверка; `envbox_args()` — флаг; `envbox.sh` — разбор флага + собственная проверка + эффект в `args`.
3. GUI: `gui/pages/profile_page.py` — виджет, `show_profile` (профиль → форма), `collect` (форма → профиль).
4. `core/describe.py` — строка в «Обзоре» (если влияет на то, что получит среда).
5. Если меняет установленные файлы — `ENVBOX_VERSION`. Тест на `validate`/`envbox_args` в `tests/`.
6. Не забыть `copy_profile` (что сбрасывать при копировании: `upstream_auth`, `host_confirmed`).

### 5.4. Чек-лист: новая защита (iso-ключ)

`core/isolation.py` `ISO_OPTIONS` (поле `store`: `"iso"` — в словаре `isolation`, иначе имя поля профиля;
`invert` — поле хранит обратное) → при необходимости `ISO_PRESETS` → `envbox.sh`: переменная `iso_<ключ>`, `set_iso`,
использование в сборке `args` → `gui/pages/isolation.py` подхватывает список автоматически (проверьте группу в `ISO_GROUPS`)
→ `Profile.envbox_args` выдаёт `--iso key=off` само для `store == "iso"`.

### 5.5. Другие чек-листы

- **Новая вкладка GUI**: новый класс-миксин в `gui/pages/имя.py` (импорты только `...core`, `..gtk`, `..widgets`),
  добавить в базы `EnvboxWindow` (`gui/window.py`), страницу добавить в `Gtk.Notebook` в `__init__`. Имена методов
  уникальны на всё окно (миксины делят один `self`).
- **Новая подкоманда**: ветка в `cli.main`; текст в `resources/help.txt`. Если команда служебная и часто вызывается
  из `envbox.sh` — класть в `net/` и в `NET_OPTIONS` (быстрый вход), а не в `cli`.
- **Новый рецепт установки**: запись в `INSTALL_RECIPES`; `domains=[]` означает «любая публичная сеть с журналом».
- **Новый пресет среды**: `Profile.<имя>_preset` + ветка в `new_profile` + пункт в `gui/pages/sidebar.py on_new`.
- **Новый ресурс**: файл в `resources/`, в коде `ИМЯ = resource_text("файл")` на уровне модуля; сборщик вошьёт сам.
- **Новая net-команда**: функция `cmd_x(a)`, запись в `NET_OPTIONS`/`NET_REQUIRED`/`NET_POSITIONAL`, диспетчер `net_main`;
  тест в `ArgsAndReport`; проверить `FastEntry` (не тянуть тяжёлых импортов).

---

## 6. `resources/envbox.sh` — карта (ищите по заголовкам; номера строк плывут)

Один bash-файл ≈1300 строк; `set -euo pipefail`. Шаблон: `net_py=__ENVBOX_PY__` подменяется при установке
(`install.ensure_installed`: `ENVBOX_SH_TEXT.replace("__ENVBOX_PY__", shlex.quote(INSTALLED_PY))`).

| Заголовок (grep) | Что делает |
|---|---|
| `usage()` | справка `--help` (полный список флагов; обновлять вместе с флагами) |
| `# --- проверки окружения запуска` | bash ≥ 4.4, Linux, не root, `HOME` |
| `# --- разбор аргументов` | цикл `case` по флагам, `set_iso`; переменные `iso_*`, `net`, `net_log`, `allow_domains`… |
| `# --- валидация` | имя среды, оболочка (`--shell`), схемы ссылок, `real_home`, **выбор корня данных** (дублирует `core/root.py`), глобальные папки (`in_global_area`, `overlaps_envbox_data`) |
| `net_py=…` / `net_pyc` | выбор исполняемого файла шлюза: `.pyc` только если новее `.py` **и** метка `.pyc.python` совпадает с `readlink -f /usr/bin/python3` |
| `# Режим просмотра журнала` | `--net-report` → `envbox.py report` |
| `# Жёсткий режим` | при `host_net_forbidden` и сети хоста → принудительно `--net-log` |
| проверки `--upstream`, `--dns`, `--lang`, `--timezone`, `--host-files` | значения и совместимость флагов |
| `# Разбор путей хоста для --ro и --rw`, `# Глобальные папки`, `# Переменные окружения` | `resolve_host_path` (запрет HOME и данных envbox), `reserved_re`, **`loader_re`** (LD_*, GCONV_PATH… идут через `--setenv`) |
| `# --- bubblewrap` | поиск bwrap (не setuid), `bwrap_has`, `diagnose_userns` (AppArmor и пр.), пробный запуск |
| `# --- каталог среды` | создание `home etc empty run{,/links,/bin,/expose,/inbox}`; запрет симлинков; **ранний запуск прокси** (`proxy_pid`, `cleanup`, `trap … EXIT`) |
| `write_file`, шимы `open-url`/`xdg-open`, `etc/passwd group hosts hostname` | служебные файлы среды (атомарная запись) |
| `# --- PATH внутри среды` | `sandbox_path`, предупреждение «команда не найдена» (`host_view_of`) |
| `# --- аргументы bwrap` | **сборка массива `args`** (порядок важен, см. ниже) |
| `add_git_dir`, `git_snap_pids`, `protect_git_dir` | список каталогов с защитой Git; параллельные снимки; ro-монтирование `hooks`, `config`, `modules/*` |
| `# Пространства имён`, `# Жизненный цикл` | `--unshare-*`, `--hostname`, `--disable-userns`, `--die-with-parent`, `--cap-drop ALL`, `--new-session` |
| `# Мост внутри среды` | `/run/envbox/*` (net.py ro, proxy.sock, links, bin, inbox, expose, attach) |
| `# DNS внутри среды`, `etc_items` | `resolv.conf` (нейтральный/свои), белый список файлов `/etc` |
| `prepare_rc`, `seed_rc` | стартовые rc-файлы оболочек в `<среда>/home` (без перезаписи, без симлинков) |
| домашний каталог / `--ro` / `--rw` / `--global` / workdir / `--ro` поверх rw | порядок монтирований; затем защита Git и `--remount-ro /` |
| `# Базовые переменные`, `final_cmd` | `--setenv HOME USER LOGNAME SHELL PATH TERM LANG TZ`, прокси-переменные, `wrap` вокруг команды |
| `# --- запуск` | seccomp (кэш по mtime+size шлюза + набор `--allow`), `--dry-run`, ожидание снимков Git, `post_checks` |
| `run_sandbox()` | чистка окружения (`clean_env` → `unset` + `--unsetenv`), экспорт пользовательских переменных, **самопроверка bwrap**, `exec bwrap` |
| конец файла | ожидание сокета прокси (10 мс × 500), сообщение `info`, запуск, `post_checks`, выход с кодом среды |

Порядок монтирований в `args` (нарушение ломает защиту): `/usr` и симлинки `/bin /lib…` (ro) → `/proc /dev /tmp /run`
(tmpfs) → `/run/envbox/*` → `/etc/*` (список) → домашний каталог среды (`<среда>/home` как `$HOME`) → `--ro` вне записываемых
мест → `--rw` → глобальные папки → workdir (rw) → `--ro` внутри записываемых мест → защита Git → `--remount-ro /`.
При `--host-files` вместо этого `--ro-bind / /` (или `--bind`) + свои `/proc /dev /tmp /run` + скрытие корня данных tmpfs.

Размер ограничений: путь unix-сокета прокси < 100 символов (`${#sock} < 100`) — длинные имена сред/корня не работают.

---

## 7. Файлы на диске, пути, переменные окружения

### 7.1. На хосте

| Путь | Что |
|---|---|
| `~/.local/share/envbox/envbox.py` | установленная копия `dist/envbox.py`; **это и есть работающий шлюз** |
| `…/envbox.pyc`, `…/envbox.pyc.python` | предкомпилированная копия и метка «каким python собрана» (`readlink -f /usr/bin/python3`) |
| `…/envbox.sh` | `resources/envbox.sh` с подставленным путём к `envbox.py` |
| `~/.local/bin/envbox` | симлинк на `envbox.sh` |
| `~/.config/envbox/root` | указатель на выбранный каталог данных (первая строка; учитывает `XDG_CONFIG_HOME`) |
| `<корень>` = `$ENVBOX_ROOT` → указатель → `~/.envbox` | каталог данных |
| `<корень>/gui.json` | настройки GUI (`terminal`, `embedded`) |
| `<корень>/open-link.log` | журнал ссылок из браузера (без кодов входа) |
| `<корень>/_global/<имя>/` | глобальные папки (общие между средами; подключаются `--global имя:ro|rw`) |
| `<корень>/<среда>/profile.json` | профиль (0600) |
| `<корень>/<среда>/home/` | домашний каталог среды (в песочнице он монтируется как настоящий `$HOME`) |
| `<корень>/<среда>/etc/` | `passwd group hosts hostname resolv.conf` для песочницы |
| `<корень>/<среда>/rc/` | шаблоны rc-файлов оболочек |
| `<корень>/<среда>/run/` | `proxy.sock`, `links/` (исходящие ссылки), `bin/` (`open-url`, `xdg-open`), `expose/` (`<порт>.sock`), `inbox/` (входящие ссылки) |
| `<корень>/<среда>/net.log`, `net.log.1` | журнал прокси |
| `<корень>/<среда>/seccomp.bpf`, `seccomp.key` | кэш фильтра и его ключ (`mtime:size` шлюза + `--allow`) |
| `<корень>/<среда>/git.snapshot.N` | снимки Git до запуска (удаляются/перезаписываются каждым запуском) |
| `<корень>/<среда>/launch.log` | вывод фонового запуска (браузер) |
| `~/.local/share/applications/envbox-link-<схема>.desktop` | обработчик схемы ссылок (`Exec=python3 -I …/envbox.py open-link %u`) |

### 7.2. Внутри песочницы

`/run/envbox/net.py` (ro-копия шлюза), `proxy.sock`, `links/`, `bin/` (первым в `PATH`), `inbox/`, `expose/`,
`attach/<среда>/` (ro). `$HOME` = настоящий путь домашнего каталога хоста, но содержимое — `<среда>/home`.
Рабочий каталог проекта смонтирован по тому же пути, что на хосте (rw). `/usr` и системные каталоги — ro.
Порт моста — **3128** (занят; `--expose-port`/`--attach` не могут его использовать).

### 7.3. Переменные окружения

| Переменная | Где | Смысл |
|---|---|---|
| `ENVBOX_ROOT` | хост | переопределяет каталог данных |
| `ENVBOX_UPSTREAM_AUTH` | хост | `логин:пароль` вышестоящего прокси; прокси удаляет её из своего окружения, `run_sandbox` — из окружения среды |
| `ENVBOX_SESSION` | песочница | метка среды (по ней GUI находит запущенные среды в `/proc`) |
| `ENVBOX_EMBEDDED` | хост | терминал внутри GUI: обёртка не ждёт Enter |
| `ENVBOX_PKG_HINT` | хост | подсказка, как поставить `secret-tool` |
| `ENVBOX_NO_REEXEC`, `ENVBOX_GUI_REEXEC` | хост | защита от бесконечного перезапуска (установка / GTK под системным Python) |
| `ENVBOX_BROWSER_HEADLESS=new` | хост | старый режим `--headless=new` вместо ozone-headless |
| `ENVBOX_LINK_DIR` | песочница | каталог шима ссылок (по умолчанию `/run/envbox/links`) |
| `ENVBOX_BROWSER_CDP_URL` | песочница | адрес CDP при `--attach` |
| `APPIMAGETOOL`, `APPIMAGETOOL_SHA256` | хост | путь/хэш appimagetool для `build-appimage`; без `APPIMAGETOOL` и установленного appimagetool скачанный файл ставится только при совпавшем `APPIMAGETOOL_SHA256` |

В `env`/`secrets` профиля нельзя: `HOME USER LOGNAME SHELL PATH PWD OLDPWD` и всё, что начинается с `ENVBOX_`.

---

## 8. Сборка: правила и устройство

### 8.1. Правила (нарушение = ошибка `build.py` или падение теста)

1. Один файл = одно пространство имён: имена верхнего уровня (включая `_приватные`) не повторяются в разных модулях.
2. Импорты своих модулей — только `from .x import имя` на верхнем уровне и **без `as`** (сборщик вырезает всю строку).
   Импорты внутри функций — только стандартная библиотека. Единственное исключение — ленивый GUI в `cli.main`.
3. Циклов нет (§3.2). GTK только в `gui/*`; остальное обязано импортироваться без GTK (тест).
4. Ресурсы — файлами в `resources/`; `ИМЯ = resource_text("файл")`.
5. Состояние модуля (`global X`) меняется только в своём модуле; `from m import X` копирует значение.
6. После правок `python3 build.py` (иначе `test_dist_is_up_to_date` красный).
7. Менялось поведение установленных файлов → `ENVBOX_VERSION`.
8. `net/*` не импортирует модули `core`, `cdp` и `gui` (быстрый вход, §8.2).

### 8.2. Быстрый вход шлюза (важно для скорости)

`build.py` кладёт в **начало** `dist/envbox.py`: docstring `--help`, импорты только сетевой части, затем модули
`version lazy net/*`, затем блок
`if __name__ == "__main__" and sys.argv[1:2] and sys.argv[1] in NET_COMMANDS: sys.exit(net_main())`, и только потом
остальные импорты и код (core, cdp, gui внутри `_build_gui()`, cli). Так `proxy|wrap|seccomp|gitcheck|report|probe|version`
стартуют за ~15–18 мс вместо ~65 (голый `python3 -I -c pass` ≈ 11–13 мс). Эти команды вызываются при **каждом** старте среды
и каждой команде внутри неё.

Что ломает быстрый вход: `import argparse|subprocess|json|re|socket|asyncio|dataclasses|shutil` на верхнем уровне
любого `net/*` модуля (используйте `from ..lazy import …` или импорт внутри функции), любой импорт из `core`, `cdp` или `gui`
в `net/*`. Проверяет `tests/test_net.py::FastEntry` (запускает `python3 -I -X importtime dist/envbox.py version|seccomp|wrap`).
Ленивые объекты из `lazy.py` в сборке потом перекрываются настоящими импортами того же имени — это нормально.

### 8.3. Прочее про сборку

- `build.py map` обновляет `MAP.md` (не править руками). `build.build_if_stale()` пересобирает, только если исходники новее
  (его использует `dev.py install`/AppImage).
- В `dev`-режиме `SELF` = `sys.argv[0]`; установка берёт свежий `dist/envbox.py` (иначе в шлюз попал бы пакет, а не файл).
- Версия Python обновилась → `.pyc` нечитаем: `envbox.sh` проверяет метку, GUI/`install` пересобирает (`install.compile_installed`).
  Сравнение версий там числовое (`2026.11.01.1` == `(2026, 11, 1, 1)`); строковое сравнение ломается на ведущих нулях.

---

## 9. Безопасность: модель и инварианты

### 9.1. Границы доверия

**Доверенное**: пользователь, его профили в `<корень>/<среда>/profile.json`, код envbox, хост.
**НЕдоверенное** (приходит из среды — ВСЁ надо валидировать как ввод злоумышленника):
запросы к прокси (строка запроса, заголовки, `host`), ответы DNS/вышестоящего прокси, файлы в `run/links`, `run/expose`
(сокеты и ссылки на них), содержимое `<среда>/home`, `.git` проекта, данные CDP от браузера, строки в `net.log`
(имена хостов!), входящие файлы `inbox`, `.result`.

### 9.2. Инварианты, которые нельзя ломать

1. Любое имя хоста от клиента проходит `canon_host()` ДО allowlist/проверки частных адресов/DNS/SOCKS (иначе IDNA-обход: `1²7.0.0.1`).
2. Прокси подключается к IP, который сам разрешил и проверил `is_public` (нет повторного DNS → нет rebinding); в режиме
   вышестоящего прокси рядом с хостом дополнительно действует локальный DNS-страж (fail-open при ошибке DNS — осознанно).
3. Частные/loopback/link-local/CGNAT/`0.0.0.0` адреса запрещены, если нет `--net-allow-private`. Исключение — только fake-ip `198.18.0.0/15`.
4. Секреты — через окружение, никогда argv и логи; `ENVBOX_UPSTREAM_AUTH` не доходит до среды. Исключение осознанное: переменные
   загрузчика (`loader_re`) идут через `--setenv` (это не секреты), чтобы не влиять на сам bwrap.
5. Всё, что читается из каталогов, доступных среде на запись, открывается с `O_NOFOLLOW`, проверкой типа и лимитом размера
   (`read_link_spool`, `inbox_loop`, `_unix_connect`, `seed_rc`).
6. Всё, что печатается на хосте из данных среды, проходит `report.clean` (ESC и пр. в терминал не попадают).
7. `.git/hooks`, `.git/config` (и `modules/*`) смонтированы ro, а `gitcheck` предупреждает о изменённых `commondir`,
   `config.worktree`, о созданном `.git` — это обнаружение, не блокировка.
8. Защиты `iso_*` включены по умолчанию; профиль может выключать их только явно; `home_real` и `--host-files` требуют подтверждения.
9. bwrap не должен быть setuid; корень `--remount-ro /`; `--cap-drop ALL`; `--new-session` (TIOCSTI); `--disable-userns`
   (если не `--allow-userns`); seccomp-фильтр.
10. Журналирование не должно ронять прокси: исключения в `handle` пишутся как `internal`.

### 9.3. Чек-лист ревью изменения (прогоните мысленно)

- Появился новый вход от среды? Валидируется ли он (тип, размер, символы, симлинки)?
- Новый путь монтирования: не открывает ли `HOME`, корень данных, `/` (см. `resolve_host_path`, `overlaps_envbox_data`)?
- Новое поле профиля с путём/командой: нет ли подстановки в shell-строку без `shlex.quote`?
- Новый `except` не прячет ли отказ защиты (fail-open)? Для fail-open нужна причина в комментарии.
- Печатается ли что-то из недоверенных данных на хосте без `clean`?
- Новая сеть: проходит ли через `canon_host` + `is_public`?

### 9.4. Осознанно НЕ закрыто (не «чинить» молча — это обсуждается с пользователем)

Вложенные репозитории в подкаталогах проекта (хуки не защищены); seccomp-фильтр только x86_64 (на другом — предупреждение,
запуск без фильтра); allowlist только по имени (любые порты, domain fronting); общая rw-глобальная папка между средами;
рецепты установки `curl | bash` выполняются внутри среды; Git-защита — обнаружение после выхода, не предотвращение.

---

## 10. Скорость: бюджеты и правила

Измерено на этой машине (Python 3.14.8); сверяйте относительно этих чисел, а не абсолютных.

| Что | Было | Должно быть |
|---|---|---|
| `python3 -I -c pass` (нижняя граница) | 11–13 мс | — |
| вызов шлюза (`version`, `seccomp`, `wrap`, `gitcheck`) | 65–69 мс | **≤ ~18 мс** (gitcheck ~27 мс: json + sha256 + git) |
| накладные расходы `envbox.sh` вокруг bwrap (с заглушкой) | 473 мс | **~110 мс** |
| остановка прокси | +215 мс (sleep) | ≈ 3 мс |
| `asyncio` import (прокси, probe) | ~45 мс | — (запускается параллельно подготовке) |
| проход данных: прокси / мост+прокси | ~1.7 ГБ/с / ~1.1 ГБ/с | не узкое место |

Правила:

- В `net/*` — никаких тяжёлых импортов на верхнем уровне (§8.2). Измерять: `python3 -I -X importtime dist/envbox.py version`.
- В `envbox.sh` внешние процессы дороги (fork ≈ 1 мс, Python ≈ 15 мс): не добавляйте вызовы в «горячий» путь, длинное запускайте
  в фоне и `wait` позже (так сделаны прокси и снимки Git). Ждать готовность — коротким опросом (10 мс), не `sleep 0.05+`.
- Прокси: всё блокирующее (DNS, `getaddrinfo`) — в `Resolver` (свой пул), не в пуле asyncio по умолчанию.
- GUI: в таймерах (`tick`, `poll_*`) нет блокирующей работы; сканирование `/proc` — в потоке (`refresh_sessions_async`);
  сводка сети инкрементальна (`NetSummary`), журнал читается с позиции (`LogTail`). Не пересчитывать журнал целиком.
- Горячий путь прокси измерять бенчмарком (§11.4), а не на глаз: узкие места были в запуске и ожиданиях, не в копировании байтов.

---

## 11. Как проверять

### 11.1. Обязательный минимум после любой правки

```bash
python3 build.py && python3 -W error::ResourceWarning -m unittest discover -s tests
```

### 11.2. `envbox.sh` без настоящего bwrap (в песочнице Claude bwrap не запускается)

Заглушка `bwrap` проходит все ветки скрипта (проверки, прокси, снимки Git, seccomp-кэш, сборка `args`), но ничего не изолирует.
Пути должны быть КОРОТКИМИ (сокет прокси < 100 символов), поэтому временный каталог — в `/tmp`, а не в scratchpad.

```bash
L=$(mktemp -d /tmp/ebXXXX); mkdir -p $L/home $L/bin $L/proj
cat > $L/bin/bwrap <<'EOS'
#!/bin/bash
if [[ "${1:-}" == "--help" ]]; then echo "--unsetenv --disable-userns --seccomp --perms --remount-ro"; exit 0; fi
printf '%s\n' "$*" >> "$(dirname "$0")/args.log"; env | sort > "$(dirname "$0")/env.dump"; exit 0
EOS
chmod +x $L/bin/bwrap; cp dist/envbox.py $L/envbox.py
sed "s|__ENVBOX_PY__|$L/envbox.py|" src/envbox/resources/envbox.sh > $L/envbox.sh; chmod +x $L/envbox.sh
HOME=$L/home PATH=$L/bin:$PATH $L/envbox.sh -n t1 -w $L/proj --env LD_PRELOAD=/x.so -- /bin/true
cat $L/bin/args.log; tail -3 $L/home/.envbox/t1/net.log       # аргументы bwrap и журнал прокси
```

Для проверки `.pyc`: скомпилируйте в `$L/envbox.pyc`, запишите `readlink -f /usr/bin/python3` в `$L/envbox.pyc.python`,
`touch $L/envbox.pyc` (pyc должен быть новее py). Время запуска: цикл по 15 запусков, `date +%s%N` до/после.
Очистка: удалять по литеральному пути (`rm -rf /tmp/ebXXXX`) — проверка безопасности Claude блокирует `rm -rf` по переменной и внутри `bash -c`.

### 11.3. GUI без экрана

`python3 -c "import sys; sys.path.insert(0,'src'); import envbox.gui.window"` — ловит синтаксис и имена (нужен `gi`).
Живая проверка окна: `gtk4-broadwayd :7 &` (сервер без дисплея), затем скрипт с `GDK_BACKEND=broadway BROADWAY_DISPLAY=:7`
и подменённым `HOME`: в `App.do_activate` создать `EnvboxWindow(self)`, вызвать `win.tick()`, через `GLib.timeout_add(1500, …)` — `self.quit()`.
Остановку сервера делать по `kill $!`, а не `pkill -f` (шаблон совпадёт с самой командой). Не запускайте GUI на Wayland-сокете пользователя:
окно появится у него на экране.

### 11.4. Бенчмарки «до/после»

Старый шлюз лежит в `legacy/envbox-2026.10.31.18.py` (та же командная строка). Сравнивать запускаемые процессы:
`python3 -I <файл> proxy --socket S --log L --allow-private`; клиент — `asyncio.open_unix_connection(S)` + `CONNECT 127.0.0.1:порт`.
Старт: `python3 -I -X importtime dist/envbox.py version 2>&1 | sort -t'|' -k2 -n -r | head`.

### 11.5. Граф зависимостей модулей

```bash
python3 - <<'PY'
import ast, build
for mod, path in sorted(build.module_files().items()):
    t = ast.parse(open(path, encoding="utf-8").read())
    print(mod, "<-", sorted({build.resolve(mod, n) for n in t.body if isinstance(n, ast.ImportFrom) and n.level}))
PY
```
(запускать из корня проекта; `build.py` сам ловит циклы и запрещённые импорты).

### 11.6. Прокси и мост отдельно от среды

```bash
python3 -I dist/envbox.py proxy --socket /tmp/ebp/p.sock --log /tmp/ebp/p.log --allow-private &
python3 -I dist/envbox.py wrap --map 3999:/tmp/ebp/p.sock -- curl --noproxy '' -x http://127.0.0.1:3999 http://127.0.0.1:ПОРТ/
```
Порт 3128 внутри среды envbox занят её мостом — берите другой. `--noproxy ''` обязателен: в `NO_PROXY` стоит `127.0.0.1`.
Не убивайте `/run/envbox/proxy.sock` — это живой прокси, через который работает ваша же сессия.

### 11.7. Что чем проверять

| Изменение | Проверки |
|---|---|
| `net/*` | `tests/test_net.py`, `FastEntry`, бенчмарк если трогали горячий путь |
| `envbox.sh` | `bash -n`, §11.2 (+ сравнить `args.log`), на хосте `--dry-run` и реальный запуск |
| профиль/валидация | тест `validate`/`envbox_args`, §11.3 |
| GUI | импорт модулей + Broadway-дымовой тест; ручной просмотр делает пользователь |
| установка/`.pyc` | `tests/test_net.py::Install`, `install` в временном `HOME` |
| безопасность | регрессионный тест, который ПАДАЕТ без исправления (см. `HostChecks`, `GitCheck`, `ProxyTests`) |

---

## 12. Диагностика: симптом → причина → где смотреть

| Симптом у пользователя | Вероятная причина | Где смотреть / что делать |
|---|---|---|
| Claude (или другая программа) в среде «потерял сеть», просит войти заново | allowlist без `platform.claude.com` (обновление OAuth-токена) | `net.log`: `deny not-in-allowlist`; добавить `*.claude.com`, `*.claude.ai` (`CLAUDE_DOMAINS`) |
| Claude Desktop: «Connection problem», попытки каждые несколько секунд | в журнале повторяются `deny not-in-allowlist` для `bridge.claudeusercontent.com` (список профиля без него) | `CLAUDE_DESKTOP_DOMAINS` (пресет и миграция в `Profile.from_dict`); у профиля со своим списком — добавить хост вручную (вкладка «Сеть» → разрешить). Sentry/Datadog/GitHub отказы безвредны |
| Вход в браузере-среде: Google/Cloudflare пишут «браузер не прошёл проверку»; окно просмотра зависает после входа через Google | (1) порт отладки включает `navigator.webdriver`; (2) страница открыла JS-диалог (`alert`, `beforeunload`), пока он открыт, кадры не идут; (3) allowlist браузера не пускает `challenges.cloudflare.com`/`*.gstatic.com` | (1) `--disable-blink-features=AutomationControlled` в `core/browser.py browser_command`; (2) `cdp/viewer.py _page_event` закрывает диалоги сам; (3) `net.log` браузера: `deny not-in-allowlist` |
| Вход в Claude Desktop: «Couldn't verify your browser. Try again.» | allowlist среды без hCaptcha: в журнале `deny not-in-allowlist` для `js.hcaptcha.com` | `CLAUDE_DESKTOP_DOMAINS` (`*.hcaptcha.com`; миграция прежнего пресета — `OLD_CLAUDE_DESKTOP_DOMAINS`). У профиля со своим списком разрешить `*.hcaptcha.com` вручную (вкладка «Сеть»). Список всех отказов: `grep -h deny net.log`, поле `host` |
| В просмотре браузера страница не реагирует на клики, прокрутку, выделение (особенно «Finish sign-in in the Claude app») | страница перешла на `claude://…`: безоконный Chrome показал запрос о запуске программы, вкладка заблокирована | `cdp/viewer.py _page_event` (`Page.frameRequestedNavigation`) закрывает такую вкладку и отдаёт ссылку GUI (`browser_ask_external`); у среды-приложения в «Схемах ссылок» должна быть `claude` |
| Страница пишет «окно слишком маленькое» (`Authorize isn't available in a window this small`); масштаб страницу не меняет | безоконный Chrome сообщал `outerWidth/Height` 500x87 и `screen` 1x1; масштаб был CSS-зумом | `CdpViewer._apply_metrics` (экран, окно, `deviceScaleFactor`); проверка на настоящем Chrome: страница с `outerWidth`, `screen.width`, `devicePixelRatio` |
| Вход в Claude CLI: после капчи в браузере-среде «127.0.0.1 refused to connect» (`/callback?code=…`) | порт слушает CLI в другой среде, браузер до него не дотягивается | `CdpViewer` ловит `unreachableUrl` → GUI спрашивает и вызывает `send_link_to_env`; у среды CLI включено «Принимать вход по ссылке localhost» (`link_callback`) |
| Ссылка из письма (https://claude.ai/magic-link…) не передаётся Claude Desktop | кнопка «Передать приложению» отдаёт приложению https-ссылку, а оно понимает `claude://`; «В браузере компьютера» работает только со связанной схемой | диалог «Ссылка…» (`gui/pages/links.py on_open_link`): «В браузере envbox» открывает ссылку в среде-браузере, `claude://` перехватывается и передаётся приложению |
| Claude Desktop: «Войти через Google» не работает или предпросмотр/артефакты пустые | в журнале `deny not-in-allowlist` для `accounts.google.com`, `www.google.com`, `*.gstatic.com` (вход идёт окном внутри приложения: `claude.ai/login/popup-google-auth`) или `<случайное>.frame.claudeusercontent.com` | `CLAUDE_DESKTOP_DOMAINS` (миграция прежних списков пресета — `OLD_CLAUDE_DESKTOP_DOMAINS*`); у профиля со своим списком добавить эти сайты вручную |
| Claude «бесконечно думает» и/или большая загрузка (npm, 330 МБ) обрывается, хотя короткие запросы идут | вышестоящий прокси рвёт каждый туннель ровно через ~60 с после установки, независимо от активности (журнал: `close` с `end=upstream`, `ms` ≈ 60.5–63.3 с и у многих соединений одинаковый; у простаивающих `down_last` задолго до конца; у загрузок `down` десятки–сотни МБ и тот же `ms`; `end=client` у npm с `down=0` — клиент сам сдался) | `python3 -c` по `net.log`: сгруппировать `close` по `ts` и `ms`; проверка без envbox: `curl -x прокси -m 100 https://speed.cloudflare.com/__down?bytes=2000000000` — обрыв на ~60 с подтверждает предел самого прокси. Лечится у поставщика (длинная/«липкая» сессия, статический адрес, другой порт/протокол) или `direct_domains` для сайтов, которым прокси не нужен (npm). Метки `up_end/down_first/down_last` в `close` показывают, кто молчит |
| 403 «Private address forbidden» на обычных сайтах | локальный DNS отдаёт частные/нулевые адреса (fake-ip 198.18/15 уже разрешён; `0.0.0.0` от блокировщиков, split-DNS, Tailscale `100.64/10`) | `net.log`: `deny private-address`, поле `resolved`; `--dns`, `--net-allow-private` или чинить DNS |
| 502 «Upstream proxy failed» | вышестоящий прокси (VPN-клиент) не запущен/не отвечает/требует пароль; цель недоступна (ждёт 15 с) | `net.log`: `error upstream: …`; `envbox.py probe --upstream URL` |
| 502 «DNS resolution failed» | не работает DNS хоста или заданные `--dns` | `error dns: …`; `Resolver` кэширует отказ 2 с |
| Долгие зависания только на части сайтов | IPv6 «чёрная дыра» (раньше ждали 15 с) | `connect_race`; смотреть `ip` в `open` |
| Соединения «залипают» после сна/смены VPN | мёртвые TCP без keepalive | `tune_socket` (60/15/4 с) |
| Claude «бесконечно думает», «Connection problem», запросы повторяются | (1) среда работает со СТАРЫМ шлюзом: смотрите `python3 -I /run/envbox/net.py version` внутри среды и версию в заголовке GUI; (2) туннель через вышестоящий прокси умер молча, а клиент ждёт свой тайм-аут (у профиля может быть `API_TIMEOUT_MS=900000`); (3) потерянный пакет при установке туннеля: 2 с и 7 с на подключение | (2) `Proxy.pipe`: нет байтов в обе стороны `IDLE_TIMEOUT` (180 с) — прокси закрывает соединение, в журнале `close` с `idle`; (3) `Proxy.hedged_tunnel`: второй туннель через `HEDGE_DELAY` (2 с), побеждает первый готовый; не более `MAX_HEDGES` одновременно (иначе перегруженный upstream получает вдвое больше), событие `hedge` в журнале; не более `MAX_SETUPS` (8) одновременных установок туннеля, остальные ждут в очереди (`wait_ms` в `open`); в `close` поле `end` — кто закончил: `client`, `upstream`, `idle`. Статистика «60 с»: закрытия с `ms` 59000–62000 |
| «прокси сетевого журнала завершился при запуске» | прокси упал при старте: `.pyc` от другой версии Python, ошибка аргументов, нет `/usr/bin/python3` | запустить вручную `python3 -I ~/.local/share/envbox/envbox.py proxy …`; проверить `envbox.pyc.python`; `python3 envbox.py install` |
| Среда не стартует: «bubblewrap не смог создать среду» | отключить защиту, мешающую программе (`--iso k=off`) или AppArmor userns | вывод самопроверки в `run_sandbox`; `diagnose_userns` |
| После выхода «изменилось то, что запускается при командах git» | среда меняла `.git/config`, хуки, `commondir` или создала `.git` | сообщение `gitcheck verify` (код 4); проверить `ls -la .git/hooks; git config --local --list` |
| Ссылки из среды не открываются | GUI не запущен (читает `run/links`), ссылка отклонена `parse_link` | `open-link.log`, статус GUI |
| Старт GUI медленный | импорт GTK/создание окна; не путать со стартом среды | `python3 -X importtime dev.py` |

---

## 13. Ловушки (на них уже наступали)

1. **Версия с ведущим нулём** (`2026.11.01.1`): сравнивать числами (`install.compile_installed`), не строками.
2. **`as` в относительном импорте** — сборщик вырезает строку целиком, псевдоним пропадает (теперь `build.py` ругается).
3. **Путь unix-сокета ≤ 107 байт**: тесты и заглушки — в коротком каталоге; `envbox.sh` требует `${#sock} < 100`.
4. **`HOME` в тестах подменён** → `~` раскрывается в тестовый каталог; пути к исходникам давайте абсолютными.
5. **`list_sessions(proc)`**: вспомогательные `_proc_args/_proc_stat` тоже принимают `proc` (иначе тест на поддельном `/proc` читает настоящий).
6. **Python 3.14**: `argparse` тянет `_colorize → dataclasses → inspect` (~18 мс); `asyncio` ≈ 45 мс (`concurrent.futures → logging → traceback`).
7. **`os._exit(0)` в конце `cmd_proxy`**: потоки DNS могут висеть; журнал построчный, ничего буферизованного после выхода быть не должно.
8. **`pkill -f шаблон`** может убить собственный шелл, если шаблон есть в командной строке — используйте `kill $!`.
9. **Проверка безопасности Claude** блокирует `rm -rf` по переменной/внутри `bash -c`; чистите литеральными путями или оставляйте пользователю.
10. **Эта сессия сама внутри envbox**: порт 3128 занят, `NO_PROXY` включает loopback, `/run/envbox/net.py` — установленная (старая) копия шлюза.
11. **Не перезаписывайте** `~/envbox.py`, `~/.local/share/envbox/*`, `~/.envbox/*` без прямой просьбы пользователя; установку на хост делает он.
12. **`dist/envbox.py` — артефакт**: тесты запускают его как подпроцесс, поэтому после правок `src/` сначала `python3 build.py`.
13. **Имена методов миксинов GUI** общие для всего окна — перед добавлением `grep -rn "def имя" src/envbox/gui`.
14. **Кэш DNS**: `Resolver` ключуется по имени хоста; в тестах подменяйте `socket.getaddrinfo` (ленивый модуль берёт атрибут настоящего).
15. **GTK ≥ 4.10**, Vte 3.91 необязателен (без него терминал во внешнем окне).
16. **Два «одинаковых» пути к проекту.** Внутри среды (например Clauder) `/home/huesos/Projects/envbox` — это каталог в
    домашнем каталоге СРЕДЫ; на хосте он лежит в `~/.envbox/<среда>/home/Projects/envbox`, а `~/Projects/envbox` на хосте —
    другое место, которое правки агента не видят. Команды для пользователя (`install`, `build-appimage`) давайте с путём
    хоста, и просите сверить вывод `--version` (`install` теперь печатает версию файла и установленной копии).
    Признак ошибки: после `install --force` нет строки «Версия этого файла» — запущен старый файл.

---

## 14. Состояние и открытые вопросы

- Версия на момент написания: см. `src/envbox/version.py`. Последние крупные изменения: быстрый вход шлюза и ленивые модули,
  кэш DNS и Happy Eyeballs в прокси, `canon_host`, метка `.pyc.python`, расширение домена пресета Claude, раннее/параллельное
  начало работы в `envbox.sh`, инкрементальная сводка сети в GUI.
- Реальный запуск среды через bwrap после этих изменений в песочнице Claude не проверялся; `envbox.sh` проверен с заглушкой.
  Пользователь должен поставить сборку на хост (`python3 dist/envbox.py install`) и перезапустить среды.
- `envbox-x86_64.AppImage` в корне — старая сборка; пересборка (`build-appimage`) скачивает appimagetool из сети.
- Не закрыто по аудиту безопасности: §9.4.
- Есть идеи, не реализованные: ограничение портов в allowlist; защита хуков во вложенных репозиториях; seccomp для aarch64;
  замена потокового моста на более лёгкий; отказ от asyncio в прокси ради старта (сейчас перекрыт параллельным запуском).

---

## 15. Словарь

| Термин | Значение |
|---|---|
| среда | одна песочница: каталог `<корень>/<имя>` + профиль |
| профиль | `profile.json` / `Profile`: всё, что определяет запуск среды |
| каталог данных / корень | `~/.envbox` (или заданный) — хранит среды, `gui.json`, `_global` |
| глобальная папка | `_global/<имя>`: общий каталог, подключаемый к нескольким средам (ro/rw) |
| шлюз | сетевая часть: `net/*` (прокси, DNS, мосты, seccomp, gitcheck) |
| мост (`wrap`) | процесс внутри среды: 127.0.0.1:3128 ↔ unix-сокет прокси; также inbox |
| вышестоящий прокси (upstream) | внешний http/socks5-прокси, через который идёт весь трафик среды |
| сеанс | запущенная среда (внешний процесс `bwrap` с меткой `ENVBOX_SESSION`) |
| быстрый вход | начало `dist/envbox.py`: шлюз стартует, не загружая остальной код |
| inbox / links | каналы ссылок: внутрь среды / из среды наружу |
| CDP | протокол DevTools Chrome (управление браузером-средой) |
| allowlist | режим сети «только выбранные домены» (`*.x.com` = домен и все поддомены) |
