# Карта модулей

Файл создаётся командой `python3 build.py map` — не править руками.

- `src/envbox/appimage.py` (100 стр.) — Сборка AppImage.
  build_appimage()
- `src/envbox/cdp/browser.py` (85 стр.) — CDP: управление страницей браузера (навигация, вкладки, скрипты).
  CdpBrowser (8 методов)
- `src/envbox/cdp/client.py` (174 стр.) — CDP: клиент WebSocket DevTools.
  CdpClient (10 методов)
- `src/envbox/cdp/http.py` (125 стр.) — CDP: HTTP-запросы к DevTools через unix-сокет.
  cdp_listening(), CdpError (0 методов), cdp_http(), cdp_pick_page()
- `src/envbox/cdp/keys.py` (73 стр.) — CDP: перевод координат, клавиш и масштаба.
  normalize_url(), map_point(), cdp_key_events()
- `src/envbox/cdp/viewer.py` (386 стр.) — CDP: просмотр страницы в окне (кадры экрана, ввод).
  external_scheme(), local_callback_url(), CdpViewer (35 методов)
- `src/envbox/cli.py` (125 стр.) — Точка входа: разбор подкоманд (gui, install, run, root, global, net-команды…).
  cmd_root(), cmd_global(), main()
- `src/envbox/core/browser.py` (124 стр.) — Среды-браузеры: поиск Chrome/Chromium, монтирование, команда запуска, CDP-сокет.
  find_browser(), browser_mounts(), host_program_in_home(), browser_display_flag(), browser_command(), cdp_socket_path(), attach_snippets()
- `src/envbox/core/consts.py` (113 стр.) — Общие константы ядра: регулярные выражения, режимы сети, подписи, пути установки.
- `src/envbox/core/describe.py` (173 стр.) — Человеческое описание того, что получит среда (для вкладки «Обзор»).
  describe()
- `src/envbox/core/desktop.py` (43 стр.) — Ярлык и значок envbox в меню приложений.
  install_desktop_entry()
- `src/envbox/core/diagnostics.py` (95 стр.) — Диагностика: что есть на компьютере для работы envbox.
  diagnostics()
- `src/envbox/core/fsutil.py` (50 стр.) — Файловые помощники: приватная запись, надёжное удаление, проверка вложенности путей.
  tilde()
- `src/envbox/core/isolation.py` (200 стр.) — Параметры изоляции, пресеты и рецепты установки программ.
  env_has_tool(), recipe_warning(), recipe_placeholders()
- `src/envbox/core/keyring.py` (38 стр.) — Секреты в keyring (secret-tool).
  secret_tool_available(), secret_store(), secret_exists(), secret_lookup(), secret_clear()
- `src/envbox/core/link_handler.py` (98 стр.) — Обработчик ссылок envbox в системе (xdg desktop) и команда open-link.
  link_handler_desktop(), install_link_handler(), link_handler_installed(), remove_link_handler(), cmd_open_link()
- `src/envbox/core/links.py` (313 стр.) — Ссылки из среды: очередь, выбор браузера, отправка в среду.
  parse_link(), link_spool_dir(), read_link_spool(), link_spool_pending(), cdp_open_url(), browser_profiles_names(), url_scheme(), parse_inbound(), inbox_dir(), send_link(), inbox_result(), env_running(), find_env_for_url(), open_link_in_env() …
- `src/envbox/core/netlog.py` (103 стр.) — Журнал сети среды: чтение с хвоста, сводка, очистка.
  net_log_path(), LogTail (2 методов), NetSummary (3 методов), summarize(), clear_net_log()
- `src/envbox/core/profile.py` (572 стр.) — Профиль среды (dataclass Profile) и его проверка.
  Profile (20 методов), locale_available(), timezone_exists(), new_profile()
- `src/envbox/core/root.py` (139 стр.) — Каталог данных envbox и глобальные папки (_global): выбор, создание, перенос.
  default_root(), root_pointer_path(), configured_root(), root_error(), envbox_root(), reset_root_cache(), set_root(), box_dir(), global_root(), global_path(), list_global_folders(), create_global_folder()
- `src/envbox/core/rootops.py` (129 стр.) — Операции над каталогом данных и глобальными папками, затрагивающие профили и сеансы: перенос, удаление, список пользователей.
  global_folder_users(), delete_global_folder(), move_root()
- `src/envbox/core/sessions.py` (105 стр.) — Запущенные сеансы сред: поиск в /proc, остановка.
  Session (0 методов), list_sessions(), stop_session(), format_duration()
- `src/envbox/core/store.py` (106 стр.) — Хранение профилей и настроек на диске.
  browser_profiles(), profile_path(), list_profiles(), load_profile(), save_profile(), copy_profile(), delete_profile(), settings_path(), load_settings(), save_settings()
- `src/envbox/core/system.py` (47 стр.) — Сведения о системе: доступные оболочки, дистрибутив, подсказки по установке пакетов.
  installed_shells(), pkg_hint()
- `src/envbox/core/terminal.py` (111 стр.) — Запуск терминала со средой (внешнее окно, пробный запуск, фон).
  detect_terminal(), terminal_argv(), dry_run(), launch_background(), read_tail()
- `src/envbox/core/upstream.py` (70 стр.) — Вышестоящий прокси профиля: разбор URL, чтение из файла, проверка.
  split_proxy_url(), read_proxy_file(), probe_upstream()
- `src/envbox/core/vpn.py` (616 стр.) — Хранилище VPN-конфигураций: импорт, список, удаление и проверка наличия клиента.
  vpn_dir(), vpn_path(), vpn_name_from_file(), exit_chain(), exit_mode(), normalize_name(), free_name(), looks_like_source(), is_subscription_url(), clean_folder(), load_meta(), save_meta(), set_folder(), human_bytes() …
- `src/envbox/gui/app.py` (24 стр.) — Приложение GTK и точка входа gui_main.
  App (2 методов), gui_main()
- `src/envbox/gui/browser/page.py` (412 стр.) — Страница встроенного браузера: подключение, отключение, запуск.
  BrowserPageMixin (20 методов)
- `src/envbox/gui/browser/view.py` (406 стр.) — Встроенный браузер: вкладки, масштаб, поиск, меню, мышь и клавиатура.
  BrowserViewMixin (24 методов)
- `src/envbox/gui/consts.py` (23 стр.) — Константы GUI: CSS, значки, метки.
- `src/envbox/gui/gtk.py` (43 стр.) — Импорт GTK 4 (с перезапуском под системным Python и понятной ошибкой).
- `src/envbox/gui/pages/folders.py` (284 стр.) — Глобальные папки и каталог данных.
  FoldersMixin (8 методов)
- `src/envbox/gui/pages/isolation.py` (234 стр.) — Вкладка «Изоляция».
  IsolationMixin (13 методов)
- `src/envbox/gui/pages/launch.py` (224 стр.) — Запуск среды: терминал, браузер, установка программ, остановка.
  LaunchMixin (7 методов)
- `src/envbox/gui/pages/links.py` (502 стр.) — Ссылки: очередь запросов, выбор браузера, привязка схем.
  LinksMixin (16 методов)
- `src/envbox/gui/pages/net_page.py` (166 стр.) — Вкладка «Сеть»: журнал, фильтр, разрешение доменов, сеансы.
  NetPageMixin (11 методов)
- `src/envbox/gui/pages/overview.py` (162 стр.) — Страницы «Добро пожаловать» и «Обзор».
  OverviewMixin (3 методов)
- `src/envbox/gui/pages/profile_net.py` (331 стр.) — Настройки сети среды: секрет, прокси, подключение приложений, CDP.
  ProfileNetMixin (18 методов)
- `src/envbox/gui/pages/profile_page.py` (570 стр.) — Страница настроек среды: сбор формы, сохранение.
  ProfilePageMixin (10 методов)
- `src/envbox/gui/pages/settings.py` (114 стр.) — Настройки приложения, диагностика, ярлык.
  version_line(), SettingsMixin (5 методов)
- `src/envbox/gui/pages/sidebar.py` (212 стр.) — Боковая панель: список сред, создание, копирование, удаление.
  SidebarMixin (6 методов)
- `src/envbox/gui/pages/terminal.py` (276 стр.) — Встроенный терминал (VTE).
  TerminalMixin (9 методов)
- `src/envbox/gui/pages/vpn.py` (391 стр.) — Вкладка «VPN»: серверы по папкам (сервисам), поиск, пинг, загрузка, проверка и удаление.
  VpnPageMixin (21 методов)
- `src/envbox/gui/tables.py` (62 стр.) — Таблицы и строки списков GUI.
  Row (1 методов), Table (5 методов)
- `src/envbox/gui/widgets.py` (222 стр.) — Мелкие виджеты и диалоги GTK: кнопки, карточки, переключатели, alert/choose/prompt.
  to_home(), margins(), text_area(), get_text(), get_lines(), set_text(), hint(), alert(), choose(), prompt(), icon_button(), set_button_text(), badge(), card() …
- `src/envbox/gui/window.py` (234 стр.) — Главное окно: собирается из миксинов страниц (gui/pages/*, gui/browser/*).
  EnvboxWindow (10 методов)
- `src/envbox/install.py` (128 стр.) — Установка: самокопирование в ~/.local/share/envbox, извлечение envbox.sh, команда envbox.
  file_version_text(), file_version(), compile_installed(), ensure_installed()
- `src/envbox/lazy.py` (29 стр.) — Ленивые модули стандартной библиотеки: настоящий import происходит при первом обращении к атрибуту.
  _LazyModule (2 методов)
- `src/envbox/net/bridge.py` (255 стр.) — Сетевой шлюз: мосты unix-сокет <-> localhost, канал ссылок (команды wrap, probe).
  pump(), dial_unix(), dial_tcp(), parse_port(), inbox_handle(), inbox_loop(), cmd_wrap(), cmd_probe()
- `src/envbox/net/chain.py` (109 стр.) — Сетевой шлюз: цепочка каналов выхода (прокси, VPN-клиент, прямой выход) с переключением на запасной.
  Channel (2 методов), Chain (8 методов), parse_chain_spec(), probe()
- `src/envbox/net/common.py` (122 стр.) — Сетевой шлюз: общие константы и мелкие помощники (время, host:port, публичные адреса, имена хостов).
  now(), split_hostport(), is_public(), canon_host(), tune_socket()
- `src/envbox/net/connect.py` (73 стр.) — Сетевой шлюз: подключение к одному из адресов хоста (Happy Eyeballs).
  interleave(), connect_race()
- `src/envbox/net/dns.py` (253 стр.) — Сетевой шлюз: свой DNS-клиент и проверки имён/адресов.
  dns_lookup(), dns_resolve_blocking(), Resolver (3 методов), is_private_name(), is_ip_literal()
- `src/envbox/net/entry.py` (124 стр.) — Диспетчер служебных команд envbox.py, вызываемых из envbox.sh и из песочницы.
  NetArgs (1 методов), net_usage(), net_parse(), net_main()
- `src/envbox/net/gitcheck.py` (112 стр.) — Проверка Git после работы среды: хуки и config проекта не должны меняться незаметно.
  git_state(), cmd_gitcheck()
- `src/envbox/net/proxy.py` (551 стр.) — Сетевой шлюз: журналирующий прокси (команда proxy).
  host_matches(), err_text(), PrivateAddress (1 методов), OpenFailed (1 методов), Proxy (7 методов), build_chain(), cmd_proxy()
- `src/envbox/net/report.py` (112 стр.) — Сетевой шлюз: чтение и вывод журнала соединений (команда report).
  human(), clean(), events(), fmt_event(), cmd_report()
- `src/envbox/net/seccomp.py` (52 стр.) — seccomp-фильтр для bwrap (команда seccomp).
  seccomp_program_x86_64(), cmd_seccomp()
- `src/envbox/net/upstream.py` (121 стр.) — Сетевой шлюз: вышестоящий прокси (http / socks5 / socks5h).
  UpstreamError (0 методов), Upstream (2 методов)
- `src/envbox/net/vpn.py` (566 стр.) — Сетевой шлюз: VPN-клиенты как локальные SOCKS-прокси.
  detect_kind(), wg_sections(), wg_validate(), wg_runtime(), share_scheme(), b64decode(), stream_settings(), check_server(), parse_vmess_json(), parse_shadowsocks(), parse_share_link(), link_server(), is_stub_link(), stub_remark() …
- `src/envbox/resources.py` (9 стр.) — Встроенные ресурсы (envbox.sh, значки, CSS…): файлы из resources/; в собранном envbox.py они вшиты строками.
  resource_text()
- `src/envbox/selfpath.py` (21 стр.) — Пути к самому envbox: точка запуска (SELF) и единый файл для установки (bundle_path).
  bundle_path()
- `src/envbox/version.py` (4 стр.) — Версия envbox (строка читается регулярным выражением при установке — не менять формат).
