"""Человеческое описание того, что получит среда (для вкладки «Обзор»)."""

from .consts import ATTACH_RE
from .fsutil import tilde
from .isolation import ISO_OPTIONS
from .root import GLOBAL_ENTRY_RE, box_dir, global_root


def describe(p):
    """Что получает среда — простыми словами: список (уровень, текст).

    Уровни: ok — защита, info — справка, warn — то, что ослабляет изоляцию.
    """
    out = []
    home = f"{tilde(box_dir(p.name))}/home"
    if p.host_files:
        mode = "только чтение (писать можно в проект)" if p.host_files == "ro" else "чтение и запись"
        out.append(("warn", f"ДОСТУП К КОМПЬЮТЕРУ: среда видит все ваши файлы, включая настоящий домашний "
                            f"каталог, ключи SSH и браузерные профили — {mode}. Это почти не песочница: "
                            "всё, что программа прочитает, она может отправить на разрешённые сайты. "
                            "Сеть, язык, пояс и DNS остаются заданными; данные других сред envbox скрыты."))
    elif p.ephemeral:
        out.append(("ok", "Домашний каталог временный: после выхода всё в нём стирается. "
                          "Ваши настоящие файлы скрыты."))
    else:
        out.append(("ok", f"Свой домашний каталог {home}. Ваши настоящие файлы, ключи SSH и "
                          "браузерные профили скрыты."))
    if p.host_files:
        pass
    elif p.no_workdir and not p.is_browser:
        out.append(("ok", "Каталога проекта нет: записывает только в свой домашний каталог."))
    elif p.is_browser:
        out.append(("ok", "Записывает только в собственный профиль браузера внутри этого каталога."))
    else:
        out.append(("ok", f"Записывать может только в проект: {p.workdir or '— не выбран —'}."))
    if p.rw:
        out.append(("warn", "Дополнительно может записывать в папки: " + ", ".join(p.rw) + ". "
                            "Всё, что программа там изменит или удалит, на вашем компьютере изменится по-настоящему."))
    if p.global_on:
        active = [g for g in p.global_folders if GLOBAL_ENTRY_RE.match(g)]
        if active:
            names = ", ".join(f"{g.split(':')[0]} ({'чтение и запись' if g.endswith(':rw') else 'только чтение'})"
                              for g in active)
            level = "warn" if any(g.endswith(":rw") for g in active) else "info"
            out.append((level, f"Глобальные папки ({tilde(global_root())}): {names}. Они лежат отдельно от среды: "
                               "при удалении среды остаются на месте."))
        else:
            out.append(("info", "Глобальные папки разрешены, но ни одна не выбрана."))
    off = [o for o in ISO_OPTIONS if o["warn_off"] and not p.iso_on(o["key"])
           and not (p.is_browser and (o.get("app_only")
                                      or (o["key"] == "no_userns" and p.browser_chrome_sandbox)))]
    if p.iso_on("home_real") and not p.host_files:
        out.append(("warn", "Среда работает с настоящим домашним каталогом: личные файлы, ключи SSH и "
                            "браузерные профили доступны и могут быть изменены. Изоляция от вашей "
                            "учётной записи практически отсутствует."))
    if not off:
        out.append(("ok", "Все защиты включены: фильтр системных вызовов, скрытые процессы, свой IPC и "
                          "имя компьютера, только прокси для сети, адреса ваших DNS скрыты."))
    for o in off:
        out.append(("warn", f"Выключено: «{o['title']}» — {o['risk']}"))
    reads = "Системные программы и библиотеки (/usr) видны только на чтение"
    if p.ro:
        reads += "; дополнительно читает: " + ", ".join(p.ro)
    out.append(("info", reads + "."))
    if not p.is_browser and p.shell_cmd != "bash":
        out.append(("info", f"Оболочка в терминале: {p.shell_cmd} (программа берётся с компьютера, только чтение; "
                            "стартовые настройки лежат в домашнем каталоге среды)."))
    names = [e.split("=", 1)[0] for e in p.env] + list(p.secrets)
    if names:
        tail = " (значения секретов берутся из keyring)" if p.secrets else ""
        out.append(("info", "Из окружения получает только: " + ", ".join(names) + tail + "."))
    else:
        out.append(("ok", "Переменные окружения компьютера не передаются."))

    if p.lang or p.timezone:
        bits = ([f"язык {p.lang}"] if p.lang else []) + ([f"часовой пояс {p.timezone}"] if p.timezone else [])
        out.append(("info", "Система внутри среды: " + ", ".join(bits) + "."))
    if p.net == "off":
        out.append(("ok", "Сети нет: программа работает офлайн."))
    elif p.net == "log":
        out.append(("info", "В сеть выходит только через прокси на вашем компьютере; "
                            "каждое обращение записывается в журнал."))
    elif p.net == "allowlist":
        out.append(("ok", "В сеть выходит только к: " + (", ".join(p.allow_domains) or "— список пуст —")
                    + ". Всё остальное блокируется и записывается в журнал."))
        out.append(("info", "Список ограничивает сайты, но не порты, и не мешает передать данные "
                            "самим разрешённым сервисам (например, в облачное хранилище). "
                            "Для строгого контроля смотрите журнал сети."))
    else:
        out.append(("warn", "Сеть общая с компьютером: доступны все сервисы на localhost "
                            "(базы данных, отладочные порты). Для ИИ этот режим не подходит."))
    if p.dns and p.net != "off" and not (p.upstream and p.net in ("log", "allowlist")):
        out.append(("info", "Имена сайтов разрешают DNS-серверы " + ", ".join(p.dns)
                    + ": запросы идут по сети без шифрования, их видит сеть и владелец сервера."))
    if p.upstream and p.net in ("log", "allowlist"):
        who = "логином и паролем из keyring" if p.upstream_auth else "без логина"
        out.append(("info", f"Дальше трафик идёт через ваш прокси {p.upstream} ({who}); "
                            "имена сайтов разрешает он."))
        if p.direct_domains:
            out.append(("warn", "Напрямую, мимо этого прокси, пойдут: " + ", ".join(p.direct_domains) +
                        ". Эти сайты увидят ваш настоящий адрес. Программа в среде по-прежнему видит только "
                        "прокси envbox."))
    if not p.is_browser and (p.link_handler or p.link_callback):
        bits = []
        if p.link_handler:
            bits.append("ссылки " + ", ".join(f"{x}://" for x in p.link_schemes + ["http(s)"]) +
                        f" передаются приложению внутри среды командой «{p.link_handler}»")
        if p.link_callback:
            bits.append("адреса вида http://localhost:порт/… (вход по ссылке в CLI) выполняются внутри среды")
        out.append(("info", "Приём ссылок: " + "; ".join(bits) + ". Отправляете их вы: кнопкой «Ссылка…» или "
                            "из браузера, если схема связана с этой средой."))
    if p.net_allow_private and p.net in ("log", "allowlist"):
        out.append(("warn", "Прокси пускает и на частные адреса (localhost, локальная сеть): "
                            "среда сможет обращаться к сервисам вашего компьютера."))
    if p.is_browser:
        if p.browser_visible:
            out.append(("warn", "Окно браузера показывается через Wayland: доступ к сокету Wayland "
                                "ослабляет изоляцию (композитор может отдавать снимки экрана)."))
        else:
            out.append(("ok", "Браузер без отдельного окна: страницу видно на вкладке «Окно браузера» в приложении; "
                              "управлять им могут только подключённые к нему среды (через CDP по закрытому "
                              "unix-сокету)."))
        if not p.browser_chrome_sandbox:
            out.append(("warn", "Встроенный sandbox Chrome выключен: защита держится только на bubblewrap."))
    else:
        if p.protect_git:
            out.append(("ok", "Хуки и config в .git защищены от записи, сам .git нельзя заменить; "
                              "после выхода envbox сравнит их с состоянием до запуска и предупредит, "
                              "если что-то изменилось (проверяйте перед git-командами на компьютере)."))
        else:
            out.append(("warn", "Защита .git/hooks выключена: программа может подложить хук, "
                                "который выполнится у вас при git-командах."))
    if p.allow_userns:
        out.append(("warn", "Разрешены вложенные user namespaces: шире поверхность атаки на ядро."))
    if not p.is_browser:
        if p.expose_ports:
            out.append(("info", "Порты " + ", ".join(p.expose_ports) + " доступны подключённым средам через "
                                "закрытый сокет (никому больше); сама среда к ним не подключается."))
        if p.gui_wayland:
            out.append(("warn", "Окно приложения показывается через Wayland: доступ к сокету Wayland ослабляет "
                                "изоляцию (композитор может отдавать снимки экрана)."))
        out.append(("info", "Установка («Установить…»): без вашего проекта и секретов; сеть — "
                            + ("только " + ", ".join(p.install_domains) if p.install_domains
                               else "любые публичные сайты с журналом") + "."))
    for spec in p.attach:
        m = ATTACH_RE.match(spec)
        target = m.group(1) if m else spec
        out.append(("warn", f"Подключён браузер «{target}»: среда получает полный контроль над ним "
                            "(страницы, cookies, сеансы в его профиле)."))
        if p.net == "off":
            out.append(("warn", "Своей сети нет, но через браузер выход в интернет возможен."))
        elif p.net == "allowlist":
            out.append(("warn", "Список сайтов этой среды не ограничивает браузер: "
                                "у него действуют собственные правила сети."))
    return out
