"""Точка входа: разбор подкоманд (gui, install, run, root, global, net-команды…)."""

import os
import sys

from .appimage import build_appimage
from .core.consts import ENVBOX_SH, INSTALL_DIR, INSTALLED_PY
from .core.desktop import install_desktop_entry
from .core.link_handler import cmd_open_link
from .core.root import (
    configured_root,
    create_global_folder,
    default_root,
    envbox_root,
    global_root,
    list_global_folders,
    root_error,
    set_root,
)
from .core.rootops import delete_global_folder, move_root
from .install import ensure_installed, file_version_text
from .net.entry import NET_COMMANDS, net_main
from .resources import resource_text
from .version import ENVBOX_VERSION


def cmd_root(argv):
    """envbox root [ПУТЬ | --reset] [--move]: показать или сменить каталог данных."""
    move = "--move" in argv
    rest = [a for a in argv if a != "--move"]
    try:
        if not rest:
            print(envbox_root())
            src = ("ENVBOX_ROOT" if os.environ.get("ENVBOX_ROOT", "").strip() else
                   "выбран пользователем" if configured_root() else "стандартный")
            print(f"({src}; глобальные папки: {global_root()})", file=sys.stderr)
            return 0
        if len(rest) != 1:
            raise ValueError("ожидается один путь или --reset")
        if os.environ.get("ENVBOX_ROOT", "").strip():
            raise ValueError("каталог задан переменной ENVBOX_ROOT: уберите её, чтобы менять выбор")
        old = envbox_root()
        target = os.path.realpath(default_root()) if rest[0] == "--reset" else os.path.realpath(
            os.path.expanduser(rest[0]))
        if rest[0] != "--reset" and not os.path.isabs(os.path.expanduser(rest[0])):
            raise ValueError("нужен абсолютный путь")
        err = root_error(target)
        if err:
            raise ValueError(err)
        if move:
            move_root(old, target)
        set_root("" if target == os.path.realpath(default_root()) else target)
        print(f"Каталог данных: {envbox_root()}" + (" (данные перенесены)" if move and old != target else ""))
        return 0
    except (OSError, ValueError) as e:
        print(f"envbox: {e}", file=sys.stderr)
        return 1


def cmd_global(argv):
    """envbox global [list | create ИМЯ | delete ИМЯ]: глобальные папки."""
    sub = argv[0] if argv else "list"
    try:
        if sub == "list" and len(argv) <= 1:
            for n in list_global_folders():
                print(n)
            return 0
        if sub == "create" and len(argv) == 2:
            print(create_global_folder(argv[1]))
            return 0
        if sub == "delete" and len(argv) == 2:
            delete_global_folder(argv[1])
            print(f"Глобальная папка «{argv[1]}» удалена")
            return 0
        raise ValueError("использование: envbox.py global [list | create ИМЯ | delete ИМЯ]")
    except (OSError, ValueError) as e:
        print(f"envbox: {e}", file=sys.stderr)
        return 1


def main():
    argv = sys.argv[1:]
    cmd = argv[0] if argv else "gui"
    if cmd in NET_COMMANDS:          # сетевой шлюз: вызывается из envbox.sh и из песочницы
        return net_main()
    if cmd in ("-h", "--help", "help"):
        print(resource_text("help.txt"))
        return 0
    if cmd in ("-V", "--version"):
        print(ENVBOX_VERSION)
        return 0
    if cmd == "build-appimage":
        return build_appimage(argv[1:])
    if cmd == "root":
        return cmd_root(argv[1:])
    if cmd == "global":
        return cmd_global(argv[1:])
    if cmd == "install":
        changed = ensure_installed(force="--force" in argv[1:])
        print("Установлено в", INSTALL_DIR if changed else f"{INSTALL_DIR} (уже актуально)")
        print("Команда: ~/.local/bin/envbox  (добавьте ~/.local/bin в PATH, если его там нет)")
        installed = file_version_text(INSTALLED_PY)
        print(f"Версия этого файла: {ENVBOX_VERSION}; установленной копии: {installed or 'нет'}")
        if installed != ENVBOX_VERSION:
            print("⚠ Установленная копия отличается от этого файла: шлюз и среды работают из неё. "
                  "Повторите: python3 envbox.py install --force", file=sys.stderr)
            return 1
        return 0
    if cmd == "run":
        ensure_installed()
        os.execv(ENVBOX_SH, [ENVBOX_SH, *argv[1:]])
    if cmd == "open-link":
        return cmd_open_link(argv[1:])
    if cmd == "--install-desktop":
        ensure_installed()
        print("Ярлык создан:", install_desktop_entry())
        return 0
    if cmd == "gui":
        argv = argv[1:]
    if argv:
        print(f"envbox: неизвестная команда: {argv[0]} (см. python3 envbox.py --help)", file=sys.stderr)
        return 2
    ensure_installed()
    from .gui.app import gui_main
    return gui_main()
