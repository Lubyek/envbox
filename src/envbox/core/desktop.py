"""Ярлык и значок envbox в меню приложений."""

import os
import re

from ..resources import resource_text
from .consts import INSTALLED_PY


# ------------------------------------------------------------ ярлык меню

def _desktop_quote(arg):
    """Кавычки по спецификации Desktop Entry (только двойные)."""
    if re.fullmatch(r"[A-Za-z0-9_./+-]+", arg):
        return arg
    return '"' + re.sub(r'(["`$\\])', r"\\\1", arg).replace("%", "%%") + '"'


ICON_SVG = resource_text("icon.svg")


def install_desktop_entry(gui_path=None):
    """Ярлык в меню приложений и значок. В AppImage ярлык указывает на сам файл AppImage."""
    data = os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share")
    apps = os.path.join(data, "applications")
    icons = os.path.join(data, "icons", "hicolor", "scalable", "apps")
    os.makedirs(apps, exist_ok=True)
    os.makedirs(icons, exist_ok=True)
    with open(os.path.join(icons, "envbox.svg"), "w", encoding="utf-8") as f:
        f.write(ICON_SVG)
    appimage = os.environ.get("APPIMAGE", "")
    if appimage and os.path.isfile(appimage):
        exec_line = _desktop_quote(os.path.realpath(appimage))
    else:
        exec_line = "/usr/bin/python3 " + _desktop_quote(INSTALLED_PY)
    path = os.path.join(apps, "envbox.desktop")
    text = ("[Desktop Entry]\nType=Application\nName=envbox\n"
            "Comment=Изолированные среды на bubblewrap\n"
            f"Exec={exec_line}\n"
            "Icon=envbox\nTerminal=false\nCategories=System;Security;\n")
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return path
