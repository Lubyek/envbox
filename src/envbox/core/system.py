"""Сведения о системе: доступные оболочки, дистрибутив, подсказки по установке пакетов."""

import re
import shutil

from .consts import SHELLS


def installed_shells():
    """Оболочки, доступные в среде: берутся с компьютера (bash есть всегда)."""
    return [x for x in SHELLS if x == "bash" or shutil.which(x)]


def _distro_id():
    try:
        with open("/etc/os-release", encoding="utf-8") as f:
            data = f.read()
    except OSError:
        return ""
    ids = re.findall(r"^(?:ID|ID_LIKE)=(.*)$", data, re.M)
    return " ".join(x.strip().strip('"') for x in ids).lower()


_PKGS = {
    "secret-tool": {"arch": "libsecret", "debian": "libsecret-tools", "fedora": "libsecret"},
    "bubblewrap": {"arch": "bubblewrap", "debian": "bubblewrap", "fedora": "bubblewrap"},
    "vte": {"arch": "vte4", "debian": "gir1.2-vte-3.91", "fedora": "vte291-gtk4"},
    "chromium": {"arch": "chromium", "debian": "chromium", "fedora": "chromium"},
    "fish": {"arch": "fish", "debian": "fish", "fedora": "fish"},
    "zsh": {"arch": "zsh", "debian": "zsh", "fedora": "zsh"},
    "nodejs": {"arch": "nodejs npm", "debian": "nodejs npm", "fedora": "nodejs npm"},
    "unzip": {"arch": "unzip", "debian": "unzip", "fedora": "unzip"},
    "gcc": {"arch": "base-devel", "debian": "build-essential", "fedora": "gcc"},
}


def pkg_hint(what):
    """Команда установки пакета для вашего дистрибутива (по /etc/os-release)."""
    ids = _distro_id()
    row = _PKGS[what]
    if "arch" in ids:
        return "sudo pacman -S " + row["arch"]
    if "fedora" in ids or "rhel" in ids:
        return "sudo dnf install " + row["fedora"]
    if "debian" in ids or "ubuntu" in ids:
        return "sudo apt install " + row["debian"]
    return "установите пакет «" + row["arch"] + "» средствами вашего дистрибутива"
