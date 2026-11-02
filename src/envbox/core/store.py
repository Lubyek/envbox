"""Хранение профилей и настроек на диске."""

import json
import os
import subprocess
from dataclasses import asdict

from .consts import NAME_RE
from .fsutil import _force_rmtree, _write_private
from .keyring import secret_clear, secret_tool_available
from .profile import Profile
from .root import box_dir, envbox_root
from .sessions import list_sessions


def browser_profiles():
    out = []
    for n in list_profiles():
        try:
            if load_profile(n).is_browser:
                out.append(n)
        except (OSError, ValueError):
            pass
    return out


def profile_path(name):
    return os.path.join(box_dir(name), "profile.json")


def list_profiles():
    root = envbox_root()
    if not os.path.isdir(root):
        return []
    return sorted(n for n in os.listdir(root)
                  if NAME_RE.match(n) and os.path.isfile(profile_path(n)))


def load_profile(name):
    with open(profile_path(name), encoding="utf-8") as f:
        d = json.load(f)
    d["name"] = name  # имя профиля — это имя каталога
    return Profile.from_dict(d)


def save_profile(p):
    if not NAME_RE.match(p.name):
        raise ValueError(f"недопустимое имя профиля: '{p.name}'")
    if "@" in p.upstream:
        raise ValueError("в адресе прокси не должно быть логина и пароля: они хранятся в keyring")
    _write_private(profile_path(p.name), json.dumps(asdict(p), ensure_ascii=False, indent=2) + "\n")


def copy_profile(src, dst):
    if not NAME_RE.match(dst):
        raise ValueError(f"недопустимое имя профиля: '{dst}'")
    if os.path.exists(box_dir(dst)) or os.path.exists(profile_path(dst)):
        raise ValueError(f"среда '{dst}' уже существует")
    p = load_profile(src)
    p.name = dst
    p.upstream_auth = False  # пароль прокси лежит в keyring под именем исходной среды
    p.host_confirmed = False  # доступ к файлам компьютера подтверждается заново для каждой среды
    save_profile(p)  # домашний каталог новой среды будет пустым


def delete_profile(name, with_home=False):
    if not NAME_RE.match(name):
        raise ValueError(f"недопустимое имя профиля: '{name}'")
    if any(s.name == name for s in list_sessions()):
        raise ValueError(f"среда «{name}» сейчас запущена: сначала остановите её")
    try:
        p = load_profile(name)
        secrets = p.wrapper_secrets()
    except (OSError, ValueError):
        secrets = []
    d = box_dir(name)
    if with_home:
        if os.path.isdir(d) and not os.path.islink(d):
            _force_rmtree(d)
        if os.path.lexists(profile_path(name)):
            os.unlink(profile_path(name))
        if secrets and secret_tool_available():
            for var in secrets:
                try:
                    secret_clear(name, var)
                except (OSError, subprocess.SubprocessError):
                    pass
    else:
        os.unlink(profile_path(name))


def settings_path():
    return os.path.join(envbox_root(), "gui.json")


def load_settings():
    try:
        with open(settings_path(), encoding="utf-8") as f:
            s = json.load(f)
    except (OSError, ValueError):
        s = {}
    return {"terminal": str(s.get("terminal", "")), "embedded": bool(s.get("embedded", True))}


def save_settings(s):
    _write_private(settings_path(), json.dumps(s, ensure_ascii=False, indent=2) + "\n")
