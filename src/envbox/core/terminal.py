"""Запуск терминала со средой (внешнее окно, пробный запуск, фон)."""

import os
import shlex
import shutil
import subprocess

from ..resources import resource_text
from .consts import ENVBOX_SH, UPSTREAM_AUTH_VAR
from .keyring import _secret_attrs, secret_tool_available
from .root import box_dir
from .system import pkg_hint


# (бинарник, аргументы перед командой); команда добавляется в конец как argv
TERMINALS = [
    ("gnome-terminal", ["--"]),
    ("ptyxis", ["--"]),
    ("konsole", ["-e"]),
    ("xfce4-terminal", ["-x"]),
    ("ghostty", ["-e"]),
    ("kitty", []),
    ("alacritty", ["-e"]),
    ("foot", []),
    ("wezterm", ["start", "--"]),
    ("terminator", ["-x"]),
    ("xterm", ["-e"]),
    ("x-terminal-emulator", ["-e"]),
]


def detect_terminal(settings=None):
    """Префикс argv терминала или None. Свой вариант задаётся в настройках."""
    custom = (settings or {}).get("terminal", "").strip()
    if custom:
        return shlex.split(custom)
    env_term = os.environ.get("TERMINAL", "")
    for binary, prefix in TERMINALS:
        if env_term and os.path.basename(env_term) == binary and shutil.which(env_term):
            return [env_term] + prefix
    for binary, prefix in TERMINALS:
        if shutil.which(binary):
            return [binary] + prefix
    return None


# Скрипт внутри окна терминала (на хосте): достаёт секреты из keyring,
# экспортирует их (значения не попадают в argv) и запускает envbox.sh.
TERMINAL_WRAPPER = resource_text("terminal_wrapper.sh")


def terminal_argv(prefix, profile, command=None, install=False, install_domains=None):
    """argv терминала. install=True — режим установки (см. Profile.install_view)."""
    if install:
        profile = profile.install_view(install_domains)
    inner = ["env", "ENVBOX_PKG_HINT=" + pkg_hint("secret-tool"),
             "bash", "-c", TERMINAL_WRAPPER, "envbox-term", ENVBOX_SH, profile.name,
             *profile.wrapper_secrets(), "--", *profile.envbox_args(command)]
    return list(prefix) + inner


def dry_run(profile, command=None, install=False, install_domains=None):
    """(код возврата, вывод) для envbox.sh --dry-run."""
    if install:
        profile = profile.install_view(install_domains)
    # Секреты подставит обёртка терминала из keyring; для проверки хватит заглушки
    # (envbox --dry-run печатает только имена переменных, не значения).
    env = dict(os.environ)
    for s in profile.wrapper_secrets():
        env.setdefault(s, "x:x" if s == UPSTREAM_AUTH_VAR else "<keyring>")
    r = subprocess.run([ENVBOX_SH, "--dry-run", *profile.envbox_args(command)], env=env,
                       stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
    return r.returncode, (r.stdout + r.stderr).strip()


def launch_background(profile, command=None):
    """Запуск без окна терминала (для браузера). Секреты берутся из keyring и
    передаются через окружение; вывод пишется в ~/.envbox/<имя>/launch.log."""
    env = dict(os.environ)
    env.pop(UPSTREAM_AUTH_VAR, None)
    missing = []
    for var in profile.wrapper_secrets():
        if secret_tool_available():
            r = subprocess.run(["secret-tool", "lookup", *_secret_attrs(profile.name, var)],
                               stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
            if r.returncode == 0 and r.stdout:
                env[var] = r.stdout
                continue
        env.pop(var, None)
        missing.append(var)
    os.makedirs(box_dir(profile.name), mode=0o700, exist_ok=True)
    log_path = os.path.join(box_dir(profile.name), "launch.log")
    fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as log:
        if missing:
            log.write("envbox: в keyring не найдено: " + ", ".join(missing) + "\n")
            log.flush()
        proc = subprocess.Popen([ENVBOX_SH, *profile.envbox_args(command)], env=env,
                                stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                start_new_session=True)
    return proc, log_path


def read_tail(path, max_bytes=4000):
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            f.seek(max(0, f.tell() - max_bytes))
            return f.read().decode("utf-8", "replace").strip()
    except OSError:
        return ""
