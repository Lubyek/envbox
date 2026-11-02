"""Секреты в keyring (secret-tool)."""

import shutil
import subprocess


def _secret_attrs(name, var):
    return ["service", "envbox", "profile", name, "var", var]


def secret_tool_available():
    return shutil.which("secret-tool") is not None


def secret_store(name, var, value):
    r = subprocess.run(["secret-tool", "store", "--label", f"envbox {name} {var}",
                        *_secret_attrs(name, var)],
                       input=value, capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip() or "secret-tool store завершился с ошибкой")


def secret_exists(name, var):
    r = subprocess.run(["secret-tool", "lookup", *_secret_attrs(name, var)],
                       stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
    return r.returncode == 0 and bool(r.stdout)


def secret_lookup(name, var):
    """Значение секрета или пустая строка."""
    r = subprocess.run(["secret-tool", "lookup", *_secret_attrs(name, var)],
                       stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
    return r.stdout if r.returncode == 0 else ""


def secret_clear(name, var):
    subprocess.run(["secret-tool", "clear", *_secret_attrs(name, var)],
                   stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
