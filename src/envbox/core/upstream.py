"""Вышестоящий прокси профиля: разбор URL, чтение из файла, проверка."""

import os
import subprocess
import urllib.parse

from .consts import ENVBOX_NET, UPSTREAM_AUTH_VAR


def split_proxy_url(text, allow_auth=True):
    """Разобрать адрес одного прокси.

    Возвращает (чистый_url, 'логин:пароль' или ''). Допускает 'host:port' (= http://).
    Списки адресов не поддерживаются сознательно: один прокси на среду.
    """
    text = text.strip()
    if not text:
        raise ValueError("пустой адрес")
    if any(c.isspace() for c in text):
        raise ValueError("ожидается один адрес без пробелов (списки и ротация прокси не поддерживаются)")
    if "://" not in text:
        text = "http://" + text
    u = urllib.parse.urlsplit(text)
    scheme = u.scheme.lower()
    if scheme not in ("http", "socks5", "socks5h"):
        raise ValueError("поддерживаются http://, socks5:// и socks5h://")
    if not u.hostname:
        raise ValueError("не указан хост")
    try:
        port = u.port
    except ValueError:
        raise ValueError("неверный порт") from None
    if not port:
        raise ValueError("не указан порт")
    if u.path not in ("", "/") or u.query or u.fragment:
        raise ValueError("адрес прокси не должен содержать путь")
    auth = ""
    if u.username is not None or u.password is not None:
        if not allow_auth:
            raise ValueError("логин и пароль хранятся в keyring, а не в адресе профиля")
        auth = f"{urllib.parse.unquote(u.username or '')}:{urllib.parse.unquote(u.password or '')}"
    host = f"[{u.hostname}]" if ":" in u.hostname else u.hostname
    return f"{scheme}://{host}:{port}", auth


def read_proxy_file(path):
    """Прочитать адрес одного прокси из файла (пустые строки и # игнорируются)."""
    with open(path, encoding="utf-8", errors="replace") as f:
        lines = [l.strip() for l in f if l.strip() and not l.lstrip().startswith("#")]
    if not lines:
        raise ValueError("в файле нет адреса прокси")
    if len(lines) > 1:
        raise ValueError(f"в файле {len(lines)} адресов: поддерживается один прокси на среду "
                         "(списки и ротация не поддерживаются)")
    return lines[0]


def probe_upstream(url, auth="", target="example.com:443"):
    """Проверить прокси: (успех, сообщение)."""
    env = dict(os.environ)
    env.pop(UPSTREAM_AUTH_VAR, None)
    if auth:
        env[UPSTREAM_AUTH_VAR] = auth
    try:
        r = subprocess.run(["/usr/bin/python3", "-I", ENVBOX_NET, "probe", "--upstream", url,
                            "--target", target], env=env, stdin=subprocess.DEVNULL,
                           capture_output=True, text=True, timeout=40)
    except (OSError, subprocess.SubprocessError) as e:
        return False, str(e)
    return r.returncode == 0, (r.stdout + r.stderr).strip()
