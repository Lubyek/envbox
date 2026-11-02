"""Ссылки из среды: очередь, выбор браузера, отправка в среду."""

import datetime as dt
import os
import re
import shlex
import shutil
import stat
import subprocess
import time
import urllib.parse

from ..cdp.browser import CdpBrowser
from ..cdp.viewer import LINK_MAX
from .browser import cdp_socket_path
from .root import box_dir, envbox_root
from .sessions import list_sessions
from .store import list_profiles, load_profile
from .terminal import launch_background


def parse_link(text):
    """Проверка адреса, пришедшего из среды (недоверенные данные): только http/https, без логина в адресе."""
    t = (text or "").strip()
    if not t or len(t) > LINK_MAX:
        raise ValueError("пустая или слишком длинная ссылка")
    if any(ord(c) < 32 or ord(c) == 127 or c.isspace() for c in t):
        raise ValueError("в ссылке есть пробелы или управляющие символы")
    if not re.match(r"^https?://", t, re.I):
        raise ValueError("открываются только ссылки http и https")
    u = urllib.parse.urlsplit(t)
    if not u.hostname:
        raise ValueError("в ссылке нет адреса сайта")
    if "@" in u.netloc:
        raise ValueError("в ссылке указан логин или пароль перед адресом сайта: так часто маскируют поддельные сайты")
    return t


def link_spool_dir(name):
    return os.path.join(box_dir(name), "run", "links")


def read_link_spool(name, max_age=600, limit=20):
    """Запросы на открытие ссылок от среды `name`: [(адрес, ошибка)] — прочитанные файлы удаляются.

    Каталог доступен среде на запись, поэтому всё из него недоверенное: символические ссылки, FIFO и
    большие файлы пропускаются, число запросов за раз ограничено, старые стираются без показа."""
    d = link_spool_dir(name)
    try:
        st = os.lstat(d)
        if not stat.S_ISDIR(st.st_mode):
            return []
        entries = sorted(os.listdir(d))
    except OSError:
        return []
    out = []
    now_ts = time.time()
    for fname in entries:
        path = os.path.join(d, fname)
        if fname.endswith(".tmp"):
            try:
                if now_ts - os.lstat(path).st_mtime > 60:
                    os.unlink(path)
            except OSError:
                pass
            continue
        fd = None
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            fst = os.fstat(fd)
            if not stat.S_ISREG(fst.st_mode):
                os.close(fd)
                fd = None
                try:
                    os.unlink(path)
                except OSError:
                    pass
                continue
            data = os.read(fd, LINK_MAX + 64)
            stale = now_ts - fst.st_mtime > max_age
        except OSError:
            if fd is not None:
                os.close(fd)
            try:
                os.unlink(path)  # символическая ссылка и прочее подозрительное
            except OSError:
                pass
            continue
        os.close(fd)
        try:
            os.unlink(path)
        except OSError:
            pass
        if stale:
            continue
        if len(out) >= limit:
            continue  # лишние запросы отбрасываются: среда не должна заваливать вас окнами
        try:
            out.append((parse_link(data.decode("utf-8", "replace").splitlines()[0] if data else ""), ""))
        except ValueError as e:
            out.append(("", str(e)))
    return out


def link_spool_pending(name):
    """Есть ли в канале ссылок среды необработанные запросы (дешёвая проверка для опроса)."""
    try:
        return any(not f.endswith(".tmp") for f in os.listdir(link_spool_dir(name)))
    except OSError:
        return False


def cdp_open_url(name, url):
    """Открыть ссылку новой вкладкой в запущенном браузере-среде; возвращает id вкладки."""
    url = parse_link(url)
    b = CdpBrowser(cdp_socket_path(name))
    try:
        b.connect()
        return b.new_tab(url)
    finally:
        b.close()


def browser_profiles_names():
    """Имена сред-браузеров."""
    out = []
    for n in list_profiles():
        try:
            if load_profile(n).is_browser:
                out.append(n)
        except (OSError, ValueError):
            pass
    return out


def url_scheme(url):
    m = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*):", url or "")
    return m.group(1).lower() if m else ""


def parse_inbound(text, schemes=()):
    """Ссылка, которую пользователь отправляет в среду: http/https или схема приложения (claude://…)."""
    t = (text or "").strip()
    if not t or len(t) > LINK_MAX:
        raise ValueError("пустая или слишком длинная ссылка")
    if any(ord(c) < 32 or ord(c) == 127 or c.isspace() for c in t):
        raise ValueError("в ссылке есть пробелы или управляющие символы")
    sc = url_scheme(t)
    if sc in ("http", "https"):
        return parse_link(t)
    if sc and sc in [x.lower() for x in schemes]:
        return t
    raise ValueError(f"схема «{sc or '?'}» не разрешена для этой среды (разрешены http, https"
                     + "".join(f", {x}" for x in schemes) + ")")


def inbox_dir(name):
    return os.path.join(box_dir(name), "run", "inbox")


def send_link(name, url):
    """Положить ссылку в канал inbox запущенной среды (её читает наблюдатель внутри песочницы)."""
    p = load_profile(name)
    if not (p.link_handler or p.link_callback):
        raise ValueError(f"в среде «{name}» не включён приём ссылок: задайте «Команду открытия ссылок» в настройках")
    url = parse_inbound(url, p.link_schemes)
    run = os.path.join(box_dir(name), "run")
    d = inbox_dir(name)
    for path in (run, d):
        if os.path.islink(path):
            raise ValueError(f"{path} — символическая ссылка; это запрещено")
    os.makedirs(d, mode=0o700, exist_ok=True)
    fname = f"{int(time.time() * 1000)}.{os.getpid()}"
    tmp = os.path.join(d, fname + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, (url + "\n").encode("utf-8"))
    finally:
        os.close(fd)
    os.replace(tmp, os.path.join(d, fname))
    return fname


def inbox_result(name, fname, wait=8.0):
    """Ответ среды на отправленную ссылку; пустая строка, если за wait секунд ответа не было."""
    path = os.path.join(inbox_dir(name), fname + ".result")
    end = time.monotonic() + wait
    while time.monotonic() < end:
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError:
            time.sleep(0.2)
            continue
        try:
            data = os.read(fd, 400).decode("utf-8", "replace").strip()
        finally:
            os.close(fd)
        try:
            os.unlink(path)
        except OSError:
            pass
        return data
    return ""


def env_running(name):
    return any(s.name == name for s in list_sessions())


def find_env_for_url(url):
    """Подходящие среды для ссылки (запущенные первыми): по схеме приложения или для вызова localhost."""
    sc = url_scheme(url)
    host = (urllib.parse.urlsplit(url).hostname or "").lower() if sc in ("http", "https") else ""
    found = []
    for n in list_profiles():
        try:
            p = load_profile(n)
        except (OSError, ValueError):
            continue
        if p.is_browser:
            continue
        if sc in [x.lower() for x in p.link_schemes] or (p.link_callback and sc == "http" and host in ("localhost", "127.0.0.1", "::1")):
            found.append(n)
    return sorted(found, key=lambda n: (not env_running(n), n))


def open_link_in_env(url, env=None, start=True):
    """Открыть ссылку в приложении внутри среды. Возвращает (имя среды, сообщение).

    Запущенной среде ссылка передаётся через inbox; если среда не запущена, запускается её приложение со ссылкой."""
    if env is None:
        cands = find_env_for_url(url.strip())
        if not cands:
            raise ValueError("не нашёл среду для этой ссылки: укажите среду вручную или задайте у среды «Схемы ссылок»")
        env = cands[0]
    p = load_profile(env)
    url = parse_inbound(url, p.link_schemes)
    if env_running(env):
        fname = send_link(env, url)
        answer = inbox_result(env, fname)
        return env, answer or "ссылка отправлена, ответа от среды нет (смотрите окно приложения)"
    if not start:
        raise ValueError(f"среда «{env}» не запущена")
    if not p.link_handler:
        raise ValueError(f"среда «{env}» не запущена, а запускать с этой ссылкой нечем: задайте «Команду открытия ссылок»")
    errs = p.validate()
    if errs:
        raise ValueError("среда не готова к запуску: " + "; ".join(errs))
    launch_background(p, f"{p.link_handler} {shlex.quote(url)}")
    return env, "среда запущена, приложение открывается со ссылкой"


def open_in_host_browser(url):
    """Открыть http/https-ссылку в обычном браузере на компьютере (вне песочницы); возвращает имя программы."""
    url = parse_link(url)
    for tool in (["xdg-open"], ["gio", "open"]):
        if shutil.which(tool[0]):
            subprocess.Popen(tool + [url], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, start_new_session=True)
            return tool[0]
    raise OSError("не найден xdg-open (пакет xdg-utils): откройте ссылку в браузере вручную")


def open_in_file_manager(path):
    """Открыть каталог в файловом менеджере компьютера (вне песочницы); возвращает имя программы."""
    if not os.path.isdir(path):
        raise OSError(f"каталог не существует: {path}")
    for tool in (["xdg-open"], ["gio", "open"]):
        if shutil.which(tool[0]):
            subprocess.Popen(tool + [path], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, start_new_session=True)
            return tool[0]
    raise OSError("не найден xdg-open (пакет xdg-utils): откройте каталог вручную")


def notify_desktop(title, text):
    """Уведомление рабочего стола (если есть notify-send): ссылки приходят из браузера без окна envbox."""
    if not shutil.which("notify-send"):
        return False
    try:
        subprocess.run(["notify-send", "-a", "envbox", title, text], timeout=5, capture_output=True,
                       stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return False
    return True


def safe_link_label(url):
    """Адрес без параметров и части после «#»: в них коды входа, их нельзя писать в журнал и уведомления."""
    try:
        u = urllib.parse.urlsplit(url or "")
    except ValueError:
        return "?"
    base = f"{u.scheme}://{u.netloc}{u.path}"
    return base if len(base) <= 100 else base[:100] + "…"


def log_link_event(label, outcome):
    """Журнал <каталог данных>/open-link.log: что приходило из браузера и что с этим сделали (без кодов входа)."""
    try:
        root = envbox_root()
        os.makedirs(root, mode=0o700, exist_ok=True)
        path = os.path.join(root, "open-link.log")
        try:
            if os.path.getsize(path) > 200_000:
                os.replace(path, path + ".1")
        except OSError:
            pass
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(f"{dt.datetime.now().isoformat(timespec='seconds')} {label} — {outcome}\n")
    except OSError:
        pass
