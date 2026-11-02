"""Запущенные сеансы сред: поиск в /proc, остановка."""

import os
import shlex
import signal
from dataclasses import dataclass


@dataclass
class Session:
    pid: int
    name: str
    seconds: int
    command: str
    inner: tuple = ()


def _proc_args(pid, proc="/proc"):
    with open(f"{proc}/{pid}/cmdline", "rb") as f:
        return [a.decode("utf-8", "replace") for a in f.read().split(b"\0") if a]


def _proc_stat(pid, proc="/proc"):
    with open(f"{proc}/{pid}/stat", encoding="utf-8", errors="replace") as f:
        rest = f.read().rsplit(")", 1)[1].split()
    return int(rest[1]), int(rest[19])  # ppid, starttime (тики с загрузки)


def _session_name(args):
    """Имя среды по аргументам bwrap: метка ENVBOX_SESSION или (старые версии) имя компьютера."""
    for i in range(len(args) - 2):
        if args[i] == "--setenv" and args[i + 1] == "ENVBOX_SESSION":
            return args[i + 2]
    if "--hostname" in args:
        host = args[args.index("--hostname") + 1]
        if host.startswith("envbox-"):
            return host[len("envbox-"):]
    return ""


def _session_command(args):
    try:
        cmd = args[args.index("--") + 1:]
    except ValueError:
        return ""
    if cmd[:4] == ["/usr/bin/python3", "-I", "/run/envbox/net.py", "wrap"] and "--" in cmd:
        cmd = cmd[cmd.index("--") + 1:]
    return shlex.join(cmd)


def list_sessions(proc="/proc"):
    """Запущенные среды текущего пользователя (внешние процессы bwrap)."""
    uid = os.getuid()
    found = {}
    for entry in os.listdir(proc):
        if not entry.isdigit():
            continue
        pid = int(entry)
        try:
            # название процесса читается одним коротким файлом; тяжёлое (cmdline, stat) — только для bwrap.
            # Раньше cmdline читался у всех процессов компьютера каждую секунду.
            with open(f"{proc}/{pid}/comm", "rb") as f:
                if f.read(16).rstrip(b"\n") != b"bwrap":
                    continue
            if os.stat(f"{proc}/{pid}").st_uid != uid:
                continue
            args = _proc_args(pid, proc)
            if not args or os.path.basename(args[0]) != "bwrap":
                continue
            name = _session_name(args)
            if not name:
                continue
            ppid, start = _proc_stat(pid, proc)
        except (OSError, IndexError, ValueError):
            continue
        found[pid] = (name, ppid, start, _session_command(args))
    try:
        with open(f"{proc}/uptime") as f:
            uptime = float(f.read().split()[0])
    except OSError:
        uptime = 0.0
    tck = os.sysconf("SC_CLK_TCK")
    out = []
    for pid, (name, ppid, start, cmd) in found.items():
        if ppid in found and found[ppid][0] == name:
            continue  # внутренний bwrap (pid 1 в namespace) той же среды
        inner = tuple(q for q, v in found.items() if v[1] == pid and v[0] == name)
        out.append(Session(pid, name, max(0, int(uptime - start / tck)), cmd, inner))
    return sorted(out, key=lambda s: (s.name, s.pid))


def stop_session(session):
    """SIGTERM внешнему bwrap и pid 1 среды; процессы внутри завершит ядро."""
    os.kill(session.pid, signal.SIGTERM)
    for q in session.inner:
        try:
            os.kill(q, signal.SIGTERM)
        except ProcessLookupError:
            pass


def format_duration(sec):
    h, rem = divmod(sec, 3600)
    m, s = divmod(rem, 60)
    return f"{h}:{m:02d}:{s:02d}" if h else f"{m}:{s:02d}"
