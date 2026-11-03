"""Диспетчер служебных команд envbox.py, вызываемых из envbox.sh и из песочницы."""

import sys

from ..version import ENVBOX_VERSION
from .bridge import cmd_probe, cmd_wrap
from .gitcheck import cmd_gitcheck
from .proxy import cmd_proxy
from .report import cmd_report
from .seccomp import cmd_seccomp


# Разбор аргументов написан вручную: argparse в Python 3.14 тянет за собой ~18 мс импортов, а эти команды
# запускаются при каждом старте среды и каждой команде внутри неё.
# Вид: команда -> {параметр: вид}, где вид: str, int, list (повторяемый) или flag.
NET_OPTIONS = {
    "proxy": {"--socket": "str", "--log": "str", "--allow": "list", "--allow-private": "flag",
              "--parent-pid": "int", "--upstream": "str", "--dns": "list", "--direct": "list", "--chain": "list",
              "--no-accel": "flag", "--live": "str"},
    "wrap": {"--map": "list", "--serve": "list", "--inbox": "str", "--inbox-cmd": "str",
             "--inbox-scheme": "list", "--inbox-callback": "flag"},
    "seccomp": {"--allow": "list"},
    "version": {},
    "gitcheck": {},
    "probe": {"--upstream": "str", "--target": "str"},
    "report": {"--follow": "flag", "--raw": "flag"},
}


NET_REQUIRED = {"proxy": ("socket", "log"), "probe": ("upstream",)}


NET_POSITIONAL = {"gitcheck": ("action", "workdir", "snapshot"), "report": ("log",)}


NET_OPTIONAL_POSITIONAL = {"gitcheck": 1}   # сколько последних позиционных необязательны


NET_DEFAULTS = {"target": "example.com:443"}


class NetArgs:
    """Результат разбора: атрибуты по именам параметров (как у argparse.Namespace)."""

    def __init__(self, mode):
        self.mode = mode


def net_usage(msg):
    print(f"envbox-net: ошибка: {msg}", file=sys.stderr)
    sys.exit(2)


def net_parse(mode, argv):
    spec = NET_OPTIONS[mode]
    a = NetArgs(mode)
    for opt, kind in spec.items():
        dest = opt[2:].replace("-", "_")
        setattr(a, dest, [] if kind == "list" else False if kind == "flag" else 0 if kind == "int"
                else NET_DEFAULTS.get(dest, ""))
    names = NET_POSITIONAL.get(mode, ())
    for n in names:
        setattr(a, n, None)
    if mode == "wrap":
        a.cmd = []
    positional = []
    i = 0
    while i < len(argv):
        arg = argv[i]
        i += 1
        if mode == "wrap" and (arg == "--" or not arg.startswith("-")):
            a.cmd = argv[i:] if arg == "--" else argv[i - 1:]   # всё остальное — команда
            break
        if arg == "--" or not arg.startswith("-") or arg == "-":
            positional.append(arg)
            continue
        opt, eq, value = arg.partition("=")
        kind = spec.get(opt)
        if kind is None:
            net_usage(f"неизвестный параметр {opt} (команда {mode})")
        dest = opt[2:].replace("-", "_")
        if kind == "flag":
            if eq:
                net_usage(f"параметр {opt} не принимает значение")
            setattr(a, dest, True)
            continue
        if not eq:
            if i >= len(argv):
                net_usage(f"параметру {opt} нужно значение")
            value = argv[i]
            i += 1
        if kind == "list":
            getattr(a, dest).append(value)
        elif kind == "int":
            try:
                setattr(a, dest, int(value))
            except ValueError:
                net_usage(f"параметр {opt}: ожидается число, получено {value!r}")
        else:
            setattr(a, dest, value)
    required = len(names) - NET_OPTIONAL_POSITIONAL.get(mode, 0)
    if len(positional) < required or len(positional) > len(names):
        net_usage(f"команда {mode}: ожидаются аргументы: {' '.join(names)}")
    for n, v in zip(names, positional):
        setattr(a, n, v)
    for n in NET_REQUIRED.get(mode, ()):
        if not getattr(a, n):
            net_usage(f"команда {mode}: не указан параметр --{n.replace('_', '-')}")
    if mode == "gitcheck" and a.action not in ("snapshot", "verify"):
        net_usage("gitcheck: действие должно быть snapshot или verify")
    return a


def net_main():
    argv = sys.argv[1:]
    mode = argv[0] if argv else ""
    if mode not in NET_OPTIONS:
        net_usage("ожидается одна из команд: " + ", ".join(NET_OPTIONS))
    a = net_parse(mode, argv[1:])
    {"proxy": cmd_proxy, "wrap": cmd_wrap, "probe": cmd_probe, "report": cmd_report,
     "seccomp": cmd_seccomp, "gitcheck": cmd_gitcheck,
     "version": lambda _a: print(ENVBOX_VERSION)}[a.mode](a)


NET_COMMANDS = tuple(NET_OPTIONS)
