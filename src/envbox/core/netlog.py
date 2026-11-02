"""Журнал сети среды: чтение с хвоста, сводка, очистка."""

import json
import os

from ..net.report import fmt_event, human
from .root import box_dir


# --------------------------------------------------------- сетевой журнал

format_event = fmt_event


human_size = human


def net_log_path(name):
    return os.path.join(box_dir(name), "net.log")


class LogTail:
    """Чтение новых событий из net.log; переживает очистку файла."""

    def __init__(self, path):
        self.path = path
        self.pos = 0
        self.partial = ""

    def read_new(self):
        try:
            size = os.path.getsize(self.path)
        except OSError:
            return []
        if size < self.pos:
            self.pos, self.partial = 0, ""
        if size == self.pos:
            return []
        with open(self.path, encoding="utf-8", errors="replace") as f:
            f.seek(self.pos)
            chunk = f.read()
            self.pos = f.tell()
        data = self.partial + chunk
        lines = data.split("\n")
        self.partial = lines.pop()
        out = []
        for line in lines:
            try:
                out.append(json.loads(line))
            except ValueError:
                pass
        return out


class NetSummary:
    """Сводка по хостам, которая дополняется новыми событиями. Пересчитывать весь журнал каждую секунду
    (а он бывает на десятки тысяч записей) в потоке окна не нужно."""

    def __init__(self):
        self.agg = {}

    def add(self, events):
        agg = self.agg
        for e in events:
            if "host" not in e:
                continue
            key = (e["host"], e.get("port"))
            s = agg.get(key)
            if s is None:
                s = agg[key] = {"host": e["host"], "port": e.get("port"), "open": 0,
                                "deny": 0, "error": 0, "up": 0, "down": 0,
                                "last": e.get("ts", ""), "ips": set(), "via": ""}
            s["last"] = e.get("ts", s["last"])
            ev = e.get("event")
            if e.get("via"):
                s["via"] = e["via"]
            if ev == "open":
                s["open"] += 1
                if e.get("ip"):
                    s["ips"].add(e["ip"])
            elif ev in ("deny", "error"):
                s[ev] += 1
            elif ev == "close":
                s["up"] += e.get("up", 0)
                s["down"] += e.get("down", 0)

    def rows(self):
        """Список словарей, последние обращения в конце."""
        return sorted(self.agg.values(), key=lambda s: s["last"])


def summarize(events):
    """Сводка по хостам: список словарей, последние обращения в конце."""
    s = NetSummary()
    s.add(events)
    return s.rows()


def clear_net_log(name):
    p = net_log_path(name)
    if os.path.exists(p):
        with open(p, "w"):
            pass
