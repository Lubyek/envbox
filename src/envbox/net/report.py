"""Сетевой шлюз: чтение и вывод журнала соединений (команда report)."""

import time

from ..lazy import json


def human(n):
    for unit in ("Б", "КБ", "МБ", "ГБ"):
        if n < 1024 or unit == "ГБ":
            return f"{n:.0f} {unit}" if unit == "Б" else f"{n:.1f} {unit}"
        n /= 1024


def clean(value):
    """Строка для вывода в терминал: управляющие символы (в том числе ESC) заменяются на «?».
    Имена хостов и адреса приходят из среды, и последовательность вроде \\e]0;… не должна управлять терминалом."""
    return "".join("?" if ord(c) < 32 or 0x7F <= ord(c) < 0xA0 else c for c in str(value))


def events(path):
    with open(path, encoding="utf-8") as f:
        for line in f:
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def fmt_event(e):
    return clean(_fmt_event(e))


def _fmt_event(e):
    ev = e.get("event", "?")
    if ev in ("proxy-start", "proxy-stop"):
        extra = f" разрешено: {', '.join(map(str, e.get('allow', [])))}" if ev == "proxy-start" else ""
        return f"{e.get('ts', '')}  --- {ev}{extra}"
    target = f"{e.get('host', '?')}:{e.get('port', '?')}"
    label = {"open": "ОТКРЫТО", "close": "ЗАКРЫТО", "deny": "ЗАПРЕТ", "error": "ОШИБКА"}.get(ev, ev)
    tail = ""
    if ev == "open":
        tail = f" ({e.get('ip') or 'через ' + str(e.get('via', '?'))}{', напрямую' if e.get('direct') else ''})"
        if e.get("url"):
            tail += f" {e.get('method', '')} {e['url']}"
    elif ev == "close":
        tail = f" ↑{human(e.get('up', 0))} ↓{human(e.get('down', 0))} {e.get('ms', 0)} мс"
        if e.get("idle"):
            tail += " (закрыто: не было данных)"
        elif e.get("end"):
            tail += " (закрыл " + {"client": "клиент", "upstream": "сервер или прокси"}.get(e["end"], e["end"]) + ")"
    elif ev in ("deny", "error"):
        tail = f" {e.get('reason', '')}"
    return f"{e.get('ts', '')}  {label:<8} {target}{tail}"


def cmd_report(a):
    if a.follow:
        with open(a.log, encoding="utf-8") as f:
            try:
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(0.5)
                        continue
                    try:
                        print(fmt_event(json.loads(line)), flush=True)
                    except json.JSONDecodeError:
                        pass
            except KeyboardInterrupt:
                return
    if a.raw:
        for e in events(a.log):
            print(fmt_event(e))
        return
    agg = {}
    for e in events(a.log):
        if "host" not in e:
            continue
        key = (e["host"], e.get("port"))
        s = agg.setdefault(key, {"n": 0, "deny": 0, "err": 0, "up": 0, "down": 0,
                                 "first": e["ts"], "last": e["ts"], "ips": set()})
        s["last"] = e["ts"]
        ev = e.get("event")
        if ev == "open":
            s["n"] += 1
            if e.get("ip"):
                s["ips"].add(e["ip"])
        elif ev == "deny":
            s["deny"] += 1
        elif ev == "error":
            s["err"] += 1
        elif ev == "close":
            s["up"] += e.get("up", 0)
            s["down"] += e.get("down", 0)
    if not agg:
        print("В журнале нет сетевых обращений.")
        return
    rows = sorted(agg.items(), key=lambda kv: kv[1]["last"])
    hdr = f"{'последнее':<25} {'хост:порт':<40} {'соед':>5} {'запр':>5} {'ошиб':>5} {'отпр':>10} {'получ':>10}  IP"
    print(hdr)
    print("-" * len(hdr))
    for (host, port), s in rows:
        print(clean(f"{s['last']:<25} {f'{host}:{port}':<40} {s['n']:>5} {s['deny']:>5} {s['err']:>5} "
                    f"{human(s['up']):>10} {human(s['down']):>10}  {', '.join(sorted(s['ips']))}"))
