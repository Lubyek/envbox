"""Диагностика «Claude зависает»: что показывает сетевой журнал шлюза и записи самого Claude об ошибках.

Причины ищутся по признакам в журнале (поля close: end, ms, up, down, up_end, down_first, down_last, warm, setup_ms):
- туннель оборван на 58–66-й секунде посреди передачи: у вашего прокси жёсткий лимит жизни туннеля;
- много соединений оборвано в одну секунду: прокси или его выходной адрес «моргнули» разом (зависание сразу во всех чатах);
- запрос ушёл, а ответа нет: молчащий или мёртвый туннель;
- долгие ответы: модель думает или стрим идёт дольше лимита туннеля;
- ошибки в записях Claude: тайм-ауты, ECONNRESET, перегрузка, лимиты."""

import os
import re
import time
from datetime import datetime

from ..net.warm import is_hot
from .root import box_dir
from .netlog import net_log_path


# Сколько секунд соединению разрешено «жить», чтобы считаться оборванным по лимиту поставщика
CAP_RANGE = (58000, 66000)


# Сколько соединений, оборванных в одну секунду, считается «разом»
MASS_DROP = 4


ERR_RE = re.compile(
    r"(API Error: [^\"\\\n]{0,140}|Request timed out[^\"\\\n]{0,60}|Connection error[^\"\\\n]{0,60}|ECONNRESET|"
    r"ETIMEDOUT|EPIPE|socket hang up|Premature close|overloaded_error|rate_limit_error|authentication_error|"
    r"Unable to connect[^\"\\\n]{0,60}|[Rr]etrying in \d+ seconds[^\"\\\n]{0,40}|stream (?:ended|closed)[^\"\\\n]{0,60})")


def parse_ts(text):
    try:
        return datetime.fromisoformat(text).timestamp()
    except (TypeError, ValueError):
        return None


def read_events(path, since):
    """События журнала не старше `since` (секунды с начала эпохи); битые строки пропускаются."""
    import json
    out = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                if '"host"' not in line and '"channel"' not in line:
                    continue
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                ts = parse_ts(e.get("ts"))
                if ts is not None and ts >= since:
                    e["_t"] = ts
                    out.append(e)
    except OSError:
        pass
    return out


def pct(values, q):
    values = sorted(values)
    return values[min(len(values) - 1, int(len(values) * q))] if values else 0


def analyze(events, hours):
    """Выводы по событиям журнала: [(уровень, текст)] и числа для отчёта."""
    hot_open = [e for e in events if e.get("event") == "open" and e.get("host") and is_hot(e["host"])]
    hot_close = [e for e in events if e.get("event") == "close" and e.get("host") and is_hot(e["host"])]
    out = []
    if not hot_close and not hot_open:
        return [("warn", f"в журнале за последние {hours:g} ч нет соединений с сайтами Claude. Проверьте, что среда "
                         "запущена в режиме «через журнал» и приложение работало в это время")], {}
    stats = {"connections": len(hot_open), "warm": sum(1 for e in hot_open if e.get("warm"))}
    setups = [e["setup_ms"] for e in hot_open if e.get("setup_ms") is not None]
    ends = {}
    for e in hot_close:
        ends[e.get("end", "?")] = ends.get(e.get("end", "?"), 0) + 1
    stats["ends"] = ends
    out.append(("ok" if hot_open else "warn",
                f"соединений к сайтам Claude: {len(hot_open)}, из них взяли готовый туннель {stats['warm']}"
                + (f"; обычная установка туннеля: медиана {pct(setups, 0.5)} мс, 95% — {pct(setups, 0.95)} мс" if setups else "")))
    # 1) оборваны на ~60-й секунде посреди передачи (данные шли до самого обрыва)
    capped = [e for e in hot_close if e.get("end") == "upstream" and CAP_RANGE[0] <= e.get("ms", 0) <= CAP_RANGE[1]]
    active = [e for e in capped if e.get("ms", 0) - e.get("down_last", 0) < 4000 and e.get("down", 0) > 8000]
    idle = [e for e in capped if e not in active]
    if len(active) >= 2:
        out.append(("bad", f"{len(active)} соединений оборваны вышестоящим прокси на {CAP_RANGE[0] // 1000}–{CAP_RANGE[1] // 1000}-й "
                           "секунде прямо посреди передачи данных: у вашего прокси жёсткий лимит жизни туннеля (около минуты). "
                           "Ответ Claude, идущий дольше этого срока, обрывается и запрашивается заново, поэтому «думает» без "
                           "конца. Лечится у поставщика (долгие сессии, другой порт или протокол) или сменой прокси"))
    if idle:
        out.append(("ok", f"{len(idle)} соединений закрыты на ~60-й секунде, когда уже не было данных: это обычное закрытие "
                          "простаивающих keep-alive-соединений, вреда нет"))
    # 2) обрывы разом
    by_sec = {}
    for e in hot_close:
        if e.get("end") == "upstream":
            by_sec.setdefault(int(e["_t"]), []).append(e)
    bursts = {s: v for s, v in by_sec.items() if len(v) >= MASS_DROP and any(x.get("ms", 0) < CAP_RANGE[0] or x.get("down", 0) > 8000 for x in v)}
    if bursts:
        worst = max(bursts.items(), key=lambda kv: len(kv[1]))
        when = datetime.fromtimestamp(worst[0]).strftime("%H:%M:%S")
        out.append(("bad", f"{len(bursts)} раз(а) прокси обрывал сразу много соединений в одну секунду (больше всего — "
                           f"{len(worst[1])} в {when}). Так бывает, когда прокси или его выходной адрес «моргают» разом: "
                           "тогда зависают все чаты одновременно. Сверьте время с зависаниями; лечится сменой прокси или "
                           "цепочкой с запасным каналом (VPN)"))
    # 3) запрос ушёл, ответа нет
    silent = [e for e in hot_close if e.get("up", 0) >= 20000 and e.get("down", 0) <= 7000 and e.get("ms", 0) >= 30000]
    if silent:
        out.append(("bad", f"{len(silent)} запросов (от 20 КБ) отправлены, а ответа нет совсем ({sorted(e['ms'] for e in silent)[len(silent) // 2] // 1000} с "
                           "ожидания в среднем): туннель принимает данные, но сервер или прокси не отвечает"))
    stalls = ends.get("stall", 0)
    if stalls:
        out.append(("warn", f"шлюз сам оборвал {stalls} зависших туннелей (запрос без ответа дольше срока): приложение при этом "
                            "повторяет запрос"))
    # 4) долгие ответы
    long_resp = [e.get("down_last", 0) - e.get("up_end", 0) for e in hot_close if e.get("down", 0) > 8000 and e.get("down_last") and e.get("up_end") is not None]
    if long_resp:
        longest = max(long_resp) / 1000
        out.append(("warn" if longest > 55 else "ok",
                    f"самый долгий ответ шёл {longest:.0f} с; дольше 20 с: {sum(1 for x in long_resp if x > 20000)} из {len(long_resp)}"
                    + (" (это дольше лимита туннеля в минуту: такие ответы рискуют обрываться)" if longest > 55 else "")))
    # 5) медленная отправка
    slow_up = [e for e in hot_close if e.get("up", 0) >= 100000 and e.get("up_end", 0) > 0 and e["up"] / (e["up_end"] / 1000) < 100000]
    if slow_up:
        out.append(("warn", f"{len(slow_up)} крупных запросов (от 100 КБ) уходили медленнее 100 КБ/с: исходящий канал прокси "
                            "узкий, большой контекст отправляется секундами"))
    # 6) каналы
    flips = [e for e in events if e.get("event") == "channel" and e.get("state") in ("down", "up")]
    if flips:
        out.append(("warn", f"каналы выхода переключались {len(flips)} раз(а): смотрите события «КАНАЛ» в журнале сети"))
    if not any(lvl in ("bad", "warn") for lvl, _t in out[1:]):
        out.append(("ok", "в журнале шлюза нет признаков зависших или оборванных туннелей за этот период: если Claude в это "
                          "время зависал, смотрите записи самого Claude ниже"))
    return out, stats


def claude_errors(home, since, max_files=20, tail=1_500_000):
    """Ошибки в записях Claude внутри среды: {текст: сколько раз}. Содержимое переписки не читается и не выводится."""
    root = os.path.join(home, ".claude")
    files = []
    for base, _dirs, names in os.walk(root):
        for n in names:
            p = os.path.join(base, n)
            if n.endswith((".jsonl", ".log")):
                try:
                    mt = os.path.getmtime(p)
                except OSError:
                    continue
                if mt >= since:
                    files.append((mt, p))
    counts = {}
    for _mt, p in sorted(files, reverse=True)[:max_files]:
        try:
            with open(p, "rb") as f:
                f.seek(0, 2)
                f.seek(max(0, f.tell() - tail))
                text = f.read().decode("utf-8", "replace")
        except OSError:
            continue
        for m in ERR_RE.finditer(text):
            key = re.sub(r"\d+", "N", m.group(1)).strip()[:120]
            counts[key] = counts.get(key, 0) + 1
    return counts


def diagnose_claude(name, hours=3.0, now=None):
    """Отчёт «почему Claude зависает» по среде `name` за последние `hours` часов (строка)."""
    now = now or time.time()
    since = now - hours * 3600
    events = read_events(net_log_path(name), since)
    findings, _stats = analyze(events, hours)
    mark = {"ok": "✔", "warn": "⚠", "bad": "✖"}
    lines = [f"Среда «{name}», последние {hours:g} ч", "", "Сетевой журнал шлюза:"]
    lines += [f"  {mark[lvl]} {t}" for lvl, t in findings]
    errs = claude_errors(os.path.join(box_dir(name), "home"), since)
    lines += ["", "Записи самого Claude об ошибках (без содержимого переписки):"]
    if errs:
        top = sorted(errs.items(), key=lambda kv: -kv[1])[:8]
        lines += [f"  ⚠ {n} × {t}" for t, n in top]
    else:
        lines.append("  ✔ ошибок связи в записях Claude не найдено (или записей нет: среда не запускалась, или Claude пишет их в другое место)")
    lines += ["", "Что делать: воспроизведите зависание, затем откройте этот отчёт сразу и пришлите его. Если в журнале "
                  "есть обрывы разом или на ~60-й секунде, причина в прокси; если обрывов нет, а чаты висят, "
                  "дело не в сети шлюза."]
    return "\n".join(lines)
