"""Проверка выхода в интернет (VPN, прокси, этот компьютер) с точки зрения Claude.

Что смотрим: выходной адрес (страна, регион, город, провайдер, тип сети, пометки «дата-центр / VPN / прокси / Tor /
жалобы»), не совпадает ли он с вашим настоящим, открываются ли claude.ai и api.anthropic.com из этого региона и не
просит ли Cloudflare проверку браузера, часовой пояс региона и безопасность самого VPN-транспорта.

Запросы идут через проверяемый выход к сторонним сервисам определения адреса (их список — GEO_PROVIDERS): они видят
выходной адрес, а настоящий видит только один запрос напрямую (для сравнения; его можно отключить)."""

import json
import time

from ..net.vpn import VpnClient, transport_report
from .vpn import http_errors, http_request, vpn_binary_problem, vpn_dir, vpn_source


# Сервисы определения адреса: (адрес запроса, разбор ответа). Берём ответы всех, кто ответил: у одних есть пометки
# «дата-центр/VPN», у других точнее город. Порядок — важность для основных полей.
def _dict(x):
    """Поле, которое должно быть словарём; если сервис отдал другое (строку, список), считаем его пустым."""
    return x if isinstance(x, dict) else {}


def _text(x):
    return x if isinstance(x, str) else ""


def _parse_ipapi_is(d):
    if not isinstance(d, dict) or not d.get("ip"):
        return None
    loc, comp, asn = _dict(d.get("location")), _dict(d.get("company")), _dict(d.get("asn"))
    return {"ip": _text(d["ip"]), "country": _text(loc.get("country")), "code": _text(loc.get("country_code")),
            "region": _text(loc.get("state")), "city": _text(loc.get("city")), "timezone": _text(loc.get("timezone")),
            "org": _text(comp.get("name")) or _text(asn.get("org")),
            "asn": f"AS{asn['asn']}" if asn.get("asn") else "",
            "net_type": _text(comp.get("type")) or _text(asn.get("type")),
            "flags": {"datacenter": bool(d.get("is_datacenter")), "proxy": bool(d.get("is_proxy")),
                      "vpn": bool(d.get("is_vpn")), "tor": bool(d.get("is_tor")), "abuser": bool(d.get("is_abuser")),
                      "mobile": bool(d.get("is_mobile"))}}


def _parse_ip_api(d):
    if not isinstance(d, dict) or d.get("status") != "success":
        return None
    return {"ip": _text(d.get("query")), "country": _text(d.get("country")), "code": _text(d.get("countryCode")),
            "region": _text(d.get("regionName")), "city": _text(d.get("city")), "timezone": _text(d.get("timezone")),
            "org": _text(d.get("org")) or _text(d.get("isp")), "asn": _text(d.get("as")).split(" ")[0], "net_type": "",
            "flags": {"datacenter": bool(d.get("hosting")), "proxy": bool(d.get("proxy")),
                      "mobile": bool(d.get("mobile"))}}


def _parse_ipwho(d):
    if not isinstance(d, dict) or not d.get("success", True) or not d.get("ip"):
        return None
    conn, tz = _dict(d.get("connection")), d.get("timezone")
    return {"ip": _text(d["ip"]), "country": _text(d.get("country")), "code": _text(d.get("country_code")),
            "region": _text(d.get("region")), "city": _text(d.get("city")),
            "timezone": _text(tz.get("id")) if isinstance(tz, dict) else _text(tz),
            "org": _text(conn.get("org")) or _text(conn.get("isp")),
            "asn": f"AS{conn['asn']}" if conn.get("asn") else "", "net_type": "", "flags": {}}


GEO_PROVIDERS = [
    ("https://api.ipapi.is/", _parse_ipapi_is),
    ("http://ip-api.com/json/?fields=status,message,country,countryCode,regionName,city,timezone,isp,org,as,"
     "mobile,proxy,hosting,query", _parse_ip_api),
    ("https://ipwho.is/", _parse_ipwho),
]


# Что открываем «как Claude»: без ключа сервисы отвечают предсказуемо (api: 401 из разрешённого региона, 403 из запрещённого)
CLAUDE_SITE = "https://claude.ai/"


CLAUDE_API = "https://api.anthropic.com/v1/models"


# Страны, из которых Claude, по сообщениям Anthropic, недоступен. Список может устареть: настоящий ответ api.anthropic.com
# важнее, это только запасное предупреждение, если проверить сервис не удалось.
CLAUDE_UNSUPPORTED = ("CN", "RU", "BY", "IR", "KP", "CU", "SY")


FLAG_TEXT = {"datacenter": "дата-центр / хостинг", "proxy": "известный прокси", "vpn": "известный VPN",
             "tor": "выходной узел Tor", "abuser": "жалобы на злоупотребления"}


def judge_claude_site(status, headers, body):
    """Ответ claude.ai без входа -> (уровень, текст)."""
    loc = headers.get("location", "")
    text = body[:4000].decode("utf-8", "replace") if isinstance(body, bytes) else str(body)[:4000]
    if "app-unavailable-in-region" in loc or "app-unavailable-in-region" in text:
        return "bad", "claude.ai: недоступен в этом регионе (app-unavailable-in-region)"
    if headers.get("cf-mitigated") == "challenge" or (
            status in (403, 429, 503) and ("Just a moment" in text or "challenge-platform" in text)):
        return "warn", ("claude.ai: Cloudflare требует проверку браузера. У адреса плохая репутация: вход часто "
                        "заканчивается «Couldn't verify your browser»")
    if status in (200, 301, 302, 303, 307, 308):
        return "ok", f"claude.ai: открывается (HTTP {status})"
    if status == 403:
        return "bad", "claude.ai: HTTP 403, доступ запрещён (вероятно, регион или блокировка адреса)"
    return "warn", f"claude.ai: неожиданный ответ HTTP {status}"


def judge_claude_api(status, body):
    """Ответ api.anthropic.com без ключа -> (уровень, текст)."""
    text = body[:500].decode("utf-8", "replace") if isinstance(body, bytes) else str(body)[:500]
    if status == 401:
        return "ok", "api.anthropic.com: регион разрешён (без ключа ответ 401, как и должно быть)"
    if status == 403:
        return "bad", "api.anthropic.com: HTTP 403 («Request not allowed»): регион или адрес не разрешён"
    if status in (400, 404, 405):
        return "ok", f"api.anthropic.com: отвечает (HTTP {status})"
    if status == 429:
        return "warn", "api.anthropic.com: HTTP 429, слишком много запросов с этого адреса"
    return "warn", f"api.anthropic.com: неожиданный ответ HTTP {status} {text[:60]}".strip()


def utc_hours(tzid):
    """Смещение пояса tzid от UTC в часах сейчас или None."""
    try:
        from datetime import datetime
        from zoneinfo import ZoneInfo
        return datetime.now(ZoneInfo(tzid)).utcoffset().total_seconds() / 3600
    except Exception:  # noqa: BLE001  нет базы часовых поясов или неизвестный пояс
        return None


def merge_geo(found):
    """Объединить ответы сервисов: основные поля — от первого ответившего, пометки — от всех."""
    merged, flags = {}, {}
    for g in found:
        for k, v in g.items():
            if k == "flags":
                for f, on in v.items():
                    flags[f] = flags.get(f, False) or on
            elif v and not merged.get(k):
                merged[k] = v
    merged["flags"] = flags
    merged["sources"] = len(found)
    return merged


def assess(exit_info, real_ip, claude, env_tz="", host_offset=None):
    """Выводы по результатам: [(уровень, текст)]."""
    out = []
    if not exit_info:
        return [("bad", "не удалось определить выходной адрес: сервисы определения не ответили через этот выход")]
    ip, code = exit_info.get("ip", ""), (exit_info.get("code") or "").upper()
    if real_ip:
        if real_ip == ip:
            out.append(("bad", "ВЫХОД СОВПАДАЕТ С ВАШИМ НАСТОЯЩИМ АДРЕСОМ: защиты нет, трафик идёт мимо VPN или прокси"))
        else:
            out.append(("ok", "выходной адрес отличается от настоящего: настоящий адрес сайтам не виден"))
    bad = [FLAG_TEXT[f] for f in FLAG_TEXT if exit_info["flags"].get(f)]
    if bad:
        out.append(("warn", "адрес помечен как «" + "», «".join(bad) + "»: Claude и Cloudflare чаще просят проверку, "
                            "а аккаунты с таких адресов чаще блокируют; надёжнее домашний (residential) адрес"))
    elif exit_info["flags"]:
        out.append(("ok", "адрес не значится ни дата-центром, ни VPN/прокси, ни Tor, жалоб нет"))
    else:
        out.append(("warn", "сервисы определения не дали пометок о типе сети (дата-центр/VPN): репутацию адреса "
                            "проверить не удалось"))
    if exit_info.get("net_type") in ("hosting", "datacenter") and not bad:
        out.append(("warn", "тип сети: хостинг. Для Claude надёжнее провайдер домашнего интернета"))
    if exit_info["flags"].get("mobile"):
        out.append(("ok", "адрес мобильного оператора: у таких адресов хорошая репутация, но он общий для многих"))
    site, api = claude.get("site"), claude.get("api")
    for res in (site, api):
        if res:
            out.append(res)
    decided = bool(api and api[0] in ("ok", "bad"))
    if code in CLAUDE_UNSUPPORTED and not decided:
        out.append(("warn", f"страна {code} в списке регионов без Claude (список может устареть; прямая проверка "
                            "api.anthropic.com не удалась)"))
    if env_tz and exit_info.get("timezone"):
        a, b = utc_hours(env_tz), utc_hours(exit_info["timezone"])
        if a is not None and b is not None and abs(a - b) >= 1:
            out.append(("warn", f"часовой пояс среды {env_tz} не совпадает с регионом выхода ({exit_info['timezone']}): "
                                "сайты сравнивают пояс браузера с адресом; задайте поясу среды значение региона"))
        elif a is not None and b is not None:
            out.append(("ok", f"часовой пояс среды совпадает с регионом выхода ({exit_info['timezone']})"))
    elif exit_info.get("timezone") and host_offset is not None:
        b = utc_hours(exit_info["timezone"])
        if b is not None and abs(host_offset - b) >= 1:
            out.append(("warn", f"пояс региона выхода {exit_info['timezone']}, а на компьютере другой: задайте среде "
                                "часовой пояс региона выхода (настройки среды, «Система внутри среды»)"))
    return out


def verdict(findings):
    levels = {lvl for lvl, _t in findings}
    return "bad" if "bad" in levels else "warn" if "warn" in levels else "ok"


def check_exit(proxy="", auth="", timeout=15, real_url=None, compare_real=True, env_tz=""):
    """Проверить выход через `proxy` (пусто — напрямую с этого компьютера) -> словарь отчёта.

    Ключи: exit (адрес и местоположение), real_ip, claude, latency_ms, findings, verdict. Запросы к сервисам
    определения адреса идут параллельно; сбой одного сервиса не мешает остальным."""
    from concurrent.futures import ThreadPoolExecutor

    failed = []        # (сервис, причина): видно в отчёте, чтобы сбой одного сервиса не оставался загадкой

    def geo(provider, via=None):
        url, parse = provider
        host = url.split("/")[2] if "//" in url else url
        try:
            # via: None — через проверяемый выход; "" — напрямую (настоящий адрес для сравнения)
            status, _h, body, _ms = (http_request(url, proxy, auth, timeout) if via is None
                                     else http_request(url, via, "", timeout))
        except http_errors() as e:
            failed.append((host, f"не ответил: {e or type(e).__name__}"))
            return None
        if status != 200:
            failed.append((host, f"HTTP {status}"))
            return None
        try:
            got = parse(json.loads(body.decode("utf-8", "replace")))
        except Exception as e:  # noqa: BLE001  чужой ответ может быть любым: разбор не должен валить проверку
            failed.append((host, f"ответ не разобран ({type(e).__name__})"))
            return None
        if got is None:
            failed.append((host, "в ответе нет адреса"))
        return got

    def claude_get(url):
        try:
            return http_request(url, proxy, auth, timeout)
        except http_errors() as e:
            return e

    with ThreadPoolExecutor(max_workers=5) as pool:
        geo_jobs = [pool.submit(geo, p) for p in GEO_PROVIDERS]
        site_job = pool.submit(claude_get, CLAUDE_SITE)
        api_job = pool.submit(claude_get, CLAUDE_API)
        real_job = pool.submit(geo, ((real_url or GEO_PROVIDERS[0][0]), GEO_PROVIDERS[0][1]), "") if (
            compare_real and proxy) else None
        found = [g for g in (j.result() for j in geo_jobs) if g]
        site, api = site_job.result(), api_job.result()
        real = real_job.result() if real_job else None
    exit_info = merge_geo(found) if found else None
    claude = {}
    for key, res, judge in (("site", site, lambda r: judge_claude_site(r[0], r[1], r[2])),
                            ("api", api, lambda r: judge_claude_api(r[0], r[2]))):
        if isinstance(res, Exception):
            name = "claude.ai" if key == "site" else "api.anthropic.com"
            claude[key] = ("bad", f"{name}: не открылся через этот выход ({res})")
        else:
            claude[key] = judge(res)
    latency = api[3] if not isinstance(api, Exception) else None
    findings = assess(exit_info, (real or {}).get("ip", ""), claude, env_tz=env_tz,
                      host_offset=time.localtime().tm_gmtoff / 3600)
    if compare_real and proxy and not real:
        findings.append(("warn", "настоящий адрес определить не удалось: сравнить выход с ним нельзя"))
    return {"exit": exit_info, "real_ip": (real or {}).get("ip", ""), "claude": claude, "latency_ms": latency,
            "findings": findings, "verdict": verdict(findings), "sources_failed": failed}


def check_vpn(name, timeout=15, compare_real=True, env_tz=""):
    """Запустить клиент VPN `name`, проверить выход через него (check_exit) и остановить клиент."""
    import asyncio
    kind, path = vpn_source(name)
    problem = vpn_binary_problem(kind)
    if problem:
        raise ValueError(problem)
    with open(path, encoding="utf-8") as f:
        text = f.read()
    client = VpnClient(kind, path, vpn_dir() + "/" + name + ".test.log")
    try:
        try:
            asyncio.run(client.start())
        except OSError as e:
            raise ValueError(f"VPN «{name}» не запустился: {e}") from None
        report = check_exit(client.upstream.label, client.upstream.auth or "", timeout, compare_real=compare_real,
                            env_tz=env_tz)
    finally:
        client.stop()
    report["transport"] = transport_report(kind, text)
    report["verdict"] = verdict(report["findings"] + report["transport"])
    return report


def format_report(report, title=""):
    """Отчёт текстом для окна: ✔ хорошо, ⚠ предупреждение, ✖ плохо."""
    mark = {"ok": "✔", "warn": "⚠", "bad": "✖"}
    lines = [title] if title else []
    e = report.get("exit")
    if e:
        place = ", ".join(x for x in (e.get("city"), e.get("region"), e.get("country")) if x)
        lines += [f"Адрес выхода:  {e.get('ip', '?')}",
                  f"Место:         {place or '?'}" + (f" ({e['code']})" if e.get("code") else ""),
                  f"Провайдер:     {e.get('org') or '?'}" + (f" · {e['asn']}" if e.get("asn") else "")
                  + (f" · тип: {e['net_type']}" if e.get("net_type") else ""),
                  f"Часовой пояс:  {e.get('timezone') or '?'}",
                  f"Источников:    {e.get('sources', 0)} из {len(GEO_PROVIDERS)}"]
    if report.get("real_ip"):
        lines.append(f"Настоящий:     {report['real_ip']}")
    if report.get("latency_ms") is not None:
        lines.append(f"Задержка до api.anthropic.com через выход: {report['latency_ms']} мс")
    if report.get("sources_failed"):
        lines.append("Сервисы без ответа: " + "; ".join(f"{h} ({why})" for h, why in report["sources_failed"]))
    lines += ["", "Выводы:"] + [f"  {mark[lvl]} {t}" for lvl, t in report["findings"]]
    if report.get("transport"):
        lines += ["", "Безопасность и отпечаток VPN-транспорта:"] + [f"  {mark[lvl]} {t}" for lvl, t in report["transport"]]
    final = {"ok": "ИТОГ: подходит для Claude", "warn": "ИТОГ: работать можно, но есть риски (см. ⚠)",
             "bad": "ИТОГ: для Claude не подходит или не защищает (см. ✖)"}[report["verdict"]]
    return "\n".join(lines + ["", final])

