"""Сетевой шлюз: подключение к одному из адресов хоста (Happy Eyeballs)."""

from ..lazy import asyncio, ipaddress
from .common import CONNECT_TIMEOUT, tune_socket


STAGGER = 0.25   # через сколько начинать следующий адрес, если предыдущий ещё не ответил


def interleave(ips):
    """Адреса вперемешку по семействам (v6, v4, v6, v4…), начиная с семейства первого адреса:
    если IPv6 «чёрная дыра», IPv4 попробуется почти сразу, а не через весь тайм-аут."""
    groups, order = {}, []
    for ip in ips:
        try:
            fam = ipaddress.ip_address(ip.split("%", 1)[0]).version
        except ValueError:
            fam = 4
        if fam not in groups:
            groups[fam] = []
            order.append(fam)
        groups[fam].append(ip)
    out = []
    while any(groups.values()):
        for fam in order:
            if groups[fam]:
                out.append(groups[fam].pop(0))
    return out


async def connect_race(ips, port, timeout=CONNECT_TIMEOUT, stagger=STAGGER):
    """(адрес, reader, writer) первого успешного подключения. Остальные попытки отменяются.
    OSError (последняя ошибка) или TimeoutError, если не удалось ни одно."""
    loop = asyncio.get_running_loop()
    queue = interleave(ips)
    tasks = {}
    last = None
    end = loop.time() + timeout
    try:
        while True:
            if queue:
                ip = queue.pop(0)
                tasks[asyncio.ensure_future(asyncio.open_connection(ip, port))] = ip
            if not tasks:
                break
            remaining = end - loop.time()
            if remaining <= 0:
                break
            done, _ = await asyncio.wait(set(tasks), timeout=min(stagger, remaining) if queue else remaining,
                                         return_when=asyncio.FIRST_COMPLETED)
            for t in done:
                ip = tasks.pop(t)
                try:
                    r, w = t.result()
                except OSError as e:
                    last = e
                    continue
                tune_socket(w.get_extra_info("socket"))
                return ip, r, w
            if not queue and not tasks:
                break
    finally:
        for t in tasks:
            t.cancel()
        for t, _ip in list(tasks.items()):
            try:
                _r, w = await t
                w.close()    # подключение успело завершиться в момент отмены
            except BaseException:   # noqa: BLE001 — отменённые и неудавшиеся попытки не важны
                pass
    if last is not None:
        raise last
    raise asyncio.TimeoutError()
