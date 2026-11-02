"""Сетевой шлюз: цепочка каналов выхода (прокси, VPN-клиент, прямой выход) с переключением на запасной.

Каналы идут по порядку: пока первый работает, через него идёт всё. Если установить соединение через канал не
удалось, он считается упавшим и пропускается, а соединение идёт через следующий. Упавшие каналы в фоне
проверяются, и как только предпочитаемый снова отвечает, новые соединения возвращаются на него. Без такой
проверки канал, у которого «остыл» таймер, снова стоил бы первому же соединению весь тайм-аут подключения.
Уже открытые соединения не переносятся (TLS-поток нельзя пересадить на другой канал): они доживают на прежнем."""

from ..lazy import asyncio


# Как часто в фоне проверяются упавшие каналы и сколько ждать ответа на проверку
PROBE_EVERY = 5.0


PROBE_TIMEOUT = 8.0


PROBE_TARGET = ("example.com", 443)


CHANNEL_KINDS = ("proxy", "vpn", "direct")


class Channel:
    """Один канал выхода. proxy: вышестоящий прокси; vpn: VPN-клиент (запускается шлюзом); direct: собственный
    выход этого компьютера (если на нём включён системный VPN, это и есть выход через него)."""

    def __init__(self, name, kind, upstream=None, client=None):
        if kind not in CHANNEL_KINDS:
            raise ValueError(f"неизвестный вид канала: {kind}")
        self.name, self.kind = name, kind
        self.upstream = upstream      # Upstream (для vpn появляется после запуска клиента); None у direct
        self.client = client          # VpnClient или None
        self.down = False             # упал: пропускается, пока проверка в фоне не подтвердит, что он снова отвечает
        self.error = ""               # почему упал последний раз
        self.broken = False           # не запустился совсем (нет программы, плохой конфиг): не пробуем
        self.ready = None             # asyncio.Event: клиент VPN запущен или не запустился

    @property
    def label(self):
        if self.kind == "direct":
            return "direct"
        return self.name if self.kind == "vpn" else (self.upstream.label if self.upstream else self.name)


class Chain:
    def __init__(self, channels):
        self.channels = list(channels)

    def __bool__(self):
        return bool(self.channels)

    @staticmethod
    def usable(ch):
        return not ch.broken and not ch.down

    def order(self):
        """Каналы в порядке попыток: исправные по списку, затем упавшие (последняя надежда). Сломанные — никогда."""
        live = [c for c in self.channels if self.usable(c)]
        fallen = [c for c in self.channels if not c.broken and c.down]
        return live + fallen

    @staticmethod
    def failed(ch, reason):
        """Канал не отвечает. Возвращает True, если до этого он считался исправным (стоит записать в журнал)."""
        was_up = not ch.down
        ch.down, ch.error = True, reason
        return was_up

    @staticmethod
    def worked(ch):
        """Через канал удалось установить соединение. True, если он до этого числился упавшим."""
        was_down = ch.down
        ch.down, ch.error = False, ""
        return was_down

    def active(self):
        """Первый исправный канал (его сейчас получают новые соединения) или None."""
        return next((c for c in self.channels if self.usable(c)), None)

    def describe(self):
        return " → ".join(c.label for c in self.channels)


def parse_chain_spec(spec):
    """Строка канала из командной строки: proxy, direct или vpn:<вид>:<путь к конфигурации>."""
    if spec in ("proxy", "direct"):
        return spec, None, None
    if spec.startswith("vpn:"):
        _, _, rest = spec.partition(":")
        kind, _, path = rest.partition(":")
        if kind in ("wireguard", "xray", "singbox") and path.startswith("/"):
            return "vpn", kind, path
    raise ValueError(f"недопустимый канал '{spec}': нужен proxy, direct или vpn:<wireguard|xray|singbox>:/путь")


async def probe(ch):
    """Ответил ли канал: открыть туннель до PROBE_TARGET. direct и ещё не запущенный VPN считаем ответившими."""
    up = ch.upstream
    if up is None:
        return True
    try:
        _r, w = await asyncio.wait_for(up.tunnel(*PROBE_TARGET), PROBE_TIMEOUT)
    except (OSError, asyncio.TimeoutError):
        return False
    w.close()
    return True

