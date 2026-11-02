"""Сетевой шлюз: заранее открытые туннели к «горячим» сайтам (Claude), чтобы новое соединение не ждало подключения.

Каждое новое соединение через вышестоящий прокси начинается с запроса CONNECT: путь до прокси, подключение прокси к сайту,
ответ — от десятых долей секунды до секунды (платные прокси часто далеко). Для сайтов, к которым ходят постоянно
(Claude открывает десятки соединений), шлюз держит в запасе пару уже открытых туннелей: клиент получает готовый и
начинает TLS сразу. Запас обновляется в фоне, живёт недолго (прокси режут простаивающие и долгие туннели) и поддерживается,
только пока сайтом пользуются. Туннели открываются только к сайтам, к которым клиент уже успешно подключался, то есть
политику (список разрешённых сайтов, частные адреса) пул не обходит."""

import time

from ..lazy import asyncio


# Сайты, к которым запас держится сразу (остальные можно добавить при создании шлюза)
HOT_SUFFIXES = ("anthropic.com", "claude.ai", "claude.com")


# Сколько готовых туннелей на сайт и сколько секунд один живёт: прокси режут простаивающие туннели, а у части поставщиков
# туннель живёт не дольше минуты, поэтому запас обновляется заметно чаще
WARM_SIZE = 2


WARM_TTL = 20.0


# Сколько секунд после последнего использования сайта запас ещё поддерживается
WARM_KEEP = 120.0


# Пауза после неудачной попытки открыть запасной туннель (не долбить перегруженный прокси)
WARM_RETRY = 5.0


def is_hot(host, extra=()):
    """Относится ли сайт к «горячим»: host равен суффиксу или его поддомен."""
    h = host.lower().rstrip(".")
    return any(h == s or h.endswith("." + s) for s in tuple(HOT_SUFFIXES) + tuple(extra))


class WarmPool:
    """Запас готовых туннелей по ключу (прокси, хост, порт)."""

    def __init__(self, size=WARM_SIZE, ttl=WARM_TTL, keep=WARM_KEEP, clock=time.monotonic):
        self.size, self.ttl, self.keep, self.clock = size, ttl, keep, clock
        self.pool = {}        # ключ -> [(когда открыт, reader, writer)]
        self.used = {}        # ключ -> когда последний раз брали или просили запас
        self.makers = {}      # ключ -> корутина-фабрика нового туннеля
        self.backoff = {}     # ключ -> до какого момента не пробуем снова
        self.filling = set()
        self.tasks = set()    # фоновые пополнения: при остановке отменяются, а не висят до сборщика мусора
        self.hits = 0
        self.misses = 0

    def stale(self, entry, now):
        created, reader, writer = entry
        return now - created > self.ttl or writer.is_closing() or reader.at_eof()

    def take(self, key):
        """Готовый туннель (reader, writer) или None. Просроченные и закрытые прокси выбрасываются."""
        now = self.clock()
        self.used[key] = now
        items = self.pool.get(key, [])
        while items:
            entry = items.pop(0)
            if self.stale(entry, now):
                entry[2].close()
                continue
            self.hits += 1
            return entry[1], entry[2]
        self.misses += 1
        return None

    def want(self, key, make):
        """Сайтом пользуются: поддерживать запас. make() — корутина, открывающая новый туннель."""
        self.used[key] = self.clock()
        self.makers[key] = make
        if key not in self.filling:
            self.spawn(self.fill(key, make))

    def spawn(self, coro):
        task = asyncio.ensure_future(coro)
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def fill(self, key, make):
        if key in self.filling or self.clock() < self.backoff.get(key, 0.0):
            return
        self.filling.add(key)
        try:
            while self.clock() - self.used.get(key, 0.0) < self.keep:
                items = self.pool.setdefault(key, [])
                now = self.clock()
                for entry in [e for e in items if self.stale(e, now)]:
                    items.remove(entry)
                    entry[2].close()
                if len(items) >= self.size:
                    break
                try:
                    reader, writer = await make()
                except (OSError, asyncio.TimeoutError):
                    self.backoff[key] = self.clock() + WARM_RETRY
                    break
                items.append((self.clock(), reader, writer))
        finally:
            self.filling.discard(key)

    async def maintain(self):
        """Фоновое обновление: устаревшие туннели заменяются, запас неиспользуемых сайтов закрывается."""
        while True:
            await asyncio.sleep(self.ttl / 2)
            now = self.clock()
            for key, make in list(self.makers.items()):
                if now - self.used.get(key, 0.0) >= self.keep:
                    for entry in self.pool.pop(key, []):
                        entry[2].close()
                    self.makers.pop(key, None)
                    continue
                self.spawn(self.fill(key, make))

    def flush(self, label, pause=WARM_RETRY * 3):
        """Прокси `label` подвёл (запрос без ответа): запасные туннели к нему, скорее всего, тоже мёртвые. Закрываем их и на
        `pause` секунд прекращаем пополнение: ближайшие соединения пойдут обычным путём и быстро покажут, жив ли прокси."""
        for key in [k for k in self.pool if k[0] == label]:
            for entry in self.pool.pop(key, []):
                entry[2].close()
        for key in [k for k in self.makers if k[0] == label]:
            self.backoff[key] = self.clock() + pause

    def close_all(self):
        for task in list(self.tasks):
            task.cancel()
        for items in self.pool.values():
            for entry in items:
                entry[2].close()
        self.pool.clear()
        self.makers.clear()


class SetupGate:
    """Сколько туннелей к вышестоящему прокси можно открывать одновременно; лимит подстраивается.

    Платные прокси плохо переносят всплеск соединений, поэтому лимит ограничен (по умолчанию 8). Но когда прокси
    отвечает быстро, а соединения всё равно стоят в очереди, лимит растёт по одному (до тройного): очередь стоит клиенту
    секунд. Сбой или тайм-аут установки вдвое сжимает лимит: прокси перегружен, давить на него не нужно."""

    def __init__(self, base):
        self.limit = self.base = base
        self.ceiling = base * 3
        self.floor = max(2, base // 2)
        self.active = 0
        self.waiters = []         # короткая очередь ожидающих: список не дороже deque, а импорт collections не нужен

    async def acquire(self):
        while self.active >= self.limit:
            fut = asyncio.get_running_loop().create_future()
            self.waiters.append(fut)
            try:
                await fut
            except BaseException:
                if fut in self.waiters:
                    self.waiters.remove(fut)
                raise
        self.active += 1

    def release(self):
        self.active -= 1
        for _ in range(max(0, self.limit - self.active)):
            while self.waiters:
                fut = self.waiters.pop(0)
                if not fut.done():
                    fut.set_result(None)
                    break

    async def __aenter__(self):
        await self.acquire()

    async def __aexit__(self, *exc):
        self.release()

    def fast(self, took, waited):
        """Туннель открылся быстро, но клиент стоял в очереди: можно пускать больше."""
        if waited > 0.2 and took < 1.0:
            self.limit = min(self.ceiling, self.limit + 1)

    def slow(self):
        self.limit = max(self.floor, self.limit // 2)
