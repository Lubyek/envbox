"""Ленивые модули стандартной библиотеки: настоящий import происходит при первом обращении к атрибуту.

Служебные команды шлюза (seccomp, version, gitcheck, мост внутри среды) запускаются десятки раз в день, и каждая
не должна платить за то, что нужно только другой: asyncio занимает ~45 мс, json и re ~6 мс, socket ~3 мс."""


class _LazyModule:
    def __init__(self, name):
        self._name = name
        self._real = None

    def __getattr__(self, attr):
        real = self.__dict__["_real"]
        if real is None:
            import importlib
            real = self.__dict__["_real"] = importlib.import_module(self.__dict__["_name"])
        return getattr(real, attr)


asyncio = _LazyModule("asyncio")
base64 = _LazyModule("base64")
datetime = _LazyModule("datetime")
ipaddress = _LazyModule("ipaddress")
json = _LazyModule("json")
re = _LazyModule("re")
signal = _LazyModule("signal")
socket = _LazyModule("socket")
threading = _LazyModule("threading")
urllib_parse = _LazyModule("urllib.parse")
