"""Сетевой шлюз: общие константы и мелкие помощники (время, host:port, публичные адреса, имена хостов)."""

from ..lazy import datetime, ipaddress, socket


HEAD_LIMIT = 64 * 1024


HEAD_TIMEOUT = 30


CONNECT_TIMEOUT = 15


# Соединение, по которому нет ни байта в обе стороны дольше этого, прокси закрывает сам: клиент увидит обрыв и повторит
# запрос, а не будет ждать мёртвый туннель до своего большого тайм-аута (после сна, смены сети, падения VPN).
# Живые потоки (SSE, WebSocket с пингами) байты передают, поэтому их это не затрагивает.
IDLE_TIMEOUT = 180


# Если туннель через вышестоящий прокси не готов за это время, рядом запускается второй такой же: побеждает первый
# готовый. Потерянный пакет в начале соединения иначе стоит 1, 3, 7 секунд ожидания.
HEDGE_DELAY = 2.0


# Сколько вторых туннелей может строиться одновременно. Когда вышестоящий прокси перегружен или отвечает медленно
# для всех, повтор каждого соединения удвоил бы нагрузку на него и сделал бы хуже.
MAX_HEDGES = 4


# Сколько туннелей к вышестоящему прокси может устанавливаться одновременно. Приложения (Claude Desktop) открывают
# десятки соединений за секунду; платные прокси такой всплеск часто принимают, но не обслуживают (соединения висят
# до тайм-аута клиента). Лишние ждут своей очереди: установка занимает около полусекунды, всплеск рассасывается за секунды.
MAX_SETUPS = 8


# Клиент отправил запрос, а ответа нет столько секунд: туннель мёртв (прокси бросил соединение молча или сменил адрес).
# Без этого приложение ждёт свой огромный тайм-аут (у Claude минуты), а на экране «думает» без конца. Применяется только
# к «горячим» сайтам (Claude): у стриминговых ответов приходят хотя бы пинги, а ответ дольше этого срока — аномалия.
STALL_TIMEOUT = 45


# К «горячим» сайтам: и стрим, замолчавший посреди ответа (ни байта в обе стороны), мёртв. Сервер Claude присылает хотя бы
# пинги; обычный лимит простоя (3 минуты) для этого слишком долог. Это не касается простаивающих keep-alive: их и так
# закрывает сервер примерно через минуту.
HOT_IDLE = 90


BUF = 64 * 1024


# Диапазон 198.18.0.0/15 зарезервирован для стендов и в обычных сетях не маршрутизируется. Его отдают
# DNS-серверы VPN и прокси-клиентов в режиме fake-ip (Clash, sing-box, Hiddify…): сам клиент подменяет
# такой адрес настоящим. Если считать его «частным», при таком VPN не откроется ни один сайт.
FAKE_IP_PREFIX = 0xC6120000 >> 17   # 198.18.0.0/15: старшие 15 бит адреса


def now():
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


def split_hostport(s, default_port):
    if s.startswith("["):
        end = s.find("]")
        if end < 0:
            raise ValueError(s)
        host, rest = s[1:end], s[end + 1:]
        if rest.startswith(":"):
            port = int(rest[1:])
        elif rest == "":
            port = default_port
        else:
            raise ValueError(s)
    elif s.count(":") == 1:
        host, p = s.split(":")
        port = int(p)
    elif ":" in s:
        raise ValueError(s)
    else:
        host, port = s, default_port
    if not host or not 0 < port < 65536:
        raise ValueError(s)
    return host, port


def is_public(ip_str):
    ip = ipaddress.ip_address(ip_str.split("%", 1)[0])
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.version == 4 and int(ip) >> 17 == FAKE_IP_PREFIX:
        return True
    return ip.is_global and not ip.is_multicast


_HOST_BAD = frozenset(" \t/\\@?#<>\"'`|^{}%;,*")


def canon_host(host):
    """Каноничное ASCII-имя хоста или ValueError.

    Имя приводится к той форме, в которой оно уйдёт дальше (IDNA, нижний регистр), и только потом проверяется:
    иначе «1²7.0.0.1» не распознаётся как IP, но после IDNA-кодирования превращается в 127.0.0.1.
    Управляющие символы и разделители запрещены (из имени нельзя собрать лишние строки запроса)."""
    if not host or len(host) > 253:
        raise ValueError("недопустимое имя хоста")
    if any(ord(c) < 33 or ord(c) == 127 or c in _HOST_BAD for c in host):
        raise ValueError("недопустимые символы в имени хоста")
    if ":" in host:    # IPv6-литерал
        try:
            return str(ipaddress.ip_address(host))
        except ValueError:
            raise ValueError("недопустимый IPv6-адрес") from None
    try:
        name = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ValueError("недопустимое имя хоста") from None
    if not name or len(name) > 253 or any(not 0 < len(label) < 64 for label in name.rstrip(".").split(".")):
        raise ValueError("недопустимое имя хоста")
    return name


# Управление перегрузкой для соединений шлюза (вышестоящий прокси): BBR заметно быстрее CUBIC на длинных каналах с потерями,
# где обычно и работают платные прокси: исходящие данные (отправка запросов, загрузка) не «проседают» после каждой потери.
# Ядро разрешает выбирать BBR обычному пользователю только если он есть в net.ipv4.tcp_allowed_congestion_control.
CONGESTION_CHOICE = b"bbr"


_CC_STATE = {"name": None}


def congestion_control():
    """Какое управление перегрузкой получат соединения шлюза: 'bbr' или системное (например 'cubic')."""
    if _CC_STATE["name"] is None:
        try:
            with open("/proc/sys/net/ipv4/tcp_allowed_congestion_control", encoding="ascii") as f:
                allowed = f.read().split()
            default = open("/proc/sys/net/ipv4/tcp_congestion_control", encoding="ascii").read().strip()
        except OSError:
            allowed, default = [], "?"
        _CC_STATE["name"] = CONGESTION_CHOICE.decode() if CONGESTION_CHOICE.decode() in allowed else default
    return _CC_STATE["name"]


def tune_socket(sock):
    """Живые соединения не должны зависать насовсем: после сна компьютера, смены сети или перезапуска VPN
    мёртвый сокет обнаруживается за пару минут, а не остаётся «открытым» навсегда. Мелкие записи не ждут."""
    if sock is None or sock.family not in (socket.AF_INET, socket.AF_INET6):
        return
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 15)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 4)
    except (OSError, AttributeError):
        pass
    if congestion_control() == CONGESTION_CHOICE.decode():
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_CONGESTION, CONGESTION_CHOICE)
        except (OSError, AttributeError):
            pass
