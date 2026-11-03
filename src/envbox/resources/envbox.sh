#!/usr/bin/env bash
# envbox — запуск одной команды в изолированной среде на базе bubblewrap.
#
#   envbox -n <имя> -w <каталог> [опции] -- <команда> [аргументы...]
#
# (Этот файл извлекается из envbox.py автоматически: правьте envbox.py.)
# Требования: Linux, bash >= 4.4, bubblewrap (>= 0.8 для --disable-userns),
# GNU coreutils (realpath). Запуск только от обычного пользователя.

set -euo pipefail

readonly PROG="envbox"

die()  { printf '%s: ошибка: %s\n' "$PROG" "$*" >&2; exit 1; }
warn() { printf '%s: предупреждение: %s\n' "$PROG" "$*" >&2; }
info() { printf '%s: %s\n' "$PROG" "$*" >&2; }

usage() {
  cat <<'EOF'
Использование:
  envbox -n <имя> -w <каталог> [опции] -- <команда> [аргументы...]

Обязательные:
  -n, --name <имя>        имя среды: [A-Za-z0-9][A-Za-z0-9._-]*, до 48 символов;
                          домашний каталог среды: <корень>/<имя>/home
                          (корень по умолчанию ~/.envbox, см. --root)
  -w, --workdir <каталог> рабочий каталог проекта (единственный путь хоста,
                          доступный на запись; не нужен с --no-workdir)

Опции:
  --root <каталог>        каталог данных envbox (по умолчанию ~/.envbox). Если не задан,
                          берётся переменная ENVBOX_ROOT, затем первая строка файла
                          ~/.config/envbox/root (его пишет GUI)
  --no-net                отключить сеть (остаётся только loopback внутри среды)
  --net-log               своей сети у среды нет; выход наружу только через
                          HTTP(S)-прокси на хосте, который журналирует каждое
                          соединение в <корень>/<имя>/net.log
  --allow-domain <домен>  разрешить только эти домены (включает --net-log);
                          'example.com' — точное совпадение, '*.example.com' —
                          домен и все поддомены; повторяемый
  --upstream <URL>        пускать весь трафик через вышестоящий прокси (включает --net-log):
                          http://хост:порт, socks5://хост:порт, socks5h://хост:порт.
                          Логин:пароль — только через переменную окружения
                          ENVBOX_UPSTREAM_AUTH=логин:пароль (в argv они были бы видны в ps).
                          Имена хостов тогда разрешает вышестоящий прокси, а не этот компьютер
  --chain <канал>         канал выхода по порядку (включает --net-log; повторяемый). Первый рабочий
                          получает все новые соединения, при его отказе берётся следующий, упавший
                          проверяется в фоне и при возвращении снова становится первым. Каналы:
                          proxy (это --upstream), direct (выход этого компьютера, в том числе его
                          системный VPN), vpn:<wireguard|xray|singbox>:/путь/к/конфигурации (клиент
                          запускается и останавливается вместе со средой, без root)
  --no-accel              отключить ускорение прокси: по умолчанию к сайтам Claude шлюз держит наготове открытые
                          туннели (новое соединение не ждёт подключения прокси), подстраивает повторы и очередь и
                          быстро рвёт мёртвый туннель, чтобы приложение повторило запрос, а не «думало» без конца
  --direct-domain <домен> с --upstream: подключаться к этому сайту напрямую, мимо вышестоящего
                          прокси (сайт видит ваш настоящий адрес, а не адрес прокси). Среда по-прежнему
                          выходит только через прокси envbox. Формат как у --allow-domain; в режиме
                          --allow-domain такой сайт разрешён автоматически; повторяемый
  --expose-port <порт>    сделать порт 127.0.0.1:<порт> внутри среды доступным другим средам
                          через unix-сокет <корень>/<имя>/run/expose (нужен --net-log
                          или --no-net); повторяемый
  --attach <среда[:порт[:локальный]]>
                          внутри этой среды слушать 127.0.0.1:<локальный> (по умолчанию
                          <порт>, по умолчанию 9222) и пересылать на порт, открытый
                          средой <среда> через --expose-port (нужен --net-log или --no-net)
  --lang <локаль>         язык системы внутри среды (LANG), например ru_RU.UTF-8; локаль должна
                          быть сгенерирована на компьютере (locale -a)
  --timezone <пояс>       часовой пояс внутри среды, например Europe/Moscow (файл из
                          /usr/share/zoneinfo). Это пояс, а не подмена часов: время то же,
                          что у компьютера
  --dns <ip>              DNS-сервер для разрешения имён (повторяемый). С --net-log имена
                          разрешает прокси на компьютере через эти серверы; в режиме общей сети
                          они записываются в /etc/resolv.conf среды. Несовместим с --no-net
                          и --upstream (там имена разрешает вышестоящий прокси)
  --iso КЛЮЧ=on|off       включить или выключить одну защиту (повторяемый). По умолчанию включены все:
                          seccomp — фильтр системных вызовов (ptrace, bpf, io_uring, mount…)
                          pid — скрывать процессы компьютера   ipc — своя общая память (IPC)
                          uts — своё имя компьютера            cgroup — скрывать cgroup
                          session — без управляющего терминала (защита от TIOCSTI)
                          die_parent — завершать среду вместе с envbox
                          caps — сбросить capabilities         ro_root — корень среды только для чтения
                          clean_env — передавать только перечисленные переменные
                          neutral_dns — скрывать адреса ваших DNS в /etc/resolv.conf
                          host_net_forbidden — запретить сеть компьютера (сеть — только через прокси)
                          home_real=on — настоящий домашний каталог (нужен --confirm-host-access)
  --relaxed               старый «мягкий» набор: --iso seccomp=off --iso neutral_dns=off
                          --iso host_net_forbidden=off
  --host-files ro|rw      ВЫХОД ЗА ПЕСОЧНИЦУ: среда видит весь компьютер (ro — писать только в
                          проект, rw — писать везде) и работает с настоящим домашним каталогом.
                          Сеть, язык, часовой пояс и DNS остаются заданными. Требует
                          --confirm-host-access
  --confirm-host-access   подтверждение для --host-files: «я понимаю, что среда получает доступ
                          к моим файлам»
  --no-workdir            не монтировать рабочий каталог проекта (без -w); начальный
                          каталог — домашний каталог среды
  --wayland               пробросить сокет Wayland хоста (для окна браузера; ослабляет
                          изоляцию: композитор может отдавать снимки экрана любому клиенту)
  --net-allow-private     разрешить прокси соединяться с частными и loopback-
                          адресами (по умолчанию запрещено: это путь к сервисам хоста)
  --env VAR              передать переменную VAR со значением из окружения хоста
  --env VAR=значение      задать переменную явно (значение попадёт в argv envbox!)
  --ro <путь>             дополнительно смонтировать путь хоста только на чтение
                          (по тому же пути); повторяемый
  --rw <путь>             дополнительно смонтировать путь хоста на чтение и запись
                          (по тому же пути; как и проект, с защитой .git); повторяемый
  --global <имя>[:ro|:rw] подключить глобальную папку <корень>/_global/<имя> (по умолчанию
                          :rw) по её настоящему пути. Такие папки лежат отдельно от каталогов
                          сред: удаление среды их не затрагивает; повторяемый
  --path <каталог>        добавить каталог в начало PATH внутри среды; повторяемый
  --inbox-cmd <команда>   принимать ссылки от envbox: внутри среды запускается «команда ссылка»
                          (например claude-desktop: приложение откроет claude://… у себя)
  --inbox-scheme <схема>  разрешить ссылки такой схемы (например claude); http и https разрешены всегда; повторяемый
  --inbox-callback        принимать адреса http://localhost:порт/… и выполнять запрос внутри среды
                          (вход в Claude CLI: браузер на компьютере не может достучаться до порта среды)
  --shell <имя>           оболочка для интерактивной работы: bash (по умолчанию), fish или zsh.
                          Должна быть установлена на компьютере (в среде виден только /usr, на чтение).
                          Для удобства в пустой домашний каталог среды кладётся стартовый конфиг
  --ephemeral             домашний каталог среды в tmpfs (ничего не сохраняется)
  --no-protect-git        не защищать .git/hooks и .git/config от записи
  --allow-userns          разрешить вложенные user namespaces внутри среды
                          (нужно, если приложение само запускает bwrap/podman)
  --keep-session          то же, что --iso session=off; допустимо только если ядро запрещает
                          TIOCSTI (dev.tty.legacy_tiocsti = 0)
  --dry-run               показать команду bwrap и выйти (значения переменных
                          не печатаются)
  -h, --help              эта справка

Просмотр сетевого журнала среды:
  envbox --net-report -n <имя> [--follow | --raw]
    без флагов — сводка по хостам; --raw — все события; --follow — в реальном времени

Всегда передаются: HOME, USER, LOGNAME, SHELL, PATH, TERM (если задана на хосте),
LANG (C.UTF-8, если не передана через --env). Всё остальное окружение удаляется.
EOF
}

# --- проверки окружения запуска ---------------------------------------------

if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 4) )); then
  die "нужен bash >= 4.4, текущий: $BASH_VERSION"
fi
[[ "$(uname -s)" == Linux ]] || die "envbox работает только в Linux (bubblewrap использует namespaces ядра Linux)"
(( EUID != 0 )) || die "не запускайте envbox от root: изоляция рассчитана на непривилегированный user namespace"
[[ -n "${HOME:-}" && "$HOME" == /* && -d "$HOME" ]] || die "переменная HOME не задана или указывает на несуществующий каталог"

# --- разбор аргументов --------------------------------------------------------

name=""
workdir=""
net=1
ephemeral=0
protect_git=1
shell_name=bash
inbox_cmd=""
inbox_schemes=()
inbox_callback=0
allow_userns=0
dry_run=0
net_log=0
net_allow_private=0
net_report=0
report_mode=""
upstream=""
chain_specs=()
chain_remote=0
accel=1
iso_seccomp=1 iso_pid=1 iso_ipc=1 iso_uts=1 iso_cgroup=1 iso_session=1 iso_die_parent=1
iso_caps=1 iso_ro_root=1 iso_clean_env=1 iso_neutral_dns=1 iso_net_forced=1 iso_home_real=0
host_files=""
host_confirm=0
lang=""
timezone=""
dns_servers=()
expose_ports=()
attach_specs=()
wayland=0
no_workdir=0
allow_domains=()
direct_domains=()
env_specs=()
ro_specs=()
rw_specs=()
global_specs=()
root_opt=""
path_specs=()

set_iso() {
  local key=${1%%=*} val=${1#*=} v
  [[ "$1" == *=* ]] || die "--iso: ожидается КЛЮЧ=on|off, получено '$1'"
  case "$val" in
    on|1|true|yes) v=1 ;;
    off|0|false|no) v=0 ;;
    *) die "--iso $key: значение должно быть on или off, получено '$val'" ;;
  esac
  case "$key" in
    seccomp) iso_seccomp=$v ;;
    pid) iso_pid=$v ;;
    ipc) iso_ipc=$v ;;
    uts) iso_uts=$v ;;
    cgroup) iso_cgroup=$v ;;
    session) iso_session=$v ;;
    die_parent) iso_die_parent=$v ;;
    caps) iso_caps=$v ;;
    ro_root) iso_ro_root=$v ;;
    clean_env) iso_clean_env=$v ;;
    neutral_dns) iso_neutral_dns=$v ;;
    host_net_forbidden) iso_net_forced=$v ;;
    home_real) iso_home_real=$v ;;
    *) die "--iso: неизвестная защита '$key' (см. --help)" ;;
  esac
}

need_arg() { (( $2 >= 2 )) || die "параметру $1 нужно значение (см. --help)"; }

while (( $# )); do
  case "$1" in
    -n|--name)        need_arg "$1" $#; name=$2; shift 2 ;;
    -w|--workdir)     need_arg "$1" $#; workdir=$2; shift 2 ;;
    --no-net)         net=0; shift ;;
    --net-log)        net_log=1; shift ;;
    --allow-domain)   need_arg "$1" $#; allow_domains+=("$2"); net_log=1; shift 2 ;;
    --net-allow-private) net_allow_private=1; shift ;;
    --direct-domain)  need_arg "$1" $#; direct_domains+=("$2"); shift 2 ;;
    --upstream)      need_arg "$1" $#; upstream=$2; net_log=1; shift 2 ;;
    --chain)         need_arg "$1" $#; chain_specs+=("$2"); net_log=1; shift 2 ;;
    --no-accel)      accel=0; shift ;;
    --iso)            need_arg "$1" $#; set_iso "$2"; shift 2 ;;
    --relaxed)        iso_seccomp=0; iso_neutral_dns=0; iso_net_forced=0; shift ;;
    --host-files)     need_arg "$1" $#; host_files=$2; shift 2 ;;
    --confirm-host-access) host_confirm=1; shift ;;
    --lang)           need_arg "$1" $#; lang=$2; shift 2 ;;
    --timezone)       need_arg "$1" $#; timezone=$2; shift 2 ;;
    --dns)            need_arg "$1" $#; dns_servers+=("$2"); shift 2 ;;
    --expose-port)    need_arg "$1" $#; expose_ports+=("$2"); shift 2 ;;
    --attach)         need_arg "$1" $#; attach_specs+=("$2"); shift 2 ;;
    --wayland)        wayland=1; shift ;;
    --no-workdir)     no_workdir=1; shift ;;
    --net-report)     net_report=1; shift ;;
    --follow)         report_mode=--follow; shift ;;
    --raw)            report_mode=--raw; shift ;;
    --env)            need_arg "$1" $#; env_specs+=("$2"); shift 2 ;;
    --ro)             need_arg "$1" $#; ro_specs+=("$2"); shift 2 ;;
    --rw)             need_arg "$1" $#; rw_specs+=("$2"); shift 2 ;;
    --global)         need_arg "$1" $#; global_specs+=("$2"); shift 2 ;;
    --root)           need_arg "$1" $#; root_opt=$2; shift 2 ;;
    --path)           need_arg "$1" $#; path_specs+=("$2"); shift 2 ;;
    --shell)          need_arg "$1" $#; shell_name=$2; shift 2 ;;
    --inbox-cmd)      need_arg "$1" $#; inbox_cmd=$2; shift 2 ;;
    --inbox-scheme)   need_arg "$1" $#; inbox_schemes+=("$2"); shift 2 ;;
    --inbox-callback) inbox_callback=1; shift ;;
    --ephemeral)      ephemeral=1; shift ;;
    --no-protect-git) protect_git=0; shift ;;
    --allow-userns)   allow_userns=1; shift ;;
    --keep-session)   iso_session=0; shift ;;
    --dry-run)        dry_run=1; shift ;;
    -h|--help)        usage; exit 0 ;;
    --)               shift; break ;;
    -*)               die "неизвестный параметр: $1 (см. --help)" ;;
    *)                die "команда должна идти после '--' (встречено: $1)" ;;
  esac
done

cmd=("$@")

# --- валидация ------------------------------------------------------------------

[[ -n "$name" ]] || die "не задано имя среды (-n)"
[[ "$name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,47}$ ]] \
  || die "недопустимое имя среды '$name': разрешены латиница, цифры, '.', '_', '-', первый символ — буква или цифра, длина до 48"

# true, если путь $1 совпадает с $2 или лежит внутри него (оба — абсолютные, без '/' в конце)
is_under() { [[ "$1" == "$2" || "$1" == "$2"/* ]]; }

# Оболочка: берётся с компьютера (/usr виден в среде только на чтение)
login_shell=/bin/bash
case "$shell_name" in
  bash) ;;
  fish|zsh)
    shell_host=$(command -v "$shell_name" 2>/dev/null || true)
    [[ -n "$shell_host" ]] || die "оболочка $shell_name не установлена на компьютере (sudo pacman -S $shell_name)"
    shell_real=$(realpath -e -- "$shell_host") || die "не удалось разрешить путь $shell_host"
    is_under "$shell_real" /usr || die "оболочка $shell_name лежит вне /usr ($shell_real): в среде её не будет видно"
    login_shell=$shell_real ;;
  *) die "--shell: допустимы bash, fish, zsh (получено '$shell_name')" ;;
esac
# Приём ссылок
for sc in "${inbox_schemes[@]}"; do
  [[ "$sc" =~ ^[a-z][a-z0-9+.-]{0,30}$ ]] || die "--inbox-scheme: недопустимая схема '$sc' (строчные латинские буквы, цифры, '+', '.', '-')"
done
if (( ${#inbox_schemes[@]} )) && [[ -z "$inbox_cmd" ]]; then
  die "--inbox-scheme нужна вместе с --inbox-cmd: без команды ссылку некому открыть"
fi
inbox_on=0
if [[ -n "$inbox_cmd" ]] || (( inbox_callback )); then inbox_on=1; fi
# стартовые конфиги нужны только когда запускается сама оболочка
want_rc=0
case "$(basename -- "${cmd[0]:-}")" in bash|fish|zsh) want_rc=1 ;; esac

real_home=$(realpath -e -- "$HOME") || die "не удалось разрешить путь HOME: $HOME"
[[ "$real_home" != / ]] || die "HOME указывает на '/', так нельзя"

# Каталог данных: --root, затем ENVBOX_ROOT, затем файл ~/.config/envbox/root, иначе ~/.envbox
if [[ -z "$root_opt" ]]; then root_opt=${ENVBOX_ROOT:-}; fi
if [[ -z "$root_opt" ]]; then
  root_ptr="${XDG_CONFIG_HOME:-$real_home/.config}/envbox/root"
  if [[ -f "$root_ptr" && -r "$root_ptr" ]]; then IFS= read -r root_opt < "$root_ptr" || true; fi
fi
if [[ -z "$root_opt" ]]; then
  envbox_root="$real_home/.envbox"
else
  [[ "$root_opt" == /* ]] || die "каталог данных (--root) должен быть абсолютным путём: $root_opt"
  envbox_root=$(realpath -m -- "$root_opt") || die "не удалось разрешить каталог данных: $root_opt"
  [[ "$envbox_root" != / ]] || die "каталог данных не может быть '/'"
  if is_under "$real_home" "$envbox_root"; then
    die "каталог данных $envbox_root совпадает с HOME или содержит его — туда нельзя класть данные сред"
  fi
  if ! is_under "$envbox_root" "$real_home"; then   # HOME сам может лежать в /var/home
    case "$envbox_root" in
      /usr|/usr/*|/bin|/bin/*|/sbin|/sbin/*|/lib|/lib/*|/lib64|/lib64/*|/etc|/etc/*|/proc|/proc/*|/sys|/sys/*|/dev|/dev/*|/run|/run/*|/boot|/boot/*|/var|/var/*)
        die "каталог данных не может лежать в системном каталоге: $envbox_root" ;;
    esac
  fi
fi
# Глобальные папки: отдельные каталоги внутри корня, которые не принадлежат ни одной среде
global_root="$envbox_root/_global"
# true, если путь лежит строго внутри <корень>/_global (в глобальной папке, а не сам _global)
in_global_area() { [[ "$1" == "$global_root"/?* ]]; }
# true, если путь пересекается с данными envbox (корнем и каталогами сред), кроме глобальных папок
overlaps_envbox_data() {
  if in_global_area "$1"; then return 1; fi
  is_under "$1" "$envbox_root" || is_under "$envbox_root" "$1"
}

net_py=__ENVBOX_PY__
# Предкомпилированная копия запускается в разы быстрее: не нужно разбирать 10 000 строк при каждом вызове
# (seccomp, проверка git, мост, прокси). Если она устарела, собрана другой версией Python (после обновления
# системы файл .pyc перестаёт читаться) или отсутствует — используется обычный файл.
net_pyc="${net_py%.py}.pyc"
if [[ "$net_py" == *.py && -f "$net_pyc" && ! "$net_py" -nt "$net_pyc" && -r "$net_pyc.python" ]] \
   && [[ "$(< "$net_pyc.python")" == "$(readlink -f /usr/bin/python3 2>/dev/null)" ]]; then
  net_py=$net_pyc
fi
need_net_py() {
  [[ -f "$net_py" ]] || die "не найден $net_py — запустите: python3 envbox.py install"
  [[ -x /usr/bin/python3 ]] || die "для сетевого журнала нужен /usr/bin/python3"
}

# Режим просмотра журнала: команда не нужна
if (( net_report )); then
  (( ${#cmd[@]} == 0 )) || die "--net-report не принимает команду"
  need_net_py
  log_file="$envbox_root/$name/net.log"
  [[ -f "$log_file" ]] || die "журнал не найден: $log_file (среда запускалась с --net-log?)"
  exec /usr/bin/python3 -I "$net_py" report "$log_file" ${report_mode:+"$report_mode"}
fi
[[ -z "$report_mode" ]] || die "--follow и --raw используются только с --net-report"

(( ${#cmd[@]} )) || die "не указана команда после '--'"

# Жёсткий режим: сети компьютера нет, если явно не выбран другой режим сети
if (( iso_net_forced && net && ! net_log )); then
  net_log=1
  info "сеть компьютера запрещена: выход только через прокси с журналом (разрешить: --iso host_net_forbidden=off)"
fi

if (( net_log )); then
  (( net )) || die "--no-net и --net-log/--allow-domain взаимоисключающие"
  need_net_py
  for d in "${allow_domains[@]}"; do
    [[ "$d" =~ ^(\*\.)?[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$ ]] \
      || die "недопустимый домен для --allow-domain: '$d'"
  done
elif (( net_allow_private )); then
  die "--net-allow-private имеет смысл только вместе с --net-log"
fi

if [[ -n "$upstream" ]]; then
  upstream_re='^(http|socks5|socks5h)://[][A-Za-z0-9._:-]+$'
  [[ "$upstream" != *@* ]] \
    || die "логин и пароль нельзя указывать в --upstream (они видны в ps). Задайте переменную окружения ENVBOX_UPSTREAM_AUTH=логин:пароль"
  [[ "$upstream" =~ $upstream_re ]] \
    || die "недопустимый --upstream '$upstream': нужен http://хост:порт, socks5://хост:порт или socks5h://хост:порт"
fi
chain_has_proxy=0
if (( ${#chain_specs[@]} )); then
  for c in "${chain_specs[@]}"; do
    case "$c" in
      proxy)
        [[ -n "$upstream" ]] || die "--chain proxy требует --upstream"
        chain_has_proxy=1; chain_remote=1 ;;
      direct) ;;
      vpn:wireguard:/*|vpn:xray:/*|vpn:singbox:/*)
        [[ "$c" =~ ^vpn:(wireguard|xray|singbox):/[^[:cntrl:]]+$ ]] || die "недопустимый --chain '$c': в пути управляющие символы"
        [[ -f "${c#vpn:*:}" ]] || die "--chain: нет файла конфигурации VPN: ${c#vpn:*:}"
        chain_remote=1 ;;
      *) die "недопустимый --chain '$c': нужен proxy, direct или vpn:<wireguard|xray|singbox>:/путь" ;;
    esac
  done
  if [[ -n "$upstream" ]] && (( ! chain_has_proxy )); then
    die "задан --upstream, но в --chain нет proxy: прокси не будет использован"
  fi
fi
(( chain_remote )) || [[ -z "$upstream" ]] || chain_remote=1
if (( ${#direct_domains[@]} )); then
  for d in "${direct_domains[@]}"; do
    [[ "$d" =~ ^(\*\.)?[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$ ]] \
      || die "недопустимый домен для --direct-domain: '$d'"
  done
  if (( ! chain_remote )); then
    warn "--direct-domain имеет смысл только вместе с --upstream или VPN в --chain (без них все соединения и так идут напрямую) — игнорирую"
    direct_domains=()
  fi
fi
if [[ -n "${ENVBOX_UPSTREAM_AUTH:-}" && -z "$upstream" ]]; then
  warn "ENVBOX_UPSTREAM_AUTH задана, но --upstream не указан — игнорирую"
fi

if (( iso_home_real )); then
  (( host_confirm )) || die "настоящий домашний каталог (--iso home_real=on) открывает среде ваши личные файлы. Если вы это понимаете, добавьте --confirm-host-access"
  warn "ВНИМАНИЕ: среда работает с настоящим домашним каталогом"
fi
if [[ -n "$host_files" ]]; then
  [[ "$host_files" == ro || "$host_files" == rw ]] || die "--host-files принимает ro или rw"
  (( host_confirm )) || die "--host-files даёт среде доступ к вашему компьютеру. Если вы это понимаете, добавьте --confirm-host-access"
  (( ! net || net_log )) || die "--host-files несовместим с сетью компьютера: используйте --net-log или --no-net"
  warn "ВНИМАНИЕ: включён доступ к файлам компьютера (--host-files $host_files). Среда видит настоящий домашний каталог"
fi

valid_ip() {
  local ip=$1 o
  if [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
    for o in "${BASH_REMATCH[@]:1}"; do (( 10#$o <= 255 )) || return 1; done
    return 0
  fi
  [[ "$ip" == *:* && "$ip" =~ ^[0-9A-Fa-f:.]+$ && ${#ip} -le 45 ]]
}
if [[ -n "$lang" ]]; then
  lang_re='^([A-Za-z]{2,3}(_[A-Za-z]{2,3})?(\.[A-Za-z0-9-]+)?(@[A-Za-z0-9]+)?|C|POSIX|C\.[A-Za-z0-9-]+)$'
  [[ "$lang" =~ $lang_re ]] || die "недопустимая локаль '$lang': ожидается вид ru_RU.UTF-8"
  case "$lang" in
    C|POSIX|C.*) ;;
    *)
      if command -v locale >/dev/null 2>&1; then
        want=${lang,,}; want=${want//utf-8/utf8}
        avail=$(locale -a 2>/dev/null | tr 'A-Z' 'a-z' | sed 's/utf-8/utf8/' || true)
        if ! grep -qxF -- "$want" <<<"$avail"; then
          warn "локаль '$lang' не найдена на этом компьютере (locale -a): программы вернутся к английскому. Сгенерируйте её (Arch: раскомментируйте строку в /etc/locale.gen и выполните sudo locale-gen)"
        fi
      fi ;;
  esac
fi
if [[ -n "$timezone" ]]; then
  tz_re='^[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+){0,2}$'
  [[ "$timezone" =~ $tz_re ]] || die "недопустимый часовой пояс '$timezone': ожидается вид Europe/Moscow"
  [[ -f "/usr/share/zoneinfo/$timezone" ]] \
    || die "часовой пояс '$timezone' не найден в /usr/share/zoneinfo (нужен пакет tzdata)"
fi
if (( ${#dns_servers[@]} )); then
  for d in "${dns_servers[@]}"; do
    valid_ip "$d" || die "недопустимый DNS-сервер '$d': нужен IP-адрес"
  done
  (( net )) || die "--dns не имеет смысла с --no-net: сети нет"
  (( ! chain_remote )) || die "--dns несовместим с --upstream и VPN: имена разрешает вышестоящий канал"
fi

box_dir="$envbox_root/$name"

if (( no_workdir )); then
  [[ -z "$workdir" ]] || die "--no-workdir несовместим с -w"
else
  [[ -n "$workdir" ]] || die "не задан рабочий каталог (-w); для среды без проекта используйте --no-workdir"
  [[ -e "$workdir" ]] || die "рабочий каталог не существует: $workdir"
  [[ -d "$workdir" ]] || die "рабочий путь не является каталогом: $workdir"
  workdir=$(realpath -e -- "$workdir") || die "не удалось разрешить путь рабочего каталога"
  [[ -w "$workdir" ]] || die "нет прав на запись в рабочий каталог: $workdir"
  [[ "$workdir" != / ]] || die "рабочий каталог не может быть '/'"
  if is_under "$real_home" "$workdir"; then
    die "рабочий каталог $workdir совпадает с HOME или содержит его — это открыло бы весь домашний каталог на запись"
  fi
  if overlaps_envbox_data "$workdir"; then
    die "рабочий каталог не может пересекаться с $envbox_root (кроме глобальных папок в $global_root)"
  fi
fi
# true, если путь лежит внутри смонтированного рабочего каталога
in_workdir() { (( ! no_workdir )) && is_under "$1" "$workdir"; }

# --expose-port и --attach
valid_port() { [[ "$1" =~ ^[0-9]{1,5}$ ]] && (( 10#$1 > 0 && 10#$1 < 65536 )); }
if (( ${#expose_ports[@]} || ${#attach_specs[@]} )); then
  (( ! net || net_log )) \
    || die "--expose-port и --attach требуют --net-log или --no-net: иначе порты открылись бы на сети хоста"
fi
for pt in "${expose_ports[@]}"; do
  valid_port "$pt" || die "недопустимый порт для --expose-port: '$pt'"
done
attach_names=(); attach_remote=(); attach_local=()
used_local=()
(( ! net_log )) || used_local+=(3128)
for pt in "${expose_ports[@]}"; do used_local+=("$((10#$pt))"); done
for spec in "${attach_specs[@]}"; do
  IFS=: read -r a_name a_port a_local extra <<<"$spec"
  [[ -z "${extra:-}" ]] || die "недопустимый формат --attach '$spec': нужно среда[:порт[:локальный_порт]]"
  a_port=${a_port:-9222}
  a_local=${a_local:-$a_port}
  [[ "$a_name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,47}$ ]] || die "недопустимое имя среды в --attach: '$a_name'"
  [[ "$a_name" != "$name" ]] || die "среда не может подключаться сама к себе (--attach $a_name)"
  valid_port "$a_port" || die "недопустимый порт в --attach: '$a_port'"
  valid_port "$a_local" || die "недопустимый локальный порт в --attach: '$a_local'"
  a_port=$((10#$a_port)); a_local=$((10#$a_local))
  for u in "${used_local[@]}"; do
    [[ "$u" != "$a_local" ]] || die "порт $a_local внутри среды уже занят (прокси, --expose-port или другой --attach)"
  done
  [[ -d "$envbox_root/$a_name" && ! -L "$envbox_root/$a_name" ]] \
    || die "среда '$a_name' не найдена в $envbox_root (создайте и запустите её сначала)"
  attach_names+=("$a_name"); attach_remote+=("$a_port"); attach_local+=("$a_local")
  used_local+=("$a_local")
done

if (( wayland )); then
  [[ -n "${WAYLAND_DISPLAY:-}" && -n "${XDG_RUNTIME_DIR:-}" ]] \
    || die "--wayland: на хосте не заданы WAYLAND_DISPLAY и XDG_RUNTIME_DIR (сеанс Wayland не запущен?)"
  [[ "$WAYLAND_DISPLAY" != */* && "$WAYLAND_DISPLAY" =~ ^[A-Za-z0-9._-]+$ ]] \
    || die "--wayland: значение WAYLAND_DISPLAY='$WAYLAND_DISPLAY' не поддерживается (нужно простое имя сокета)"
  wl_sock="$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY"
  [[ -S "$wl_sock" ]] || die "--wayland: нет сокета $wl_sock"
fi

# Разбор путей хоста для --ro и --rw: <ключ> <путь> -> результат в $resolved_path
resolve_host_path() {
  local opt=$1 p=$2 rp
  [[ -e "$p" ]] || die "путь для $opt не существует: $p"
  rp=$(realpath -e -- "$p") || die "не удалось разрешить путь $opt: $p"
  [[ "$rp" != / ]] || die "$opt / откроет всю файловую систему; укажите конкретные каталоги"
  if is_under "$real_home" "$rp"; then
    die "$opt $p совпадает с HOME или содержит его — реальный домашний каталог стал бы виден"
  fi
  if overlaps_envbox_data "$rp"; then
    die "$opt $p пересекается с $envbox_root (каталогами сред). Для общих данных используйте глобальные папки: --global"
  fi
  resolved_path=$rp
}

ro_paths=()
for p in "${ro_specs[@]}"; do
  resolve_host_path --ro "$p"
  ro_paths+=("$resolved_path")
done

rw_paths=()
for p in "${rw_specs[@]}"; do
  resolve_host_path --rw "$p"
  [[ -d "$resolved_path" ]] || die "--rw принимает только каталог: $p"
  [[ -w "$resolved_path" ]] || die "нет прав на запись в каталог для --rw: $p"
  rw_paths+=("$resolved_path")
done

# Глобальные папки: <корень>/_global/<имя>[:ro|:rw]. Только настоящие каталоги прямо внутри _global:
# ссылки запрещены, иначе папка вывела бы за пределы данных envbox.
global_paths=(); global_modes=()
for spec in "${global_specs[@]}"; do
  g_name=${spec%%:*}
  g_mode=rw
  if [[ "$spec" == *:* ]]; then g_mode=${spec#*:}; fi
  [[ "$g_name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,47}$ ]] \
    || die "--global: недопустимое имя папки '$g_name' (латиница, цифры, '.', '_', '-')"
  [[ "$g_mode" == ro || "$g_mode" == rw ]] || die "--global $g_name: режим должен быть ro или rw, получено '$g_mode'"
  g_path="$global_root/$g_name"
  [[ -d "$g_path" ]] || die "глобальная папка '$g_name' не найдена: $g_path (создайте её в GUI или командой mkdir)"
  for d in "$envbox_root" "$global_root" "$g_path"; do
    [[ ! -L "$d" ]] || die "$d — символическая ссылка; из соображений безопасности это запрещено"
  done
  [[ "$(realpath -e -- "$g_path")" == "$g_path" ]] || die "глобальная папка $g_path лежит не там, где указано (ссылки в пути)"
  if [[ "$g_mode" == rw ]]; then [[ -w "$g_path" ]] || die "нет прав на запись в глобальную папку $g_path"; fi
  for known in "${global_paths[@]}"; do
    [[ "$known" != "$g_path" ]] || die "глобальная папка '$g_name' указана дважды"
  done
  global_paths+=("$g_path"); global_modes+=("$g_mode")
done

for d in "${path_specs[@]}"; do
  [[ "$d" == /* ]] || die "--path требует абсолютный путь: $d"
  [[ "$d" != *:* ]] || die "--path не может содержать ':': $d"
done

# Переменные окружения: ключи в порядке появления, значения отдельно.
reserved_re='^(HOME|USER|LOGNAME|SHELL|PATH|PWD|OLDPWD)$'
loader_re='^(LD_.*|GCONV_PATH|GLIBC_TUNABLES|LOCPATH|NLSPATH|MALLOC_.*|HOSTALIASES|RES_OPTIONS|LOCALDOMAIN|BASH_ENV|BASH_FUNC_.*|ENV|PROMPT_COMMAND|SHELLOPTS|BASHOPTS|IFS|CDPATH|GLOBIGNORE|PS4)$'
env_keys=()
declare -A env_vals=()
for spec in "${env_specs[@]}"; do
  if [[ "$spec" == *=* ]]; then
    key=${spec%%=*}
    val=${spec#*=}
  else
    key=$spec
    if [[ ! "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
      die "недопустимое имя переменной: '$key'"
    fi
    if [[ -z "${!key+x}" ]]; then
      warn "переменная $key не задана на хосте — не передаю"
      continue
    fi
    val=${!key}
  fi
  [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || die "недопустимое имя переменной: '$key'"
  [[ ! "$key" =~ $reserved_re ]] || die "переменную $key задаёт сам envbox; используйте --path для PATH"
  [[ -n "${env_vals[$key]+x}" ]] || env_keys+=("$key")
  env_vals[$key]=$val
done

# --- bubblewrap ---------------------------------------------------------------

bwrap_bin=$(command -v bwrap) \
  || die "bwrap не найден. Установите: sudo pacman -S bubblewrap (Arch), sudo apt install bubblewrap (Debian/Ubuntu), sudo dnf install bubblewrap (Fedora)"
bwrap_bin=$(realpath -e -- "$bwrap_bin")
if [[ -u "$bwrap_bin" ]]; then
  die "$bwrap_bin установлен с setuid-битом. envbox рассчитан на непривилегированный режим; используйте bwrap без setuid (ядро должно разрешать user namespaces)"
fi

bwrap_help=$("$bwrap_bin" --help 2>&1 || true)
bwrap_has() { [[ "$bwrap_help" == *"$1"* ]]; }
has_unsetenv=0
bwrap_has --unsetenv && has_unsetenv=1

diagnose_userns() {
  local err=$1 v
  printf '%s: ошибка: bwrap не смог создать user namespace:\n  %s\n' "$PROG" "$err" >&2
  if [[ -r /proc/sys/kernel/apparmor_restrict_unprivileged_userns ]]; then
    v=$(< /proc/sys/kernel/apparmor_restrict_unprivileged_userns)
    if [[ "$v" == 1 ]]; then
      cat >&2 <<EOF

Причина, скорее всего: AppArmor ограничивает непривилегированные user namespaces
(kernel.apparmor_restrict_unprivileged_userns = 1, по умолчанию в Ubuntu 23.10+).
Не отключайте ограничение глобально. Разрешите userns только бинарнику bwrap:

  sudo tee /etc/apparmor.d/envbox-bwrap >/dev/null <<'PROFILE'
abi <abi/4.0>,
include <tunables/global>

profile envbox-bwrap $bwrap_bin flags=(unconfined) {
  userns,
  include if exists <local/envbox-bwrap>
}
PROFILE
  sudo apparmor_parser -r /etc/apparmor.d/envbox-bwrap

Сначала проверьте, нет ли уже профиля для bwrap: grep -rl bwrap /etc/apparmor.d/
EOF
      exit 1
    fi
  fi
  if [[ -r /proc/sys/kernel/unprivileged_userns_clone ]] && [[ "$(< /proc/sys/kernel/unprivileged_userns_clone)" == 0 ]]; then
    printf '\nkernel.unprivileged_userns_clone = 0: ядро запрещает непривилегированные user namespaces.\n' >&2
  fi
  if [[ -r /proc/sys/user/max_user_namespaces ]] && [[ "$(< /proc/sys/user/max_user_namespaces)" == 0 ]]; then
    printf '\nuser.max_user_namespaces = 0: user namespaces отключены.\n' >&2
  fi
  exit 1
}

if ! probe_err=$("$bwrap_bin" --unshare-user --ro-bind / / -- /usr/bin/true 2>&1); then
  diagnose_userns "$probe_err"
fi

if (( ! iso_session )); then
  tiocsti=""
  [[ -r /proc/sys/dev/tty/legacy_tiocsti ]] && tiocsti=$(< /proc/sys/dev/tty/legacy_tiocsti)
  [[ "$tiocsti" == 0 ]] \
    || die "отключать управляющий терминал нельзя (--iso session=off / --keep-session): ядро разрешает TIOCSTI (dev.tty.legacy_tiocsti != 0 или параметр отсутствует)"
fi

# --- каталог среды ----------------------------------------------------------

for d in "$envbox_root" "$box_dir" "$box_dir/home" "$box_dir/etc" "$box_dir/empty"; do
  [[ ! -L "$d" ]] || die "$d — символическая ссылка; из соображений безопасности это запрещено"
  if [[ ! -d "$d" ]]; then
    mkdir -m 700 -- "$d" || die "не удалось создать каталог $d"
  fi
done
chmod 700 -- "$envbox_root" "$box_dir"

if true; then   # каталог run нужен всегда: в нём каналы ссылок
  run_dir="$box_dir/run"
  [[ ! -L "$run_dir" ]] || die "$run_dir — символическая ссылка; это запрещено"
  [[ -d "$run_dir" ]] || mkdir -m 700 -- "$run_dir"
fi
if (( ${#expose_ports[@]} )); then
  [[ ! -L "$run_dir/expose" ]] || die "$run_dir/expose — символическая ссылка; это запрещено"
  [[ -d "$run_dir/expose" ]] || mkdir -m 700 -- "$run_dir/expose"
fi
if (( inbox_on )); then
  [[ ! -L "$run_dir/inbox" ]] || die "$run_dir/inbox — символическая ссылка; это запрещено"
  [[ -d "$run_dir/inbox" ]] || mkdir -m 700 -- "$run_dir/inbox"
fi
# Канал links: программа в среде (xdg-open, $BROWSER, Electron, CLI) просит открыть ссылку; envbox на компьютере
# читает этот каталог, проверяет адреса и открывает их в изолированном браузере. Среда сама ничего не открывает.
for d in links bin; do
  [[ ! -L "$run_dir/$d" ]] || die "$run_dir/$d — символическая ссылка; это запрещено"
  [[ -d "$run_dir/$d" ]] || mkdir -m 700 -- "$run_dir/$d"
done


for a_name in "${attach_names[@]}"; do
  for d in "$envbox_root/$a_name/run" "$envbox_root/$a_name/run/expose"; do
    [[ ! -L "$d" ]] || die "$d — символическая ссылка; это запрещено"
    [[ -d "$d" ]] || mkdir -m 700 -- "$d"
  done
done
proxy_pid=""
cleanup() {
  if [[ -n "$proxy_pid" ]]; then
    kill "$proxy_pid" 2>/dev/null || true
    wait "$proxy_pid" 2>/dev/null || true
  fi
  [[ -z "${sock:-}" ]] || rm -f -- "$sock"
}
if (( net_log )); then
  sock="$run_dir/proxy.sock"
  (( ${#sock} < 100 )) || die "слишком длинный путь к сокету прокси ($sock); укоротите имя среды"
  net_log_file="$box_dir/net.log"
  readonly bridge_port=3128
  trap cleanup EXIT
  if (( ! dry_run )); then
    # С --net-log прокси на хосте живёт, пока работает среда. Запускаем его сразу: старт (~0,1 с) идёт параллельно
    # остальной подготовке, а к запуску bwrap сокет уже готов.
    proxy_args=()
    for d in "${allow_domains[@]}"; do proxy_args+=(--allow "$d"); done
    (( net_allow_private )) && proxy_args+=(--allow-private)
    [[ -z "$upstream" ]] || proxy_args+=(--upstream "$upstream")
    for c in "${chain_specs[@]}"; do proxy_args+=(--chain "$c"); done
    (( accel )) || proxy_args+=(--no-accel)
    proxy_args+=(--live "$box_dir/live.json")    # GUI обновляет файл, шлюз применяет новые списки сайтов сразу
    for d in "${direct_domains[@]}"; do proxy_args+=(--direct "$d"); done
    for d in "${dns_servers[@]}"; do proxy_args+=(--dns "$d"); done
    rm -f -- "$sock"
    /usr/bin/python3 -I "$net_py" proxy --socket "$sock" --log "$net_log_file" \
      --parent-pid $$ "${proxy_args[@]}" </dev/null &
    proxy_pid=$!
  fi
fi

uid=$(id -u); gid=$(id -g)
user=$(id -un); group=$(id -gn)
hostname="envbox-$name"

write_file() {  # атомарная запись: write_file <путь> <содержимое>
  local tmp
  tmp=$(mktemp -- "$1.XXXXXX")
  printf '%s' "$2" > "$tmp"
  chmod 644 -- "$tmp"
  mv -f -- "$tmp" "$1"
}
# Шимы канала ссылок (каталоги links и bin созданы выше)
IFS= read -r -d '' open_url_shim <<'SHIM_EOF' || true
#!/bin/sh
# envbox: передаёт ссылку приложению envbox на компьютере; она откроется в изолированном браузере
url=$1
case "$url" in
  http://*|https://*) ;;
  *) echo "envbox: открываются только ссылки http и https" >&2; exit 1 ;;
esac
d=${ENVBOX_LINK_DIR:-/run/envbox/links}
[ -d "$d" ] || { echo "envbox: канал ссылок недоступен" >&2; exit 1; }
f="$d/$(date +%s%N 2>/dev/null || date +%s).$$"
printf '%s\n' "$url" > "$f.tmp" && mv "$f.tmp" "$f" || exit 1
echo "envbox: ссылка передана приложению envbox; если оно запущено, оно откроет её в изолированном браузере: $url" >&2
SHIM_EOF
write_file "$run_dir/bin/open-url" "$open_url_shim"
chmod 755 -- "$run_dir/bin/open-url"
ln -sf open-url "$run_dir/bin/xdg-open"

write_file "$box_dir/etc/passwd" \
"$user:x:$uid:$gid:envbox:$real_home:$login_shell
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
"
write_file "$box_dir/etc/group" \
"$group:x:$gid:
nogroup:x:65534:
"
write_file "$box_dir/etc/hosts" \
"127.0.0.1 localhost
::1 localhost ip6-localhost ip6-loopback
127.0.1.1 $hostname
"
write_file "$box_dir/etc/hostname" "$hostname
"

# --- PATH внутри среды -------------------------------------------------------

# каталоги, куда ставятся Node, Go, Rust, Bun, Deno из рецептов установки (если их нет — не мешают)
sandbox_path_parts=("${path_specs[@]}" "$real_home/.local/bin" "$real_home/.local/go/bin"
  "$real_home/go/bin" "$real_home/.cargo/bin" "$real_home/.bun/bin" "$real_home/.deno/bin"
  /usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin)
sandbox_path=$(IFS=:; printf '%s' "${sandbox_path_parts[*]}")
sandbox_path="/run/envbox/bin:$sandbox_path"   # xdg-open и open-url из канала ссылок идут первыми

# Где на хосте реально лежит каталог $1 так, как его увидит среда.
host_view_of() {
  local d=$1 rp
  if in_workdir "$d"; then printf '%s' "$d"; return; fi
  for rp in "${ro_paths[@]}"; do
    if is_under "$d" "$rp"; then printf '%s' "$d"; return; fi
  done
  if is_under "$d" "$real_home"; then
    (( ephemeral )) && return 1
    printf '%s' "$box_dir/home${d#"$real_home"}"; return
  fi
  case "$d" in
    /usr|/usr/*|/bin|/sbin) printf '%s' "$d" ;;
    *) return 1 ;;
  esac
}

# Предупредить, если команда не будет найдена внутри среды.
if [[ "${cmd[0]}" != */* ]]; then
  found=0
  for d in "${sandbox_path_parts[@]}"; do
    hv=$(host_view_of "$d") || continue
    if [[ -x "$hv/${cmd[0]}" ]]; then found=1; break; fi
  done
  if (( ! found )); then
    host_loc=$(command -v -- "${cmd[0]}" 2>/dev/null || true)
    if [[ -n "$host_loc" ]]; then
      warn "'${cmd[0]}' не будет найден внутри среды. На хосте он лежит в $host_loc ($(realpath -- "$host_loc" 2>/dev/null || echo '?')). Добавьте нужные каталоги через --ro и --path или установите программу внутри среды"
    else
      warn "'${cmd[0]}' не найден ни в PATH среды, ни на хосте"
    fi
  fi
fi

# --- аргументы bwrap ------------------------------------------------------------

args=()

# true, если путь лежит в месте, доступном среде на запись: проект, --rw или глобальная папка в режиме rw.
# Поверх таких мест путь «только чтение» монтируется отдельно, после них.
in_writable() {
  local x i
  in_workdir "$1" && return 0
  for x in "${rw_paths[@]}"; do is_under "$1" "$x" && return 0; done
  for i in "${!global_paths[@]}"; do
    [[ "${global_modes[i]}" == rw ]] && is_under "$1" "${global_paths[i]}" && return 0
  done
  return 1
}

# Каталоги, где защищаются .git/hooks и .git/config: проект, --rw и глобальные папки с записью
git_dirs=()
add_git_dir() {
  local x
  for x in "${git_dirs[@]}"; do [[ "$x" != "$1" ]] || return 0; done
  git_dirs+=("$1")
}
if (( protect_git )); then
  (( no_workdir )) || add_git_dir "$workdir"
  for rp in "${rw_paths[@]}"; do add_git_dir "$rp"; done
  for i in "${!global_paths[@]}"; do
    [[ "${global_modes[i]}" != rw ]] || add_git_dir "${global_paths[i]}"
  done
fi
# Снимки состояния Git запускаются сразу и работают параллельно подготовке; результат ждём перед запуском среды
git_snap_pids=()
if (( ! dry_run )); then
  for gi in "${!git_dirs[@]}"; do
    /usr/bin/python3 -I "$net_py" gitcheck snapshot "${git_dirs[gi]}" >"$box_dir/git.snapshot.$gi" 2>/dev/null &
    git_snap_pids[gi]=$!
  done
fi

# Защита Git для каталога $1: хуки и config недоступны на запись, сам .git нельзя переименовать или заменить
# (иначе программа подложила бы хук, который выполнится у вас при команде git)
protect_git_dir() {
  local dir=$1 gitp gp hp
  gitp="$dir/.git"
  if [[ -L "$gitp" ]]; then
    warn ".git в $dir — символическая ссылка: защита Git не применяется"
  elif [[ -d "$gitp" ]]; then
    args+=(--bind "$gitp" "$gitp")
    if [[ -d "$gitp/hooks" ]]; then
      args+=(--ro-bind "$gitp/hooks" "$gitp/hooks")
    else
      args+=(--ro-bind "$box_dir/empty" "$gitp/hooks")
    fi
    [[ ! -e "$gitp/config" ]] || args+=(--ro-bind "$gitp/config" "$gitp/config")
    if [[ -d "$gitp/modules" ]]; then
      while IFS= read -r gp; do
        args+=(--ro-bind "$gp" "$gp")
      done < <(find "$gitp/modules" -maxdepth 5 \( -type d -name hooks -o -type f -name config \) 2>/dev/null)
    fi
    hp=$(git config --file "$gitp/config" --get core.hooksPath 2>/dev/null || true)
    if [[ -n "$hp" ]]; then
      [[ "$hp" == /* ]] || hp="$dir/$hp"
      hp=$(realpath -m -- "$hp")
      if [[ -d "$hp" ]] && is_under "$hp" "$dir" && ! is_under "$hp" "$gitp"; then
        args+=(--ro-bind "$hp" "$hp")
      fi
    fi
  elif [[ -f "$gitp" ]]; then
    args+=(--ro-bind "$gitp" "$gitp")
  fi
}

# Данные envbox: при доступе к файлам компьютера скрываем другие среды (там токены) и защищаем код envbox
hide_envbox_data() {
  local inst
  inst=$(dirname "$net_py")
  args+=(--tmpfs "$envbox_root")
  if [[ -d "$inst" ]]; then args+=(--ro-bind "$inst" "$inst"); fi
}

# Пространства имён
args+=(--unshare-user)
(( ! iso_ipc )) || args+=(--unshare-ipc)
(( ! iso_pid )) || args+=(--unshare-pid)
(( ! iso_uts )) || args+=(--unshare-uts --hostname "$hostname")
(( ! iso_cgroup )) || args+=(--unshare-cgroup)
args+=(--setenv ENVBOX_SESSION "$name")   # метка для списка запущенных сред
(( net && ! net_log )) || args+=(--unshare-net)
if (( ! allow_userns )); then
  if bwrap_has --disable-userns; then
    args+=(--disable-userns)
  else
    warn "ваш bwrap не поддерживает --disable-userns (нужен >= 0.8): вложенные user namespaces внутри среды не запрещены"
  fi
fi

# Жизненный цикл и привилегии
(( ! iso_die_parent )) || args+=(--die-with-parent)
(( ! iso_caps )) || args+=(--cap-drop ALL)
(( ! iso_session )) || args+=(--new-session)

# /proc: свой (в своём пространстве процессов) или, если оно отключено, процессы компьютера
proc_args=(--proc /proc)
(( iso_pid )) || proc_args=(--ro-bind /proc /proc)

if [[ -n "$host_files" ]]; then
  # ВЫХОД ЗА ПЕСОЧНИЦУ: весь компьютер (ro или rw), поверх — свои /proc, /dev, /tmp, /run
  if [[ "$host_files" == rw ]]; then args+=(--bind / /); else args+=(--ro-bind / /); fi
  args+=("${proc_args[@]}" --dev /dev --tmpfs /dev/shm --tmpfs /tmp --tmpfs /run)
  hide_envbox_data
else
  # Системные каталоги: только чтение
  args+=(--ro-bind /usr /usr)
  for d in bin sbin lib lib32 lib64 libx32; do
    if [[ -L "/$d" ]]; then
      args+=(--symlink "$(readlink -- "/$d")" "/$d")
    elif [[ -d "/$d" ]]; then
      args+=(--ro-bind "/$d" "/$d")
    fi
  done

  # Виртуальные ФС и временные каталоги (не на диске хоста)
  args+=("${proc_args[@]}" --dev /dev --tmpfs /dev/shm --tmpfs /tmp --tmpfs /run
         --dir /var --tmpfs /var/tmp)
fi

# Мост внутри среды: сокет прокси хоста, порты для других сред, порты чужих сред
need_wrap=0
(( net_log || ${#expose_ports[@]} || ${#attach_names[@]} || inbox_on )) && need_wrap=1
args+=(--dir /run/envbox --bind "$run_dir/links" /run/envbox/links --ro-bind "$run_dir/bin" /run/envbox/bin)
if (( need_wrap )); then
  args+=(--ro-bind "$net_py" /run/envbox/net.py)
fi
if (( net_log )); then
  args+=(--bind "$sock" /run/envbox/proxy.sock)
fi
if (( ${#expose_ports[@]} )); then
  args+=(--bind "$run_dir/expose" /run/envbox/expose)
fi
if (( inbox_on )); then
  args+=(--bind "$run_dir/inbox" /run/envbox/inbox)
fi
for i in "${!attach_names[@]}"; do
  args+=(--ro-bind "$envbox_root/${attach_names[i]}/run/expose" "/run/envbox/attach/${attach_names[i]}")
done
if (( wayland )); then
  args+=(--perms 0700 --dir "/run/user/$uid" --bind "$wl_sock" "/run/user/$uid/$WAYLAND_DISPLAY")
fi

# DNS внутри среды: заданные серверы; в жёстком режиме без сети компьютера — нейтральный файл
# (адреса ваших DNS-серверов среде не раскрываются)
resolv=""
if (( ${#dns_servers[@]} )); then
  for d in "${dns_servers[@]}"; do resolv+="nameserver $d"$'\n'; done
elif (( iso_neutral_dns && ( ! net || net_log ) )); then
  resolv=$'# envbox: имена разрешает прокси на компьютере\nnameserver 127.0.0.1\n'
fi
if [[ -n "$resolv" ]]; then
  write_file "$box_dir/etc/resolv.conf" "$resolv"
fi

if [[ -z "$host_files" ]]; then
  # /etc: только нужное для динамической линковки, TLS, DNS, локали, времени
  etc_items=(ssl ca-certificates pki crypto-policies resolv.conf nsswitch.conf
    host.conf gai.conf localtime ld.so.cache ld.so.conf ld.so.conf.d alternatives
    terminfo os-release protocols services mime.types fonts)
  for i in "${etc_items[@]}"; do
    [[ "$i" == localtime && -n "$timezone" ]] && continue
    [[ "$i" == resolv.conf && -n "$resolv" ]] && continue
    [[ -e "/etc/$i" ]] && args+=(--ro-bind "/etc/$i" "/etc/$i")
  done
  if [[ -n "$timezone" ]]; then
    args+=(--symlink "/usr/share/zoneinfo/$timezone" /etc/localtime)
  fi
  if [[ -n "$resolv" ]]; then
    args+=(--ro-bind "$box_dir/etc/resolv.conf" /etc/resolv.conf)
  fi
  for f in passwd group hosts hostname; do
    args+=(--ro-bind "$box_dir/etc/$f" "/etc/$f")
  done
elif [[ -n "$resolv" ]]; then
  # настоящий /etc виден; подменяем только файл DNS (по ссылке, если это ссылка)
  args+=(--ro-bind "$box_dir/etc/resolv.conf" "$(realpath -m /etc/resolv.conf)")
fi

# Стартовые настройки оболочек: в пустом домашнем каталоге среды приглашение было бы голым «bash-5.3$».
# Файлы кладутся в домашний каталог среды, только если их там нет (ваши правки не затираются).
prepare_rc() {
  local d="$box_dir/rc" bashrc zshrc fishrc
  mkdir -p -- "$d"
  IFS= read -r -d '' bashrc <<'RC_EOF' || true
# envbox: настройки bash по умолчанию. Файл можно менять: пока он существует, envbox его не трогает.
[[ $- == *i* ]] || return 0
shopt -s histappend checkwinsize cmdhist 2>/dev/null
HISTSIZE=50000; HISTFILESIZE=100000; HISTCONTROL=ignoreboth:erasedups
[[ -r /usr/share/bash-completion/bash_completion ]] && . /usr/share/bash-completion/bash_completion
bind 'set completion-ignore-case on' 2>/dev/null
bind 'set show-all-if-ambiguous on' 2>/dev/null
bind '"\e[A": history-search-backward' 2>/dev/null
bind '"\e[B": history-search-forward' 2>/dev/null
PS1='\[\e[1;32m\][${ENVBOX_SESSION:-envbox}]\[\e[0m\] \[\e[1;34m\]\w\[\e[0m\] \$ '
alias ls='ls --color=auto'; alias ll='ls -lah'; alias la='ls -A'; alias grep='grep --color=auto'
RC_EOF
  write_file "$d/bashrc" "$bashrc"
  write_file "$d/bash_profile" $'[[ -f ~/.bashrc ]] && . ~/.bashrc\n'
  IFS= read -r -d '' zshrc <<'RC_EOF' || true
# envbox: настройки zsh по умолчанию. Файл можно менять: пока он существует, envbox его не трогает.
autoload -Uz compinit && compinit -u -d ~/.zcompdump
zstyle ':completion:*' menu select
zstyle ':completion:*' matcher-list 'm:{a-zA-Z}={A-Za-z}'
HISTFILE=~/.zsh_history; HISTSIZE=50000; SAVEHIST=50000
setopt SHARE_HISTORY HIST_IGNORE_ALL_DUPS AUTO_CD INTERACTIVE_COMMENTS PROMPT_SUBST
bindkey -e
bindkey '^[[A' history-beginning-search-backward
bindkey '^[[B' history-beginning-search-forward
bindkey '^[[3~' delete-char; bindkey '^[[H' beginning-of-line; bindkey '^[[F' end-of-line
PROMPT='%F{green}[${ENVBOX_SESSION:-envbox}]%f %F{blue}%~%f %# '
alias ls='ls --color=auto'; alias ll='ls -lah'; alias la='ls -A'; alias grep='grep --color=auto'
RC_EOF
  write_file "$d/zshrc" "$zshrc"
  IFS= read -r -d '' fishrc <<'RC_EOF' || true
# envbox: настройки fish по умолчанию. Файл можно менять: пока он существует, envbox его не трогает.
set -g fish_greeting
function fish_prompt
    set -l last $status
    set_color green; echo -n "[$ENVBOX_SESSION] "
    set_color blue; echo -n (prompt_pwd)
    if test $last -ne 0
        set_color red; echo -n " [$last]"
    end
    set_color normal; echo -n ' > '
end
alias ll 'ls -lah'
alias la 'ls -A'
RC_EOF
  write_file "$d/fish_config" "$fishrc"
}
seed_rc() {  # seed_rc <файл в rc> <путь в домашнем каталоге среды>
  # Домашний каталог среды пишет сама среда: она могла заменить .config ссылкой на каталог компьютера.
  # Ссылки в пути не раскрываются, а файл создаётся только если его ещё нет (noclobber = O_EXCL).
  local src="$box_dir/rc/$1" dst=$2 cur="$box_dir/home" comps i
  [[ ! -e "$dst" && ! -L "$dst" ]] || return 0
  IFS=/ read -ra comps <<<"${dst#"$cur"/}"
  for ((i = 0; i < ${#comps[@]} - 1; i++)); do
    cur="$cur/${comps[i]}"
    [[ ! -L "$cur" ]] || return 0
    [[ -d "$cur" ]] || mkdir -- "$cur" 2>/dev/null || return 0
  done
  ( set -C; cat -- "$src" > "$dst" ) 2>/dev/null || true
}

# Домашний каталог среды по пути реального HOME (при --host-files виден настоящий)
if [[ -z "$host_files" ]]; then
  if (( iso_home_real )); then
    args+=(--bind "$real_home" "$real_home")
    hide_envbox_data
  elif (( ephemeral )); then
    args+=(--tmpfs "$real_home")
    if (( want_rc )); then
      prepare_rc
      case "$shell_name" in
        bash) args+=(--ro-bind "$box_dir/rc/bashrc" "$real_home/.bashrc"
                     --ro-bind "$box_dir/rc/bash_profile" "$real_home/.bash_profile") ;;
        zsh)  args+=(--ro-bind "$box_dir/rc/zshrc" "$real_home/.zshrc") ;;
        fish) args+=(--ro-bind "$box_dir/rc/fish_config" "$real_home/.config/fish/config.fish") ;;
      esac
    fi
  else
    if (( want_rc )); then
      prepare_rc
      case "$shell_name" in
        bash) seed_rc bashrc "$box_dir/home/.bashrc"; seed_rc bash_profile "$box_dir/home/.bash_profile" ;;
        zsh)  seed_rc zshrc "$box_dir/home/.zshrc" ;;
        fish) seed_rc fish_config "$box_dir/home/.config/fish/config.fish" ;;
      esac
    fi
    args+=(--bind "$box_dir/home" "$real_home")
  fi

  # Пути только для чтения, лежащие вне мест с записью
  for rp in "${ro_paths[@]}"; do
    in_writable "$rp" || args+=(--ro-bind "$rp" "$rp")
  done
fi

# Дополнительные папки с записью (--rw); при --host-files ro они остаются доступными на запись
for rp in "${rw_paths[@]}"; do
  in_workdir "$rp" || args+=(--bind "$rp" "$rp")
done

# Глобальные папки: подключаются и при --host-files (там корень данных скрыт tmpfs)
for i in "${!global_paths[@]}"; do
  if [[ "${global_modes[i]}" == rw ]]; then
    args+=(--bind "${global_paths[i]}" "${global_paths[i]}")
  else
    args+=(--ro-bind "${global_paths[i]}" "${global_paths[i]}")
  fi
done

# Рабочий каталог: чтение и запись
if (( ! no_workdir )); then
  args+=(--bind "$workdir" "$workdir")
fi

# Пути только для чтения внутри мест с записью (поверх них)
for rp in "${ro_paths[@]}"; do
  if in_writable "$rp"; then args+=(--ro-bind "$rp" "$rp"); fi
done

# Защита Git: проект, папки --rw и глобальные папки с записью
for d in "${git_dirs[@]}"; do
  protect_git_dir "$d"
done

# Корень (tmpfs, созданный bwrap) — только чтение
(( ! iso_ro_root )) || [[ -n "$host_files" ]] || args+=(--remount-ro /)

if (( no_workdir )); then
  args+=(--chdir "$real_home")
else
  args+=(--chdir "$workdir")
fi

# Базовые переменные без секретов (через argv, это безопасно)
args+=(--setenv HOME "$real_home" --setenv USER "$user" --setenv LOGNAME "$user"
       --setenv SHELL "$login_shell" --setenv PATH "$sandbox_path")
[[ -n "${TERM:-}" ]] && args+=(--setenv TERM "$TERM")
[[ -n "${env_vals[BROWSER]+x}" ]] || args+=(--setenv BROWSER /run/envbox/bin/open-url)
if [[ -n "$lang" ]]; then
  args+=(--setenv LANG "$lang")
  if [[ "$lang" == *_* ]]; then
    args+=(--setenv LANGUAGE "${lang%%.*}:${lang%%_*}")
  fi
elif [[ -z "${env_vals[LANG]+x}" ]]; then
  args+=(--setenv LANG C.UTF-8)
fi
[[ -z "$timezone" ]] || args+=(--setenv TZ "$timezone")

if (( wayland )); then
  args+=(--setenv XDG_RUNTIME_DIR "/run/user/$uid" --setenv WAYLAND_DISPLAY "$WAYLAND_DISPLAY")
fi

final_cmd=("${cmd[@]}")
if (( need_wrap )); then
  wrap_args=()
  if (( net_log )); then
    proxy_url="http://127.0.0.1:$bridge_port"
    for v in HTTP_PROXY http_proxy HTTPS_PROXY https_proxy; do
      args+=(--setenv "$v" "$proxy_url")
    done
    args+=(--setenv NODE_USE_ENV_PROXY 1)
    wrap_args+=(--map "$bridge_port:/run/envbox/proxy.sock")
  fi
  # локальные адреса (в том числе проброшенный порт браузера) идут мимо прокси
  args+=(--setenv NO_PROXY "localhost,127.0.0.1,::1" --setenv no_proxy "localhost,127.0.0.1,::1")
  for pt in "${expose_ports[@]}"; do
    pt=$((10#$pt))
    wrap_args+=(--serve "/run/envbox/expose/$pt.sock:$pt")
  done
  for i in "${!attach_names[@]}"; do
    wrap_args+=(--map "${attach_local[i]}:/run/envbox/attach/${attach_names[i]}/${attach_remote[i]}.sock")
  done
  if (( ${#attach_names[@]} )); then
    args+=(--setenv ENVBOX_BROWSER_CDP_URL "http://127.0.0.1:${attach_local[0]}")
  fi
  if (( inbox_on )); then
    wrap_args+=(--inbox /run/envbox/inbox)
    [[ -z "$inbox_cmd" ]] || wrap_args+=(--inbox-cmd "$inbox_cmd")
    for sc in "${inbox_schemes[@]}"; do wrap_args+=(--inbox-scheme "$sc"); done
    if (( inbox_callback )); then wrap_args+=(--inbox-callback); fi
  fi
  final_cmd=(/usr/bin/python3 -I /run/envbox/net.py wrap "${wrap_args[@]}" -- "${cmd[@]}")
fi

# --- запуск ---------------------------------------------------------------------

# Фильтр системных вызовов: запрещает ptrace, bpf, io_uring, mount, perf и т. п.
seccomp_file=""
if (( iso_seccomp )); then
  seccomp_allow=()
  (( ! allow_userns )) || seccomp_allow=(--allow chroot)   # песочнице Chrome нужен chroot во вложенном пространстве имён
  # Фильтр зависит только от версии envbox и набора исключений: готовый переиспользуется (~65 мс экономии)
  seccomp_key="$(stat -c '%Y:%s' -- "$net_py" 2>/dev/null || echo ?):${seccomp_allow[*]:-}"
  if [[ -s "$box_dir/seccomp.bpf" && -r "$box_dir/seccomp.key" && "$(< "$box_dir/seccomp.key")" == "$seccomp_key" ]]; then
    seccomp_file="$box_dir/seccomp.bpf"
  elif /usr/bin/python3 -I "$net_py" seccomp "${seccomp_allow[@]}" >"$box_dir/seccomp.bpf.new" 2>/dev/null && [[ -s "$box_dir/seccomp.bpf.new" ]]; then
    mv -f -- "$box_dir/seccomp.bpf.new" "$box_dir/seccomp.bpf"
    printf '%s' "$seccomp_key" > "$box_dir/seccomp.key"
    seccomp_file="$box_dir/seccomp.bpf"
  else
    warn "фильтр системных вызовов недоступен (нужны x86_64 и /usr/bin/python3): среда запустится без него"
  fi
fi

if (( dry_run )); then
  printf '%s: seccomp-фильтр: %s\n' "$PROG" "${seccomp_file:-нет}"
  printf '%s: команда:\n' "$PROG"
  printf '%q ' "$bwrap_bin" "${args[@]}" -- "${final_cmd[@]}"
  printf '\n%s: дополнительные переменные (значения скрыты):' "$PROG"
  printf ' %s' "${env_keys[@]}"
  printf '\n'
  exit 0
fi

# Git: снимок состояния до запуска; после выхода envbox сравнит и предупредит об изменениях.
# Снимок делается и для проекта без .git: среда может создать его сама, подложив хук или config.
git_watch_dirs=(); git_watch_snaps=()
for gi in "${!git_snap_pids[@]}"; do
  if wait "${git_snap_pids[gi]}" 2>/dev/null; then
    git_watch_dirs+=("${git_dirs[gi]}"); git_watch_snaps+=("$box_dir/git.snapshot.$gi")
  fi
done
post_checks() {
  local k
  for k in "${!git_watch_dirs[@]}"; do
    /usr/bin/python3 -I "$net_py" gitcheck verify "${git_watch_dirs[k]}" "${git_watch_snaps[k]}" || true
  done
}

# Пользовательские переменные (в том числе секреты) передаются через окружение,
# а не через argv, иначе они видны в `ps` всем пользователям хоста.
declare -A allowed=()
for k in "${env_keys[@]}"; do allowed[$k]=1; done

run_sandbox() {
  local v leftovers=() sfd pfd perr true_bin probe_args
  unset -v ENVBOX_UPSTREAM_AUTH 2>/dev/null || true   # прокси уже получил пароль; среде он не нужен ни при каких настройках
  if (( iso_clean_env )); then
    while IFS= read -r v; do
      [[ -n "${allowed[$v]+x}" ]] && continue
      unset -v "$v" 2>/dev/null || true
    done < <(compgen -e)
    # Переменные, которые не удалось удалить (readonly), снимаем на стороне bwrap
    while IFS= read -r v; do
      [[ -n "${allowed[$v]+x}" ]] || leftovers+=("$v")
    done < <(compgen -e)
  fi
  for v in "${leftovers[@]}"; do
    if (( has_unsetenv )); then
      args=(--unsetenv "$v" "${args[@]}")
    else
      die "не удалось удалить переменную $v, а bwrap не поддерживает --unsetenv"
    fi
  done
  # bash сам добавляет '_' и SHLVL в окружение процесса при exec
  if (( has_unsetenv && iso_clean_env )); then
    args=(--unsetenv _ "${args[@]}")
    [[ -n "${allowed[SHLVL]+x}" ]] || args=(--unsetenv SHLVL "${args[@]}")
  fi
  # Переменные, меняющие работу загрузчика и libc (LD_PRELOAD, GCONV_PATH…), действовали бы на сам bwrap на
  # компьютере до создания среды. Их значения передаются через --setenv (в argv: это не секреты), остальные — окружением.
  for k in "${env_keys[@]}"; do
    if [[ "$k" =~ $loader_re ]]; then
      unset -v "$k" 2>/dev/null || true
      args=(--setenv "$k" "${env_vals[$k]}" "${args[@]}")
    else
      export "$k=${env_vals[$k]}"
    fi
  done
  umask 022
  probe_args=("${args[@]}")
  if [[ -n "$seccomp_file" ]]; then
    exec {sfd}<"$seccomp_file"
    exec {pfd}<"$seccomp_file"
    args+=(--seccomp "$sfd")
    probe_args+=(--seccomp "$pfd")
  fi
  # самопроверка: те же параметры с пустой командой; при ошибке — понятное сообщение
  true_bin=/usr/bin/true; [[ -x "$true_bin" ]] || true_bin=/bin/true
  if ! perr=$("$bwrap_bin" "${probe_args[@]}" -- "$true_bin" 2>&1 </dev/null); then
    die "bubblewrap не смог создать среду с этими настройками:
  $perr
Если дело в одной из защит, отключите её (раздел «Изоляция» в GUI или --iso КЛЮЧ=off) и пришлите это сообщение."
  fi
  [[ -z "$seccomp_file" ]] || exec {pfd}<&-
  exec "$bwrap_bin" "${args[@]}" -- "${final_cmd[@]}"
}

if (( ! net_log )); then
  rc=0
  ( run_sandbox ) || rc=$?
  post_checks
  exit "$rc"
fi

# С --net-log прокси на хосте уже запущен (см. выше); ждём его сокет
for ((i = 0; i < 500; i++)); do
  [[ -S "$sock" ]] && break
  kill -0 "$proxy_pid" 2>/dev/null || die "прокси сетевого журнала завершился при запуске"
  sleep 0.01
done
[[ -S "$sock" ]] || die "прокси не создал сокет за 5 секунд: $sock"

via=""
[[ -z "$upstream" ]] || via=", вышестоящий прокси: $upstream"
if (( ${#chain_specs[@]} )); then
  chain_names=()
  for c in "${chain_specs[@]}"; do
    case "$c" in
      vpn:*) b=$(basename -- "${c#vpn:*:}"); chain_names+=("vpn:${b%.*}") ;;
      *) chain_names+=("$c") ;;
    esac
  done
  via="$via, каналы по порядку: ${chain_names[*]}"
fi
if (( ${#allow_domains[@]} )); then
  info "сеть: только через прокси, разрешены: ${allow_domains[*]}$via; журнал: $net_log_file"
else
  info "сеть: только через журналирующий прокси (все публичные адреса)$via; журнал: $net_log_file"
fi

rc=0
( run_sandbox ) || rc=$?
post_checks
exit "$rc"
