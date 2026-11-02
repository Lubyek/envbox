
envbox_sh=$1 name=$2; shift 2
secrets=()
while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do secrets+=("$1"); shift; done
shift
printf '\033]0;envbox: %s\007' "$name"
for v in "${secrets[@]}"; do
  if ! command -v secret-tool >/dev/null 2>&1; then
    echo "envbox: для секретов нужен secret-tool — $ENVBOX_PKG_HINT"
    unset "$v"; continue
  fi
  if val=$(secret-tool lookup service envbox profile "$name" var "$v") && [ -n "$val" ]; then
    export "$v=$val"
  else
    echo "envbox: секрет $v для среды $name не найден в keyring — не передаю"
    unset "$v"   # значение из окружения рабочего стола в среду не попадёт
  fi
done
unset val
"$envbox_sh" "$@"
rc=$?
if [ -n "${ENVBOX_EMBEDDED:-}" ]; then
  printf '\n[envbox: сеанс завершён, код %d]\n' "$rc"
else
  printf '\n[envbox: сеанс завершён, код %d. Нажмите Enter, чтобы закрыть окно]' "$rc"
  read -r _
fi
