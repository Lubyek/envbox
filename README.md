# envbox

Изолированные среды на bubblewrap. Запуск и установка:

```bash
python3 dist/envbox.py            # GUI (при первом запуске — установка в ~/.local/share/envbox)
python3 dist/envbox.py --help     # все команды
```

`dist/envbox.py` — готовый единый файл, его можно копировать и запускать отдельно.

## Разработка
Исходники — пакет `src/envbox/`; запуск без сборки: `python3 dev.py`. Сборка единого файла:
`python3 build.py`. Устройство и правила — в [CLAUDE.md](CLAUDE.md), список модулей — в [MAP.md](MAP.md),
подробный путеводитель для ИИ-агентов (где что менять и как проверять) — в [AI_GUIDE.md](AI_GUIDE.md).

```
build.py  dev.py  tests/
src/envbox/
  cli.py install.py appimage.py     подкоманды, установка, AppImage
  net/       сетевой шлюз: прокси, DNS, мосты, seccomp, gitcheck
  core/      ядро: профили, изоляция, запуск, ссылки, сеансы, диагностика
  cdp/       управление Chrome через DevTools Protocol
  gui/       GTK 4: window.py + pages/ + browser/ (миксины окна)
  resources/ envbox.sh, значки, CSS, текст --help
dist/envbox.py                      собранный единый файл
```
# envbox
# envbox
# envbox
