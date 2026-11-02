"""Параметры изоляции, пресеты и рецепты установки программ."""

import os
import re
import shutil

from .root import box_dir
from .system import pkg_hint


ISO_OPTIONS = [
    dict(key="protect_git", group="Файлы", store="protect_git", invert=False, warn_off=True, app_only=True,
         title="Защита хуков Git",
         text="Каталог .git/hooks и файл .git/config нельзя изменить изнутри среды.",
         risk="программа может подложить git-хук, который выполнится у вас при следующей команде git."),
    dict(key="ephemeral", group="Файлы", store="ephemeral", invert=False, warn_off=False, presets=False,
         title="Стирать домашний каталог после выхода",
         text="Всё, что программа сохранила у себя дома (история, вход в аккаунт), удаляется при выходе из среды.",
         risk=""),
    dict(key="ro_root", group="Файлы", store="iso", warn_off=True,
         title="Корень среды только для чтения",
         text="Программа не может создавать файлы в системных каталогах среды, только в разрешённых местах.",
         risk="программа сможет создавать временные файлы в корне среды (они исчезнут при выходе)."),
    dict(key="pid", group="Процессы и система", store="iso", warn_off=True,
         title="Скрывать процессы компьютера",
         text="Внутри видны только процессы самой среды: ps не показывает ваши программы.",
         risk="программа видит все ваши процессы, читает их окружение (там могут быть токены) и может их завершать."),
    dict(key="ipc", group="Процессы и система", store="iso", warn_off=True,
         title="Своя общая память и очереди сообщений",
         text="Отдельное пространство IPC: программа не видит общую память других ваших программ.",
         risk="программа может читать общую память и очереди сообщений других ваших программ."),
    dict(key="uts", group="Процессы и система", store="iso", warn_off=True,
         title="Своё имя компьютера",
         text="Внутри среды другое имя компьютера (envbox-<имя>) вместо настоящего.",
         risk="программа узнаёт настоящее имя вашего компьютера."),
    dict(key="cgroup", group="Процессы и система", store="iso", warn_off=True,
         title="Скрывать группы ресурсов (cgroup)",
         text="Программа не видит, в какой группе systemd и сеансе работает ваш рабочий стол.",
         risk="программа видит структуру ваших сеансов и служб."),
    dict(key="seccomp", group="Процессы и система", store="iso", warn_off=True,
         title="Фильтр системных вызовов",
         text="Запрещены опасные вызовы ядра: ptrace, bpf, io_uring, mount, perf, загрузка модулей, смена часов.",
         risk="больше возможностей атаковать ядро; отключайте, только если какая-то программа не работает с фильтром."),
    dict(key="no_userns", group="Процессы и система", store="allow_userns", invert=True, warn_off=True,
         title="Запретить вложенные изолированные среды",
         text="Внутри нельзя создать ещё одно пространство имён (user namespace).",
         risk="шире поверхность атаки на ядро. Включать нужно только для Chrome со своим sandbox, podman и вложенного bwrap."),
    dict(key="session", group="Процессы и система", store="iso", warn_off=True,
         title="Отключить управляющий терминал",
         text="Защита от TIOCSTI: программа не может подсунуть команды в ваш настоящий терминал.",
         risk="программа может вводить текст в ваш терминал (если ядро это допускает)."),
    dict(key="die_parent", group="Процессы и система", store="iso", warn_off=True,
         title="Завершать среду вместе с envbox",
         text="Если окно или терминал закрыты, все процессы среды завершаются.",
         risk="процессы могут остаться работать в фоне после закрытия окна."),
    dict(key="caps", group="Процессы и система", store="iso", warn_off=True,
         title="Сбросить особые привилегии (capabilities)",
         text="У процессов внутри нет ни одной особой привилегии.",
         risk="у процессов внутри остаются привилегии пространства имён."),
    dict(key="host_net_forbidden", group="Сеть", store="iso", warn_off=True,
         title="Запретить сеть компьютера",
         text="Выход в сеть возможен только через прокси с журналом; режим «общая с компьютером» недоступен.",
         risk="можно выбрать общую сеть: программа тогда видит все сервисы компьютера на localhost."),
    dict(key="neutral_dns", group="Сеть", store="iso", warn_off=True,
         title="Скрывать адреса ваших DNS-серверов",
         text="В /etc/resolv.conf внутри среды нейтральная запись вместо адресов вашего роутера и провайдера.",
         risk="программа видит адреса DNS-серверов вашей сети."),
    dict(key="clean_env", group="Окружение", store="iso", warn_off=True,
         title="Передавать только перечисленные переменные",
         text="Из окружения компьютера в среду попадают только переменные, которые вы указали.",
         risk="в среду попадают все переменные компьютера, в том числе токены и пути."),
]


ISO_KEYS = {o["key"] for o in ISO_OPTIONS if o["store"] == "iso"} | {"home_real"}


ISO_PRESETS = [
    ("max", "Максимум (рекомендуется)", "Все защиты включены.", {}),
    ("compat", "Совместимость",
     "Как максимум, но без фильтра системных вызовов и нейтрального resolv.conf, а вложенные пространства "
     "имён разрешены (Chrome со своим sandbox, podman).",
     {"seccomp": False, "no_userns": False, "neutral_dns": False}),
    ("min", "Минимум — только для отладки",
     "Дополнительно без своих IPC и cgroup, с записью в корень среды и с возможностью выбрать сеть компьютера.",
     {"seccomp": False, "no_userns": False, "neutral_dns": False, "ipc": False, "cgroup": False,
      "ro_root": False, "host_net_forbidden": False}),
]


ISO_RISKY_DEFAULT = {"home_real": False}


# Рецепты установки: команда вводится в установочном терминале (её можно поправить до запуска).
# domains — сайты, нужные установщику; пусто = заранее неизвестно, сеть открывается на любые публичные
# адреса с журналом (после установки список можно сузить по журналу).
INSTALL_RECIPES = [
    dict(id="node", title="Node.js (LTS, официальный архив)", domains=["nodejs.org"],
         command=r"""cd /tmp && b=https://nodejs.org/dist/latest-v24.x && a=x64; [ "$(uname -m)" = aarch64 ] && a=arm64; f=$(curl -fsSL $b/SHASUMS256.txt | grep -o "node-v[0-9.]*-linux-$a.tar.xz" | head -1) && curl -fsSLO $b/$f && curl -fsSL $b/SHASUMS256.txt | grep " $f\$" | sha256sum -c - && mkdir -p ~/.local && tar -xJf $f --strip-components=1 -C ~/.local --exclude='*.md' --exclude=LICENSE && node -v""",
         note="Ставит node и npm в домашний каталог среды, ничего не меняя на компьютере (pacman не нужен). "
              "Контрольная сумма проверяется."),
    dict(id="claude-native", title="Claude Code (официальный установщик, без Node)", domains=[],
         command="curl -fsSL https://claude.ai/install.sh | bash",
         note="Рекомендуемый способ: Node не нужен, команда claude появится в ~/.local/bin. Установщик "
              "скачивает файлы с нескольких сайтов, поэтому сеть открыта на любые публичные адреса с журналом."),
    dict(id="claude-desktop", title="Claude Desktop (неофициальная сборка для Linux, AppImage)", domains=[],
         command=r"""mkdir -p ~/.local/opt ~/.local/bin && cd ~/.local/opt && u=$(curl -fsSL https://api.github.com/repos/patrickjaja/claude-desktop-bin/releases/latest | grep -o 'https://[^"]*x86_64\.AppImage' | head -1) && [ -n "$u" ] && curl -fL --retry 8 --retry-all-errors --retry-delay 2 -C - -o cd.AppImage "$u" && chmod +x cd.AppImage && rm -rf squashfs-root claude-desktop && ./cd.AppImage --appimage-extract >/dev/null && mv squashfs-root claude-desktop && rm -f cd.AppImage && printf '%s\n' '#!/bin/sh' 'exec "$HOME/.local/opt/claude-desktop/AppRun" --no-sandbox --disable-gpu --ozone-platform=wayland --password-store=basic --proxy-server=http://127.0.0.1:3128 "$@"' > ~/.local/bin/claude-desktop && chmod +x ~/.local/bin/claude-desktop && echo "Готово: запускайте командой claude-desktop" """.strip(),
         note="Сообщество перепаковывает официальное приложение (не подписано Anthropic). Скачивается с GitHub и "
              "распаковывается без FUSE в ~/.local/opt; запуск — командой claude-desktop. Нужен шаблон среды "
              "«Claude Desktop» (окно через Wayland). Если не запускается из-за библиотеки, поставьте её на "
              "компьютере через pacman. Файл большой (~220 МБ): при обрыве загрузка сама докачивается, а если не помогло — "
              "запустите команду ещё раз (докачка продолжится). Весь трафик идёт через ваш прокси. Сайты загрузки "
              "заранее неизвестны, поэтому сеть открыта на любые публичные адреса."),
    dict(id="npm-claude", title="Claude Code (через npm)", domains=["registry.npmjs.org"], needs=["node"],
         command="npm config set prefix ~/.local && npm install -g --allow-scripts=@anthropic-ai/claude-code @anthropic-ai/claude-code && claude --version",
         note="Устаревший способ (есть официальный установщик выше). Нужен node внутри среды. Флаг "
              "--allow-scripts разрешает пакету его установочный скрипт (новые версии npm о нём предупреждают)."),
    dict(id="npm-codex", title="Codex CLI (через npm)", domains=["registry.npmjs.org"], needs=["node"],
         command="npm config set prefix ~/.local && npm install -g @openai/codex",
         note="Нужен node внутри среды. Команда codex появится в ~/.local/bin."),
    dict(id="npm-gemini", title="Gemini CLI (через npm)", domains=["registry.npmjs.org"], needs=["node"],
         command="npm config set prefix ~/.local && npm install -g @google/gemini-cli",
         note="Нужен node внутри среды. Команда gemini появится в ~/.local/bin."),
    dict(id="pnpm", title="pnpm (менеджер пакетов Node)", domains=["registry.npmjs.org"], needs=["node"],
         command="npm config set prefix ~/.local && npm install -g pnpm",
         note="Нужен node внутри среды."),
    dict(id="bun", title="Bun (среда выполнения JavaScript)", domains=[], needs=["unzip"],
         command="curl -fsSL https://bun.sh/install | bash",
         note="Ставится в ~/.bun. Установщик скачивает архив с GitHub, поэтому сеть открыта на любые "
              "публичные адреса с журналом."),
    dict(id="deno", title="Deno (среда выполнения JavaScript/TypeScript)", domains=[], needs=["unzip"],
         command="curl -fsSL https://deno.land/install.sh | sh -s -- --no-modify-path",
         note="Ставится в ~/.deno. Сайты загрузки заранее неизвестны, поэтому сеть открыта на любые "
              "публичные адреса с журналом."),
    dict(id="rust", title="Rust (rustup, cargo)", domains=["sh.rustup.rs", "static.rust-lang.org"], needs=["cc"],
         command="curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path",
         note="Ставится в ~/.cargo и ~/.rustup. Для сборки программ нужен компилятор C на компьютере. "
              "Чтобы cargo скачивал пакеты, потом разрешите crates.io, index.crates.io, static.crates.io."),
    dict(id="go", title="Go (официальный архив)", domains=["go.dev", "dl.google.com"],
         command=r"""cd /tmp && v=$(curl -fsSL "https://go.dev/VERSION?m=text" | head -1) && a=amd64; [ "$(uname -m)" = aarch64 ] && a=arm64; mkdir -p ~/.local && curl -fsSL https://go.dev/dl/$v.linux-$a.tar.gz | tar -xz -C ~/.local && go version""",
         note="Ставится в ~/.local/go. Для go get потом нужны proxy.golang.org и sum.golang.org."),
    dict(id="uv", title="uv и uvx (Python, MCP-серверы на Python)", domains=[],
         command="curl -LsSf https://astral.sh/uv/install.sh | sh",
         note="Установщик скачивает файлы с нескольких сайтов, поэтому сеть открыта на любые публичные "
              "адреса с журналом."),
    dict(id="aider", title="Aider (ИИ-помощник для кода, через uv)", domains=[], needs=["uv"],
         command="uv tool install --python 3.12 aider-chat",
         note="Нужен uv (см. выше). uv сам скачает Python 3.12, поэтому сеть открыта на любые публичные адреса."),
    dict(id="pip", title="Python-пакет (pip, в свой каталог)", domains=["pypi.org", "files.pythonhosted.org"],
         command="python3 -m pip install --user --break-system-packages <пакет>",
         note="Замените <пакет> на название. Пакет ставится в домашний каталог среды, система не меняется."),
    dict(id="npm", title="Другой инструмент Node (npm)", domains=["registry.npmjs.org"], needs=["node"],
         command="npm config set prefix ~/.local && npm install -g <пакет>",
         note="Замените <пакет> на название."),
    dict(id="git-clone", title="Склонировать репозиторий GitHub", domains=["github.com"],
         command="git clone https://github.com/<владелец>/<репозиторий>",
         note="Замените <владелец>/<репозиторий>. Репозиторий окажется в домашнем каталоге среды."),
    dict(id="archive", title="Скачать архив и распаковать (Blender и другие программы)", domains=[],
         command="mkdir -p ~/.local/opt && cd ~/.local/opt && curl -fLO <ссылка на архив> && tar -xf <файл>",
         note="Замените ссылку и имя файла. Сайты загрузки заранее неизвестны, поэтому сеть открыта на любые "
              "публичные адреса с журналом."),
]


# где в домашнем каталоге среды лежат программы, поставленные рецептами (они же добавлены в PATH среды)
RECIPE_TOOL_DIRS = [".local/bin", ".local/go/bin", "go/bin", ".cargo/bin", ".bun/bin", ".deno/bin"]


def env_has_tool(name, tool):
    """Есть ли программа внутри среды: на компьютере (/usr) или в её домашнем каталоге."""
    found = shutil.which(tool)
    if found and os.path.realpath(found).startswith(("/usr/", "/bin/")):
        return True
    home = os.path.join(box_dir(name), "home")
    return any(os.access(os.path.join(home, d, tool), os.X_OK) for d in RECIPE_TOOL_DIRS)


def recipe_warning(recipe, name):
    """Чего не хватает для рецепта (текст на русском) или пустая строка."""
    out = []
    for tool in recipe.get("needs", []):
        if env_has_tool(name, tool):
            continue
        if tool == "node":
            out.append("в среде нет node: сначала установите «Node.js (LTS, официальный архив)» "
                       "из этого списка (или на компьютере: " + pkg_hint("nodejs") + ")")
        elif tool == "uv":
            out.append("в среде нет uv: сначала установите «uv и uvx» из этого списка")
        elif tool == "unzip":
            out.append("на компьютере нет unzip: " + pkg_hint("unzip"))
        elif tool == "cc":
            out.append("на компьютере нет компилятора C: " + pkg_hint("gcc"))
        else:
            out.append(f"не найден {tool}")
    return ("⚠ " + "; ".join(out) + ".") if out else ""


def recipe_placeholders(command):
    """Незаполненные места вида <пакет> в команде."""
    return re.findall(r"<[^<>\n]+>", command)
