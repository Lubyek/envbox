#!/usr/bin/env python3
"""Сборка единого файла dist/envbox.py из пакета src/envbox/.

  python3 build.py            собрать dist/envbox.py
  python3 build.py --check    проверить сборку (синтаксис, дубликаты имён) без записи
  python3 build.py map        обновить MAP.md (карта модулей для навигации)

Как собирается: модули кладутся в один файл в порядке зависимостей, относительные импорты
(from .x import y) убираются, стандартные импорты переносятся наверх, resources/* вшиваются
строками. Модули gui/* заворачиваются в функцию _build_gui(): GTK нужен только для окна,
консольным командам и сетевому шлюзу он не нужен. Сетевой шлюз (version, lazy, net/*) идёт в начале
файла со своими импортами, сразу после него — быстрый вход: служебные вызовы из envbox.sh (прокси, мост,
seccomp, проверка Git) запускаются десятки раз в день и не должны каждый раз загружать всё остальное.
Править dist/envbox.py руками нельзя."""
import ast
import io
import os
import sys
import tempfile
import tokenize

ROOT = os.path.dirname(os.path.realpath(__file__))
SRC = os.path.join(ROOT, "src", "envbox")
DIST = os.path.join(ROOT, "dist", "envbox.py")
FIRST = ["version", "lazy", "resources", "selfpath"]   # порядок при равенстве зависимостей
FAST = ("version", "lazy")                             # вместе с net/* — часть, нужная быстрому входу


class BuildError(Exception):
    pass


def module_files():
    """{id модуля: путь}; id как в импортах: core.store, gui.pages.sidebar…"""
    out = {}
    for base, _dirs, files in os.walk(SRC):
        for f in files:
            if f.endswith(".py") and f != "__init__.py":
                path = os.path.join(base, f)
                rel = os.path.relpath(path, SRC)[:-3]
                out[rel.replace(os.sep, ".")] = path
    return out


def resolve(mod, node):
    """id модуля, на который указывает относительный импорт."""
    pkg = mod.split(".")[:-1]
    if node.level > 1:
        pkg = pkg[:len(pkg) - (node.level - 1)]
    target = pkg + (node.module.split(".") if node.module else [])
    return ".".join(target)


def string_continuation_rows(text):
    rows, stack = set(), []
    for t in tokenize.generate_tokens(io.StringIO(text).readline):
        if t.type == tokenize.STRING and t.end[0] > t.start[0]:
            rows.update(range(t.start[0] + 1, t.end[0] + 1))
        elif t.type == tokenize.FSTRING_START:
            stack.append(t.start[0])
        elif t.type == tokenize.FSTRING_END:
            s = stack.pop()
            if t.end[0] > s:
                rows.update(range(s + 1, t.end[0] + 1))
    return rows


def top_names(tree):
    names = []
    for n in tree.body:
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.append(n.name)
        elif isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = n.targets if isinstance(n, ast.Assign) else [n.target]
            for t in targets:
                names += [x.id for x in ast.walk(t) if isinstance(x, ast.Name)]
    return names


def embedded_resources():
    d = os.path.join(SRC, "resources")
    out = {}
    for f in sorted(os.listdir(d)):
        with open(os.path.join(d, f), encoding="utf-8", newline="") as fh:
            out[f] = fh.read()
    return out


def literal(text):
    """Строковый литерал, дающий ровно text; читаемый, где это безопасно."""
    if "'''" not in text and "\\" not in text and "\r" not in text and not text.endswith("'") \
            and all(ch == "\n" or ch >= " " for ch in text):
        return "'''" + text + "'''"
    if "\\" in text and "'''" not in text and "\r" not in text and not text.endswith(("'", "\\")) \
            and all(ch == "\n" or ch >= " " for ch in text):
        return "r'''" + text + "'''"
    return repr(text)


def resources_module():
    body = ["_RESOURCES = {"]
    for name, text in embedded_resources().items():
        body.append(f"    {name!r}: {literal(text)},")
    body.append("}\n\n\ndef resource_text(name):\n    return _RESOURCES[name]\n")
    return "\n".join(body)


def order(mods, deps, done=()):
    """Топологический порядок; при равных условиях — по FIRST, затем по имени. done — уже выложенные модули."""
    def key(m):
        return (FIRST.index(m) if m in FIRST else len(FIRST), m)
    seen, out = set(done), []

    def visit(m, trail=()):
        if m in seen:
            return
        if m in trail:
            raise BuildError("цикл импортов: " + " -> ".join(trail + (m,)))
        for d in sorted(deps[m], key=key):
            visit(d, trail + (m,))
        seen.add(m)
        out.append(m)
    for m in sorted(mods, key=key):
        visit(m)
    return out


def build_text():
    files = module_files()
    info, deps, hoisted, mod_hoisted = {}, {}, set(), {}
    seen_names = {}
    for mod, path in files.items():
        with open(path, encoding="utf-8") as f:
            text = f.read()
        tree = ast.parse(text, path)
        lines = text.split("\n")
        drop = set()
        deps[mod] = set()
        mod_hoisted[mod] = set()
        doc = None
        for i, n in enumerate(tree.body):
            if i == 0 and isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant) \
                    and isinstance(n.value.value, str):
                doc = n.value.value
                drop.update(range(n.lineno, n.end_lineno + 1))
            elif isinstance(n, ast.ImportFrom) and n.level > 0:
                target = resolve(mod, n)
                if target not in files:
                    raise BuildError(f"{mod}: импорт неизвестного модуля {target}")
                if any(al.asname for al in n.names):
                    raise BuildError(f"{mod}, строка {n.lineno}: в относительном импорте нельзя `as` "
                                     "(в сборке импорты убираются, и псевдоним не появится)")
                deps[mod].add(target)
                drop.update(range(n.lineno, n.end_lineno + 1))
            elif isinstance(n, (ast.Import, ast.ImportFrom)):
                hoisted.add(ast.unparse(n))
                mod_hoisted[mod].add(ast.unparse(n))
                drop.update(range(n.lineno, n.end_lineno + 1))
        for name in top_names(tree):
            if name in seen_names and seen_names[name] != mod:
                raise BuildError(f"имя {name} определено и в {seen_names[name]}, и в {mod}: "
                                 "в сборке все модули делят одно пространство имён")
            seen_names[name] = mod
        info[mod] = (lines, drop, doc, text)

    gui = [m for m in files if m == "gui" or m.startswith("gui.")]
    plain = [m for m in files if m not in gui]
    for m in plain:
        bad = [d for d in deps[m] if d in gui]
        if bad and m != "cli":
            raise BuildError(f"{m} импортирует GUI-модули {bad}: GUI подключается только из cli")
    # cli подключает gui лениво (внутри функции), такой импорт в deps не попадает: он не на верхнем уровне

    def render(mod, indent):
        lines, drop, doc, text = info[mod]
        cont = string_continuation_rows(text)
        out = []
        for ln, t in enumerate(lines, 1):
            if ln in drop:
                continue
            if indent and ln not in cont and t.strip():
                t = " " * indent + t
            out.append(t)
        code = "\n".join(out).strip("\n")
        if mod == "resources":
            code = resources_module().strip("\n")
            if indent:
                raise BuildError("resources не может быть внутри gui")
        if mod == "selfpath":
            if "BUNDLED = False" not in code:
                raise BuildError("в selfpath.py нет строки BUNDLED = False")
            code = code.replace("BUNDLED = False", "BUNDLED = True", 1)
        if mod == "cli":   # единственный ленивый импорт GUI
            lazy = "    from .gui.app import gui_main\n    return gui_main()"
            if lazy not in code:
                raise BuildError("в cli.py не найден ленивый импорт GUI")
            code = code.replace(lazy, "    return _build_gui()()")
        one = (doc or "").strip().split("\n")[0]
        pad = " " * indent
        banner = f"{pad}# ---- {mod.replace('.', '/')}.py" + (f": {one}" if one else "")
        return banner + "\n\n" + code + "\n"

    fast = [m for m in plain if m in FAST or m.startswith("net.")]
    for m in fast:
        bad = sorted(d for d in deps[m] if d not in fast)
        if bad:
            raise BuildError(f"{m} (сетевой шлюз) зависит от {bad}: быстрый вход не должен тянуть остальной код")
    fast_order = order(fast, {m: deps[m] & set(fast) for m in fast})
    rest_order = order(plain, {m: deps[m] & set(plain) for m in plain}, done=fast_order)
    parts = [render(m, 0) for m in fast_order]
    fast_imports = set().union(*(mod_hoisted[m] for m in fast))
    if "import sys" not in fast_imports:
        raise BuildError("в сетевом шлюзе нет import sys: нужен для быстрого входа")
    if "NET_COMMANDS" not in top_names(ast.parse(info["net.entry"][3])):
        raise BuildError("в net/entry.py нет NET_COMMANDS")
    parts.append("# ---- быстрый вход: служебные команды шлюза не загружают остальной код\n\n"
                 "if __name__ == \"__main__\" and sys.argv[1:2] and sys.argv[1] in NET_COMMANDS:\n"
                 "    sys.exit(net_main())\n")
    rest_marker = len(parts)
    for mod in rest_order:
        parts.append(render(mod, 0))
    gui_order = order(gui, {m: deps[m] & set(gui) for m in gui})
    gui_parts = [render(m, 4) for m in gui_order]
    parts.append(
        "# ---- gui/*: графический интерфейс. Классы требуют импортированного GTK, поэтому\n"
        "# весь раздел собирается внутри функции и выполняется только при запуске окна.\n"
        "def _build_gui():\n    \"\"\"Определяет классы интерфейса и возвращает gui_main.\"\"\"\n"
        + "\n\n".join(gui_parts) + "\n    return gui_main\n")

    with open(os.path.join(SRC, "resources", "help.txt"), encoding="utf-8", newline="") as f:
        help_text = f.read()
    def import_block(items):
        return "\n".join(sorted(h for h in items if h.startswith("import ")) +
                         sorted(h for h in items if h.startswith("from ")))

    header = ("#!/usr/bin/env python3\n"
              "# ВНИМАНИЕ: файл собран build.py из src/envbox/. Правьте исходники, а не его.\n"
              + '"""' + help_text.replace("\\", "\\\\").replace('"""', '\\"\\"\\"') + '"""\n'
              + import_block(fast_imports) + "\n\n\n")
    rest_imports = import_block(hoisted - fast_imports)
    parts.insert(rest_marker, rest_imports + "\n")
    return header + "\n\n".join(parts).rstrip("\n") + "\n\n\nif __name__ == \"__main__\":\n    sys.exit(main())\n"


def check_syntax(text):
    try:
        tree = ast.parse(text, "envbox.py")
    except SyntaxError as e:
        raise BuildError(f"синтаксис собранного файла: {e}") from e
    for n in ast.walk(tree):
        if isinstance(n, ast.ImportFrom) and n.level:
            raise BuildError(f"в сборке остался относительный импорт (строка {n.lineno}): "
                             "импорты внутри функций собрать нельзя, поднимите их наверх модуля")


def build(write=True):
    text = build_text()
    check_syntax(text)
    if write:
        os.makedirs(os.path.dirname(DIST), exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(DIST), prefix=".envbox.", suffix=".new")
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
            f.write(text)
        os.chmod(tmp, 0o755)
        os.replace(tmp, DIST)
    return DIST


def newest_source():
    m = os.path.getmtime(os.path.join(ROOT, "build.py"))
    for base, _d, files in os.walk(SRC):
        for f in files:
            if not f.endswith(".pyc"):
                m = max(m, os.path.getmtime(os.path.join(base, f)))
    return m


def build_if_stale():
    """Путь к dist/envbox.py; пересобирает, только если исходники новее (используют dev.py и install)."""
    try:
        if os.path.getmtime(DIST) >= newest_source():
            return DIST
    except OSError:
        pass
    return build()


def make_map():
    lines = ["# Карта модулей", "",
             "Файл создаётся командой `python3 build.py map` — не править руками.", ""]
    for mod, path in sorted(module_files().items()):
        with open(path, encoding="utf-8") as f:
            text = f.read()
        tree = ast.parse(text)
        doc = ast.get_docstring(tree) or ""
        syms = []
        for n in tree.body:
            if isinstance(n, ast.ClassDef):
                syms.append(f"{n.name} ({sum(isinstance(x, ast.FunctionDef) for x in n.body)} методов)")
            elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and not n.name.startswith("_"):
                syms.append(n.name + "()")
        rel = os.path.relpath(path, ROOT)
        lines.append(f"- `{rel}` ({len(text.splitlines())} стр.) — {doc.splitlines()[0] if doc else ''}")
        if syms:
            lines.append("  " + ", ".join(syms[:14]) + (" …" if len(syms) > 14 else ""))
    with open(os.path.join(ROOT, "MAP.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def main(argv):
    try:
        if argv[:1] == ["map"]:
            make_map()
            print("MAP.md обновлён")
        elif argv[:1] == ["--check"]:
            build(write=False)
            print("OK: сборка проходит")
        elif not argv:
            path = build()
            print(f"Собрано: {path} ({os.path.getsize(path) // 1024} КБ)")
        else:
            print(__doc__)
            return 2
    except BuildError as e:
        print(f"build: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
