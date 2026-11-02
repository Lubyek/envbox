"""Проверка Git после работы среды: хуки и config проекта не должны меняться незаметно."""

import os
import stat
import sys

from ..lazy import json


# ---- проверка Git после работы среды: хуки и config в проекте не должны меняться незаметно

def _sha256(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _walk_files(root, base, out, depth=6):
    if depth < 0 or not os.path.isdir(root) or os.path.islink(root):
        return
    for name in sorted(os.listdir(root)):
        path = os.path.join(root, name)
        rel = os.path.relpath(path, base)
        if os.path.islink(path):
            out[rel] = "link:" + os.readlink(path)
        elif os.path.isdir(path):
            _walk_files(path, base, out, depth - 1)
        elif os.path.isfile(path) and not name.endswith(".sample"):   # *.sample git не запускает
            out[rel] = _sha256(path)


def git_state(workdir):
    """Состояние того, что запускается при командах git: сам .git, config, хуки, hooksPath, подмодули."""
    gp = os.path.join(workdir, ".git")
    try:
        st = os.lstat(gp)
    except OSError:
        return {"kind": "none", "ino": [0, 0], "files": {}}
    kind = "link" if stat.S_ISLNK(st.st_mode) else "dir" if stat.S_ISDIR(st.st_mode) else "file"
    files = {}
    if kind == "file":
        files[".git"] = _sha256(gp)
    elif kind == "dir":
        cfg = os.path.join(gp, "config")
        if os.path.isfile(cfg):
            files[".git/config"] = _sha256(cfg)
        # commondir подменяет каталог, откуда git берёт config и хуки; config.worktree читается при extensions.worktreeConfig
        for extra in ("commondir", "config.worktree"):
            path = os.path.join(gp, extra)
            if os.path.islink(path):
                files[".git/" + extra] = "link:" + os.readlink(path)
            elif os.path.isfile(path):
                files[".git/" + extra] = _sha256(path)
        _walk_files(os.path.join(gp, "hooks"), workdir, files)
        files[".git/hooks/"] = "каталог" if os.path.isdir(os.path.join(gp, "hooks")) else "нет"
        mods = os.path.join(gp, "modules")
        for root, dirs, names in os.walk(mods):
            if root.count(os.sep) - mods.count(os.sep) > 5:
                dirs[:] = []
                continue
            for d in list(dirs):
                if d == "hooks":
                    _walk_files(os.path.join(root, d), workdir, files)
            if "config" in names:
                path = os.path.join(root, "config")
                files[os.path.relpath(path, workdir)] = _sha256(path)
        hp = ""
        if os.path.isfile(cfg):
            import subprocess
            try:
                hp = subprocess.run(["git", "config", "--file", cfg, "--get", "core.hooksPath"],
                                    capture_output=True, text=True, timeout=10).stdout.strip()
            except (OSError, subprocess.SubprocessError):
                hp = ""
        if hp:
            hp = os.path.realpath(hp if os.path.isabs(hp) else os.path.join(workdir, hp))
            if hp.startswith(os.path.realpath(workdir) + os.sep):
                _walk_files(hp, workdir, files)
    return {"kind": kind, "ino": [st.st_dev, st.st_ino], "files": files}


def cmd_gitcheck(a):
    if a.action == "snapshot":
        json.dump(git_state(a.workdir), sys.stdout)
        return
    try:
        with open(a.snapshot, encoding="utf-8") as f:
            before = json.load(f)
    except (OSError, ValueError):
        return
    after = git_state(a.workdir)
    notes = []
    if before["kind"] == "none" and after["kind"] != "none":
        notes.append("«.git» создан внутри среды (раньше в проекте репозитория не было)")
    elif before["kind"] != after["kind"] or before["ino"] != after["ino"]:
        notes.append("«.git» заменён или пересоздан (другой объект на диске)")
    for key in sorted(set(before["files"]) | set(after["files"])):
        old, new = before["files"].get(key), after["files"].get(key)
        if old == new:
            continue
        what = "добавлен" if old is None else "удалён" if new is None else "изменён"
        notes.append(f"{what}: {key}")
    if notes:
        print("\n⚠ envbox: после работы среды изменилось то, что запускается при командах git "
              "в проекте — проверьте, прежде чем использовать git на компьютере:", file=sys.stderr)
        for n in notes:
            print("   · " + n, file=sys.stderr)
        print("   Проверка: ls -la .git/hooks; git config --local --list", file=sys.stderr)
        sys.exit(4)
