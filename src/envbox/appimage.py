"""Сборка AppImage."""

import base64
import hashlib
import os
import shutil
import subprocess
import sys

from .core.desktop import ICON_SVG
from .core.fsutil import _atomic_write
from .resources import resource_text
from .selfpath import bundle_path
from .version import ENVBOX_VERSION


ICON_PNG_B64 = resource_text("icon.png.b64")


APPRUN_TEXT = resource_text("AppRun.sh")


DESKTOP_TEXT = resource_text("envbox.desktop")


def build_appimage(args):
    """Собирает «тонкий» AppImage: внутри только envbox.py; Python, GTK и bubblewrap — из системы."""
    import tempfile
    import urllib.request

    arch = os.uname().machine
    if arch not in ("x86_64", "aarch64"):
        print(f"envbox: неподдерживаемая архитектура: {arch}", file=sys.stderr)
        return 1
    tool = os.environ.get("APPIMAGETOOL") or shutil.which("appimagetool") or ""
    if not tool:
        cache = os.path.join(os.environ.get("XDG_CACHE_HOME") or
                             os.path.join(os.path.expanduser("~"), ".cache"), "envbox-build")
        os.makedirs(cache, exist_ok=True)
        tool = os.path.join(cache, f"appimagetool-{arch}.AppImage")
        if not os.access(tool, os.X_OK):
            url = ("https://github.com/AppImage/appimagetool/releases/download/continuous/"
                   f"appimagetool-{arch}.AppImage")
            print(f"envbox: скачиваю appimagetool: {url}", file=sys.stderr)
            try:
                with urllib.request.urlopen(url, timeout=60) as r, open(tool + ".part", "wb") as f:
                    shutil.copyfileobj(r, f)
            except (OSError, ValueError) as e:
                print(f"envbox: не удалось скачать appimagetool: {e}\n"
                      "Установите его (AUR: appimagetool-bin) или задайте APPIMAGETOOL=/путь", file=sys.stderr)
                return 1
            with open(tool + ".part", "rb") as f:
                digest = hashlib.sha256(f.read()).hexdigest()
            want = os.environ.get("APPIMAGETOOL_SHA256", "").strip().lower()
            if digest != want:
                # скачанный файл потом запускается, поэтому без совпавшей суммы он не устанавливается
                os.unlink(tool + ".part")
                if want:
                    print(f"envbox: контрольная сумма appimagetool не совпала ({digest})", file=sys.stderr)
                else:
                    print(f"envbox: sha256 скачанного appimagetool: {digest}\n"
                          "        Файл не установлен. Сверьте сумму с релизом на GitHub и повторите с "
                          "APPIMAGETOOL_SHA256=<сумма>", file=sys.stderr)
                return 1
            os.chmod(tool + ".part", 0o755)
            os.replace(tool + ".part", tool)
    out = os.path.join(os.getcwd(), f"envbox-{arch}.AppImage")
    with tempfile.TemporaryDirectory() as work:
        appdir = os.path.join(work, "envbox.AppDir")
        os.makedirs(os.path.join(appdir, "usr", "share", "envbox"))
        with open(bundle_path(), "rb") as f:
            _atomic_write(os.path.join(appdir, "usr", "share", "envbox", "envbox.py"), f.read(), 0o755)
        with open(os.path.join(appdir, "envbox.png"), "wb") as f:
            f.write(base64.b64decode(ICON_PNG_B64))
        with open(os.path.join(appdir, "envbox.svg"), "w", encoding="utf-8") as f:
            f.write(ICON_SVG)
        with open(os.path.join(appdir, "envbox.desktop"), "w", encoding="utf-8") as f:
            f.write(DESKTOP_TEXT.rstrip("\n") + f"\nX-AppImage-Version={ENVBOX_VERSION}\n")
        _atomic_write(os.path.join(appdir, "AppRun"), APPRUN_TEXT.encode("utf-8"), 0o755)
        env = dict(os.environ, ARCH=arch, APPIMAGE_EXTRACT_AND_RUN="1")
        # Старый AppImage может быть запущен (окно envbox): запись в него даёт «Text file busy». Собираем рядом
        # под другим именем, а потом подменяем — rename запущенного файла разрешён, процесс держит старый inode.
        tmp_out = out + ".new"
        rc = subprocess.run([tool, appdir, tmp_out], env=env).returncode
        if rc == 0:
            try:
                os.replace(tmp_out, out)
            except OSError as e:
                print(f"envbox: не удалось заменить {out}: {e}", file=sys.stderr)
                rc = 1
        if rc != 0 and os.path.lexists(tmp_out):
            try:
                os.unlink(tmp_out)
            except OSError:
                pass
    if rc != 0:
        print("envbox: appimagetool завершился с ошибкой", file=sys.stderr)
        return rc
    print(f"Готово: {out} (версия {ENVBOX_VERSION}; проверка: {out} --version)")
    return 0
