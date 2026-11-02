"""Пути к самому envbox: точка запуска (SELF) и единый файл для установки (bundle_path)."""
import os
import sys

BUNDLED = False   # build.py ставит True в собранном dist/envbox.py

# что перезапускать (execv) и откуда читать версию: собранный файл или dev.py
SELF = os.path.realpath(__file__ if BUNDLED else sys.argv[0])


def bundle_path():
    """Единый файл envbox.py для установки и AppImage.

    В собранном файле это он сам; при запуске из исходников — свежая сборка dist/envbox.py."""
    if BUNDLED:
        return SELF
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
    if root not in sys.path:
        sys.path.insert(0, root)
    import build
    return build.build_if_stale()
