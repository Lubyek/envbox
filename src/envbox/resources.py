"""Встроенные ресурсы (envbox.sh, значки, CSS…): файлы из resources/; в собранном envbox.py они вшиты строками."""
import os

_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "resources")


def resource_text(name):
    with open(os.path.join(_DIR, name), encoding="utf-8", newline="") as f:
        return f.read()
