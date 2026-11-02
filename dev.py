#!/usr/bin/env python3
"""Запуск envbox из исходников (src/envbox/) без сборки: python3 dev.py [команда…].

Установка и AppImage при этом берут свежую сборку dist/envbox.py (см. build.py)."""
import os
import sys

sys.dont_write_bytecode = True   # не мусорить __pycache__ в src/
sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), "src"))

from envbox.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
