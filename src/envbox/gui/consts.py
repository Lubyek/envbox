"""Константы GUI: CSS, значки, метки."""

import os

from ..resources import resource_text


HOME = os.path.expanduser("~")


SHELL_COMMAND = "@shell"   # метка: подставляется оболочка выбранной среды


STATUS_SECONDS = 8


CSS = resource_text("gui.css")


LEVEL_ICONS = {"ok": ("✔", "eb-ok"), "info": ("•", "eb-info"), "warn": ("⚠", "eb-warn")}


KIND_ICONS = {"app": "utilities-terminal-symbolic", "browser": "web-browser-symbolic"}
