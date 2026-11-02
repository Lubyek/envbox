"""CDP: перевод координат, клавиш и масштаба."""

import re

from .http import CDP_MOD_ALT, CDP_MOD_CTRL, CDP_MOD_META


def normalize_url(text):
    """Адрес из строки ввода: только http/https (и about:blank); без схемы добавляется https://."""
    t = text.strip()
    if not t:
        return "about:blank"
    if t == "about:blank":
        return t
    if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", t):
        if not re.match(r"^https?://", t, re.I):
            raise ValueError("поддерживаются только адреса http и https")
        url = t
    else:
        url = "https://" + t
    if any(c.isspace() for c in url):
        raise ValueError("адрес не может содержать пробелы")
    return url


def map_point(x, y, widget_w, widget_h, frame_w, frame_h):
    """Точка в виджете (картинка вписана с сохранением пропорций) -> точка на странице; None вне кадра."""
    if min(widget_w, widget_h, frame_w, frame_h) <= 0:
        return None
    scale = min(widget_w / frame_w, widget_h / frame_h)
    off_x, off_y = (widget_w - frame_w * scale) / 2, (widget_h - frame_h * scale) / 2
    px, py = (x - off_x) / scale, (y - off_y) / scale
    if px < 0 or py < 0 or px > frame_w or py > frame_h:
        return None
    return px, py


_CDP_KEYS = {
    "Return": ("Enter", "Enter", 13, "\r"), "KP_Enter": ("Enter", "NumpadEnter", 13, "\r"),
    "BackSpace": ("Backspace", "Backspace", 8, ""), "Tab": ("Tab", "Tab", 9, ""),
    "ISO_Left_Tab": ("Tab", "Tab", 9, ""), "Escape": ("Escape", "Escape", 27, ""),
    "Delete": ("Delete", "Delete", 46, ""), "Insert": ("Insert", "Insert", 45, ""),
    "Left": ("ArrowLeft", "ArrowLeft", 37, ""), "Up": ("ArrowUp", "ArrowUp", 38, ""),
    "Right": ("ArrowRight", "ArrowRight", 39, ""), "Down": ("ArrowDown", "ArrowDown", 40, ""),
    "Home": ("Home", "Home", 36, ""), "End": ("End", "End", 35, ""),
    "Page_Up": ("PageUp", "PageUp", 33, ""), "Page_Down": ("PageDown", "PageDown", 34, ""),
}


_CDP_EDIT_COMMANDS = {"a": "selectAll", "c": "copy", "x": "cut", "z": "undo", "y": "redo"}


def cdp_key_events(keyname, char, mods, pressed):
    """Параметры Input.dispatchKeyEvent для нажатия/отпускания клавиши (список; бывает пустым)."""
    if keyname in _CDP_KEYS:
        key, code, vk, text = _CDP_KEYS[keyname]
        if not pressed:
            return [{"type": "keyUp", "key": key, "code": code, "windowsVirtualKeyCode": vk, "modifiers": mods}]
        ev = {"type": "keyDown" if text else "rawKeyDown", "key": key, "code": code,
              "windowsVirtualKeyCode": vk, "modifiers": mods}
        if text:
            ev["text"] = ev["unmodifiedText"] = text
        return [ev]
    if not char or not char.isprintable():
        return []
    if mods & (CDP_MOD_CTRL | CDP_MOD_ALT | CDP_MOD_META):
        ev = {"type": ("rawKeyDown" if pressed else "keyUp"), "key": char, "modifiers": mods}
        if pressed and mods & CDP_MOD_CTRL and char.lower() in _CDP_EDIT_COMMANDS:
            ev["commands"] = [_CDP_EDIT_COMMANDS[char.lower()]]
        return [ev]
    if pressed:
        return [{"type": "keyDown", "key": char, "text": char, "unmodifiedText": char, "modifiers": mods}]
    return [{"type": "keyUp", "key": char, "modifiers": mods}]
