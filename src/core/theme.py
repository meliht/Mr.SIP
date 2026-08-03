"""
Single source of truth for terminal color/style. Every ANSI escape code used
anywhere in Mr.SIP (banner, log formatting, per-module summaries) goes through
this module instead of being hardcoded inline at each call site.
"""

import os
import re
import sys

_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*m")

RESET = "\033[0m"
BOLD = "\033[1m"

MUTED = "\033[90m"
ACCENT = "\033[36m"
SUCCESS = "\033[32m"
WARNING = "\033[33m"
ERROR = "\033[31m"
CRITICAL = "\033[1;31m"

BOX_HORIZONTAL = "─"
BOX_VERTICAL = "│"
BOX_TOP_LEFT = "┌"
BOX_TOP_RIGHT = "┐"
BOX_BOTTOM_LEFT = "└"
BOX_BOTTOM_RIGHT = "┘"


def supports_color() -> bool:
    """Whether the current stdout should receive ANSI escape codes.

    Off when NO_COLOR is set (https://no-color.org) or stdout isn't a real
    terminal (piped, redirected to a file, captured by a test runner).
    """
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def colorize(text: str, color: str) -> str:
    """Wrap *text* in *color*, or return it unchanged when color is disabled."""
    if not supports_color():
        return text
    return f"{color}{text}{RESET}"


def strip_ansi(text: str) -> str:
    """Remove ANSI escape codes from *text*. Single source of this regex -
    used for the on-disk log file (which must stay plain text) and for any
    pre-colored string (e.g. the startup banner) printed when color support
    is auto-disabled (NO_COLOR, non-tty).
    """
    return _ANSI_ESCAPE_RE.sub("", text)


def panel(title: str, lines: list[str]) -> str:
    """Render a boxed summary panel for a module's final run summary.

    Falls back to plain, unboxed text (still readable, just no box-drawing/
    color) when color is disabled - box-drawing characters are Unicode, not
    ANSI, so they'd otherwise still render even when colors are off; keeping
    the fallback plain avoids a half-styled look on genuinely dumb output
    (e.g. piped into a file meant to be diffed as plain text).
    """
    if not supports_color():
        rendered = [title, *lines]
        return "\n".join(rendered)

    width = max([len(title), *(len(line) for line in lines)]) + 2
    top = f"{ACCENT}{BOX_TOP_LEFT}{BOX_HORIZONTAL * width}{BOX_TOP_RIGHT}{RESET}"
    bottom = f"{ACCENT}{BOX_BOTTOM_LEFT}{BOX_HORIZONTAL * width}{BOX_BOTTOM_RIGHT}{RESET}"
    header = f"{ACCENT}{BOX_VERTICAL}{RESET} {BOLD}{title}{RESET}{' ' * (width - len(title) - 1)}{ACCENT}{BOX_VERTICAL}{RESET}"
    body = [
        f"{ACCENT}{BOX_VERTICAL}{RESET} {line}{' ' * (width - len(line) - 1)}{ACCENT}{BOX_VERTICAL}{RESET}"
        for line in lines
    ]
    return "\n".join([top, header, *body, bottom])
