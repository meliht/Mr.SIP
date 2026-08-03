import logging
import os
import sys
from datetime import datetime

from src.core import theme

CONSOLE_FORMAT = "%(message)s"
FILE_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"

def _make_log_method(level):
    """Build a logging.Logger method that logs at a fixed custom *level*.

    Every custom level below (FOUND, FOUND_UNCONFIRMED, BLANKET_WARN) needs
    the exact same three-line method - only the level constant it closes
    over differs - so it's generated once here instead of once per level.
    """
    def _log_method(self, message, *args, **kwargs):
        if self.isEnabledFor(level):
            self._log(level, message, args, **kwargs)
    return _log_method


# Custom level for "a live target / valid extension was found" results.
# Sits between INFO and WARNING so it's a real, filterable log level instead
# of the old ad-hoc "[+]" string prefix buried inside .info() messages.
FOUND = 25
logging.addLevelName(FOUND, "FOUND")
logging.Logger.found = _make_log_method(FOUND)

# Two more custom levels, both specific to SIP-ENUM's blanket-rejection
# scenario: a target that rejects every unmatched
# request the same way makes routine WARN/FOUND coloring blend in with the
# rest of a run, even though this is exactly the moment an operator most
# needs their eye drawn to. Distinct levels - not just a different color at
# the same levelno - keep both filterable/greppable in the file log too,
# same reasoning FOUND itself was originally given.

# A "found" result that matched the target's own blanket-rejection baseline
# (see enum.py's _classify_confidence()) - still shown by default (sits
# above INFO), but as a distinct, yellow "[ FOUND ]" so it doesn't read as
# equally trustworthy as a real (green) FOUND.
FOUND_UNCONFIRMED = 24
logging.addLevelName(FOUND_UNCONFIRMED, "FOUND_UNCONFIRMED")
logging.Logger.found_unconfirmed = _make_log_method(FOUND_UNCONFIRMED)

# SIP-ENUM's pre-flight blanket-rejection warning. Kept at/above
# logging.WARNING (not below it) so existing callers that use
# caplog.at_level(logging.WARNING)/--verbose-independent thresholds elsewhere
# in this tool still capture it - only the *color* is meant to differ, not
# whether it's shown by default.
BLANKET_WARN = 31
logging.addLevelName(BLANKET_WARN, "BLANKET_WARN")
logging.Logger.blanket_warn = _make_log_method(BLANKET_WARN)

# levelno -> (short tag, color). Tags are padded to equal width in
# ColorFormatter so console output stays aligned regardless of level.
_LEVEL_STYLE = {
    logging.DEBUG: ("DEBUG", theme.MUTED),
    logging.INFO: ("INFO", theme.ACCENT),
    FOUND_UNCONFIRMED: ("FOUND", theme.WARNING),
    FOUND: ("FOUND", theme.SUCCESS),
    logging.WARNING: ("WARN", theme.WARNING),
    BLANKET_WARN: ("WARN", theme.ERROR),
    logging.ERROR: ("ERROR", theme.ERROR),
    logging.CRITICAL: ("CRIT", theme.CRITICAL),
}


class ColorFormatter(logging.Formatter):
    """Prefixes every console line with a colored '[ LEVEL ]' tag.

    Replaces the old convention of hardcoding ANSI color codes and ad-hoc
    "[!]"/"[+]" markers inline at each call site - callers now just log at
    the right level (.debug/.info/.found/.warning/.error) and this formatter
    is the single place that decides how that looks. Auto-disabled via
    theme.supports_color() (NO_COLOR, non-tty output).
    """

    def format(self, record):
        message = super().format(record)
        tag, color = _LEVEL_STYLE.get(record.levelno, (record.levelname, theme.ACCENT))
        prefix = theme.colorize(f"[ {tag:<5} ]", color)
        return "\n".join(f"{prefix} {line}" for line in message.split("\n"))


class StripAnsiFormatter(logging.Formatter):
    """Strips ANSI color codes before writing to the log file, so the on-disk
    log stays plain text (it's meant to double as pentest evidence/report
    material) while the console keeps its colored output untouched."""

    def format(self, record):
        record.message = record.getMessage()
        if self.usesTime():
            record.asctime = self.formatTime(record, self.datefmt)
        
        orig_message = record.message
        if "\n" in orig_message:
            lines = orig_message.split("\n")
            formatted_lines = []
            for line in lines:
                record.message = line
                formatted_lines.append(self.formatMessage(record))
            record.message = orig_message
            formatted = "\n".join(formatted_lines)
        else:
            formatted = self.formatMessage(record)
            
        if record.exc_info and not record.exc_text:
            record.exc_text = self.formatException(record.exc_info)
        if record.exc_text:
            if not formatted.endswith("\n"):
                formatted = formatted + "\n"
            formatted = formatted + record.exc_text
        if record.stack_info:
            if not formatted.endswith("\n"):
                formatted = formatted + "\n"
            formatted = formatted + self.formatStack(record.stack_info)
            
        return theme.strip_ansi(formatted)


class TqdmLoggingHandler(logging.Handler):
    """A logging handler that writes logs via tqdm.write to prevent progress bar corruption."""

    def emit(self, record):
        try:
            msg = self.format(record)
            from tqdm import tqdm
            tqdm.write(msg, file=sys.stdout)
            self.flush()
        except Exception:
            self.handleError(record)


def setup_logging(verbose: bool, log_dir: str = "logs") -> logging.Logger:
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    # Log messages can echo back user-controlled strings (a target name, a
    # file path in an error message, ...) that may contain characters the
    # console can't encode - e.g. a lone surrogate from a CLI argument with
    # invalid-UTF-8 bytes (argv is decoded with errors="surrogateescape").
    # Without this, such a message crashes the stream's write() with
    # UnicodeEncodeError instead of printing a readable escaped fallback.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="backslashreplace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(errors="backslashreplace")

    console_handler = TqdmLoggingHandler()
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    console_handler.setFormatter(ColorFormatter(CONSOLE_FORMAT))
    logger.addHandler(console_handler)

    os.makedirs(log_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_path = os.path.join(log_dir, f"mrsip_{timestamp}.log")
    # Same rationale as the stdout.reconfigure() above - the log file must
    # not crash on a message containing characters invalid for its encoding.
    file_handler = logging.FileHandler(file_path, encoding="utf-8", errors="backslashreplace")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(StripAnsiFormatter(FILE_FORMAT))
    logger.addHandler(file_handler)

    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    return logger
