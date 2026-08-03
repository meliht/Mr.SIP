"""
Shared worker-pool helper used by SIP-NES and SIP-ENUM. Replaces the
duplicated thread-setup/busy-wait/y-n-prompt code that used to live
separately in each module.
"""

import logging
import os
import queue
import sys
import threading
import time
from tqdm import tqdm

from src.core import theme

logger = logging.getLogger(__name__)


def _read_single_char():
    """Read exactly one keypress from the controlling terminal, no Enter needed.

    Opens /dev/tty directly (bypasses any stdin redirection or Python buffering).
    Uses tty.setcbreak() to disable line buffering only - unlike tty.setraw(),
    this leaves echo and output post-processing (CR/LF translation) alone, so
    the terminal displays the keypress itself instead of a doubled/misaligned
    "y" (setraw() was tried first and produced exactly that garbled output on
    a real terminal). os.read() does the unbuffered single-byte read, TCSANOW
    gives an instant restore.

    Falls back to msvcrt.getch() on Windows, or line-buffered input() elsewhere.
    Raises EOFError when no controlling terminal is available.
    """
    # ── Windows ──
    try:
        import termios
        import tty
    except ImportError:
        try:
            import msvcrt
            ch = msvcrt.getch()
            if ch in (b"\x00", b"\xe0"):
                msvcrt.getch()
                return ""
            return ch.decode("utf-8", errors="ignore")
        except ImportError:
            line = input()
            return line[0] if line else ""

    # ── POSIX: open /dev/tty directly ──
    try:
        fd = os.open("/dev/tty", os.O_RDWR)
    except OSError:
        raise EOFError from None

    old = termios.tcgetattr(fd)
    try:
        # Flush stray input (e.g. leftover Enter from launching the command)
        time.sleep(0.05)  # let kernel finish delivering any pending input
        termios.tcflush(fd, termios.TCIFLUSH)
        # cbreak: disables line buffering (canonical mode) only - echo and
        # output post-processing stay on, unlike raw mode.
        tty.setcbreak(fd)
        ch = os.read(fd, 1)
    finally:
        termios.tcsetattr(fd, termios.TCSANOW, old)
        os.close(fd)

    if not ch:
        raise EOFError
    b = ch[0]
    if b == 3:   # Ctrl-C
        raise KeyboardInterrupt
    if b == 4:   # Ctrl-D
        raise EOFError
    return ch.decode("utf-8", errors="ignore")


def prompt_yes_no(message: str) -> bool:
    """Print *message*, wait for a single y/n keypress, return True/False."""
    # Strip trailing whitespace/newlines so cursor stays right after (y/n)
    clean = message.rstrip()
    sys.stdout.write(clean)
    sys.stdout.flush()

    try:
        answer = _read_single_char()
    except EOFError:
        sys.stdout.write("\n")
        sys.stdout.flush()
        logger.info("STDIN is unavailable; refusing to proceed without confirmation.")
        return False

    # Terminal is already restored — print the answer on the same line, then newline
    sys.stdout.write(answer + "\n")
    sys.stdout.flush()

    if answer in ("y", "Y"):
        return True
    if answer in ("n", "N"):
        logger.info("Terminating by user input.")
        return False
    logger.warning("Answer not understood. Please answer y/n.")
    return False


def confirm_bulk_run(subject_count, subject_label, target_count, packet_count, force=False):
    """Ask the operator to confirm a bulk send before it starts. Raises
    SystemExit(0) on decline. Single source of the "N packets will be
    generated, continue?" confirmation - previously duplicated near-verbatim
    in nes.py and enum.py, each building its own prompt text and handling
    the decline case itself.
    """
    if force:
        return
    message = (
        f"{subject_count} {subject_label} will be checked for {target_count} target network(s).\n"
        f"There will be {packet_count} packets generated. Do you want to continue? (y/n)"
    )
    if not prompt_yes_no(theme.colorize(message, theme.ACCENT)):
        raise SystemExit(0)


def run_worker_pool(work_items, worker_fn, thread_count, extra_args=()):
    """Run worker_fn(item, *extra_args) once per item in work_items, using
    thread_count daemon threads. Blocks until every item has actually been
    processed (queue.join()/task_done()), not until the queue merely looks
    empty. Returns the list of non-None values returned by worker_fn calls
    (worker_fn returns None for "no result", anything else for "a result").
    """
    work_queue = queue.Queue()
    for item in work_items:
        work_queue.put(item)

    results = queue.Queue()
    # Each worker updates the bar itself right after finishing its own item
    # (lock-guarded - tqdm's counter isn't safe against concurrent update()
    # calls without one). This keeps completion-tracking to a single
    # mechanism: work_queue.join() below is the only thing that decides
    # when run_worker_pool returns, with no separate polling thread that
    # could race or fall behind.
    pbar = tqdm(total=len(work_items), desc="Progress", unit="task", disable=not sys.stdout.isatty())
    pbar_lock = threading.Lock()

    def _runner():
        while True:
            try:
                item = work_queue.get_nowait()
            except queue.Empty:
                return
            try:
                result = worker_fn(item, *extra_args)
                if result is not None:
                    results.put(result)
            except Exception:
                logger.exception("Worker failed while processing %r", item)
            finally:
                work_queue.task_done()
                with pbar_lock:
                    pbar.update(1)

    threads = [threading.Thread(target=_runner, daemon=True) for _ in range(thread_count)]
    for t in threads:
        t.start()

    try:
        work_queue.join()
        interrupted = False
    except KeyboardInterrupt:
        # Collect whatever results the workers already finished, but still
        # propagate the interrupt - swallowing it here used to make Ctrl+C
        # during an NES/ENUM scan exit 0 like a normal completion, since
        # cli.main()'s own `except KeyboardInterrupt: ... sys.exit(130)`
        # handler was never reached. That broke automation/wrapper scripts
        # that rely on the standard 130 (SIGINT) exit code to detect an
        # interrupted run. The partial results are attached to the exception
        # itself (exc.results below) so the caller (nes.py/enum.py) can still
        # log its own summary panel before re-raising on up to cli.main().
        # Daemon threads working on in-flight requests are abandoned here,
        # same as before; this only changes what happens to results already
        # sitting in the queue.
        logger.warning("CTRL+C pressed, terminating gracefully. In-flight requests may still finish in the background.")
        interrupted = True
    finally:
        pbar.close()

    out = []
    while not results.empty():
        out.append(results.get_nowait())

    if interrupted:
        exc = KeyboardInterrupt()
        exc.results = out
        raise exc

    return out
