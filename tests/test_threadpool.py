import inspect
import threading
import time

import pytest

from src.core import threadpool


class TestRunWorkerPool:
    def test_every_item_is_processed_exactly_once(self):
        seen = []
        lock = threading.Lock()

        def worker(item):
            with lock:
                seen.append(item)
            return None

        threadpool.run_worker_pool(list(range(50)), worker, thread_count=8)
        assert sorted(seen) == list(range(50))

    def test_collects_non_none_results_only(self):
        def worker(item):
            return item * 2 if item % 2 == 0 else None

        results = threadpool.run_worker_pool(list(range(10)), worker, thread_count=4)
        assert sorted(results) == [0, 4, 8, 12, 16]

    def test_blocks_until_slow_workers_actually_finish(self):
        # Regression for F4: the old busy-wait (`while not queue.empty()`)
        # could exit before slow in-flight items were done. queue.join()
        # must block for the full duration.
        finished_at = []

        def slow_worker(item):
            time.sleep(0.05)
            finished_at.append(time.time())
            return None

        start = time.time()
        threadpool.run_worker_pool([1, 2, 3], slow_worker, thread_count=1)
        elapsed = time.time() - start
        assert len(finished_at) == 3
        assert elapsed >= 0.15  # 3 items * 0.05s sequentially on 1 thread

    def test_worker_exception_does_not_crash_the_pool(self):
        def flaky_worker(item):
            if item == 2:
                raise ValueError("boom")
            return item

        results = threadpool.run_worker_pool([1, 2, 3], flaky_worker, thread_count=4)
        assert sorted(results) == [1, 3]

    def test_empty_work_items(self):
        assert threadpool.run_worker_pool([], lambda item: item, thread_count=4) == []

    def test_keyboard_interrupt_raises_with_partial_results(self, monkeypatch):
        # Regression: KeyboardInterrupt used to re-raise past work_queue.join(),
        # skipping the caller's (nes.py/enum.py) own "N found" summary panel -
        # the single most common way an operator actually stops a long scan.
        # Now it logs a warning, attaches the partial results, and propagates it,
        # so the caller can print the summary before exiting with 130.
        import queue as queue_module

        real_join = queue_module.Queue.join
        call_count = {"n": 0}

        def _join_then_interrupt(self):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise KeyboardInterrupt
            return real_join(self)

        monkeypatch.setattr(queue_module.Queue, "join", _join_then_interrupt)

        with pytest.raises(KeyboardInterrupt) as exc_info:
            threadpool.run_worker_pool([1, 2, 3], lambda item: item, thread_count=2)
        assert hasattr(exc_info.value, "results")
        assert set(exc_info.value.results).issubset({1, 2, 3})


class TestPromptYesNo:
    def test_eof_on_stdin_defaults_to_no(self, monkeypatch):
        def raise_eof():
            raise EOFError

        monkeypatch.setattr(threadpool, "_read_single_char", raise_eof)
        assert threadpool.prompt_yes_no("continue?") is False

    def test_y_answer(self, monkeypatch):
        monkeypatch.setattr(threadpool, "_read_single_char", lambda: "y")
        assert threadpool.prompt_yes_no("continue?") is True

    def test_uppercase_y_answer(self, monkeypatch):
        monkeypatch.setattr(threadpool, "_read_single_char", lambda: "Y")
        assert threadpool.prompt_yes_no("continue?") is True

    def test_n_answer(self, monkeypatch):
        monkeypatch.setattr(threadpool, "_read_single_char", lambda: "n")
        assert threadpool.prompt_yes_no("continue?") is False

    def test_unrecognized_answer_defaults_to_no(self, monkeypatch):
        monkeypatch.setattr(threadpool, "_read_single_char", lambda: "m")
        assert threadpool.prompt_yes_no("continue?") is False


class TestReadSingleCharUsesCbreak:
    def test_source_uses_setcbreak_not_setraw(self):
        # Regression: commit de6c69d's message claimed a switch from
        # tty.setraw() to tty.setcbreak() (setraw() disables output
        # post-processing too, which produced doubled/misaligned "y" output
        # on a real terminal), but the code was never actually changed.
        # This asserts the fix is genuinely present, not just described.
        source = inspect.getsource(threadpool._read_single_char)
        assert "tty.setcbreak(fd)" in source
        assert "tty.setraw(fd)" not in source


class TestConfirmBulkRun:
    def test_declining_raises_system_exit_zero(self, monkeypatch):
        monkeypatch.setattr(threadpool, "prompt_yes_no", lambda message: False)
        with pytest.raises(SystemExit) as exc_info:
            threadpool.confirm_bulk_run(5, "user IDs", 2, 10)
        assert exc_info.value.code == 0

    def test_accepting_returns_without_raising(self, monkeypatch):
        monkeypatch.setattr(threadpool, "prompt_yes_no", lambda message: True)
        threadpool.confirm_bulk_run(5, "user IDs", 2, 10)  # must not raise

    def test_message_includes_all_counts_and_label(self, monkeypatch):
        captured = {}

        def fake_prompt(message):
            captured["message"] = message
            return True

        monkeypatch.setattr(threadpool, "prompt_yes_no", fake_prompt)
        threadpool.confirm_bulk_run(5, "user IDs", 2, 10)
        assert "5 user IDs" in captured["message"]
        assert "2 target network" in captured["message"]
        assert "10 packets" in captured["message"]
