import sys

from src.core import theme


class TestSupportsColor:
    def test_no_color_env_disables_even_on_a_tty(self, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
        assert theme.supports_color() is False

    def test_non_tty_disables_when_no_color_is_unset(self, monkeypatch):
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
        assert theme.supports_color() is False

    def test_tty_enables_when_no_color_is_unset(self, monkeypatch):
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
        assert theme.supports_color() is True


class TestColorize:
    def test_wraps_text_when_color_supported(self, monkeypatch):
        monkeypatch.setattr(theme, "supports_color", lambda: True)
        result = theme.colorize("hello", theme.SUCCESS)
        assert result == f"{theme.SUCCESS}hello{theme.RESET}"

    def test_returns_plain_text_when_color_disabled(self, monkeypatch):
        monkeypatch.setattr(theme, "supports_color", lambda: False)
        assert theme.colorize("hello", theme.SUCCESS) == "hello"


class TestStripAnsi:
    def test_removes_escape_codes(self):
        colored = f"{theme.SUCCESS}{theme.BOLD}hello{theme.RESET}"
        assert theme.strip_ansi(colored) == "hello"

    def test_leaves_plain_text_untouched(self):
        assert theme.strip_ansi("plain text") == "plain text"


class TestPanel:
    def test_plain_fallback_when_color_disabled(self, monkeypatch):
        monkeypatch.setattr(theme, "supports_color", lambda: False)
        rendered = theme.panel("Title", ["line one", "line two"])
        assert rendered == "Title\nline one\nline two"

    def test_boxed_output_when_color_enabled(self, monkeypatch):
        monkeypatch.setattr(theme, "supports_color", lambda: True)
        rendered = theme.panel("Title", ["a line"])
        assert theme.strip_ansi(rendered).count("\n") == 3  # top, header, body, bottom
        assert "Title" in rendered
        assert "a line" in rendered

    def test_panel_with_no_body_lines(self, monkeypatch):
        monkeypatch.setattr(theme, "supports_color", lambda: True)
        rendered = theme.panel("Only a title", [])
        assert "Only a title" in theme.strip_ansi(rendered)
