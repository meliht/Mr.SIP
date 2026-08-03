"""
Static sanity checks on the SIP message templates (src/data/method/*.message).

These don't send anything - they catch structurally malformed templates
(like F21: an unclosed '<' in a From header, which produced messages a
strict SIP parser like PJSIP silently drops with a "syntax error") before
they ever reach a real server. A live send never surfaces this class of bug
on the client side, since SIP-DAS's flood mode doesn't wait for a response -
it's only visible in the *target's* logs, so a static check here is the
only thing that catches it in CI.
"""

from pathlib import Path

import pytest

from src.core import net_utils

TEMPLATE_DIR = Path(net_utils.METHOD_DIR)
TEMPLATES = sorted(TEMPLATE_DIR.glob("*.message"))


@pytest.mark.parametrize("template", TEMPLATES, ids=lambda p: p.name)
def test_angle_brackets_are_balanced_per_line(template):
    # Regression for F21: `<sip:...;tag=...` (missing closing '>') is
    # invalid per RFC 3261 Section 25.1's name-addr grammar.
    for lineno, line in enumerate(template.read_text().splitlines(), start=1):
        assert line.count("<") == line.count(">"), (
            f"{template.name}:{lineno}: unbalanced angle brackets: {line!r}"
        )


@pytest.mark.parametrize("template", TEMPLATES, ids=lambda p: p.name)
def test_cseq_method_matches_request_line(template):
    # Regression for F7: cancel.message's CSeq once said "INVITE" instead
    # of "CANCEL" (RFC 3261 Section 9.1 requires them to match).
    lines = template.read_text().splitlines()
    request_method = lines[0].split(" ", 1)[0].upper()
    cseq_lines = [line for line in lines if line.upper().startswith("CSEQ:")]
    assert cseq_lines, f"{template.name} has no CSeq header"
    cseq_method = cseq_lines[0].split()[-1].upper()
    assert cseq_method == request_method, (
        f"{template.name}: CSeq method {cseq_method!r} does not match request line method {request_method!r}"
    )


def test_all_expected_templates_exist():
    names = {t.name for t in TEMPLATES}
    for expected in ("options", "invite", "register", "subscribe", "cancel", "bye", "sp-invite"):
        assert f"{expected}.message" in names


@pytest.mark.parametrize("template", TEMPLATES, ids=lambda p: p.name)
def test_content_length_matches_the_static_body(template):
    # Regression: invite.message declared Content-Length: 607 but its real
    # SDP body (LF line endings, as actually sent - sip_packet.py never
    # converts template line endings to CRLF) is 585 bytes. Same invisible-
    # from-a-live-send class of bug as F21 above: a strict SIP parser could
    # reject or misparse the message, but DAS's flood mode never waits for a
    # response, so it's only visible in the target's own logs. Only checked
    # for templates whose body has no [[placeholder]] tokens - a
    # placeholder's substituted length varies per call, so Content-Length
    # can't be statically verified for those (none currently have any).
    text = template.read_text()
    if "\n\n" not in text:
        return
    header, body = text.split("\n\n", 1)
    content_length_lines = [line for line in header.splitlines() if line.lower().startswith("content-length:")]
    assert content_length_lines, f"{template.name} has no Content-Length header"
    declared = int(content_length_lines[0].split(":", 1)[1].strip())
    if declared == 0:
        # Trailing blank lines in the file itself (not real message content)
        # are common and harmless here - only a genuinely non-empty body
        # after a declared 0 is the bug this test is for.
        assert body.strip() == "", f"{template.name}: Content-Length: 0 but body isn't empty: {body!r}"
        return
    if "[[" in body:
        return
    actual = len(body.encode("utf-8"))
    assert declared == actual, (
        f"{template.name}: Content-Length says {declared}, real body is {actual} bytes"
    )
