"""
Property-based fuzz tests (hypothesis) for every function that parses
untrusted input: CLI argparse validators, SIP packet templating, SIP
response parsing (the network-facing attack surface - a hostile or
compromised target could send back adversarial bytes), and wordlist file
reading. Each class here is a permanent regression test for a real bug
found during a dedicated fuzzing pass; example counts are kept modest
(200-500) to stay CI-fast, unlike the pass itself which ran 2000-3000
examples per function to actually find the bugs below.
"""

import argparse
import contextlib
import io
import os
import tempfile

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

from src.cli import build_parser
from src.core import errors, net_utils
from src.core.sip_packet import sip_packet

_SETTINGS = settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])


class TestCheckIpAddressFuzz:
    @given(st.text(min_size=0, max_size=100))
    @_SETTINGS
    def test_never_raises_anything_but_argument_type_error(self, s):
        # Regression: a value with more than one "/" (e.g. "1.2.3.4/24/x")
        # crashed check_ip_address with an unhandled ValueError from
        # `ip, subnet = value.split("/")` unpacking 3+ parts into 2 names.
        with contextlib.suppress(argparse.ArgumentTypeError):
            net_utils.check_ip_address(s)

    def test_multiple_slashes_raise_clean_error_not_valueerror(self):
        with pytest.raises(argparse.ArgumentTypeError):
            net_utils.check_ip_address("1.2.3.4/24/extra")


class TestPositiveIntAndPortNumberFuzz:
    @given(st.text(min_size=0, max_size=50))
    @_SETTINGS
    def test_positive_int_never_raises_anything_but_argument_type_error(self, s):
        with contextlib.suppress(argparse.ArgumentTypeError):
            net_utils.positive_int(s)

    @given(st.text(min_size=0, max_size=50))
    @_SETTINGS
    def test_port_number_never_raises_anything_but_argument_type_error(self, s):
        with contextlib.suppress(argparse.ArgumentTypeError):
            net_utils.port_number(s)

    def test_port_number_rejects_out_of_range(self):
        # Regression: --dp had no range check, so socket.connect() raised
        # a raw OverflowError deep inside generate_packet() for a port
        # outside 0-65535 instead of a clean CLI error.
        with pytest.raises(argparse.ArgumentTypeError):
            net_utils.port_number("99999999")
        with pytest.raises(argparse.ArgumentTypeError):
            net_utils.port_number("-5")
        assert net_utils.port_number("5060") == 5060

    @given(st.text(min_size=0, max_size=50))
    @_SETTINGS
    def test_positive_float_never_raises_anything_but_argument_type_error(self, s):
        with contextlib.suppress(argparse.ArgumentTypeError):
            net_utils.positive_float(s)

    def test_positive_float_rejects_zero_and_negative(self):
        # --pps=0 would make the send loop's sleep-per-packet interval
        # infinite (1.0 / 0), hanging the run forever.
        with pytest.raises(argparse.ArgumentTypeError):
            net_utils.positive_float("0")
        with pytest.raises(argparse.ArgumentTypeError):
            net_utils.positive_float("-1.5")
        assert net_utils.positive_float("2.5") == 2.5


class TestFillPacketDataFuzz:
    @given(
        from_user=st.text(alphabet=st.characters(min_codepoint=0, max_codepoint=0x10FFFF), max_size=60),
        to_user=st.text(alphabet=st.characters(min_codepoint=0, max_codepoint=0x10FFFF), max_size=60),
    )
    @_SETTINGS
    def test_never_raises_regardless_of_unicode_content(self, from_user, to_user):
        pkt = sip_packet("options", "1.2.3.4", 5060, "10.0.0.1", from_user=from_user, to_user=to_user)
        pkt.fill_packet_data("From: [[from_user]]\r\nTo: [[to_user]]\r\n")

    def test_lone_surrogate_does_not_crash_encoding(self):
        # Regression: a CLI argument containing invalid-UTF-8 bytes is
        # decoded via argv's errors="surrogateescape", producing a lone
        # surrogate character in the resulting str. fill_packet_data()'s
        # final .encode("utf-8") used to raise UnicodeEncodeError on it.
        pkt = sip_packet("options", "1.2.3.4", 5060, "10.0.0.1", from_user="\udcff\udcfe")
        result = pkt.fill_packet_data("From: [[from_user]]")
        assert b"\xed\xb3\xbf" not in result  # the raw surrogate bytes must not appear
        result.decode("utf-8")  # must not raise


class TestGetResponseFuzz:
    @given(st.text(min_size=0, max_size=300))
    @_SETTINGS
    def test_random_text_never_raises(self, resp):
        # getResponse() parses whatever bytes a target sends back - a
        # hostile or compromised SIP server is untrusted input, same as any
        # other network-facing parser.
        pkt = sip_packet("options", "1.2.3.4", 5060, "10.0.0.1")
        pkt.getResponse(resp)

    @given(
        status_line=st.text(max_size=40),
        headers=st.lists(st.text(max_size=60), max_size=8),
        body=st.text(max_size=100),
        sep=st.sampled_from(["\r\n", "\n", "\r"]),
    )
    @_SETTINGS
    def test_sip_shaped_garbage_never_raises(self, status_line, headers, body, sep):
        pkt = sip_packet("options", "1.2.3.4", 5060, "10.0.0.1")
        resp = sep.join([status_line, *headers, "", body])
        pkt.getResponse(resp)


class TestReadLinesFuzz:
    @given(st.binary(min_size=0, max_size=300))
    @settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large, HealthCheck.function_scoped_fixture])
    def test_arbitrary_binary_never_raises_anything_but_mrsiperror(self, data):
        fd, path = tempfile.mkstemp()
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            with contextlib.suppress(errors.MrSipError):
                net_utils.read_lines(path)
            with contextlib.suppress(errors.MrSipError):
                net_utils.read_ip_list(path)
        finally:
            os.unlink(path)

    def test_invalid_utf8_file_raises_clean_error_not_unicodedecodeerror(self):
        # Regression: a wordlist file that isn't valid UTF-8 (binary file
        # pointed at by mistake, Latin-1/Windows-1252 content, ...) crashed
        # with a raw UnicodeDecodeError instead of the clean CLI error every
        # other bad-input case gets.
        fd, path = tempfile.mkstemp()
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(b"1000\n1001\n\xff\xfe\x00garbage\n")
            with pytest.raises(errors.MrSipError):
                net_utils.read_lines(path)
        finally:
            os.unlink(path)


class TestCliArgvFuzz:
    _FLAGS = [
        "--nes", "--enum", "--das", "--tn", "--mt", "--dp", "--to", "--from",
        "--su", "--ua", "--il", "--if", "--tc", "--mtu", "--pps", "-v", "-i", "-c",
        "-l", "-r", "-m", "-s", "--version",
    ]

    @given(st.lists(
        st.one_of(st.sampled_from(_FLAGS), st.text(max_size=20), st.integers(min_value=-10**9, max_value=10**9).map(str)),
        max_size=10,
    ))
    @settings(max_examples=500, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])
    def test_arbitrary_argv_never_raises_anything_but_systemexit(self, argv):
        with (
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
            contextlib.suppress(SystemExit),
        ):
            build_parser().parse_args(argv)
