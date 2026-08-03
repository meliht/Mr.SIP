import pytest

from src.core import errors
from src.core.sip_packet import _read_template, sip_packet


class TestFillPacketData:
    def test_substitutes_all_placeholders(self):
        pkt = sip_packet(
            "options", "192.168.1.1", 5060, "10.0.0.1",
            from_user="1000", to_user="1001", user_agent="TestUA", sp_user="2000",
        )
        text = pkt.fill_packet_data(
            "[[server_ip]] [[server_port]] [[client_ip]] [[from_user]] [[to_user]] "
            "[[user_agent]] [[sp_user]] [[call_id]] [[branch_value]] [[tag_value]]"
        ).decode("utf-8")
        assert "[[" not in text
        assert "192.168.1.1" in text
        assert "1000" in text
        assert "1001" in text
        assert "TestUA" in text

    def test_strips_crlf_from_user_controlled_fields(self):
        # Regression for the CRLF/header-injection fix: a malicious --from
        # value must not be able to inject extra SIP headers.
        pkt = sip_packet(
            "options", "192.168.1.1", 5060, "10.0.0.1",
            from_user="attacker\r\nX-Injected: evil",
        )
        text = pkt.fill_packet_data("From: [[from_user]]").decode("utf-8")
        assert "\r\n" not in text
        assert "X-Injected" in text  # content survives, just not as a real header line
        assert text.count("\n") == 0

    def test_placeholder_shaped_value_is_not_re_substituted(self):
        # Regression: fill_packet_data() used to apply each substitution via
        # a sequential text.replace(key, value) over the same accumulating
        # string. If an earlier-processed field's value (from_user) happened
        # to contain the literal text of a later-processed placeholder
        # ("[[call_id]]"), that literal text got overwritten a second time
        # by the later placeholder's real substitution - silently corrupting
        # an unrelated field instead of preserving the literal wordlist
        # content. Each placeholder in the original template must be
        # substituted exactly once, from the original text, not from
        # already-substituted output.
        pkt = sip_packet(
            "options", "192.168.1.1", 5060, "10.0.0.1",
            from_user="[[call_id]]", to_user="1001",
        )
        text = pkt.fill_packet_data("From: [[from_user]]\r\nCall-ID: [[call_id]]").decode("utf-8")
        from_line, call_id_line = text.split("\r\n")
        assert from_line == "From: [[call_id]]"
        assert from_line != call_id_line.replace("Call-ID:", "From:")

    def test_client_port_is_per_instance_not_shared(self):
        # Regression for F13: client_port used to be a class attribute,
        # so every packet shared the same source port for the process's
        # entire lifetime.
        ports = {
            sip_packet("options", "1.2.3.4", 5060, "10.0.0.1").client_port
            for _ in range(20)
        }
        assert len(ports) > 1, "client_port should vary per instance"


class TestGeneratePacket:
    def test_unsupported_protocol_raises_packet_send_error(self):
        pkt = sip_packet("options", "192.168.1.1", 5060, "10.0.0.1", protocol="carrier-pigeon")
        with pytest.raises(errors.PacketSendError, match="Unsupported protocol"):
            pkt.generate_packet()

    def test_missing_template_raises_template_not_found(self):
        pkt = sip_packet("this-method-does-not-exist", "192.168.1.1", 5060, "10.0.0.1")
        with pytest.raises(errors.TemplateNotFoundError):
            pkt.generate_packet()

    def test_missing_template_error_lists_available_methods_not_a_raw_path(self):
        # Regression: an unsupported/misspelled --mt used to surface as a
        # raw "[Errno 2] No such file or directory: '/full/local/path/...'"
        # - technically caught, not a traceback, but the message itself
        # leaked the local install path and gave no hint of a valid value.
        # --mt is free-text (custom *.message templates are supported), so
        # this can't be an argparse choices= validator.
        pkt = sip_packet("this-method-does-not-exist", "192.168.1.1", 5060, "10.0.0.1")
        with pytest.raises(errors.TemplateNotFoundError) as exc_info:
            pkt.generate_packet()
        message = str(exc_info.value)
        assert "this-method-does-not-exist" in message
        assert "Errno" not in message
        assert "/" not in message  # no leaked filesystem path
        assert "options" in message and "invite" in message

    def test_scapy_mtu_below_minimum_rejected(self):
        pkt = sip_packet("options", "192.168.1.1", 5060, "10.0.0.1", protocol="scapy", mtu=10)
        with pytest.raises(errors.PacketSendError, match="MTU size must be at least 68 bytes"):
            pkt.generate_packet()

    def test_scapy_mtu_zero_is_not_silently_treated_as_unset(self):
        # Regression: `if self.mtu:` treated 0 the same as "no --mtu given at
        # all" (both falsy), skipping the "at least 68 bytes" guard entirely
        # instead of rejecting it. Must use `is not None` to distinguish
        # "explicitly 0" from "unset".
        pkt = sip_packet("options", "192.168.1.1", 5060, "10.0.0.1", protocol="scapy", mtu=0)
        with pytest.raises(errors.PacketSendError, match="MTU size must be at least 68 bytes"):
            pkt.generate_packet()

    def test_real_bug_is_not_masked_as_packet_send_error(self):
        # Regression for F19: a genuine programming error (not a network
        # failure) must propagate as itself, not get wrapped into a
        # misleading PacketSendError.
        pkt = sip_packet("options", "127.0.0.1", 5060, "10.0.0.1", protocol="socket")
        pkt.client_port = "not-an-int"
        with pytest.raises(ValueError):
            pkt.generate_packet()


class TestReadTemplateCaching:
    def test_second_read_of_same_path_is_a_cache_hit_not_a_fresh_disk_read(self, tmp_path):
        # das.py's flood loop calls generate_packet() (and therefore
        # _read_template) up to ~1e8 times against the same handful of
        # template paths - this must not re-read the file from disk every
        # call. A changed-on-disk file after the first read proves the
        # second call came from cache, not a fresh open().
        f = tmp_path / "custom.message"
        f.write_text("original content")
        _read_template.cache_clear()
        first = _read_template(str(f))
        f.write_text("changed content")
        second = _read_template(str(f))
        assert first == second == "original content"
        assert _read_template.cache_info().hits == 1

    def test_missing_template_still_raises_on_every_call(self, tmp_path):
        # functools.cache must not cache an exception - a missing template
        # should keep raising, not succeed after some earlier failure.
        missing = tmp_path / "does-not-exist.message"
        _read_template.cache_clear()
        with pytest.raises(OSError):
            _read_template(str(missing))
        with pytest.raises(OSError):
            _read_template(str(missing))


class TestGetResponse:
    def test_parses_status_line_and_headers(self):
        pkt = sip_packet("options", "1.2.3.4", 5060, "10.0.0.1")
        raw = (
            "SIP/2.0 200 OK\r\n"
            "Via: SIP/2.0/UDP 10.0.0.1:5060\r\n"
            "From: <sip:1000@10.0.0.1>;tag=abc\r\n"
            "To: <sip:1001@1.2.3.4>\r\n"
            "\r\n"
        )
        result = pkt.getResponse(raw)
        assert result["code"] == 200
        assert result["headers"]["via"] == ["SIP/2.0/UDP 10.0.0.1:5060"]
        assert "from" in result["headers"]

    def test_non_numeric_status_code_returns_partial_result(self):
        pkt = sip_packet("options", "1.2.3.4", 5060, "10.0.0.1")
        raw = "SIP/2.0 NOTACODE Something\r\nVia: x\r\n\r\n"
        result = pkt.getResponse(raw)
        assert "code" not in result

    def test_parses_status_line_without_headers(self):
        pkt = sip_packet("options", "1.2.3.4", 5060, "10.0.0.1")
        raw = "SIP/2.0 200 OK"
        result = pkt.getResponse(raw)
        assert result["code"] == 200
        assert result["headers"] == {}
        assert result["body"] == ""

    def test_parses_status_line_without_description(self):
        pkt = sip_packet("options", "1.2.3.4", 5060, "10.0.0.1")
        raw = "SIP/2.0 401"
        result = pkt.getResponse(raw)
        assert result["code"] == 401
        assert result["headers"] == {}
        assert result["body"] == ""
