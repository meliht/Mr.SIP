import argparse
import logging

import pytest

from src.core import errors, net_utils


class TestExpandTargetNetwork:
    def test_expand_single_ip(self):
        assert net_utils.expand_target_network("192.168.1.1") == ["192.168.1.1"]

    def test_expand_range(self):
        assert net_utils.expand_target_network("192.168.1.1-192.168.1.3") == ["192.168.1.1", "192.168.1.2", "192.168.1.3"]

    def test_expand_range_reversed_raises(self):
        # errors.MrSipError specifically, not a bare ValueError - a caller
        # that doesn't pass value_errors (the only other outcome) must still
        # get an exception cli.main()'s own handler recognizes, not one that
        # would crash with a raw traceback if ever left uncaught upstream.
        with pytest.raises(errors.MrSipError, match="must be bigger than"):
            net_utils.expand_target_network("192.168.1.3-192.168.1.1")

    def test_expand_range_with_value_errors(self):
        errors_list = []
        result = net_utils.expand_target_network("192.168.1.3-192.168.1.1", errors_list)
        assert result == []
        assert len(errors_list) == 1
        assert "must be bigger than" in errors_list[0]

    def test_expand_cidr_slash_30(self):
        # /30 net has 4 addresses, hosts() returns the 2 usable hosts
        assert net_utils.expand_target_network("192.168.1.0/30") == ["192.168.1.1", "192.168.1.2"]

    def test_expand_cidr_slash_32(self):
        assert net_utils.expand_target_network("192.168.1.1/32") == ["192.168.1.1"]


class TestCheckIpAddress:
    def test_valid_single_ip(self):
        assert net_utils.check_ip_address("192.168.1.1") == "192.168.1.1"

    def test_invalid_single_ip_not_dotted(self):
        with pytest.raises(argparse.ArgumentTypeError):
            net_utils.check_ip_address("not-an-ip")

    def test_invalid_single_ip_octet_out_of_range(self):
        with pytest.raises(argparse.ArgumentTypeError):
            net_utils.check_ip_address("999.1.1.1")

    def test_invalid_single_ip_wrong_octet_count(self):
        with pytest.raises(argparse.ArgumentTypeError):
            net_utils.check_ip_address("1.2.3")

    def test_valid_range(self):
        assert net_utils.check_ip_address("127.0.0.1-127.0.0.5") == "127.0.0.1-127.0.0.5"

    def test_invalid_range_bad_first_ip(self):
        # F: the range validator must check BOTH sides, not just the first.
        with pytest.raises(argparse.ArgumentTypeError):
            net_utils.check_ip_address("not-an-ip-127.0.0.5")

    def test_invalid_range_bad_second_ip(self):
        with pytest.raises(argparse.ArgumentTypeError):
            net_utils.check_ip_address("127.0.0.1-not-an-ip")

    @pytest.mark.parametrize("mask", [8, 16, 24, 32])
    def test_valid_cidr_within_widened_range(self, mask):
        # /8-/32 was widened from the original /24-only limitation.
        assert net_utils.check_ip_address(f"10.0.0.0/{mask}") == f"10.0.0.0/{mask}"

    def test_cidr_mask_below_8_rejected(self):
        with pytest.raises(argparse.ArgumentTypeError):
            net_utils.check_ip_address("10.0.0.0/7")

    def test_cidr_mask_above_32_rejected(self):
        with pytest.raises(argparse.ArgumentTypeError):
            net_utils.check_ip_address("10.0.0.0/33")

    def test_cidr_non_numeric_mask_rejected(self):
        with pytest.raises(argparse.ArgumentTypeError):
            net_utils.check_ip_address("10.0.0.0/abc")

    def test_cidr_non_numeric_mask_has_no_chained_traceback(self):
        # Regression for the B904 fix: this is a deliberate translation into
        # a clean CLI error, not a wrapped/propagated one.
        with pytest.raises(argparse.ArgumentTypeError) as exc_info:
            net_utils.check_ip_address("10.0.0.0/abc")
        assert exc_info.value.__cause__ is None

    def test_plain_ip_non_numeric_octet_raises_clean_error_not_valueerror(self):
        # Regression: the plain-IP and range branches used to call bare
        # int(number) with no try/except, unlike the CIDR branch - a
        # non-numeric octet raised an unguarded ValueError instead of the
        # intended ArgumentTypeError. _validate_dotted_quad() unifies this.
        with pytest.raises(argparse.ArgumentTypeError):
            net_utils.check_ip_address("1.2.3.a")

    def test_range_non_numeric_octet_raises_clean_error_not_valueerror(self):
        with pytest.raises(argparse.ArgumentTypeError):
            net_utils.check_ip_address("1.2.3.a-1.2.3.5")


class TestPositiveInt:
    def test_accepts_positive_values(self):
        assert net_utils.positive_int("10") == 10
        assert net_utils.positive_int("1") == 1

    def test_rejects_zero(self):
        # Regression: threadpool.run_worker_pool() starts range(thread_count)
        # worker threads - 0 (or negative) means no thread ever drains the
        # queue, hanging the run forever. This must be rejected at parse time.
        with pytest.raises(argparse.ArgumentTypeError):
            net_utils.positive_int("0")

    def test_rejects_negative(self):
        with pytest.raises(argparse.ArgumentTypeError):
            net_utils.positive_int("-1")

    def test_rejects_non_numeric(self):
        with pytest.raises(argparse.ArgumentTypeError):
            net_utils.positive_int("not-a-number")


class TestNonNegativeInt:
    def test_accepts_zero_and_positive_values(self):
        assert net_utils.non_negative_int("0") == 0
        assert net_utils.non_negative_int("10") == 10

    def test_rejects_negative(self):
        # Regression: das.py's `while infinite or i < counter` sends 0
        # packets for a negative counter instead of erroring - a negative
        # -c/--count must be rejected at parse time, not silently no-op.
        with pytest.raises(argparse.ArgumentTypeError):
            net_utils.non_negative_int("-1")

    def test_rejects_non_numeric(self):
        with pytest.raises(argparse.ArgumentTypeError):
            net_utils.non_negative_int("not-a-number")


class TestMtuSize:
    def test_accepts_minimum_and_above(self):
        assert net_utils.mtu_size("68") == 68
        assert net_utils.mtu_size("1500") == 1500

    def test_rejects_below_minimum(self):
        with pytest.raises(argparse.ArgumentTypeError):
            net_utils.mtu_size("67")

    def test_rejects_zero(self):
        with pytest.raises(argparse.ArgumentTypeError):
            net_utils.mtu_size("0")

    def test_rejects_negative(self):
        with pytest.raises(argparse.ArgumentTypeError):
            net_utils.mtu_size("-1")

    def test_rejects_non_numeric(self):
        with pytest.raises(argparse.ArgumentTypeError):
            net_utils.mtu_size("jumbo")


class TestProbeLiveness:
    def test_returns_response_dict_when_target_answers(self, monkeypatch):
        def mock_generate_packet(self):
            return {"status": True, "response": {"code": 200, "headers": {}, "body": ""}}

        monkeypatch.setattr(net_utils.sip_packet.sip_packet, "generate_packet", mock_generate_packet)

        result = net_utils.probe_liveness("127.0.0.1", 5060, "10.0.0.1")
        assert result == {"status": True, "response": {"code": 200, "headers": {}, "body": ""}}

    def test_returns_none_when_target_does_not_respond(self, monkeypatch):
        from src.core import errors

        def mock_generate_packet(self):
            raise errors.PacketSendError("timed out")

        monkeypatch.setattr(net_utils.sip_packet.sip_packet, "generate_packet", mock_generate_packet)

        assert net_utils.probe_liveness("127.0.0.1", 5060, "10.0.0.1") is None

    def test_uses_a_short_timeout_by_default(self, monkeypatch):
        # The whole point of probe_liveness vs. a normal probe is a much
        # shorter default timeout (2s) than sip_packet's own 5s default.
        captured = {}

        def mock_generate_packet(self):
            captured["timeout"] = self.timeout
            return {"status": True, "response": {"code": 200, "headers": {}, "body": ""}}

        monkeypatch.setattr(net_utils.sip_packet.sip_packet, "generate_packet", mock_generate_packet)

        net_utils.probe_liveness("127.0.0.1", 5060, "10.0.0.1")
        assert captured["timeout"] == 2
        assert captured["timeout"] < 5


class TestPromisc:
    def test_non_linux_skips_without_calling_subprocess(self, monkeypatch):
        monkeypatch.setattr(net_utils.sys, "platform", "darwin")
        called = []
        monkeypatch.setattr(net_utils.subprocess, "run", lambda *a, **k: called.append(a))
        net_utils.promisc("on", "en0")
        assert called == []

    def test_linux_nonzero_returncode_warns(self, monkeypatch, caplog):
        monkeypatch.setattr(net_utils.sys, "platform", "linux")

        class FakeResult:
            returncode = 1

        monkeypatch.setattr(net_utils.subprocess, "run", lambda *a, **k: FakeResult())
        with caplog.at_level(logging.WARNING):
            net_utils.promisc("on", "eth0")
        assert any("root permissions" in r.message for r in caplog.records)

    def test_linux_zero_returncode_does_not_warn(self, monkeypatch, caplog):
        monkeypatch.setattr(net_utils.sys, "platform", "linux")

        class FakeResult:
            returncode = 0

        monkeypatch.setattr(net_utils.subprocess, "run", lambda *a, **k: FakeResult())
        with caplog.at_level(logging.WARNING):
            net_utils.promisc("on", "eth0")
        assert not caplog.records


class TestPrintResult:
    def test_missing_headers_key_does_not_crash(self, tmp_path):
        # Regression: sip_packet.getResponse() can return {} (no "headers"
        # key at all) when the status line doesn't parse into 3 tokens.
        # printResult() used to index result["response"]["headers"]
        # unconditionally, raising KeyError.
        ip_list = tmp_path / "ip_list.txt"
        net_utils.printResult({"status": True, "response": {}}, "10.0.0.1", str(ip_list))

    def test_none_response_does_not_crash(self, tmp_path):
        # Regression: getResponse() falls through to an implicit `return
        # None` when the response has no headers past the status line at
        # all. printResult() used to crash with TypeError in that case.
        ip_list = tmp_path / "ip_list.txt"
        net_utils.printResult({"status": True, "response": None}, "10.0.0.1", str(ip_list))

    def test_valid_response_still_records_the_host(self, tmp_path):
        ip_list = tmp_path / "ip_list.txt"
        result = {
            "status": True,
            "response": {"code": 200, "headers": {"user-agent": ["Asterisk PBX"]}},
        }
        net_utils.printResult(result, "10.0.0.1", str(ip_list))
        assert "10.0.0.1;Asterisk PBX;SIP Server" in ip_list.read_text()

    def test_same_target_found_twice_this_run_is_not_written_twice(self, tmp_path):
        # F27 regression: previously relied on a full-file dedup pass after
        # every write; the in-memory-set replacement must still produce a
        # dedup'd file, not just a faster one.
        ip_list = tmp_path / "ip_list.txt"
        result = {
            "status": True,
            "response": {"code": 200, "headers": {"user-agent": ["Asterisk PBX"]}},
        }
        net_utils.printResult(result, "10.0.0.1", str(ip_list))
        net_utils.printResult(result, "10.0.0.1", str(ip_list))
        lines = ip_list.read_text().splitlines()
        assert lines.count("10.0.0.1;Asterisk PBX;SIP Server") == 1

    def test_target_already_present_from_a_prior_run_is_not_duplicated(self, tmp_path):
        # The in-memory cache is loaded from any pre-existing file content
        # the first time a given output path is touched, so a target left
        # over from an earlier SIP-NES run (same -i path) doesn't get a
        # second, duplicate line this run either.
        ip_list = tmp_path / "ip_list.txt"
        ip_list.write_text("10.0.0.1;Old-UA;SIP Server\n")
        result = {
            "status": True,
            "response": {"code": 200, "headers": {"user-agent": ["Asterisk PBX"]}},
        }
        net_utils.printResult(result, "10.0.0.1", str(ip_list))
        lines = ip_list.read_text().splitlines()
        assert lines == ["10.0.0.1;Old-UA;SIP Server"]

    def test_directory_given_as_output_path_raises_clean_error_not_traceback(self, tmp_path):
        # Regression: -i pointing at a directory (instead of a file) used to
        # crash with a raw IsADirectoryError traceback mid-scan - both on
        # the read side (_load_existing_targets) and the write side
        # (writeFile), depending on which ran first.
        result = {
            "status": True,
            "response": {"code": 200, "headers": {"user-agent": ["Asterisk PBX"]}},
        }
        with pytest.raises(errors.MrSipError, match="Could not read"):
            net_utils.printResult(result, "10.0.0.1", str(tmp_path))

    def test_unwritable_output_path_raises_clean_error_not_traceback(self, tmp_path):
        readonly_dir = tmp_path / "readonly"
        readonly_dir.mkdir(mode=0o555)
        result = {
            "status": True,
            "response": {"code": 200, "headers": {"user-agent": ["Asterisk PBX"]}},
        }
        try:
            with pytest.raises(errors.MrSipError, match="Could not write"):
                net_utils.printResult(result, "10.0.0.1", str(readonly_dir / "ip_list.txt"))
        finally:
            readonly_dir.chmod(0o755)


class TestRandomIpHelpers:
    def test_random_ip_address_format(self):
        ip = net_utils.randomIPAddress()
        octets = ip.split(".")
        assert len(octets) == 4
        for octet in octets:
            assert 1 <= int(octet) <= 254

    def test_random_ip_from_network_stays_within_subnet(self):
        for _ in range(20):
            ip = net_utils.randomIPAddressFromNetwork("10.0.0.0", "255.255.255.0", False)
            assert ip.startswith("10.0.0.")


def test_decimal_to_octets_round_trip():
    import ipaddress

    decimal = int(ipaddress.IPv4Address("192.168.1.1"))
    assert net_utils.decimal_to_octets(decimal) == "192.168.1.1"


class TestDefineTargetType:
    def test_known_server_vendor_classified_as_server(self):
        assert net_utils.defineTargetType("Asterisk PBX 22.10.1") == "Server"

    def test_unknown_user_agent_classified_as_client(self):
        assert net_utils.defineTargetType("Totally Unknown Softphone 1.0") == "Client"


class TestReadLines:
    def test_strips_and_drops_blank_lines(self, tmp_path):
        f = tmp_path / "words.txt"
        f.write_text("1000\n\n1001\n   \n1002\n")
        assert net_utils.read_lines(str(f)) == ["1000", "1001", "1002"]

    def test_predicate_filters_lines(self, tmp_path):
        f = tmp_path / "words.txt"
        f.write_text("1000\nnot-alnum!\n1001\n")
        assert net_utils.read_lines(str(f), predicate=str.isalnum) == ["1000", "1001"]

    def test_no_predicate_keeps_non_alnum_user_agent_style_lines(self, tmp_path):
        # Regression: unifying wordlist reading must NOT apply the isalnum
        # filter to user-agent-style lines - they contain spaces/slashes/dots
        # and would be silently emptied, breaking DAS's User-Agent rotation.
        f = tmp_path / "userAgent.txt"
        f.write_text("Brcm Callctrl/1.5.1.0 MxSF/v3.2.6.26\nAsterisk PBX\n")
        result = net_utils.read_lines(str(f))
        assert "Brcm Callctrl/1.5.1.0 MxSF/v3.2.6.26" in result
        assert "Asterisk PBX" in result

    def test_bundled_user_agent_wordlist_survives_unfiltered(self):
        # Same regression, against the real bundled file.
        lines = net_utils.read_lines(str(net_utils.WORDLISTS_DIR / "userAgent.txt"))
        assert len(lines) > 0
        assert not all(line.isalnum() for line in lines)

    def test_directory_given_instead_of_a_file_raises_clean_error(self, tmp_path):
        # Regression: a --from/--to/--su/--ua/--il value that's a directory
        # (an easy mistake - e.g. tab-completing to the wrong entry) used to
        # crash with a raw IsADirectoryError traceback, leaking the local
        # filesystem path, instead of the clean error every other bad-input
        # case gets.
        with pytest.raises(errors.MrSipError, match="Could not read"):
            net_utils.read_lines(str(tmp_path))

    def test_missing_file_still_propagates_as_file_not_found(self, tmp_path):
        # FileNotFoundError must keep propagating as-is - cli.main() has its
        # own specific "File not found: X" handler for it; read_lines()'s
        # broader OSError guard must not swallow it into a generic message.
        with pytest.raises(FileNotFoundError):
            net_utils.read_lines(str(tmp_path / "does-not-exist.txt"))


class TestReadIpList:
    def test_extracts_first_field_from_ip_user_agent_type_format(self, tmp_path):
        f = tmp_path / "ip_list.txt"
        f.write_text("192.168.1.1;Asterisk PBX;SIP Server\n192.168.1.2;Some Phone;SIP Client\n")
        assert net_utils.read_ip_list(str(f)) == ["192.168.1.1", "192.168.1.2"]

    def test_works_with_plain_one_ip_per_line_file(self, tmp_path):
        f = tmp_path / "ips.txt"
        f.write_text("10.0.0.1\n10.0.0.2\n")
        assert net_utils.read_ip_list(str(f)) == ["10.0.0.1", "10.0.0.2"]


class TestLargeNetworkWarning:
    def test_expand_target_network_warns_on_large_subnet(self, caplog):
        # A /15 subnet has 131,072 addresses, which is > 65536
        with caplog.at_level(logging.WARNING):
            net_utils.expand_target_network("10.0.0.0/15")
        assert any("significant memory" in r.message for r in caplog.records)

    def test_expand_target_network_warns_on_large_range(self, caplog):
        with caplog.at_level(logging.WARNING):
            net_utils.expand_target_network("10.0.0.1-10.1.1.1")
        assert any("significant memory" in r.message for r in caplog.records)
