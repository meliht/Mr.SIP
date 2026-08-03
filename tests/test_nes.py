import argparse
import logging

import pytest

from src.core import errors
from src.core.sip_packet import sip_packet
from src.modules import nes


class TestResolveUserPairs:
    def test_register_pairs_each_from_user_with_itself(self):
        # register.message/subscribe.message need to_user == from_user (see
        # F3 in CHANGELOG.md) - a blank/independent to_user produced an
        # invalid Request-URI that Asterisk silently dropped.
        args = argparse.Namespace(from_user="/some/list.txt", to_user="/other/list.txt")
        pairs = nes._resolve_user_pairs("register", ["1000", "1001"], ["9999"], args)
        assert pairs == [("1000", "1000"), ("1001", "1001")]

    def test_subscribe_also_pairs_with_itself(self):
        args = argparse.Namespace(from_user="/some/list.txt", to_user="/other/list.txt")
        pairs = nes._resolve_user_pairs("subscribe", ["2000"], ["9999"], args)
        assert pairs == [("2000", "2000")]

    def test_default_wordlists_collapse_to_single_probe(self):
        # Leaving --from/--to at their bundled 9000-line defaults must not
        # silently queue a 9000x9000 cross-product against one host.
        args = argparse.Namespace(from_user=nes._DEFAULT_FROM_USER, to_user=nes._DEFAULT_TO_USER)
        pairs = nes._resolve_user_pairs("options", ["1000", "1001", "1002"], ["8000", "8001"], args)
        assert pairs == [("1000", "8000")]

    def test_explicit_wordlists_get_full_cross_product(self):
        # An operator-supplied --from/--to (any size) opts back into the
        # deliberate identity-aware cross-product.
        args = argparse.Namespace(from_user="/custom/from.txt", to_user="/custom/to.txt")
        pairs = nes._resolve_user_pairs("invite", ["1000", "1001"], ["8000", "8001"], args)
        assert pairs == [
            ("1000", "8000"), ("1000", "8001"),
            ("1001", "8000"), ("1001", "8001"),
        ]

    def test_default_from_explicit_to_collapses_only_the_default_side(self):
        # F20 regression: leaving --from at its default while overriding
        # --to used to still cross-product against the full 9000-line
        # default --from wordlist (9 explicit --to values x 9000 default
        # --from = 81000 probes/target instead of the intended 9). Only the
        # side still at its own default collapses; the explicit side keeps
        # every value.
        args = argparse.Namespace(from_user=nes._DEFAULT_FROM_USER, to_user="/custom/to.txt")
        pairs = nes._resolve_user_pairs("options", ["1000", "1001"], ["8000", "8001"], args)
        assert pairs == [("1000", "8000"), ("1000", "8001")]

    def test_explicit_from_default_to_collapses_only_the_default_side(self):
        # Mirror case: --to left at default, --from explicit.
        args = argparse.Namespace(from_user="/custom/from.txt", to_user=nes._DEFAULT_TO_USER)
        pairs = nes._resolve_user_pairs("options", ["1000", "1001"], ["8000", "8001"], args)
        assert pairs == [("1000", "8000"), ("1001", "8000")]


class TestWarnIfExperimentalUserLists:
    def test_warns_when_multiple_pairs_from_a_real_file(self, tmp_path, caplog):
        from_file = tmp_path / "from.txt"
        from_file.write_text("1000\n1001\n")
        args = argparse.Namespace(from_user=str(from_file), to_user="8000")
        with caplog.at_level(logging.WARNING):
            nes._warn_if_experimental_user_lists([("1000", "8000"), ("1001", "8000")], args)
        assert any("experimental feature" in r.message for r in caplog.records)

    def test_no_warning_for_a_single_pair(self, tmp_path, caplog):
        from_file = tmp_path / "from.txt"
        from_file.write_text("1000\n")
        args = argparse.Namespace(from_user=str(from_file), to_user="8000")
        with caplog.at_level(logging.WARNING):
            nes._warn_if_experimental_user_lists([("1000", "8000")], args)
        assert not caplog.records

    def test_no_warning_when_neither_side_is_a_real_file(self, caplog):
        # Multiple pairs can also come from the deliberate cross-product
        # feature with literal (non-file) --from/--to values - that's not
        # the "gave a list of user names" case this warning is about.
        args = argparse.Namespace(from_user="1000", to_user="8000")
        with caplog.at_level(logging.WARNING):
            nes._warn_if_experimental_user_lists([("1000", "8000"), ("1001", "8000")], args)
        assert not caplog.records


class TestResolveTargetNetworks:
    def test_dash_range_expands_to_octet_list(self):
        args = argparse.Namespace(target_network="192.168.1.10-192.168.1.12", from_user="x", to_user="y")
        result = nes._resolve_target_networks(args, [("a", "b")], [])
        assert result == ["192.168.1.10", "192.168.1.11", "192.168.1.12"]

    def test_dash_range_reversed_records_an_error_and_returns_empty(self):
        args = argparse.Namespace(target_network="192.168.1.20-192.168.1.10", from_user="x", to_user="y")
        value_errors = []
        result = nes._resolve_target_networks(args, [("a", "b")], value_errors)
        assert result == []
        assert len(value_errors) == 1
        assert "must be bigger than" in value_errors[0]

    def test_cidr_slash_24_excludes_network_and_broadcast(self):
        args = argparse.Namespace(target_network="192.168.1.0/24", from_user="x", to_user="y")
        result = nes._resolve_target_networks(args, [("a", "b")], [])
        assert len(result) == 254
        assert "192.168.1.0" not in result
        assert "192.168.1.255" not in result

    def test_point_to_point_slash_31_keeps_both_addresses(self):
        args = argparse.Namespace(target_network="192.168.1.0/31", from_user="x", to_user="y")
        result = nes._resolve_target_networks(args, [("a", "b")], [])
        assert result == ["192.168.1.0", "192.168.1.1"]

    def test_single_target_single_pair_returns_empty(self):
        # The synchronous single-probe path in run() handles this case
        # directly - it doesn't need target_networks populated.
        args = argparse.Namespace(target_network="192.168.1.50", from_user="x", to_user="y")
        result = nes._resolve_target_networks(args, [("a", "b")], [])
        assert result == []

    def test_single_target_multiple_pairs_warns_and_keeps_target(self, caplog):
        args = argparse.Namespace(target_network="192.168.1.50", from_user="x", to_user="y")
        with caplog.at_level(logging.WARNING):
            result = nes._resolve_target_networks(args, [("a", "b"), ("c", "d")], [])
        assert result == ["192.168.1.50"]
        assert any("permutations" in r.message for r in caplog.records)


class TestNesRunSingleProbe:
    def test_missing_target_network_raises_clean_error(self):
        args = argparse.Namespace(
            target_network=None, message_type="options",
            from_user="1000", to_user="8000", response_timeout=None,
        )
        with pytest.raises(errors.MrSipError):
            nes.run(args, conf=argparse.Namespace(iface="lo0"), client_ip="10.0.0.1")

    def test_single_target_dispatches_synchronous_probe_and_reports_found(self, tmp_path, monkeypatch, caplog):
        def mock_generate_packet(self):
            return {"status": True, "response": {"code": 200, "headers": {}, "body": ""}}

        monkeypatch.setattr(sip_packet, "generate_packet", mock_generate_packet)

        args = argparse.Namespace(
            target_network="127.0.0.1", message_type="options",
            from_user="1000", to_user="8000", dest_port=5060,
            ip_list=str(tmp_path / "ip_list.txt"), response_timeout=5.0,
        )
        conf = argparse.Namespace(iface="lo0")

        with caplog.at_level(logging.INFO):
            nes.run(args, conf, client_ip="10.0.0.1")

        assert any("1 live IP address(es) found" in r.message for r in caplog.records)

    def test_bulk_confirm_subject_count_reflects_collapsed_identities(self, tmp_path, monkeypatch):
        # F20 fix follow-up: the "N user names will be checked" confirmation
        # text must match the identities actually probed after
        # _resolve_user_pairs() collapses the default side, not the raw
        # (thousands-of-lines) wordlist file length.
        from_file = tmp_path / "from.txt"
        from_file.write_text("1000\n1001\n1002\n")

        captured = {}

        def fake_confirm(subject_count, subject_label, target_count, packet_count, **kwargs):
            captured["subject_count"] = subject_count
            captured["packet_count"] = packet_count

        monkeypatch.setattr(nes.threadpool, "confirm_bulk_run", fake_confirm)
        monkeypatch.setattr(nes.threadpool, "run_worker_pool", lambda *a, **k: [])

        args = argparse.Namespace(
            target_network="127.0.0.1", message_type="options",
            from_user=str(from_file), to_user=nes._DEFAULT_TO_USER,
            dest_port=5060, ip_list=str(tmp_path / "ip_list.txt"),
            thread_count=1, response_timeout=5.0,
        )
        conf = argparse.Namespace(iface="lo0")

        nes.run(args, conf, client_ip="10.0.0.1")

        # 3 distinct from-values + 1 collapsed to-value = 4, not 3 plus the
        # real toUser.txt's actual (thousands-line) length.
        assert captured["subject_count"] == 4
        assert captured["packet_count"] == 3

    def test_single_target_reports_zero_on_packet_send_error(self, tmp_path, monkeypatch, caplog):
        def mock_generate_packet(self):
            raise errors.PacketSendError("timed out")

        monkeypatch.setattr(sip_packet, "generate_packet", mock_generate_packet)

        args = argparse.Namespace(
            target_network="127.0.0.1", message_type="options",
            from_user="1000", to_user="8000", dest_port=5060,
            ip_list=str(tmp_path / "ip_list.txt"), response_timeout=5.0,
        )
        conf = argparse.Namespace(iface="lo0")

        with caplog.at_level(logging.INFO):
            nes.run(args, conf, client_ip="10.0.0.1")

        assert any("0 live IP address(es) found" in r.message for r in caplog.records)

    def test_bulk_probe_counter_dedupes_by_host_not_by_probe(self, tmp_path, monkeypatch, caplog):
        # A single target answering every identity pair in a multi-entry
        # --from/--to cross-product used to be reported as "N live IP
        # address(es) found" (N = number of successful probes) instead of
        # "1" (the actual number of distinct live hosts) - counter was
        # len(found), and _scan_one() returns the host once per successful
        # probe, not once per host. Reproduced live against a mock target
        # answering all 9000 default-wordlist REGISTER probes: summary said
        # "9000 live IP address(es) found" for what -i's own deduplicated
        # output file correctly recorded as a single host.
        from_file = tmp_path / "from.txt"
        from_file.write_text("1000\n1001\n1002\n")

        monkeypatch.setattr(sip_packet, "generate_packet", lambda self: {"status": True})
        monkeypatch.setattr(nes.threadpool, "confirm_bulk_run", lambda *a, **k: None)

        args = argparse.Namespace(
            target_network="127.0.0.1", message_type="options",
            from_user=str(from_file), to_user=nes._DEFAULT_TO_USER,
            dest_port=5060, ip_list=str(tmp_path / "ip_list.txt"),
            thread_count=2, response_timeout=5.0,
        )
        conf = argparse.Namespace(iface="lo0")

        with caplog.at_level(logging.INFO):
            nes.run(args, conf, client_ip="10.0.0.1")

        # 3 identity pairs all probed the same single host successfully -
        # the summary must count 1 distinct live host, not 3 probes.
        assert any("1 live IP address(es) found" in r.message for r in caplog.records)
        assert not any("3 live IP address(es) found" in r.message for r in caplog.records)

    def test_bulk_probe_counter_still_counts_multiple_distinct_hosts(self, tmp_path, monkeypatch, caplog):
        # The set()-based dedup fix must not accidentally collapse genuinely
        # different hosts down to 1 - only same-host duplicates should merge.
        # 2 distinct targets (a /30 CIDR - net_utils.expand_target_network()
        # gives 2 usable host addresses) x 2 identity pairs each (explicit
        # --from, default --to) = 4 successful probes total, but only 2
        # distinct live hosts.
        from_file = tmp_path / "from.txt"
        from_file.write_text("1000\n1001\n")

        monkeypatch.setattr(sip_packet, "generate_packet", lambda self: {"status": True})
        monkeypatch.setattr(nes.threadpool, "confirm_bulk_run", lambda *a, **k: None)

        args = argparse.Namespace(
            target_network="10.0.0.0/30", message_type="options",
            from_user=str(from_file), to_user=nes._DEFAULT_TO_USER,
            dest_port=5060, ip_list=str(tmp_path / "ip_list.txt"),
            thread_count=2, response_timeout=5.0,
        )
        conf = argparse.Namespace(iface="lo0")

        with caplog.at_level(logging.INFO):
            nes.run(args, conf, client_ip="10.0.0.1")

        assert any("2 live IP address(es) found" in r.message for r in caplog.records)
        assert not any("4 live IP address(es) found" in r.message for r in caplog.records)
        assert not any("1 live IP address(es) found" in r.message for r in caplog.records)

    def test_keyboard_interrupt_summary_also_dedupes_partial_results(self, tmp_path, monkeypatch, caplog):
        # F49's fix touched two spots: the normal-completion path above, and
        # this one - the KeyboardInterrupt handler that logs its own partial
        # summary before re-raising (see threadpool.run_worker_pool()). Both
        # read from the same kind of list (host strings, once per successful
        # probe) and must dedupe the same way.
        def _raise_with_partial_results(*a, **k):
            exc = KeyboardInterrupt()
            exc.results = ["127.0.0.1", "127.0.0.1", "127.0.0.1"]
            raise exc

        monkeypatch.setattr(nes.threadpool, "run_worker_pool", _raise_with_partial_results)
        monkeypatch.setattr(nes.threadpool, "confirm_bulk_run", lambda *a, **k: None)

        from_file = tmp_path / "from.txt"
        from_file.write_text("1000\n1001\n1002\n")

        args = argparse.Namespace(
            target_network="127.0.0.1", message_type="options",
            from_user=str(from_file), to_user=nes._DEFAULT_TO_USER,
            dest_port=5060, ip_list=str(tmp_path / "ip_list.txt"),
            thread_count=2, response_timeout=5.0,
        )
        conf = argparse.Namespace(iface="lo0")

        with caplog.at_level(logging.INFO), pytest.raises(KeyboardInterrupt):
            nes.run(args, conf, client_ip="10.0.0.1")

        assert any("1 live IP address(es) found" in r.message for r in caplog.records)
        assert not any("3 live IP address(es) found" in r.message for r in caplog.records)

    def test_response_timeout_reaches_sip_packet_single_probe_path(self, tmp_path, monkeypatch):
        # --rt exists specifically so a large-range scan (mostly non-
        # responsive hosts) isn't stuck paying the full default timeout per
        # dead host per worker thread - confirm the value actually reaches
        # sip_packet, not just parsed and dropped.
        seen_timeouts = []
        real_init = sip_packet.__init__

        def _tracking_init(self, *a, **kw):
            seen_timeouts.append(kw.get("timeout"))
            real_init(self, *a, **kw)

        monkeypatch.setattr(sip_packet, "__init__", _tracking_init)
        monkeypatch.setattr(sip_packet, "generate_packet", lambda self: {"status": True})

        args = argparse.Namespace(
            target_network="127.0.0.1", message_type="options",
            from_user="1000", to_user="8000", dest_port=5060,
            ip_list=str(tmp_path / "ip_list.txt"), response_timeout=1.5,
        )
        conf = argparse.Namespace(iface="lo0")

        nes.run(args, conf, client_ip="10.0.0.1")

        assert seen_timeouts == [1.5]

    def test_response_timeout_reaches_sip_packet_bulk_path(self, tmp_path, monkeypatch):
        seen_timeouts = []
        real_init = sip_packet.__init__

        def _tracking_init(self, *a, **kw):
            seen_timeouts.append(kw.get("timeout"))
            real_init(self, *a, **kw)

        monkeypatch.setattr(sip_packet, "__init__", _tracking_init)
        monkeypatch.setattr(sip_packet, "generate_packet", lambda self: {"status": True})
        monkeypatch.setattr(nes.threadpool, "confirm_bulk_run", lambda *a, **k: None)

        args = argparse.Namespace(
            target_network="127.0.0.1/31", message_type="options",
            from_user="1000", to_user="8000", dest_port=5060,
            ip_list=str(tmp_path / "ip_list.txt"), response_timeout=0.75,
            thread_count=2,
        )
        conf = argparse.Namespace(iface="lo0")

        nes.run(args, conf, client_ip="10.0.0.1")

        assert seen_timeouts and all(t == 0.75 for t in seen_timeouts)


class TestNesFileValidation:
    def test_looks_like_file_checks(self, tmp_path):
        # A file that doesn't exist but has path separators or a common ext should throw MrSipError
        args = argparse.Namespace(
            target_network="127.0.0.1", message_type="options",
            from_user="/path/to/nonexistent.txt", to_user="8000", dest_port=5060,
            ip_list=str(tmp_path / "ip_list.txt"), response_timeout=5.0,
        )
        conf = argparse.Namespace(iface="lo0")
        with pytest.raises(errors.MrSipError) as exc_info:
            nes.run(args, conf, client_ip="10.0.0.1")
        assert "File not found" in str(exc_info.value)
        assert "literal username" in str(exc_info.value)

        # Literal value like '8000' is fine and doesn't raise
        args = argparse.Namespace(
            target_network="127.0.0.1", message_type="options",
            from_user="1000", to_user="8000", dest_port=5060,
            ip_list=str(tmp_path / "ip_list.txt"), response_timeout=5.0,
        )
        # Mock generate_packet to avoid networking
        from unittest.mock import patch
        with patch.object(sip_packet, "generate_packet", return_value={"status": True}):
            nes.run(args, conf, client_ip="10.0.0.1")

