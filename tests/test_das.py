import argparse

import pytest

from src.core import errors
from src.modules import das
from src.modules.das import _summarize


class TestSummarize:
    def test_all_sent_reports_rate_and_avg_send_time(self):
        msg = _summarize(
            sent=100, i=100, target="10.0.0.1", failed=0, last_error=None,
            elapsed=10.0, send_time_total=2.0, send_time_count=100,
        )
        assert "100 packet(s) sent to 10.0.0.1" in msg
        assert "10.0 packets/sec" in msg
        assert "20.0 ms" in msg  # 2.0s / 100 sends = 20ms avg
        assert "failed" not in msg

    def test_partial_failure_reports_counts_and_last_error(self):
        msg = _summarize(
            sent=7, i=10, target="10.0.0.1", failed=3, last_error="timed out",
            elapsed=5.0, send_time_total=1.4, send_time_count=7,
        )
        assert "7 of 10 packets actually sent to 10.0.0.1" in msg
        assert "3 failed (last error: timed out)" in msg
        assert "1.4 packets/sec" in msg

    def test_zero_elapsed_does_not_divide_by_zero(self):
        msg = _summarize(
            sent=0, i=0, target="10.0.0.1", failed=0, last_error=None,
            elapsed=0.0, send_time_total=0.0, send_time_count=0,
        )
        assert "0.0 packets/sec" in msg
        assert "0.0 ms" in msg


class TestLivenessCheckWarnsButNeverBlocks:
    def test_warns_when_target_does_not_respond_but_flood_still_runs(self, tmp_path, monkeypatch, caplog):
        import logging

        wordlist = tmp_path / "words.txt"
        wordlist.write_text("1000\n")

        monkeypatch.setattr(das.net_utils, "promisc", lambda state, iface: None)
        monkeypatch.setattr(das.net_utils, "probe_liveness", lambda *a, **k: None)

        args = argparse.Namespace(
            message_type="invite", library=True, random=False, subnet=False, manual=False,
            manual_ip_list=None, counter=1, target_network="127.0.0.1", dest_port=5060, skip_live_check=False,
            to_user=str(wordlist), from_user=str(wordlist), sp_user=str(wordlist), user_agent=str(wordlist),
            mtu=None, pps=None, response_timeout=None,
        )
        conf = argparse.Namespace(iface="lo0")

        with caplog.at_level(logging.WARNING):
            das.run(args, conf, client_ip="10.0.0.1", client_netmask="255.255.255.0")

        warnings = [r.message for r in caplog.records if r.levelno == logging.WARNING]
        assert any("did not respond to an initial liveness probe" in w for w in warnings)

    def test_skip_live_check_suppresses_the_warning_and_the_probe_itself(self, tmp_path, monkeypatch, caplog):
        import logging

        wordlist = tmp_path / "words.txt"
        wordlist.write_text("1000\n")

        monkeypatch.setattr(das.net_utils, "promisc", lambda state, iface: None)

        def _unexpected_probe(*a, **k):
            raise AssertionError("probe_liveness should not be called when skip_live_check=True")

        monkeypatch.setattr(das.net_utils, "probe_liveness", _unexpected_probe)

        args = argparse.Namespace(
            message_type="invite", library=True, random=False, subnet=False, manual=False,
            manual_ip_list=None, counter=1, target_network="127.0.0.1", dest_port=5060, skip_live_check=True,
            to_user=str(wordlist), from_user=str(wordlist), sp_user=str(wordlist), user_agent=str(wordlist),
            mtu=None, pps=None, response_timeout=None,
        )
        conf = argparse.Namespace(iface="lo0")

        with caplog.at_level(logging.WARNING):
            das.run(args, conf, client_ip="10.0.0.1", client_netmask="255.255.255.0")

        warnings = [r.message for r in caplog.records if r.levelno == logging.WARNING]
        assert not any("liveness probe" in w for w in warnings)


class TestManualSpoofingRequiresIpList:
    def test_manual_without_il_raises_clean_error_not_a_typeerror(self):
        # Regression: args.manual_ip_list defaults to None when -m is given
        # without --il; net_utils.read_ip_list(None) used to call open(None),
        # raising a raw TypeError instead of a clean MrSipError.
        args = argparse.Namespace(
            message_type="invite", library=False, random=False, subnet=False,
            manual=True, manual_ip_list=None,
        )
        with pytest.raises(errors.MrSipError):
            das.run(args, conf=argparse.Namespace(iface="lo0"), client_ip="10.0.0.1", client_netmask="255.255.255.0")


class TestSubnetSpoofingRequiresNetmask:
    def test_subnet_without_netmask_raises_clean_error(self):
        args = argparse.Namespace(
            message_type="invite", library=False, random=False, subnet=True,
            manual=False, manual_ip_list=None,
        )
        with pytest.raises(errors.MrSipError, match="subnet spoofing.*requires.*valid netmask"):
            das.run(args, conf=argparse.Namespace(iface="lo0"), client_ip="10.0.0.1", client_netmask=None)


class TestDasSubnetValidation:
    def test_das_run_rejects_subnets_and_ranges(self):
        args = argparse.Namespace(
            message_type="invite", library=True, random=False, subnet=False,
            manual=False, manual_ip_list=None, target_network="192.168.1.100/24"
        )
        with pytest.raises(errors.MrSipError, match="requires a single target IP"):
            das.run(args, conf=argparse.Namespace(iface="lo0"), client_ip="10.0.0.1", client_netmask=None)

        args = argparse.Namespace(
            message_type="invite", library=True, random=False, subnet=False,
            manual=False, manual_ip_list=None, target_network="192.168.1.1-192.168.1.10"
        )
        with pytest.raises(errors.MrSipError, match="requires a single target IP"):
            das.run(args, conf=argparse.Namespace(iface="lo0"), client_ip="10.0.0.1", client_netmask=None)

    def test_das_run_rejects_mtu_with_library(self):
        args = argparse.Namespace(
            message_type="invite", library=True, random=False, subnet=False,
            manual=False, manual_ip_list=None, target_network="192.168.1.100", mtu=150
        )
        with pytest.raises(errors.MrSipError, match="requires raw Scapy mode"):
            das.run(args, conf=argparse.Namespace(iface="lo0"), client_ip="10.0.0.1", client_netmask=None)


class TestDasEmptyWordlistValidation:
    def test_das_run_rejects_empty_wordlists(self, tmp_path):
        empty = tmp_path / "empty.txt"
        empty.write_text("")
        nonempty = tmp_path / "words.txt"
        nonempty.write_text("1000\n")

        args = argparse.Namespace(
            message_type="invite", library=True, random=False, subnet=False, manual=False,
            manual_ip_list=None, counter=5, target_network="127.0.0.1", dest_port=5060, skip_live_check=True,
            to_user=str(empty), from_user=str(nonempty), sp_user=str(nonempty), user_agent=str(nonempty),
            mtu=None, pps=None, response_timeout=None,
        )
        conf = argparse.Namespace(iface="lo0")
        with pytest.raises(errors.MrSipError, match="To user list file.*is empty"):
            das.run(args, conf, client_ip="10.0.0.1", client_netmask="255.255.255.0")


class TestPromiscIsAlwaysRestored:
    def test_unexpected_exception_still_restores_promisc(self, tmp_path, monkeypatch):
        # Regression: promisc("off") used to run only on the KeyboardInterrupt
        # path and after normal completion - any other exception (here, an
        # empty wordlist making random.choice raise IndexError) used to
        # leave the NIC stuck in promiscuous mode.
        empty = tmp_path / "empty.txt"
        empty.write_text("")
        nonempty = tmp_path / "words.txt"
        nonempty.write_text("1000\n")

        promisc_calls = []
        monkeypatch.setattr(das.net_utils, "promisc", lambda state, iface: promisc_calls.append(state))

        # Mock random.choice to raise RuntimeError inside the loop to simulate an unexpected error.
        def raise_runtime_error(*args, **kwargs):
            raise RuntimeError("unexpected")
        monkeypatch.setattr(das.random, "choice", raise_runtime_error)

        # library=False means the flood loop opens a persistent raw socket
        # (F26) - opening a real one needs root, which the test environment
        # doesn't have. This test isn't about the socket itself, it's about
        # promisc always being restored, so a fake stand-in is enough - it
        # also lets the test assert the socket gets closed on the same
        # unexpected-exception path.
        fake_socket_closed = []

        class _FakeSocket:
            def close(self):
                fake_socket_closed.append(True)

        monkeypatch.setattr(das, "_open_scapy_socket", lambda target, iface_hint: _FakeSocket())

        args = argparse.Namespace(
            message_type="invite", library=False, random=False, subnet=False, manual=False,
            manual_ip_list=None, counter=5, target_network="127.0.0.1", dest_port=5060, skip_live_check=True,
            to_user=str(nonempty), from_user=str(nonempty), sp_user=str(nonempty), user_agent=str(nonempty),
            mtu=None, pps=None, response_timeout=None,
        )
        conf = argparse.Namespace(iface="lo0")

        with pytest.raises(RuntimeError):
            das.run(args, conf, client_ip="10.0.0.1", client_netmask="255.255.255.0")

        assert promisc_calls == ["on", "off"]
        assert fake_socket_closed == [True]


class TestZeroCounterMeansInfinite:
    def test_zero_counter_does_not_stop_after_zero_packets(self, tmp_path, monkeypatch):
        # Regression/feature: -c 0 used to mean "send 0 packets and exit
        # immediately" (while i < counter never runs for counter=0). It now
        # matches hping3/nping convention: 0 means flood indefinitely. Can't
        # actually flood forever in a test, so stop it after a few iterations
        # by raising once i reaches a threshold, and assert more than 0
        # packets were attempted.
        wordlist = tmp_path / "words.txt"
        wordlist.write_text("1000\n")

        monkeypatch.setattr(das.net_utils, "promisc", lambda state, iface: None)
        # Without this, the flood loop performs a real UDP connect()+sendall()
        # to 127.0.0.1:5060 with nothing listening - whether that raises
        # ConnectionRefusedError depends on OS/timing-specific ICMP
        # port-unreachable delivery to the connected socket, which is flaky
        # across platforms (passed locally on macOS, failed deterministically
        # on Linux CI). Mocking it removes the dependency on real network
        # behavior entirely, matching every other flood-loop test in this file.
        monkeypatch.setattr(das.sip_packet.sip_packet, "generate_packet", lambda self: {"status": True})

        sent_lengths = []

        class _StopEarly(Exception):
            pass

        real_choice = das.random.choice

        def _tracking_choice(seq):
            sent_lengths.append(1)
            if len(sent_lengths) > 25:
                raise _StopEarly
            return real_choice(seq)

        monkeypatch.setattr(das.random, "choice", _tracking_choice)

        args = argparse.Namespace(
            message_type="invite", library=True, random=False, subnet=False, manual=False,
            manual_ip_list=None, counter=0, target_network="127.0.0.1", dest_port=5060, skip_live_check=True,
            to_user=str(wordlist), from_user=str(wordlist), sp_user=str(wordlist), user_agent=str(wordlist),
            mtu=None, pps=None, response_timeout=None,
        )
        conf = argparse.Namespace(iface="lo0")

        with pytest.raises(_StopEarly):
            das.run(args, conf, client_ip="10.0.0.1", client_netmask="255.255.255.0")

        assert len(sent_lengths) > 20


class TestPpsThrottling:
    def test_pps_sleeps_between_packets(self, tmp_path, monkeypatch):
        wordlist = tmp_path / "words.txt"
        wordlist.write_text("1000\n")

        monkeypatch.setattr(das.net_utils, "promisc", lambda state, iface: None)

        sleep_calls = []
        monkeypatch.setattr(das.time, "sleep", lambda secs: sleep_calls.append(secs))

        args = argparse.Namespace(
            message_type="invite", library=True, random=False, subnet=False, manual=False,
            manual_ip_list=None, counter=3, target_network="127.0.0.1", dest_port=5060, skip_live_check=True,
            to_user=str(wordlist), from_user=str(wordlist), sp_user=str(wordlist), user_agent=str(wordlist),
            mtu=None, pps=10.0, response_timeout=None,
        )
        conf = argparse.Namespace(iface="lo0")

        das.run(args, conf, client_ip="10.0.0.1", client_netmask="255.255.255.0")

        assert len(sleep_calls) == 3
        assert all(s <= 0.1 for s in sleep_calls)

    def test_no_pps_never_sleeps(self, tmp_path, monkeypatch):
        wordlist = tmp_path / "words.txt"
        wordlist.write_text("1000\n")

        monkeypatch.setattr(das.net_utils, "promisc", lambda state, iface: None)

        sleep_calls = []
        monkeypatch.setattr(das.time, "sleep", lambda secs: sleep_calls.append(secs))

        args = argparse.Namespace(
            message_type="invite", library=True, random=False, subnet=False, manual=False,
            manual_ip_list=None, counter=3, target_network="127.0.0.1", dest_port=5060, skip_live_check=True,
            to_user=str(wordlist), from_user=str(wordlist), sp_user=str(wordlist), user_agent=str(wordlist),
            mtu=None, pps=None, response_timeout=None,
        )
        conf = argparse.Namespace(iface="lo0")

        das.run(args, conf, client_ip="10.0.0.1", client_netmask="255.255.255.0")

        assert sleep_calls == []


class TestKeyboardInterruptStillSummarizes:
    def test_ctrl_c_mid_flood_still_logs_summary_and_propagates(self, tmp_path, monkeypatch):
        # Regression: KeyboardInterrupt used to raise SystemExit before the
        # final _summarize() panel was logged, throwing away partial stats
        # on the single most common way a real flood is actually stopped.
        wordlist = tmp_path / "words.txt"
        wordlist.write_text("1000\n")

        monkeypatch.setattr(das.net_utils, "promisc", lambda state, iface: None)

        calls = {"n": 0}
        real_choice = das.random.choice

        def _interrupt_after_a_few(seq):
            calls["n"] += 1
            if calls["n"] > 8:
                raise KeyboardInterrupt
            return real_choice(seq)

        monkeypatch.setattr(das.random, "choice", _interrupt_after_a_few)

        logged = []
        monkeypatch.setattr(das.logger, "info", lambda msg: logged.append(msg))

        args = argparse.Namespace(
            message_type="invite", library=True, random=False, subnet=False, manual=False,
            manual_ip_list=None, counter=99999999, target_network="127.0.0.1", dest_port=5060, skip_live_check=True,
            to_user=str(wordlist), from_user=str(wordlist), sp_user=str(wordlist), user_agent=str(wordlist),
            mtu=None, pps=None, response_timeout=None,
        )
        conf = argparse.Namespace(iface="lo0")

        with pytest.raises(KeyboardInterrupt):
            das.run(args, conf, client_ip="10.0.0.1", client_netmask="255.255.255.0")

        assert any("SIP-DAS summary" in msg for msg in logged)


class TestOpenScapySocket:
    def test_uses_the_routed_interface_when_available(self, monkeypatch):
        calls = {}

        class _FakeIfaceObj:
            def l3socket(self, ipv6):
                calls["ipv6"] = ipv6

                def _ctor(iface):
                    calls["iface"] = iface
                    return "SOCKET"

                return _ctor

        fake_iface = _FakeIfaceObj()
        resolved_dev = {}

        class _FakePacket:
            def route(self):
                return ("eth9", "1.2.3.4", "0.0.0.0")

        monkeypatch.setattr(das, "IP", lambda dst: _FakePacket())

        def _resolve(dev):
            resolved_dev["dev"] = dev
            return fake_iface

        monkeypatch.setattr(das, "resolve_iface", _resolve)

        result = das._open_scapy_socket("10.0.0.5", "fallback0")
        assert result == "SOCKET"
        assert calls["ipv6"] is False
        assert resolved_dev["dev"] == "eth9"
        assert calls["iface"] is fake_iface

    def test_falls_back_to_iface_hint_when_route_has_no_interface(self, monkeypatch):
        # IP.route() can return an empty string for the interface when it
        # can't determine one - fall back to the caller's own conf.iface
        # (iface_hint), the same way scapy's _interface_selection() does.
        resolved = {}

        class _FakeIfaceObj:
            def l3socket(self, ipv6):
                return lambda iface: iface

        class _FakePacket:
            def route(self):
                return ("", "1.2.3.4", "0.0.0.0")

        monkeypatch.setattr(das, "IP", lambda dst: _FakePacket())

        def _resolve(dev):
            resolved["dev"] = dev
            return _FakeIfaceObj()

        monkeypatch.setattr(das, "resolve_iface", _resolve)

        das._open_scapy_socket("10.0.0.5", "fallback0")
        assert resolved["dev"] == "fallback0"


class TestScapySocketLifecycle:
    # F26: DAS's raw-Scapy flood loop (library=False, i.e. no -l) reuses one
    # persistent socket across the whole run instead of scapy.send() opening
    # and closing a fresh raw socket on every single packet. Opening a real
    # one needs root, so these tests fake _open_scapy_socket rather than
    # exercising an actual raw socket.

    def test_library_mode_never_opens_a_scapy_socket(self, tmp_path, monkeypatch):
        wordlist = tmp_path / "words.txt"
        wordlist.write_text("1000\n")

        monkeypatch.setattr(das.net_utils, "promisc", lambda state, iface: None)

        def _unexpected_open(target, iface_hint):
            raise AssertionError("_open_scapy_socket should not be called in -l/socket-library mode")

        monkeypatch.setattr(das, "_open_scapy_socket", _unexpected_open)

        args = argparse.Namespace(
            message_type="invite", library=True, random=False, subnet=False, manual=False,
            manual_ip_list=None, counter=3, target_network="127.0.0.1", dest_port=5060, skip_live_check=True,
            to_user=str(wordlist), from_user=str(wordlist), sp_user=str(wordlist), user_agent=str(wordlist),
            mtu=None, pps=None, response_timeout=None,
        )
        conf = argparse.Namespace(iface="lo0")

        das.run(args, conf, client_ip="10.0.0.1", client_netmask="255.255.255.0")

    def test_scapy_mode_opens_one_persistent_socket_and_closes_it_once(self, tmp_path, monkeypatch):
        wordlist = tmp_path / "words.txt"
        wordlist.write_text("1000\n")

        monkeypatch.setattr(das.net_utils, "promisc", lambda state, iface: None)

        open_calls = []
        close_calls = []

        class _FakeSocket:
            def close(self):
                close_calls.append(True)

        def _fake_open(target, iface_hint):
            open_calls.append((target, iface_hint))
            return _FakeSocket()

        monkeypatch.setattr(das, "_open_scapy_socket", _fake_open)

        received_sockets = []
        real_init = das.sip_packet.sip_packet.__init__

        def _tracking_init(self, *a, **kw):
            received_sockets.append(kw.get("scapy_socket"))
            real_init(self, *a, **kw)

        monkeypatch.setattr(das.sip_packet.sip_packet, "__init__", _tracking_init)
        monkeypatch.setattr(
            das.sip_packet.sip_packet, "generate_packet",
            lambda self: {"status": True},
        )

        args = argparse.Namespace(
            message_type="invite", library=False, random=False, subnet=False, manual=False,
            manual_ip_list=None, counter=3, target_network="127.0.0.1", dest_port=5060, skip_live_check=True,
            to_user=str(wordlist), from_user=str(wordlist), sp_user=str(wordlist), user_agent=str(wordlist),
            mtu=None, pps=None, response_timeout=None,
        )
        conf = argparse.Namespace(iface="lo0")

        das.run(args, conf, client_ip="10.0.0.1", client_netmask="255.255.255.0")

        # Opened exactly once for the whole run, not once per packet.
        assert len(open_calls) == 1
        assert open_calls[0] == ("127.0.0.1", "lo0")
        assert close_calls == [True]
        # Every one of the 3 packets got the same persistent socket instance.
        assert len(received_sockets) == 3
        assert all(s is received_sockets[0] for s in received_sockets)
        assert isinstance(received_sockets[0], _FakeSocket)


class TestLivenessCheckHonorsExplicitResponseTimeout:
    def test_explicit_rt_widens_the_liveness_probe_timeout(self, tmp_path, monkeypatch):
        # Regression: --rt explicitly given must also widen SIP-DAS's
        # liveness pre-check timeout, not just the (irrelevant, since the
        # flood loop never waits for a response) main send path - otherwise
        # a genuinely live but slow target still warns as unreachable
        # regardless of how patient --rt told the tool to be.
        wordlist = tmp_path / "words.txt"
        wordlist.write_text("1000\n")

        monkeypatch.setattr(das.net_utils, "promisc", lambda state, iface: None)

        seen_kwargs = {}

        def _fake_probe_liveness(*a, **kw):
            seen_kwargs.update(kw)
            return {"status": True}

        monkeypatch.setattr(das.net_utils, "probe_liveness", _fake_probe_liveness)

        args = argparse.Namespace(
            message_type="invite", library=True, random=False, subnet=False, manual=False,
            manual_ip_list=None, counter=1, target_network="127.0.0.1", dest_port=5060, skip_live_check=False,
            to_user=str(wordlist), from_user=str(wordlist), sp_user=str(wordlist), user_agent=str(wordlist),
            mtu=None, pps=None, response_timeout=10.0,
        )
        conf = argparse.Namespace(iface="lo0")

        das.run(args, conf, client_ip="10.0.0.1", client_netmask="255.255.255.0")

        assert seen_kwargs.get("timeout") == 10.0

    def test_default_rt_leaves_liveness_probe_timeout_untouched(self, tmp_path, monkeypatch):
        wordlist = tmp_path / "words.txt"
        wordlist.write_text("1000\n")

        monkeypatch.setattr(das.net_utils, "promisc", lambda state, iface: None)

        seen_kwargs = {}

        def _fake_probe_liveness(*a, **kw):
            seen_kwargs.update(kw)
            return {"status": True}

        monkeypatch.setattr(das.net_utils, "probe_liveness", _fake_probe_liveness)

        args = argparse.Namespace(
            message_type="invite", library=True, random=False, subnet=False, manual=False,
            manual_ip_list=None, counter=1, target_network="127.0.0.1", dest_port=5060, skip_live_check=False,
            to_user=str(wordlist), from_user=str(wordlist), sp_user=str(wordlist), user_agent=str(wordlist),
            mtu=None, pps=None, response_timeout=None,
        )
        conf = argparse.Namespace(iface="lo0")

        das.run(args, conf, client_ip="10.0.0.1", client_netmask="255.255.255.0")

        assert "timeout" not in seen_kwargs
