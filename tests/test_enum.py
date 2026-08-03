import argparse
import logging

import pytest

from src.core import errors, logging_config
from src.core.sip_packet import sip_packet
from src.modules import enum


def test_enum_run_warns_on_blanket_rejection(tmp_path, monkeypatch, caplog):
    from_user = tmp_path / "from.txt"
    from_user.write_text("1000\n1001\n")

    def mock_run_worker_pool(work_items, worker_fn, thread_count, extra_args=()):
        # Simulate worker function return for test target
        return [worker_fn(item, *extra_args) for item in work_items]

    monkeypatch.setattr(enum.threadpool, "confirm_bulk_run", lambda *args, **kwargs: None)
    monkeypatch.setattr(enum.threadpool, "run_worker_pool", mock_run_worker_pool)

    def mock_generate_packet(self):
        return {"status": True, "response": {"code": 401, "headers": {}, "body": ""}}

    monkeypatch.setattr(sip_packet, "generate_packet", mock_generate_packet)

    args = argparse.Namespace(
        message_type="subscribe",
        from_user=str(from_user),
        target_network="127.0.0.1",
        dest_port=5060,
        thread_count=1,
        response_timeout=5.0,
        skip_live_check=False,
    )
    conf = argparse.Namespace(iface="lo0")

    with caplog.at_level(logging.WARNING):
        enum.run(args, conf, client_ip="10.0.0.1")

    # Blanket-rejection warnings log at the dedicated BLANKET_WARN level
    # (red "[ WARN ]") rather than plain logging.WARNING, so this specific
    # signal stands out from routine warnings.
    warnings = [r.message for r in caplog.records if r.levelno == logging_config.BLANKET_WARN]
    assert any("blanket-rejection" in w for w in warnings)
    # Regression (F45): the warning used to single out PJSIP as "the" cause
    # ("e.g. PJSIP"), which is incomplete - modern chan_sip blanket-rejects
    # too, by default, via alwaysauthreject (Asterisk's compiled default for
    # chan_sip flipped from FALSE to TRUE at 1.8, ~2011, confirmed directly
    # against the Asterisk source and unrelated to which channel driver is
    # in use). The message must not imply PJSIP is the only/primary cause.
    assert any("chan_sip" in w and "alwaysauthreject" in w for w in warnings)


def test_enum_run_no_warning_on_normal_response(tmp_path, monkeypatch, caplog):
    from_user = tmp_path / "from.txt"
    from_user.write_text("1000\n1001\n")

    def mock_run_worker_pool(work_items, worker_fn, thread_count, extra_args=()):
        return [worker_fn(item, *extra_args) for item in work_items]

    monkeypatch.setattr(enum.threadpool, "confirm_bulk_run", lambda *args, **kwargs: None)
    monkeypatch.setattr(enum.threadpool, "run_worker_pool", mock_run_worker_pool)

    def mock_generate_packet(self):
        return {"status": True, "response": {"code": 200, "headers": {}, "body": ""}}

    monkeypatch.setattr(sip_packet, "generate_packet", mock_generate_packet)

    args = argparse.Namespace(
        message_type="subscribe",
        from_user=str(from_user),
        target_network="127.0.0.1",
        dest_port=5060,
        thread_count=1,
        response_timeout=5.0,
        skip_live_check=False,
    )
    conf = argparse.Namespace(iface="lo0")

    with caplog.at_level(logging.WARNING):
        enum.run(args, conf, client_ip="10.0.0.1")

    # Checked across every captured record regardless of level, so this stays
    # a meaningful negative assertion whether a false positive would have
    # logged at plain WARNING or the dedicated BLANKET_WARN level.
    assert not any("blanket-rejection" in r.message for r in caplog.records)


def test_enum_run_handles_packet_send_error_gracefully(tmp_path, monkeypatch, caplog):
    # skip_live_check=True: this test is specifically about the worker pool
    # tolerating a per-item PacketSendError, not about the (separate)
    # liveness pre-filter - with every generate_packet() call raising, the
    # liveness filter would otherwise drop the only target and this test
    # would be exercising _resolve_live_targets instead of _check_one.
    from_user = tmp_path / "from.txt"
    from_user.write_text("1000\n1001\n")

    monkeypatch.setattr(enum.threadpool, "confirm_bulk_run", lambda *args, **kwargs: None)
    monkeypatch.setattr(enum.threadpool, "run_worker_pool", lambda *args, **kwargs: [])

    def mock_generate_packet(self):
        raise errors.PacketSendError("Connection timed out")

    monkeypatch.setattr(sip_packet, "generate_packet", mock_generate_packet)

    args = argparse.Namespace(
        message_type="subscribe",
        from_user=str(from_user),
        target_network="127.0.0.1",
        dest_port=5060,
        thread_count=1,
        response_timeout=5.0,
        skip_live_check=True,
    )
    conf = argparse.Namespace(iface="lo0")

    with caplog.at_level(logging.WARNING):
        enum.run(args, conf, client_ip="10.0.0.1")

    warnings = [r.message for r in caplog.records if r.levelno == logging.WARNING]
    assert not warnings


def test_resolve_live_targets_skips_non_responsive_targets_and_warns(monkeypatch, caplog):
    def mock_generate_packet(self):
        if self.server_ip == "10.0.0.1":
            raise errors.PacketSendError("timed out")
        return {"status": True, "response": {"code": 200, "headers": {}, "body": ""}}

    monkeypatch.setattr(sip_packet, "generate_packet", mock_generate_packet)

    with caplog.at_level(logging.WARNING):
        live, _baseline_map = enum._resolve_live_targets(
            ["10.0.0.1", "10.0.0.2"], "subscribe", 5060, "10.0.0.9", skip_live_check=False,
        )

    assert live == ["10.0.0.2"]
    warnings = [r.message for r in caplog.records if r.levelno == logging.WARNING]
    assert any("did not respond to a liveness probe" in w and "10.0.0.1" in w for w in warnings)


def test_resolve_live_targets_aggregates_multiple_skips(monkeypatch, caplog):
    def mock_generate_packet(self):
        raise errors.PacketSendError("timed out")

    monkeypatch.setattr(sip_packet, "generate_packet", mock_generate_packet)

    # 6 targets, all skip. Should output count summary warning
    with caplog.at_level(logging.WARNING):
        live, _baseline_map = enum._resolve_live_targets(
            ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6"],
            "subscribe", 5060, "10.0.0.9", skip_live_check=False,
        )

    assert live == []
    warnings = [r.message for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "6 target(s) did not respond" in warnings[0]


def test_resolve_live_targets_caps_blanket_rejection_summary_past_five(monkeypatch, caplog):
    # Regression: the blanket-rejection branch lacked the same >5 cap the
    # skipped_targets branch above has - past 5 it used to join every
    # target IP into one unbounded line (e.g. 20+ IPs on one WARN line for
    # a real /24 of identical PJSIP boxes), which is worse noise than the
    # per-target warnings it was meant to replace.
    def mock_probe_liveness(target, *a, **kw):
        return {"status": True, "response": {"code": 401, "headers": {}, "body": ""}}

    monkeypatch.setattr(enum.net_utils, "probe_liveness", mock_probe_liveness)

    targets = [f"192.168.1.{i}" for i in range(1, 21)]
    with caplog.at_level(logging.WARNING):
        live, _baseline_map = enum._resolve_live_targets(targets, "subscribe", 5060, "10.0.0.9", skip_live_check=False, thread_count=10)

    assert live == targets
    warnings = [r.message for r in caplog.records if r.levelno == logging_config.BLANKET_WARN]
    assert len(warnings) == 1
    assert "20 target(s) returned 401/403" in warnings[0]
    assert "192.168.1.1" not in warnings[0]


def test_resolve_live_targets_skip_flag_bypasses_probing_entirely(monkeypatch):
    def mock_generate_packet(self):
        raise AssertionError("probe_liveness should not be called when skip_live_check=True")

    monkeypatch.setattr(sip_packet, "generate_packet", mock_generate_packet)

    live, _baseline_map = enum._resolve_live_targets(
        ["10.0.0.1", "10.0.0.2"], "subscribe", 5060, "10.0.0.9", skip_live_check=True,
    )
    assert live == ["10.0.0.1", "10.0.0.2"]


def test_resolve_live_targets_default_timeout_untouched_when_rt_not_given(monkeypatch):
    # override_timeout=None (the --rt-not-given case) must leave
    # probe_liveness()'s own short fixed default alone - no timeout= kwarg
    # forwarded to it at all.
    seen_kwargs = {}

    def _fake_probe_liveness(*a, **kw):
        seen_kwargs.update(kw)
        return {"status": True, "response": {"code": 200, "headers": {}, "body": ""}}

    monkeypatch.setattr(enum.net_utils, "probe_liveness", _fake_probe_liveness)

    enum._resolve_live_targets(["10.0.0.1"], "subscribe", 5060, "10.0.0.9", skip_live_check=False, override_timeout=None)

    assert "timeout" not in seen_kwargs


def test_resolve_live_targets_honors_explicit_rt_override(monkeypatch):
    # Regression: --rt explicitly given must widen the liveness pre-check's
    # patience too - otherwise a genuinely live but slow target is silently
    # filtered out as unreachable regardless of how long --rt told the real
    # enumeration probes to wait.
    seen_kwargs = {}

    def _fake_probe_liveness(*a, **kw):
        seen_kwargs.update(kw)
        return {"status": True, "response": {"code": 200, "headers": {}, "body": ""}}

    monkeypatch.setattr(enum.net_utils, "probe_liveness", _fake_probe_liveness)

    enum._resolve_live_targets(["10.0.0.1"], "subscribe", 5060, "10.0.0.9", skip_live_check=False, override_timeout=10.0)

    assert seen_kwargs.get("timeout") == 10.0


def test_enum_run_raises_clean_error_when_no_target_responds(tmp_path, monkeypatch):
    from_user = tmp_path / "from.txt"
    from_user.write_text("1000\n")

    def mock_generate_packet(self):
        raise errors.PacketSendError("timed out")

    monkeypatch.setattr(sip_packet, "generate_packet", mock_generate_packet)

    args = argparse.Namespace(
        message_type="subscribe",
        from_user=str(from_user),
        target_network="10.0.0.1",
        dest_port=5060,
        thread_count=1,
        response_timeout=5.0,
        skip_live_check=False,
    )
    conf = argparse.Namespace(iface="lo0")

    with pytest.raises(errors.MrSipError, match="nothing to enumerate"):
        enum.run(args, conf, client_ip="10.0.0.9")


def test_response_timeout_reaches_check_one(tmp_path, monkeypatch):
    # --rt exists so a large target list of mostly-non-responsive hosts
    # doesn't pay the full default per-probe timeout - confirm it's
    # actually threaded through to sip_packet, not just parsed and dropped.
    from_user = tmp_path / "from.txt"
    from_user.write_text("1000\n1001\n")

    monkeypatch.setattr(enum.threadpool, "confirm_bulk_run", lambda *args, **kwargs: None)

    seen_timeouts = []
    real_init = sip_packet.__init__

    def _tracking_init(self, *a, **kw):
        seen_timeouts.append(kw.get("timeout"))
        real_init(self, *a, **kw)

    monkeypatch.setattr(sip_packet, "__init__", _tracking_init)
    monkeypatch.setattr(sip_packet, "generate_packet", lambda self: {"status": True, "response": {"code": 200, "headers": {}, "body": ""}})

    args = argparse.Namespace(
        message_type="subscribe",
        from_user=str(from_user),
        target_network="127.0.0.1",
        dest_port=5060,
        thread_count=1,
        response_timeout=2.5,
        skip_live_check=True,
    )
    conf = argparse.Namespace(iface="lo0")

    enum.run(args, conf, client_ip="10.0.0.1")

    assert seen_timeouts and all(t == 2.5 for t in seen_timeouts)


def test_enum_run_aggregates_blanket_rejection_warnings(tmp_path, monkeypatch, caplog):
    from_user = tmp_path / "from.txt"
    from_user.write_text("1000\n")

    # Create dummy ip_list.txt with multiple targets
    ip_list_file = tmp_path / "ip_list.txt"
    ip_list_file.write_text("10.0.0.1;UserAgent;Server\n10.0.0.2;UserAgent;Server\n")

    def mock_run_worker_pool(work_items, worker_fn, thread_count, extra_args=()):
        return [worker_fn(item, *extra_args) for item in work_items]

    monkeypatch.setattr(enum.threadpool, "confirm_bulk_run", lambda *args, **kwargs: None)
    monkeypatch.setattr(enum.threadpool, "run_worker_pool", mock_run_worker_pool)

    # Mock probe_liveness to simulate blanket rejection on both targets
    def mock_probe_liveness(target, *args, **kwargs):
        return {"status": True, "response": {"code": 401, "headers": {}, "body": ""}}

    monkeypatch.setattr(enum.net_utils, "probe_liveness", mock_probe_liveness)

    # The real enumeration pass (after the liveness pre-check) also goes
    # through run_worker_pool - without mocking generate_packet too, this
    # fell through to a real UDP send with the real 5s default timeout for
    # both targets, ~10s total. Every other run()-level test in this file
    # mocks this; this one just missed it.
    monkeypatch.setattr(sip_packet, "generate_packet", lambda self: {"status": True, "response": {"code": 401, "headers": {}, "body": ""}})

    args = argparse.Namespace(
        message_type="subscribe",
        from_user=str(from_user),
        target_network=None,  # Forces reading from ip_list.txt
        ip_list=str(ip_list_file),
        dest_port=5060,
        thread_count=1,
        response_timeout=5.0,
        skip_live_check=False,
    )
    conf = argparse.Namespace(iface="lo0")

    with caplog.at_level(logging.WARNING):
        enum.run(args, conf, client_ip="10.0.0.9")

    warnings = [r.message for r in caplog.records if r.levelno == logging_config.BLANKET_WARN]

    # Verify warning aggregation: should contain targets 10.0.0.1 and 10.0.0.2 in a single warning
    assert len(warnings) == 1
    assert "10.0.0.1, 10.0.0.2" in warnings[0]
    assert "blanket-rejection" in warnings[0]


def test_resolve_live_targets_handles_arbitrary_fuzz_data(monkeypatch):
    # If probe_liveness returns empty, invalid, or raises/returns None, it should not crash.
    def mock_probe_liveness(target, *args, **kwargs):
        if target == "error":
            raise errors.PacketSendError("socket error")
        if target == "invalid_resp":
            return {"status": True, "response": None}
        return None

    monkeypatch.setattr(enum.net_utils, "probe_liveness", mock_probe_liveness)

    live, baseline_map = enum._resolve_live_targets(
        ["error", "invalid_resp", "no_response"],
        "subscribe", 5060, "10.0.0.9", skip_live_check=False,
    )
    assert live == ["invalid_resp"]
    assert baseline_map == {"invalid_resp": None}


# --- F6 improvement: response-header surfacing + confirmed/unconfirmed grading ---


def test_resolve_live_targets_returns_baseline_map_with_observed_codes(monkeypatch):
    def mock_probe_liveness(target, *args, **kwargs):
        code = 401 if target == "10.0.0.1" else 404
        return {"status": True, "response": {"code": code, "headers": {}, "body": ""}}

    monkeypatch.setattr(enum.net_utils, "probe_liveness", mock_probe_liveness)

    live, baseline_map = enum._resolve_live_targets(
        ["10.0.0.1", "10.0.0.2"], "subscribe", 5060, "10.0.0.9", skip_live_check=False,
    )

    assert live == ["10.0.0.1", "10.0.0.2"]
    assert baseline_map == {"10.0.0.1": 401, "10.0.0.2": 404}


def test_resolve_live_targets_skip_flag_returns_empty_baseline_map(monkeypatch):
    def mock_generate_packet(self):
        raise AssertionError("probe_liveness should not be called when skip_live_check=True")

    monkeypatch.setattr(sip_packet, "generate_packet", mock_generate_packet)

    _live, baseline_map = enum._resolve_live_targets(
        ["10.0.0.1"], "subscribe", 5060, "10.0.0.9", skip_live_check=True,
    )
    assert baseline_map == {}


def test_classify_confidence_exact_baseline_match_is_unconfirmed():
    # Real response matches the blanket-rejection baseline exactly (same
    # code a guaranteed-nonexistent random user also got) - can't tell this
    # apart from every other unmatched request the target rejects the same
    # way.
    assert enum._classify_confidence(401, 401) is False


def test_classify_confidence_baseline_mismatch_is_confirmed():
    # Real response differs from the baseline entirely (401 vs the
    # baseline's 403) - a real distinguishing signal, classic chan_sip-style
    # behavior.
    assert enum._classify_confidence(401, 403) is True


def test_classify_confidence_no_baseline_defaults_confirmed():
    # No baseline available at all (--skip-live-check) - nothing to compare
    # against, so don't downgrade a finding the operator explicitly chose to
    # get without the pre-check.
    assert enum._classify_confidence(401, None) is True


def test_classify_confidence_no_auth_required_always_confirmed():
    # code=200 ("no auth required") is treated as confirmed even if the
    # baseline probe also got 200 for a random nonexistent user - that
    # combination means the server accepts *anyone* without auth, which is
    # itself a real, actionable finding, not a false positive to suppress.
    assert enum._classify_confidence(200, 200) is True


def test_extract_realm_parses_www_authenticate():
    headers = {"www-authenticate": ['Digest realm="asterisk"', 'nonce="16354512"']}
    assert enum._extract_realm(headers) == "asterisk"


def test_extract_realm_missing_header_returns_none():
    assert enum._extract_realm({}) is None


def test_extract_realm_header_present_but_no_realm_param_returns_none():
    headers = {"www-authenticate": ["Digest nonce=\"16354512\""]}
    assert enum._extract_realm(headers) is None


def test_check_one_unconfirmed_when_matches_blanket_baseline(monkeypatch, caplog):
    def mock_generate_packet(self):
        return {
            "status": True,
            "response": {"code": 401, "headers": {"www-authenticate": ['Digest realm="asterisk"']}, "body": ""},
        }

    monkeypatch.setattr(sip_packet, "generate_packet", mock_generate_packet)

    # Unconfirmed findings log at the dedicated FOUND_UNCONFIRMED level
    # (yellow "[ FOUND ]"), not the regular (green) FOUND level a confirmed
    # match uses.
    with caplog.at_level(logging_config.FOUND_UNCONFIRMED):
        result = enum._check_one(
            ("10.0.0.1", "1000"), "subscribe", 5060, "10.0.0.9", 5.0, {"10.0.0.1": 401},
        )

    assert result == {"user": "1000", "confirmed": False}
    found_messages = [r.message for r in caplog.records if r.levelno == logging_config.FOUND_UNCONFIRMED]
    assert any("unconfirmed" in m for m in found_messages)


def test_check_one_confirmed_when_baseline_differs(monkeypatch, caplog):
    def mock_generate_packet(self):
        return {
            "status": True,
            "response": {"code": 401, "headers": {"www-authenticate": ['Digest realm="asterisk"']}, "body": ""},
        }

    monkeypatch.setattr(sip_packet, "generate_packet", mock_generate_packet)

    with caplog.at_level(25):
        result = enum._check_one(
            ("10.0.0.1", "1000"), "subscribe", 5060, "10.0.0.9", 5.0, {"10.0.0.1": 404},
        )

    assert result == {"user": "1000", "confirmed": True}
    found_messages = [r.message for r in caplog.records if r.levelno == 25]
    assert any("authentication required" in m and "unconfirmed" not in m for m in found_messages)


def test_check_one_surfaces_realm_in_found_message(monkeypatch, caplog):
    def mock_generate_packet(self):
        return {
            "status": True,
            "response": {"code": 401, "headers": {"www-authenticate": ['Digest realm="asterisk"']}, "body": ""},
        }

    monkeypatch.setattr(sip_packet, "generate_packet", mock_generate_packet)

    with caplog.at_level(25):
        enum._check_one(("10.0.0.1", "1000"), "subscribe", 5060, "10.0.0.9", 5.0, {})

    found_messages = [r.message for r in caplog.records if r.levelno == 25]
    assert any("asterisk" in m for m in found_messages)


def test_check_one_surfaces_server_header_for_no_auth_case(monkeypatch, caplog):
    def mock_generate_packet(self):
        return {
            "status": True,
            "response": {"code": 200, "headers": {"server": ["Asterisk PBX 18.0"]}, "body": ""},
        }

    monkeypatch.setattr(sip_packet, "generate_packet", mock_generate_packet)

    with caplog.at_level(25):
        result = enum._check_one(("10.0.0.1", "1000"), "subscribe", 5060, "10.0.0.9", 5.0, {})

    assert result == {"user": "1000", "confirmed": True}
    found_messages = [r.message for r in caplog.records if r.levelno == 25]
    assert any("Asterisk PBX 18.0" in m for m in found_messages)


def test_check_one_debug_line_includes_baseline_code(monkeypatch, caplog):
    # -v/DEBUG output should show what baseline a check was graded against,
    # without needing to cross-reference the earlier blanket-rejection
    # warning by hand.
    def mock_generate_packet(self):
        return {"status": True, "response": {"code": 404, "headers": {}, "body": ""}}

    monkeypatch.setattr(sip_packet, "generate_packet", mock_generate_packet)

    with caplog.at_level(logging.DEBUG):
        enum._check_one(("10.0.0.1", "1000"), "subscribe", 5060, "10.0.0.9", 5.0, {"10.0.0.1": 401})

    debug_messages = [r.message for r in caplog.records if r.levelno == logging.DEBUG]
    assert any("baseline=401" in m for m in debug_messages)


def test_check_one_debug_line_shows_no_baseline_when_none_available(monkeypatch, caplog):
    def mock_generate_packet(self):
        return {"status": True, "response": {"code": 404, "headers": {}, "body": ""}}

    monkeypatch.setattr(sip_packet, "generate_packet", mock_generate_packet)

    with caplog.at_level(logging.DEBUG):
        enum._check_one(("10.0.0.1", "1000"), "subscribe", 5060, "10.0.0.9", 5.0, {})

    debug_messages = [r.message for r in caplog.records if r.levelno == logging.DEBUG]
    assert any("baseline=None" in m for m in debug_messages)


def test_check_one_returns_none_when_no_match(monkeypatch):
    def mock_generate_packet(self):
        return {"status": True, "response": {"code": 404, "headers": {}, "body": ""}}

    monkeypatch.setattr(sip_packet, "generate_packet", mock_generate_packet)

    result = enum._check_one(("10.0.0.1", "1000"), "subscribe", 5060, "10.0.0.9", 5.0, {})

    assert result is None


def test_enum_run_summary_reports_confirmed_and_unconfirmed_split(tmp_path, monkeypatch, caplog):
    from_user = tmp_path / "from.txt"
    from_user.write_text("1000\n1001\n")

    def mock_run_worker_pool(work_items, worker_fn, thread_count, extra_args=()):
        return [worker_fn(item, *extra_args) for item in work_items]

    monkeypatch.setattr(enum.threadpool, "confirm_bulk_run", lambda *args, **kwargs: None)
    monkeypatch.setattr(enum.threadpool, "run_worker_pool", mock_run_worker_pool)

    # Baseline (liveness pre-check, random nonexistent user) always gets 401.
    def mock_probe_liveness(target, *args, **kwargs):
        return {"status": True, "response": {"code": 401, "headers": {}, "body": ""}}

    monkeypatch.setattr(enum.net_utils, "probe_liveness", mock_probe_liveness)

    # Real enumeration probes: "1000" matches the blanket baseline (401,
    # unconfirmed); "1001" gets in with no auth at all (200, confirmed).
    def mock_generate_packet(self):
        if self.from_user == "1000":
            return {"status": True, "response": {"code": 401, "headers": {}, "body": ""}}
        return {"status": True, "response": {"code": 200, "headers": {}, "body": ""}}

    monkeypatch.setattr(sip_packet, "generate_packet", mock_generate_packet)

    args = argparse.Namespace(
        message_type="subscribe",
        from_user=str(from_user),
        target_network="127.0.0.1",
        dest_port=5060,
        thread_count=1,
        response_timeout=5.0,
        skip_live_check=False,
    )
    conf = argparse.Namespace(iface="lo0")

    with caplog.at_level(logging.INFO):
        enum.run(args, conf, client_ip="10.0.0.1")

    info_messages = [r.message for r in caplog.records if r.levelno == logging.INFO]
    summary = next(m for m in info_messages if "SIP-ENUM summary" in m)
    assert "2 SIP extension(s) found" in summary
    assert "1 confirmed" in summary
    assert "1 unconfirmed" in summary


def test_enum_run_summary_keeps_old_format_when_all_confirmed(tmp_path, monkeypatch, caplog):
    from_user = tmp_path / "from.txt"
    from_user.write_text("1000\n")

    def mock_run_worker_pool(work_items, worker_fn, thread_count, extra_args=()):
        return [worker_fn(item, *extra_args) for item in work_items]

    monkeypatch.setattr(enum.threadpool, "confirm_bulk_run", lambda *args, **kwargs: None)
    monkeypatch.setattr(enum.threadpool, "run_worker_pool", mock_run_worker_pool)

    def mock_generate_packet(self):
        return {"status": True, "response": {"code": 200, "headers": {}, "body": ""}}

    monkeypatch.setattr(sip_packet, "generate_packet", mock_generate_packet)

    args = argparse.Namespace(
        message_type="subscribe",
        from_user=str(from_user),
        target_network="127.0.0.1",
        dest_port=5060,
        thread_count=1,
        response_timeout=5.0,
        skip_live_check=True,
    )
    conf = argparse.Namespace(iface="lo0")

    with caplog.at_level(logging.INFO):
        enum.run(args, conf, client_ip="10.0.0.1")

    info_messages = [r.message for r in caplog.records if r.levelno == logging.INFO]
    summary = next(m for m in info_messages if "SIP-ENUM summary" in m)
    assert "1 SIP extension(s) found." in summary
    assert "confirmed" not in summary


