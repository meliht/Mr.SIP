import pytest

from src import __version__
from src.cli import build_parser, main


def test_no_module_specified_points_to_the_live_pro_site(monkeypatch, capsys):
    # Regression: this message used to point at https://mrsip.gitlab.io/,
    # which redirects to a GitLab Pages auth wall with no reachable content
    # (see CHANGELOG.md 1.5.1 - the same dead link was already fixed in
    # README.md/docs/mrsip-pro.md, but this runtime message was missed, so
    # it kept sending real operators to a dead page).
    monkeypatch.setattr("sys.argv", ["mr.sip.py"])
    main()
    out = capsys.readouterr().out
    assert "mrsip.gitlab.io" not in out
    assert "https://www.mrsip.pro/" in out


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc_info:
        build_parser().parse_args(["--version"])
    assert exc_info.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_missing_wordlist_file_is_a_clean_exit_not_a_traceback(monkeypatch, capsys):
    # DAS's -l (socket) mode reads --to before ever touching the network, so
    # this exercises the real FileNotFoundError -> clean-CLI-error path
    # without needing a live target. logging_config sets up its own handler
    # with propagate disabled, so assert on captured stdout, not caplog.
    monkeypatch.setattr(
        "sys.argv",
        ["mr.sip.py", "--das", "--mt=invite", "-c", "1", "--tn=127.0.0.1", "--to=/nonexistent/wordlist.txt", "-l"],
    )
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 1
    assert "File not found" in capsys.readouterr().out


def test_nonexistent_interface_is_a_clean_exit_not_a_traceback(monkeypatch, capsys):
    # Regression: --if naming an interface that doesn't exist on this
    # system used to crash with a full raw traceback through Scapy's own
    # conf.iface setter (the assignment ran before main()'s try: block
    # existed) instead of the clean CLI error every other bad-input case
    # gets. A typo'd interface name is one of the easiest, most common
    # mistakes to make with this flag (see docs/usage-guide.md).
    monkeypatch.setattr(
        "sys.argv",
        ["mr.sip.py", "--nes", "--tn=127.0.0.1", "--if=definitely_not_a_real_interface0"],
    )
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 1
    out = capsys.readouterr().out
    assert "Traceback" not in out
    assert "not found" in out


class TestDefaults:
    def test_defaults_match_documented_behavior(self):
        args = build_parser().parse_args(["--nes", "--tn=127.0.0.1"])
        assert args.dest_port == 5060
        assert args.thread_count == 10
        assert args.counter == 99999999
        assert args.mtu is None
        assert args.library is False
        assert args.verbose is False
        assert args.skip_live_check is False

    def test_skip_live_check_flag_parses(self):
        args = build_parser().parse_args(["--enum", "--tn=127.0.0.1", "--skip-live-check"])
        assert args.skip_live_check is True

    def test_assume_yes_flag_parses(self):
        args = build_parser().parse_args(["--enum", "--tn=127.0.0.1", "--yes"])
        assert args.assume_yes is True
        args = build_parser().parse_args(["--enum", "--tn=127.0.0.1", "-y"])
        assert args.assume_yes is True

    def test_response_timeout_defaults_to_none_meaning_not_explicitly_set(self):
        # None (not 5.0) at parse time is deliberate: nes.py/enum.py/das.py
        # each resolve None to the historical 5.0 default themselves, but
        # also use "was --rt explicitly given at all" as a signal to widen
        # SIP-ENUM/SIP-DAS's liveness pre-check timeout to match - a bare
        # 5.0 default here would be indistinguishable from an operator
        # explicitly passing --rt 5.
        args = build_parser().parse_args(["--nes", "--tn=127.0.0.1"])
        assert args.response_timeout is None

    def test_response_timeout_flag_parses(self):
        args = build_parser().parse_args(["--nes", "--tn=127.0.0.1", "--rt", "1"])
        assert args.response_timeout == 1.0
        args = build_parser().parse_args(["--nes", "--tn=127.0.0.1", "--response-timeout", "0.5"])
        assert args.response_timeout == 0.5

    def test_from_to_default_to_bundled_wordlists(self):
        args = build_parser().parse_args(["--nes", "--tn=127.0.0.1"])
        assert args.from_user.endswith("fromUser.txt")
        assert args.to_user.endswith("toUser.txt")

    def test_ip_list_defaults_to_output_directory(self):
        args = build_parser().parse_args(["--nes", "--tn=127.0.0.1"])
        assert args.ip_list == "output/ip_list.txt"


class TestValidation:
    def test_invalid_target_network_is_rejected_at_parse_time(self):
        with pytest.raises(SystemExit):
            build_parser().parse_args(["--nes", "--tn=not-an-ip"])

    def test_non_integer_count_is_rejected_at_parse_time(self):
        # Regression for F15: -c used to lack type=int, so a bad value
        # crashed deep inside das.py instead of failing cleanly here.
        with pytest.raises(SystemExit):
            build_parser().parse_args(["--das", "--tn=127.0.0.1", "-c", "not-a-number"])

    def test_non_integer_thread_count_is_rejected_at_parse_time(self):
        with pytest.raises(SystemExit):
            build_parser().parse_args(["--nes", "--tn=127.0.0.1", "--tc", "not-a-number"])

    def test_non_integer_dest_port_is_rejected_at_parse_time(self):
        with pytest.raises(SystemExit):
            build_parser().parse_args(["--nes", "--tn=127.0.0.1", "--dp", "not-a-number"])

    def test_zero_response_timeout_is_rejected_at_parse_time(self):
        # positive_float (shared with --pps): 0 would make sip_packet's
        # socket.settimeout(0) non-blocking instead of "wait 0 seconds",
        # not a sane timeout value.
        with pytest.raises(SystemExit):
            build_parser().parse_args(["--nes", "--tn=127.0.0.1", "--rt", "0"])

    def test_modules_are_mutually_exclusive(self):
        with pytest.raises(SystemExit):
            build_parser().parse_args(["--nes", "--enum", "--tn=127.0.0.1"])


class TestFlagAliases:
    @pytest.mark.parametrize("flag", ["--nes", "--network-scanner"])
    def test_nes_aliases(self, flag):
        args = build_parser().parse_args([flag, "--tn=127.0.0.1"])
        assert args.network_scanner is True

    @pytest.mark.parametrize("flag", ["--das", "--dos-attack-simulator"])
    def test_das_aliases(self, flag):
        args = build_parser().parse_args([flag, "--tn=127.0.0.1"])
        assert args.dos_attack_simulator is True


class TestRootPrivilegeCheck:
    def test_das_without_l_as_non_root_is_a_clean_exit_not_a_traceback(self, monkeypatch, capsys):
        # SIP-DAS's default (Scapy raw packet / spoofing) mode needs root.
        # Without this upfront check, a non-root run used to fail deep
        # inside Scapy with a much less clear permission error, well after
        # wordlists/liveness-probe work had already happened.
        monkeypatch.setattr("os.geteuid", lambda: 1000)
        monkeypatch.setattr(
            "sys.argv",
            ["mr.sip.py", "--das", "--mt=invite", "-c", "1", "--tn=127.0.0.1"],
        )
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1
        out = capsys.readouterr().out
        assert "root privileges" in out
        assert "sudo" in out

    def test_das_with_l_as_non_root_skips_the_check(self, monkeypatch, capsys):
        # -l (socket library mode) needs no raw packets/spoofing, so it must
        # not require root - proven here by letting the run fail at the
        # next validation step (a bad --to wordlist) instead of the root
        # check, which would fail first if it incorrectly still applied.
        monkeypatch.setattr("os.geteuid", lambda: 1000)
        monkeypatch.setattr(
            "sys.argv",
            ["mr.sip.py", "--das", "--mt=invite", "-c", "1", "--tn=127.0.0.1", "--to=/nonexistent/wordlist.txt", "-l"],
        )
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1
        out = capsys.readouterr().out
        assert "root privileges" not in out
        assert "File not found" in out

    def test_das_without_l_as_root_skips_the_check(self, monkeypatch, capsys):
        monkeypatch.setattr("os.geteuid", lambda: 0)
        monkeypatch.setattr(
            "sys.argv",
            ["mr.sip.py", "--das", "--mt=invite", "-c", "1", "--tn=127.0.0.1", "--to=/nonexistent/wordlist.txt"],
        )
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1
        out = capsys.readouterr().out
        assert "root privileges" not in out
        assert "File not found" in out
