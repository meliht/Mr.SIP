import itertools
import logging
import os

from src.core import errors, net_utils, sip_packet, theme, threadpool

logger = logging.getLogger(__name__)

_DEFAULT_FROM_USER = str(net_utils.WORDLISTS_DIR / "fromUser.txt")
_DEFAULT_TO_USER = str(net_utils.WORDLISTS_DIR / "toUser.txt")


def _scan_one(item, message_type, dest_port, client_ip, ip_list_path, timeout):
    host, from_user, to_user = item
    packet = sip_packet.sip_packet(
        message_type, host, dest_port, client_ip,
        from_user=from_user, to_user=to_user, protocol="socket", wait=True, timeout=timeout,
    )
    try:
        result = packet.generate_packet()
    except errors.PacketSendError:
        return None
    net_utils.printResult(result, str(host), ip_list_path)
    return host


def _resolve_user_pairs(message_type, from_user, to_user, args):
    """Decide which (from, to) identity pairs to probe each target with."""
    if message_type in ("register", "subscribe"):
        # register.message's Request-URI and To: header are both
        # "sip:[[to_user]]@server" - a blank to_user produced an invalid
        # "sip:@server" SIP-URI and Asterisk silently dropped every REGISTER
        # probe (this was finding F3). REGISTER/SUBSCRIBE ask "does the
        # server accept this identity", so to_user must be the same AOR as
        # from_user for each probe, not blank and not an independent
        # from_user x to_user cross-product (which would also waste probes
        # on from/to combinations that could never be valid registrations).
        return [(user, user) for user in from_user]

    # Identity is intentionally cross-producted for options/invite/etc. (the
    # original author's own comment: "both fromUser and toUser should be
    # accepted") - a deliberate feature for identity-aware probing when the
    # operator supplies their own --from/--to. But --from/--to default to
    # the bundled 9000-line wordlists, which are sized for SIP-ENUM/SIP-DAS,
    # not for NES's default invocation. Each side is collapsed to its first
    # entry independently, based on whether *that specific side* was left at
    # its own default - not only when both sides were (F20): leaving just
    # one side on the bundled wordlist while overriding the other used to
    # still cross-product against the full 9000-line default, e.g. an
    # explicit 9-entry --from against the default --to queued 9*9000
    # requests per target instead of the intended 9. An explicit --from/--to
    # (of any size) still gets the real cross-product on that side, exactly
    # as designed.
    if args.from_user == _DEFAULT_FROM_USER:
        from_user = from_user[:1]
    if args.to_user == _DEFAULT_TO_USER:
        to_user = to_user[:1]

    return list(itertools.product(from_user, to_user))


def _warn_if_experimental_user_lists(user_pairs, args):
    if len(user_pairs) > 1 and (os.path.isfile(args.from_user) or os.path.isfile(args.to_user)):
        logger.warning(
            "You gave a list of user names ('%s', '%s') for SIP-NES. "
            "This is yet an experimental feature. (WIP)",
            args.from_user, args.to_user,
        )
        logger.warning(
            "If this was not what you wanted, specify user names with "
            "'--to' and '--from' arguments."
        )


def _looks_like_file(path: str) -> bool:
    if "/" in path or "\\" in path:
        return True
    _, ext = os.path.splitext(path)
    return bool(ext and ext.lower() in (".txt", ".lst", ".csv", ".log", ".wordlist"))


def _resolve_target_networks(args, user_pairs, value_errors):
    """Expand --tn into the list of individual target IPs to probe.

    Accepts a dash range ("A-B") or a CIDR/subnet ("A.B.C.D/N"); a plain
    single address resolves to an empty list here (the caller's single-probe
    path handles that case directly) unless paired with more than one user
    pair, in which case it's kept as a one-element list and the operator is
    warned about the resulting permutation count.
    """
    target_network = args.target_network

    if "-" in target_network or "/" in target_network:
        return net_utils.expand_target_network(target_network, value_errors)

    if len(user_pairs) > 1:
        logger.warning(
            "Calculating all permutations of target network ('%s'), from user name "
            "list ('%s') and to user name list ('%s').",
            args.target_network, args.from_user, args.to_user,
        )
        logger.warning("Depending on the list sizes, this might take a long time.")
        return [args.target_network]

    return []


def run(args, conf, client_ip):
    value_errors = []
    conf.verb = 0

    # args.response_timeout is None unless --rt was explicitly given (see
    # cli.py) - resolved to sip_packet's own historical default here, rather
    # than passing None straight through, which would turn socket.settimeout()
    # into "block forever" instead of "use the default".
    response_timeout = args.response_timeout if args.response_timeout is not None else 5.0

    message_type = args.message_type.lower() if args.message_type else "options"
    if args.target_network is None:
        value_errors.append("Please specify a valid target network using the --tn flag.")

    if not os.path.isfile(args.from_user) and _looks_like_file(args.from_user):
        value_errors.append(f"File not found: '{args.from_user}'. If you intended to specify a literal username, avoid using common file extensions or path separators.")
    if not os.path.isfile(args.to_user) and _looks_like_file(args.to_user):
        value_errors.append(f"File not found: '{args.to_user}'. If you intended to specify a literal username, avoid using common file extensions or path separators.")

    # Whether --from/--to names a wordlist file or is a literal single
    # value is decided by checking the filesystem, not by guessing from the
    # string (a literal value containing "txt", or a wordlist path without
    # a ".txt" extension, used to be misclassified by a substring check).
    from_user = (
        net_utils.read_lines(args.from_user, predicate=str.isalnum)
        if os.path.isfile(args.from_user) else [args.from_user]
    )
    to_user = (
        net_utils.read_lines(args.to_user, predicate=str.isalnum)
        if os.path.isfile(args.to_user) else [args.to_user]
    )

    user_pairs = _resolve_user_pairs(message_type, from_user, to_user, args)
    _warn_if_experimental_user_lists(user_pairs, args)

    # Raised here (before touching args.target_network below) if --tn was
    # missing - target_network is guaranteed to be a real string past this
    # point.
    net_utils.check_value_errors(value_errors)

    target_networks = _resolve_target_networks(args, user_pairs, value_errors)

    # Computed once regardless of which branch above set target_networks
    # (empty list when none did, e.g. a single target with a single user
    # pair - the synchronous single-probe path below handles that case).
    target_network__fromUser__toUser = [
        (tn, fu, tu) for tn, (fu, tu) in itertools.product(target_networks, user_pairs)
    ]

    net_utils.check_value_errors(value_errors)
    net_utils.printInital("Network scan :", conf.iface, client_ip)

    counter = 0
    if "-" in args.target_network or "/" in args.target_network or len(user_pairs) > 1:
        # Distinct identities actually being probed (post-collapse), not the
        # raw wordlist file lengths - from_user/to_user above are the full
        # 9000-line files even when _resolve_user_pairs collapsed one side
        # down to a single default entry, so len(from_user) + len(to_user)
        # would misleadingly claim thousands of names were "checked" when
        # the real packet_count below reflects far fewer.
        distinct_identities = len({fu for fu, _ in user_pairs}) + len({tu for _, tu in user_pairs})
        threadpool.confirm_bulk_run(
            distinct_identities, "User names (to and from)",
            len(target_networks), len(target_network__fromUser__toUser),
            force=getattr(args, "assume_yes", False),
        )

        try:
            found = threadpool.run_worker_pool(
                target_network__fromUser__toUser,
                _scan_one,
                int(args.thread_count),
                extra_args=(message_type, args.dest_port, client_ip, args.ip_list, response_timeout),
            )
            # _scan_one() returns the target host on every successful probe,
            # once per (host, from_user, to_user) triple - counting len(found)
            # directly double-counts a host that answered more than one
            # identity pair (the default for --mt=register/subscribe, which
            # always cross-products the full wordlist - see
            # _resolve_user_pairs()). A single host answering all 9000
            # entries of the bundled default wordlist used to report as
            # "9000 live IP address(es) found" here, while the -i output
            # file (deduplicated separately by printResult()) correctly held
            # just the one line. set() makes this count match what the
            # message actually claims: distinct live hosts, not probe count.
            counter = len(set(found))
        except KeyboardInterrupt as e:
            found = getattr(e, "results", [])
            counter = len(set(found))
            logger.info(
                theme.panel("SIP-NES summary", [f"{counter} live IP address(es) found."])
            )
            raise
    else:
        if len(user_pairs) == 1:
            # Same probe-and-record logic as the bulk path's _scan_one(),
            # just called directly instead of through run_worker_pool - not
            # worth the thread-pool/queue overhead for exactly one item.
            host = args.target_network
            found = _scan_one(
                (host, *user_pairs[0]), message_type, args.dest_port, client_ip, args.ip_list, response_timeout,
            )
            counter = 1 if found is not None else 0

    logger.info(
        theme.panel("SIP-NES summary", [f"{counter} live IP address(es) found."])
    )
