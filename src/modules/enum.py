import itertools
import logging
import re

from src.core import errors, net_utils, sip_packet, theme, threadpool

logger = logging.getLogger(__name__)


def _extract_header_value(headers, name):
    """First value of a parsed response header, or None if absent/empty.

    sip_packet.getResponse() splits each header's raw value on "," into a
    list (headers like WWW-Authenticate carry multiple comma-separated
    params) and can leave a value of None for a header line with no ":" -
    both need guarding before indexing into it.
    """
    value = headers.get(name)
    if not value:
        return None
    return value[0]


def _extract_realm(headers):
    """Pull the realm="..." param out of a parsed WWW-Authenticate header.

    sip_packet.getResponse() splits the raw header value on "," (e.g.
    'Digest realm="asterisk", nonce="163545"' becomes
    ['Digest realm="asterisk"', 'nonce="163545"']), so realm is its own
    list entry rather than a separate dict key - has to be picked out with
    a regex, not a plain lookup.
    """
    parts = headers.get("www-authenticate")
    if not parts:
        return None
    for part in parts:
        match = re.search(r'realm="([^"]*)"', part)
        if match:
            return match.group(1)
    return None


def _classify_confidence(code, baseline_code):
    """Is a 401/403 "extension exists" finding trustworthy, or indistinguishable
    from this target's own blanket-rejection baseline?

    baseline_code is the status code a guaranteed-nonexistent random user got
    during the liveness pre-check for this same target - None if no baseline
    is available at all (--skip-live-check).

    An exact match against the baseline is "can't tell them apart"
    (unconfirmed); anything else - including no baseline at all - is
    confirmed. code=200 ("no auth required") is always confirmed even if the
    baseline also got 200: a server accepting *any* user without auth is
    itself a real, actionable finding, not a false positive to suppress.

    This assumes a target is internally consistent (same code every time for
    a blanket reject) - see CHANGELOG.md's 1.6.0/1.6.4 sections for the live
    lab evidence behind that assumption, not just an assumption of
    convenience.
    """
    if code == 200:
        return True
    if baseline_code is None:
        return True
    return code != baseline_code


def _check_one(item, message_type, dest_port, client_ip, timeout, baseline_map):
    target_network, raw_user_id = item
    user_id = raw_user_id.strip()
    baseline_code = baseline_map.get(target_network)
    logger.debug("Checking %s@%s (baseline=%s)", user_id, target_network, baseline_code)
    packet = sip_packet.sip_packet(
        message_type, target_network, dest_port, client_ip,
        from_user=user_id, to_user=user_id, protocol="socket", wait=True, timeout=timeout,
    )
    try:
        result = packet.generate_packet()
    except errors.PacketSendError as e:
        logger.debug("PacketSendError for %s@%s: %s", user_id, target_network, e)
        return None

    response = result.get("response") or {}
    code = response.get("code")
    headers = response.get("headers") or {}
    if not response or code == 200:
        server_info = _extract_header_value(headers, "server") or _extract_header_value(headers, "user-agent")
        suffix = f" (Server: {server_info})" if server_info else ""
        # No auth required is the more severe finding - highlight in red
        # instead of the default FOUND green, same as the 401/403 case below.
        logger.found(theme.colorize(
            f"New SIP extension found in {target_network}: {user_id}, authentication not required!{suffix}",
            theme.ERROR,
        ))
        return {"user": user_id, "confirmed": True}
    if code in (401, 403):
        confirmed = _classify_confidence(code, baseline_code)
        realm = _extract_realm(headers)
        realm_suffix = f" (realm: {realm})" if realm else ""
        if confirmed:
            logger.found(
                "New SIP extension found in %s: %s, authentication required%s.",
                target_network, user_id, realm_suffix,
            )
        else:
            logger.found_unconfirmed(
                "Possible SIP extension in %s: %s, authentication required%s - matches this target's "
                "blanket-rejection baseline, unconfirmed.",
                target_network, user_id, realm_suffix,
            )
        return {"user": user_id, "confirmed": confirmed}
    logger.debug("No match for %s@%s (code=%s)", user_id, target_network, code)
    return None


def _resolve_live_worker(target, message_type, dest_port, client_ip, override_timeout):
    random_user = f"mrsip_check_{sip_packet.sip_packet.get_rand_tag()}"
    timeout_kwargs = {} if override_timeout is None else {"timeout": override_timeout}
    result = net_utils.probe_liveness(
        target, dest_port, client_ip,
        message_type=message_type, from_user=random_user, to_user=random_user,
        **timeout_kwargs,
    )
    if result is None:
        return None

    code = (result.get("response") or {}).get("code")
    is_blanket = code in (401, 403)
    return {"target": target, "is_blanket": is_blanket, "code": code, "user": random_user}


def _log_tiered(items, log_single, log_few, log_many):
    """Log a tiered summary for a list of items instead of one line per item:
    a full single-item message for exactly one, a "name everything" message
    for 2-5, and a count-only message for 6+ - avoids a wall of near-
    identical lines on a large host list while still naming names for a
    small one.

    log_single(item) is called for exactly one item, log_few(items) for
    2-5, log_many(count) for 6+ - each callback owns its own message
    wording and logger level, since callers here log at different levels
    (logging.WARNING vs. the dedicated BLANKET_WARN) with different
    argument shapes (a bare target string vs. a (target, code, user) tuple).

    Both of _resolve_live_targets()'s tiered warnings (skipped targets,
    blanket-rejecting targets) used to implement this same three-way split
    independently - they drifted out of sync once already (one copy had
    the >5 cap, the other didn't - see CHANGELOG.md's 1.6.7 section),
    which this single shared implementation makes structurally impossible.
    """
    if not items:
        return
    if len(items) == 1:
        log_single(items[0])
    elif len(items) <= 5:
        log_few(items)
    else:
        log_many(len(items))


def _resolve_live_targets(target_networks, message_type, dest_port, client_ip, skip_live_check, thread_count=1, override_timeout=None):
    """Filter target_networks down to the ones that actually respond to a
    quick liveness probe - enumerating a target that never answers at all
    just burns the full wordlist's worth of timeouts for a guaranteed "0
    found" result. Also flags servers that reject every unmatched request
    the same way (e.g. modern PJSIP) - see docs/usage-guide.md's F6 note.

    Passing --skip-live-check disables this entirely (no probing, every
    target is used as given) for operators who already know their targets
    are live and don't want the extra round-trip per target.

    override_timeout is None unless --rt was explicitly given: the probe
    then keeps net_utils.probe_liveness()'s own short fixed timeout (fast,
    good default for scanning many hosts). Passing an explicit --rt is a
    deliberate "be more patient" request from the operator - without
    threading it through here too, a genuinely live but slow target would
    still be silently filtered out as unreachable by this pre-check
    regardless of how long --rt told the real probes to wait.

    Returns (live_targets, baseline_map) - baseline_map maps each live
    target to the status code its own liveness probe (a guaranteed-
    nonexistent random user) got, or None for a target with no baseline at
    all (--skip-live-check). The real enumeration pass uses this baseline
    to grade each 401/403 finding as confirmed or unconfirmed - see
    _classify_confidence().
    """
    if skip_live_check:
        return target_networks, {}

    logger.info("Performing liveness pre-check for %d target(s)...", len(target_networks))

    results = threadpool.run_worker_pool(
        target_networks,
        _resolve_live_worker,
        thread_count,
        extra_args=(message_type, dest_port, client_ip, override_timeout)
    )

    live_targets = []
    baseline_map = {}
    blanket_rejecting = []
    for res in results:
        if res is not None:
            live_targets.append(res["target"])
            baseline_map[res["target"]] = res["code"]
            if res["is_blanket"]:
                blanket_rejecting.append((res["target"], res["code"], res["user"]))

    skipped_targets = [t for t in target_networks if t not in live_targets]
    _log_tiered(
        skipped_targets,
        log_single=lambda t: logger.warning(
            "Target %s did not respond to a liveness probe - skipping it. "
            "Use --skip-live-check to enumerate it anyway.", t
        ),
        log_few=lambda ts: logger.warning(
            "Targets [%s] did not respond to a liveness probe - skipping them. "
            "Use --skip-live-check to enumerate them anyway.", ", ".join(ts)
        ),
        log_many=lambda n: logger.warning(
            "%d target(s) did not respond to a liveness probe - skipping them. "
            "Use --skip-live-check to enumerate anyway.", n
        ),
    )

    if blanket_rejecting:
        # blanket_warn (not plain warning()) - a dedicated, red-tagged level
        # so this specific F6 signal stands out from routine WARN noise.
        # Still a warning, not an error: the run continues.
        # "e.g. PJSIP" alone used to be the whole explanation here - misleading:
        # confirmed against Asterisk's own source that
        # chan_sip blanket-rejects by default too, on any Asterisk since 1.8
        # (~2011) via alwaysauthreject (compiled default flipped from FALSE
        # to TRUE at that release - unrelated to which channel driver is in
        # use, and not something --mt/the channel choice can work around).
        blanket_rejection_reason = (
            "e.g. PJSIP's endpoint-matching behavior, or chan_sip with alwaysauthreject "
            "enabled (Asterisk's default since 1.8, ~2011)"
        )
        _log_tiered(
            blanket_rejecting,
            log_single=lambda item: logger.blanket_warn(
                "Target %s returned %d for nonexistent user '%s'. "
                "The server may be using blanket-rejection (%s); extension enumeration might produce false positives.",
                item[0], item[1], item[2], blanket_rejection_reason
            ),
            log_few=lambda items: logger.blanket_warn(
                "Targets [%s] returned 401/403 for nonexistent users. "
                "The servers may be using blanket-rejection (%s); extension enumeration might produce false positives.",
                ", ".join(t[0] for t in items), blanket_rejection_reason
            ),
            log_many=lambda n: logger.blanket_warn(
                "%d target(s) returned 401/403 for nonexistent users. "
                "The servers may be using blanket-rejection (%s); extension enumeration might produce false positives.",
                n, blanket_rejection_reason
            ),
        )

    return live_targets, baseline_map


def run(args, conf, client_ip):
    value_errors = []
    conf.verb = 0

    # args.response_timeout is None unless --rt was explicitly given (see
    # cli.py) - resolved here rather than passed through as None, which
    # would turn socket.settimeout() into "block forever" instead of "use
    # the default".
    response_timeout = args.response_timeout if args.response_timeout is not None else 5.0

    message_type = args.message_type.lower() if args.message_type else "subscribe"

    user_list = net_utils.read_lines(args.from_user, predicate=str.isalnum)
    if not user_list:
        value_errors.append("Error: From user not found. Please enter a valid From User list.")

    if args.target_network:
        target_networks = net_utils.expand_target_network(args.target_network, value_errors)
    else:
        target_networks = net_utils.read_ip_list(args.ip_list)
        if not target_networks or len(target_networks[0]) <= 1:
            value_errors.append("Error: Target IP not found. Please run SIP-NES first to detect live hosts, or specify a target network with --tn.")

    net_utils.check_value_errors(value_errors)
    net_utils.printInital("Enumeration", conf.iface, client_ip)

    target_networks, baseline_map = _resolve_live_targets(
        target_networks, message_type, args.dest_port, client_ip, args.skip_live_check,
        int(args.thread_count), override_timeout=args.response_timeout,
    )
    if not target_networks:
        raise errors.MrSipError(
            "None of the target(s) responded to a liveness probe - nothing to enumerate. "
            "Use --skip-live-check to enumerate anyway."
        )

    target_network__user_id = list(itertools.product(target_networks, user_list))

    threadpool.confirm_bulk_run(
        len(user_list), "user IDs", len(target_networks), len(target_network__user_id),
        force=getattr(args, "assume_yes", False),
    )

    logger.debug("running with %d threads", int(args.thread_count))
    try:
        found = threadpool.run_worker_pool(
            target_network__user_id,
            _check_one,
            int(args.thread_count),
            extra_args=(message_type, args.dest_port, client_ip, response_timeout, baseline_map),
        )
    except KeyboardInterrupt as e:
        found = getattr(e, "results", [])
        logger.info(theme.panel("SIP-ENUM summary", _summary_lines(found)))
        raise

    logger.info(theme.panel("SIP-ENUM summary", _summary_lines(found)))


def _summary_lines(found):
    """Format SIP-ENUM's final summary panel body.

    Splits out unconfirmed findings (401/403 responses indistinguishable
    from this target's own blanket-rejection baseline - see
    _classify_confidence()) only when there are any; a run where every
    finding is confirmed keeps the original, simpler wording unchanged.
    """
    unconfirmed = [f for f in found if not f["confirmed"]]
    if unconfirmed:
        confirmed_count = len(found) - len(unconfirmed)
        return [
            f"{len(found)} SIP extension(s) found "
            f"({confirmed_count} confirmed, {len(unconfirmed)} unconfirmed - blanket-reject suspected)."
        ]
    return [f"{len(found)} SIP extension(s) found."]
