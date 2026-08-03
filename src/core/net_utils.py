"""
IP/network helpers, file IO, console-output helpers, and argparse `type=`
validators (check_ip_address, positive_int) shared by all three Mr.SIP
modules (NES/ENUM/DAS).
"""

import argparse
import ipaddress
import logging
import os
import random
import socket
import struct
import subprocess
import sys
import threading
from pathlib import Path

import netifaces

from src.core import errors, logging_config, sip_packet  # noqa: F401 - importing logging_config
# registers the FOUND log level and Logger.found() as an import-time side
# effect, which printResult() below depends on. Importing it here (rather
# than relying on cli.py having already done so) means this module's use of
# logger.found() doesn't depend on caller import order.

logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
WORDLISTS_DIR = DATA_DIR / "wordlists"
METHOD_DIR = DATA_DIR / "method"

file_lock = threading.Lock()


def read_lines(path, predicate=None):
    """Read *path* into a list of stripped, non-empty lines.

    *predicate*, if given, is applied to each stripped line and only lines
    passing it are kept - e.g. str.isalnum for extension wordlists
    (from/to/sp user). Left as None for wordlists like userAgent.txt whose
    real entries ("Brcm Callctrl/1.5.1.0 MxSF/v3.2.6.26") aren't
    alphanumeric; applying an isalnum filter there would silently empty the
    list instead of just skipping blank lines.

    Single source of truth for the "open a wordlist file, get usable lines
    out of it" operation - previously duplicated with divergent behavior
    across nes.py, enum.py, and das.py.
    """
    try:
        with open(path) as f:
            lines = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        # Left to propagate as-is - cli.main() already has a clean, specific
        # "File not found: X" handler for this exact exception.
        raise
    except UnicodeDecodeError as e:
        # A wordlist that isn't valid UTF-8 (a binary file pointed at by
        # mistake, a wordlist saved in Latin-1/Windows-1252, ...) used to
        # crash with a raw traceback here instead of the clean CLI error
        # every other bad-input case gets.
        raise errors.MrSipError(f"{path} is not a valid UTF-8 text file: {e}") from e
    except OSError as e:
        # Any other reason open() can fail (a directory instead of a file,
        # a permission-denied path, ...) used to crash with a raw traceback
        # revealing the full local filesystem path - a bad --from/--to/--su/
        # --ua/--il value is an easy, common typo (e.g. tab-completing to
        # the wrong entry), not something that should look like the tool
        # itself broke.
        raise errors.MrSipError(f"Could not read {path}: {e.strerror}") from e
    if predicate is not None:
        lines = [line for line in lines if predicate(line)]
    return lines


def read_ip_list(path):
    """Read SIP-NES's output/ip_list.txt format (`ip;user_agent;type` per
    line) and return just the IP field. Also works for a plain one-IP-per-
    line file. Single source of truth - previously duplicated verbatim in
    enum.py and das.py.
    """
    return [line.split(";")[0] for line in read_lines(path)]


def writeFile(file, content):
    parent = os.path.dirname(file)
    if parent:
        os.makedirs(parent, exist_ok=True)
    try:
        with open(file, "a+") as f:
            f.write(content)
    except OSError as e:
        # A directory or a permission-denied path given as -i/--ip-save-list
        # used to crash with a raw traceback mid-scan instead of a clean
        # error - the same class of gap as read_lines() above.
        raise errors.MrSipError(f"Could not write to {file}: {e.strerror}") from e


def randomIPAddressFromNetwork(IP, Netmask, Network):
    network = Network or f"{str(IP)}/{str(Netmask)}"
    targetNetwork = ipaddress.IPv4Network(str(network), strict=False)
    ipCount = int(targetNetwork.num_addresses)
    firstIpAddress = targetNetwork.network_address
    randomInt = random.randint(0, ipCount - 1)
    randomIpAddress = firstIpAddress + randomInt
    return str(randomIpAddress.exploded)


def randomIPAddress():
    return ".".join(
        [
            str(random.randrange(1, 255)),
            str(random.randrange(1, 255)),
            str(random.randrange(1, 255)),
            str(random.randrange(1, 255)),
        ]
    )


def probe_liveness(target, dest_port, client_ip, message_type="options", from_user=None, to_user=None, timeout=2):
    """Send a single, short-timeout SIP probe to check whether *target*
    responds at all. Shared by SIP-ENUM (skip a target instead of running a
    full enumeration against something that never answers) and SIP-DAS (warn
    before flooding, without blocking - see --skip-live-check).

    from_user/to_user default to a random, non-empty check-user - an empty
    to_user produces "OPTIONS sip:@host" (empty user before the @), a
    malformed Request-URI that Asterisk silently drops instead of responding
    to (the same F3 pathology CHANGELOG.md documents for register.message's
    blank to_user), which would make a perfectly live target look dead.

    Returns the response dict from sip_packet.generate_packet() on any
    reply (including an error-status SIP response - the caller decides what
    a given status code means), or None if nothing came back in time. This
    is deliberately a much shorter timeout than sip_packet's own 5s default
    - it's answering "did anything respond," not "wait for this specific
    server's full response."
    """
    if from_user is None:
        from_user = f"mrsip_check_{sip_packet.sip_packet.get_rand_tag()}"
    if to_user is None:
        to_user = from_user

    probe = sip_packet.sip_packet(
        message_type, target, dest_port, client_ip,
        from_user=from_user, to_user=to_user,
        protocol="socket", wait=True, timeout=timeout,
    )
    try:
        return probe.generate_packet()
    except errors.PacketSendError:
        return None


def promisc(state, iface):
    # Manage interface promiscuity. valid states are on or off.
    # iface is the operator's own --if CLI argument (local, trusted caller),
    # not remote/untrusted input.
    if not sys.platform.startswith("linux"):
        logger.debug(
            "Skipping promiscuous mode toggle: 'ip link set' is Linux-only, current platform is %s.",
            sys.platform,
        )
        return
    # subprocess.run's returncode is the real process exit code - unlike the
    # os.system() call this replaced, whose return value is a packed wait()
    # status (exit code shifted left 8 bits on POSIX), so a real exit-code-1
    # failure showed up as 256, not 1. The old `if ret == 1:` check could
    # therefore never fire on an actual permission failure.
    result = subprocess.run(
        ["ip", "link", "set", iface, "promisc", state],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        logger.warning("You must run this script with root permissions.")


_server_list_cache = None


def defineTargetType(user_agent):
    global _server_list_cache
    if _server_list_cache is None:
        _server_list_cache = [
            server.upper()
            for server in read_lines(str(WORDLISTS_DIR / "servers.txt"), predicate=str.isalnum)
        ]
    for server in _server_list_cache:
        if server in user_agent.upper():
            return "Server"
    return "Client"


def printInital(moduleName, client_iface, client_ip):
    logger.info("Client Interface: %s", client_iface)
    logger.info("Client IP: %s", client_ip)
    logger.info("%s process started.", moduleName)


_written_targets_cache = {}


def _load_existing_targets(path):
    """Targets already present in *path* (e.g. left over from a previous
    SIP-NES run appending to the same -i output file), keyed by the target
    field only - the same "ip;user_agent;type" format read_ip_list() parses.
    """
    try:
        with open(path) as f:
            return {line.split(";", 1)[0].strip() for line in f if line.strip()}
    except FileNotFoundError:
        return set()
    except OSError as e:
        # A directory given as -i/--ip-save-list used to crash with a raw
        # traceback here (see writeFile()'s same fix, right below).
        raise errors.MrSipError(f"Could not read {path}: {e.strerror}") from e


def printResult(result, target, ops_ip_list):
    if "." not in target:
        target = decimal_to_octets(target)
    # getResponse() can return {} (unparseable status line) or None (no
    # headers past the status line) instead of a full dict - don't assume
    # "headers" is present.
    response = result.get("response") or {}
    headers = response.get("headers") or {}
    user_agent = ""
    for key, value in headers.items():
        # value is None for a header line with no ":" (see
        # sip_packet.getResponse) - skip rather than crash on list(None).
        if key in ("user-agent", "server") and value:
            user_agent = list(value)[0]

    target_type = defineTargetType(user_agent)
    label = "SIP Server" if target_type == "Server" else "SIP Client"

    # F27: previously reread and rewrote the entire ip_list.txt (dedup via a
    # since-removed removeDuplicateLines()) on every single discovery - O(n)
    # work per host found, O(n^2) total across a scan, all done under
    # file_lock so it serialized every worker thread's result write. An
    # in-memory set (loaded once per output path from any pre-existing
    # content, e.g. a prior run's results) turns "already recorded this
    # target" into an O(1) check and a plain append, with no rewrite needed.
    with file_lock:
        seen = _written_targets_cache.setdefault(ops_ip_list, _load_existing_targets(ops_ip_list))
        if target in seen:
            return
        seen.add(target)
        writeFile(ops_ip_list, f"{target};{user_agent};{label}\n")

    if target_type == "Server":
        logger.found("New live IP found on %s, it seems as a SIP Server (%s).", target, user_agent)
    else:
        logger.found("New live IP found on %s, it seems as a SIP Client.", target)


def decimal_to_octets(dec):
    return socket.inet_ntoa(struct.pack("!L", int(dec)))


def check_value_errors(value_errors):
    if value_errors:
        # No inline color here: cli.main() logs MrSipError via logger.error(),
        # and ColorFormatter already renders the "[ ERROR ]" tag in red.
        raise errors.MrSipError("\n".join(value_errors))


def get_client_network_info(iface):
    try:
        addr_info = netifaces.ifaddresses(str(iface))[netifaces.AF_INET][0]
    except (ValueError, KeyError, IndexError):
        raise errors.InvalidInterfaceError(
            "Please specify a valid interface name with --if option."
        ) from None
    return addr_info["addr"], addr_info.get("netmask")


def positive_int(value):
    """argparse type= validator for counters that must be at least 1 (e.g.
    --tc/--thread-count). threadpool.run_worker_pool() starts
    range(thread_count) worker threads - a count of 0 or less means no
    thread ever exists to drain the work queue, hanging the run forever.
    """
    try:
        parsed = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value!r} is not an integer") from None
    if parsed < 1:
        raise argparse.ArgumentTypeError(f"must be at least 1 (got {parsed})")
    return parsed


def port_number(value):
    """argparse type= validator for a UDP/TCP port number (e.g.
    --dp/--destination-port). socket.connect()/bind() raise OverflowError
    for a value outside 0-65535, which isn't one of the exception types
    sip_packet.generate_packet() treats as a clean PacketSendError - an
    out-of-range --dp used to crash with a raw traceback deep inside a scan.
    """
    try:
        parsed = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value!r} is not an integer") from None
    if parsed < 1 or parsed > 65535:
        raise argparse.ArgumentTypeError(f"must be between 1 and 65535 (got {parsed})")
    return parsed


def non_negative_int(value):
    """argparse type= validator for counters that may legitimately be 0
    (e.g. -c/--count, where 0 means "flood indefinitely" - see das.py).
    Rejects negative values: das.py's `while infinite or i < counter` loop
    silently sends 0 packets for a negative counter instead of raising an
    error, which used to look like a hang or a silent no-op rather than the
    invalid input it actually was.
    """
    try:
        parsed = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value!r} is not an integer") from None
    if parsed < 0:
        raise argparse.ArgumentTypeError(f"must be 0 or greater (got {parsed})")
    return parsed


def mtu_size(value):
    """argparse type= validator for --mtu (Scapy fragmentation size).
    Mirrors the runtime check in sip_packet.generate_packet() - 68 bytes is
    the smallest IP datagram a compliant stack is required to handle - but
    fails at parse time instead of per-packet deep inside a flood loop,
    where a bad value would otherwise surface as a wall of "failed" sends
    (each one independently raising and being swallowed as PacketSendError)
    instead of one clear error before anything is sent.
    """
    try:
        parsed = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value!r} is not an integer") from None
    if parsed < 68:
        raise argparse.ArgumentTypeError(f"must be at least 68 bytes (got {parsed})")
    return parsed


def positive_float(value):
    """argparse type= validator for rate limits that must be > 0 (e.g.
    --pps/--packets-per-second). A value of 0 would make the send loop's
    sleep-per-packet interval infinite, hanging the run forever.
    """
    try:
        parsed = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value!r} is not a number") from None
    if parsed <= 0:
        raise argparse.ArgumentTypeError(f"must be greater than 0 (got {parsed})")
    return parsed


def _validate_dotted_quad(ip_str, error_message):
    """Validate ip_str is 4 dot-separated octets, each 0-255. Raises
    argparse.ArgumentTypeError(error_message) on any failure - single source
    of the octet-validation logic previously triplicated across
    check_ip_address's range/CIDR/plain-IP branches, two of which were
    missing the int() ValueError guard the third one had.
    """
    if "." not in ip_str:
        raise argparse.ArgumentTypeError(error_message)
    numbers = ip_str.split(".")
    if len(numbers) != 4:
        raise argparse.ArgumentTypeError(error_message)
    for number in numbers:
        try:
            num = int(number)
        except ValueError:
            raise argparse.ArgumentTypeError(error_message) from None
        if num > 255 or num < 0:
            raise argparse.ArgumentTypeError(error_message)


def check_ip_address(value):
    if "-" in value:
        for ip in value.split("-"):
            _validate_dotted_quad(ip, f"{ip} is an invalid range IP address")
        return value
    if "/" in value:
        parts = value.split("/")
        if len(parts) != 2:
            raise argparse.ArgumentTypeError(f"{value} is an invalid subnet IP address")
        ip, subnet = parts
        try:
            mask = int(subnet)
        except ValueError:
            raise argparse.ArgumentTypeError(f"{value} is an invalid subnet IP address") from None
        if mask < 8 or mask > 32:
            raise argparse.ArgumentTypeError(f"CIDR subnet mask must be between 8 and 32 (got /{subnet})")
        _validate_dotted_quad(ip, f"{value} is an invalid subnet IP address")
        return value
    _validate_dotted_quad(value, f"{value} is an invalid IP address")
    return value


def expand_target_network(target_network, value_errors=None):
    """Expand target_network (dash-range, CIDR/subnet, or single IP) into individual target IPs.

    If target_network is a single IP, returns [target_network].
    On errors (like bad ranges), appends a message to value_errors and returns []
    if given, otherwise raises errors.MrSipError (never a bare exception type -
    cli.main() only has a clean handler for MrSipError/FileNotFoundError/
    KeyboardInterrupt; anything else would crash with a raw traceback).
    Only ValueError/IndexError from malformed input is caught here - a real
    programming bug (TypeError, AttributeError, ...) should still propagate
    as itself rather than being relabeled as a validation error (same
    reasoning applied to sip_packet.generate_packet()).
    """
    if "-" in target_network:
        host_range = target_network.split("-")
        try:
            host = ipaddress.IPv4Address(str(host_range[0]))
            last = ipaddress.IPv4Address(str(host_range[1]))
            if host > last:
                raise ValueError(f"Second IP address ({last}) must be bigger than first IP address ({host})")
            num_addresses = int(last) - int(host) + 1
            if num_addresses > 65536:
                logger.warning(
                    "Expanding a large IP range (%d addresses). This may consume significant memory.",
                    num_addresses
                )
            return [decimal_to_octets(h) for h in range(int(host), int(last) + 1)]
        except (ValueError, IndexError) as e:
            if value_errors is not None:
                value_errors.append(f"Error: {e}.")
                return []
            raise errors.MrSipError(f"Error: {e}.") from e

    if "/" in target_network:
        try:
            net = ipaddress.IPv4Network(str(target_network), strict=False)
            if net.num_addresses > 65536:
                logger.warning(
                    "Expanding a large subnet /%d (%d addresses). This may consume significant memory.",
                    net.prefixlen, net.num_addresses
                )
            return [str(ip) for ip in net] if net.num_addresses <= 2 else [str(ip) for ip in net.hosts()]
        except ValueError as e:
            if value_errors is not None:
                value_errors.append(f"Error expanding subnet: {e}")
                return []
            raise errors.MrSipError(f"Error expanding subnet: {e}") from e

    return [target_network]

