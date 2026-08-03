import os
import sys
import time
from argparse import ArgumentParser, RawTextHelpFormatter

from scapy.all import conf

from src import __version__
from src.core import errors, logging_config, net_utils, theme
from src.modules import das, enum, nes

BANNER = r"""
███╗   ███╗██████╗    ███████╗██╗██████╗ 
████╗ ████║██╔══██╗   ██╔════╝██║██╔══██╗
██╔████╔██║██████╔╝   ███████╗██║██████╔╝
██║╚██╔╝██║██╔══██╗   ╚════██║██║██╔═══╝ 
██║ ╚═╝ ██║██║  ██║██╗███████║██║██║     
╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚══════╝╚═╝╚═╝     """ + theme.BOLD + theme.ACCENT + "SIP Security, Attack and Audit Framework\n" + theme.RESET

NES_HELP = "SIP-NES is a network scanner. It needs the IP range or IP subnet information as input. It sends SIP OPTIONS message to each IP address in the subnet/range and according to the responses, it provides the output of the potential SIP clients and servers on that subnet."
ENUM_HELP = "SIP-ENUM is an enumerator. It needs the output of SIP-NES and also pre-defined SIP usernames. It generates SIP REGISTER messages and sends them to all SIP components and tries to find the valid SIP users on the target network. You can write the output in a file."
DAS_HELP = "SIP-DAS is a DoS/DDoS attack simulator. It comprises four components: powerful spoofed IP address generator, SIP message generator, message sender and response parser. It needs the outputs of SIP-NES and SIP-ENUM along with some pre-defined files."

NES_USAGE = """python3 mr.sip.py --nes --tn=<target_IP> --mt=options --from=<from_extension> --to=<to_extension>
python3 mr.sip.py --nes --tn=<target_network_range> --mt=invite --from=<from_extension> --to=<to_extension>
python3 mr.sip.py --nes --tn <target_network_address> --mt=subscribe --from=<from_extension> --to=<to_extension>

NOTE: for message types other than register/subscribe, --from/--to are cross-producted (every
(from, to) pair is probed against each target) - this is deliberate, for identity-aware probing.
Passing your own --from/--to (of any size) opts into that. Without an explicit --from/--to, NES
sends a single generic probe per target instead of exploding against the bundled 9000-line
default wordlists.
"""
ENUM_USAGE = """python3 mr.sip.py --enum --from=<wordlist.txt>
python3 mr.sip.py --enum --tn=<target_IP> --from=<wordlist.txt>
"""
DAS_USAGE = """python3 mr.sip.py --das --mt=invite -c <packet_count> --tn=<target_IP> -r
python3 mr.sip.py --das --mt=invite -c <packet_count> --tn=<target_IP> -s
python3 mr.sip.py --das --mt=invite -c <packet_count> --tn=<target_IP> -m --il=output/ip_list.txt
"""


def build_parser() -> ArgumentParser:
    parser = ArgumentParser(formatter_class=RawTextHelpFormatter)
    parser.add_argument("--version", action="version", version=f"Mr.SIP {__version__}")

    module_group = parser.add_mutually_exclusive_group()
    module_group.add_argument("--nes", "--network-scanner", action="store_true", dest="network_scanner", default=False, help=NES_HELP)
    module_group.add_argument("--enum", "--sip-enumerator", action="store_true", dest="sip_enumerator", default=False, help=ENUM_HELP)
    module_group.add_argument("--das", "--dos-attack-simulator", action="store_true", dest="dos_attack_simulator", default=False, help=DAS_HELP)

    parser.add_argument_group("SIP-NES Usage", NES_USAGE)
    parser.add_argument_group("SIP-ENUM Usage", ENUM_USAGE)
    parser.add_argument_group("SIP-DAS Usage", DAS_USAGE)

    group = parser.add_argument_group("Parameters")
    group.add_argument("--tn", "--target-network", dest="target_network", type=net_utils.check_ip_address, help="Target network range to scan.")
    group.add_argument("--mt", "--message-type", dest="message_type", help="Message type selection. OPTIONS, INVITE, REGISTER, SUBSCRIBE, CANCEL, BYE or other custom method.")
    group.add_argument("--dp", "--destination-port", dest="dest_port", type=net_utils.port_number, default=5060, help="Destination SIP server port number (1-65535). Default is 5060.")
    group.add_argument("--to", "--to-user", dest="to_user", default=str(net_utils.WORDLISTS_DIR / "toUser.txt"), help="To User list file. Default is the bundled toUser.txt.")
    group.add_argument("--from", "--from-user", dest="from_user", default=str(net_utils.WORDLISTS_DIR / "fromUser.txt"), help="From User list file. Default is the bundled fromUser.txt.")
    group.add_argument("--su", "--sp-user", dest="sp_user", default=str(net_utils.WORDLISTS_DIR / "spUser.txt"), help="SP User list file. Default is the bundled spUser.txt.")
    group.add_argument("--ua", "--user-agent", dest="user_agent", default=str(net_utils.WORDLISTS_DIR / "userAgent.txt"), help="User Agent list file. Default is the bundled userAgent.txt.")
    group.add_argument("--il", "--manual-ip-list", dest="manual_ip_list", help="IP list file.")
    group.add_argument("--if", "--interface", dest="interface", help="Interface to work on.")
    group.add_argument("--tc", "--thread-count", dest="thread_count", type=net_utils.positive_int, default=10, help="Number of threads running (minimum 1). Default is 10.")
    group.add_argument("--mtu", dest="mtu", type=net_utils.mtu_size, help="MTU size for packet fragmentation (Scapy mode only, minimum 68 bytes).")
    group.add_argument(
        "--pps", "--packets-per-second", dest="pps", type=net_utils.positive_float, default=None,
        help="SIP-DAS: throttle to at most this many packets per second. Default is unthrottled (as fast as possible).",
    )
    group.add_argument(
        "--rt", "--response-timeout", dest="response_timeout", type=net_utils.positive_float, default=None,
        help="SIP-NES/SIP-ENUM: seconds to wait for a response before giving up on a single probe. "
             "Default is 5. Lower it (e.g. --rt 1) to speed up scanning a large range where most "
             "hosts won't respond at all - each non-responsive probe otherwise blocks its worker "
             "thread for the full timeout. SIP-ENUM/SIP-DAS's liveness pre-check (see "
             "--skip-live-check) normally uses its own short fixed timeout regardless of this "
             "flag; explicitly setting --rt also raises the pre-check's patience to match, so a "
             "genuinely slow-but-live target isn't wrongly skipped as unreachable.",
    )

    group.add_argument(
        "--skip-live-check", action="store_true", dest="skip_live_check", default=False,
        help="SIP-ENUM/SIP-DAS: skip the short liveness probe normally sent before enumerating/flooding "
             "a target. SIP-ENUM enumerates every target as given (no skipping non-responsive ones); "
             "SIP-DAS floods without the initial 'target didn't respond' warning.",
    )
    group.add_argument(
        "-y", "--yes", action="store_true", dest="assume_yes", default=False,
        help="Automatically answer yes to all confirmation prompts (non-interactive mode).",
    )
    group.add_argument("-v", "--verbose", action="store_true", dest="verbose", default=False, help="Enable verbose (DEBUG-level) logging.")
    group.add_argument("-i", "--ip-save-list", dest="ip_list", default="output/ip_list.txt", help="Output file to save live IP address.\n Default is output/ip_list.txt.")
    group.add_argument(
        "-c", "--count", dest="counter", type=net_utils.non_negative_int, default=99999999,
        help="Counter for how many messages to send. 0 means flood indefinitely (SIP-DAS only). If not specified, default is flood.",
    )
    group.add_argument("-l", "--lib", action="store_true", dest="library", default=False, help="Use Socket library (no spoofing), default is Scapy")
    group.add_argument("-r", "--random", action="store_true", dest="random", default=False, help="Spoof IP addresses randomly.")
    group.add_argument("-m", "--manual", action="store_true", dest="manual", default=False, help="Spoof IP addresses manually. If you choose manually, you have to specify an IP list via --il parameter.")
    group.add_argument("-s", "--subnet", action="store_true", dest="subnet", default=False, help="Spoof IP addresses from the same subnet.")

    return parser


def main():
    args = build_parser().parse_args()
    logger = logging_config.setup_logging(args.verbose)

    print(BANNER if theme.supports_color() else theme.strip_ansi(BANNER))

    start = time.time()
    show_time = True

    try:
        if args.interface is not None:
            try:
                conf.iface = args.interface
            except ValueError as e:
                # Scapy's own conf.iface setter raises a raw ValueError for
                # an unknown interface name - previously unguarded (this
                # assignment ran before the try: block existed here), so a
                # bad --if crashed with a full traceback through scapy's
                # internals instead of the clean error every other bad-input
                # case gets. A typo'd interface name is an easy, common
                # mistake (see docs/usage-guide.md's own discussion of how
                # to find the right --if value).
                raise errors.InvalidInterfaceError(str(e)) from e

        # Upfront root privilege verification for Scapy DoS simulation
        if args.dos_attack_simulator and not args.library and hasattr(os, "geteuid") and os.geteuid() != 0:
            raise errors.MrSipError("Scapy raw packet mode (and IP spoofing) requires root privileges. Please run with sudo or use the -l flag.")

        if args.network_scanner:
            client_ip, _ = net_utils.get_client_network_info(conf.iface)
            nes.run(args, conf, client_ip)
        elif args.sip_enumerator:
            client_ip, _ = net_utils.get_client_network_info(conf.iface)
            enum.run(args, conf, client_ip)
        elif args.dos_attack_simulator:
            client_ip, client_netmask = net_utils.get_client_network_info(conf.iface)
            das.run(args, conf, client_ip, client_netmask)
        else:
            logger.info("No module specified.")
            logger.info("To get more out of Mr.SIP, check out the PRO version: https://www.mrsip.pro/")
            show_time = False
    except errors.MrSipError as e:
        logger.error(str(e))
        sys.exit(1)
    except FileNotFoundError as e:
        logger.error(f"File not found: {e.filename}")
        sys.exit(1)
    except KeyboardInterrupt:
        print()
        logger.warning("Interrupted by user.")
        sys.exit(130)

    if show_time:
        logger.info(f"time duration: {time.time() - start:.2f}")


if __name__ == "__main__":
    main()
