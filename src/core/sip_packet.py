"""
SIP Packet Creator: builds a SIP message from a method/*.message template
and sends it over a plain UDP socket or a raw Scapy IP/UDP packet (with
optional spoofed source IP).
"""

import functools
import logging
import os
import random
import re
import socket
import string
from pathlib import Path

from scapy.all import IP, UDP, send

from src.core import errors

logger = logging.getLogger(__name__)


@functools.cache
def _read_template(template_path):
    """Read a method/*.message template file, cached by path.

    Template content is invariant within a run - das.py's flood loop calls
    generate_packet() (and therefore this) up to ~1e8 times at the default
    counter, so re-reading the same handful of small files from disk that
    often is pure waste (the same class of I/O this codebase already fixed
    for wordlists/servers.txt - see F8/F16 in CHANGELOG.md). lru_cache does
    not cache exceptions, so a missing template still raises OSError (and
    therefore TemplateNotFoundError) on every call, not just the first.
    """
    with open(template_path) as f:
        return f.read()


class sip_packet:
    """Builds and sends one SIP message from a data/method/*.message template.

    fill_packet_data() fills in the template's [[placeholder]] tokens (the
    full set recognized is listed below) and generate_packet() sends the
    result via plain UDP ("socket") or a raw Scapy IP/UDP packet ("scapy",
    with optional spoofed source IP). One instance represents one message -
    a fresh sip_packet is constructed per probe/packet, not reused.

    Recognized template placeholders:
    [[server_ip]]
    [[server_port]]
    [[client_ip]]
    [[client_port]]
    [[from_user]]
    [[to_user]]
    [[user_agent]]
    [[sp_user]]
    [[expire_duration]]
    [[call_id]]
    [[branch_value]]
    [[tag_value]]
    """

    def __init__(
        self,
        method,
        server_ip,
        server_port,
        client_ip,
        from_user="",
        to_user="",
        user_agent="",
        sp_user="",
        protocol="socket",
        expire_duration=3600,
        wait=False,
        mtu=None,
        timeout=5,
        scapy_socket=None,
        client_socket=None,
    ):
        self.method = method
        self.protocol = protocol
        self.server_ip = server_ip
        self.server_port = server_port
        self.client_ip = client_ip
        self.from_user = from_user
        self.to_user = to_user
        self.user_agent = user_agent
        self.sp_user = sp_user
        self.expire_duration = expire_duration
        self.wait = wait
        self.mtu = mtu
        # Optional persistent raw socket for protocol="scapy" sends.
        # Left as None, scapy.send()'s own default
        # behavior (open a fresh raw L3 socket, send one packet, close it)
        # is unchanged - callers doing a flood loop of many scapy sends
        # against the same target (das.py) build one socket once and pass
        # it here instead, since the routing lookup that determines it is
        # invariant across a fixed-target loop.
        self.scapy_socket = scapy_socket
        self.client_socket = client_socket
        # Socket-mode response timeout in seconds. Defaults to 5 (the
        # historical value) for real probes/enumeration, where waiting a bit
        # longer for a real server's response is worth it. Callers doing a
        # quick "is anything there at all" liveness check (enum.py, das.py)
        # pass a much shorter value instead - that's a different question
        # ("did *anything* answer") than "wait patiently for this specific
        # server's real response."
        self.timeout = timeout
        self.client_port = random.randint(10000, 65535)

    method_location = str(Path(__file__).resolve().parent.parent / "data" / "method")

    @staticmethod
    def get_rand_call_id():
        prefix = "".join(random.sample(string.digits + string.ascii_lowercase, 27))
        return f"{str(prefix)}{str(random.randrange(10000, 99999))}"

    @staticmethod
    def get_rand_branch():
        prefix = "".join(random.sample(string.digits, 10))
        return f"z9hG4bK-{str(prefix)}"

    @staticmethod
    def get_rand_tag():
        prefix = random.randint(100000, 999999)
        return f"{str(prefix)}"

    def fill_packet_data(self, text):
        var_dict = {
            "server_ip": str(self.server_ip),
            "server_port": str(self.server_port),
            "client_ip": str(self.client_ip),
            "client_port": str(self.client_port),
            "from_user": str(self.from_user),
            "to_user": str(self.to_user),
            "user_agent": str(self.user_agent),
            "sp_user": str(self.sp_user),
            "expire_duration": str(self.expire_duration),
            "call_id": str(self.get_rand_call_id()),
            "branch_value": str(self.get_rand_branch()),
            "tag_value": str(self.get_rand_tag()),
        }

        def _substitute(match):
            if match.group(1) not in var_dict:
                # Unrecognized token (not one of the 12 known placeholders) -
                # left untouched, matching the old behavior where a
                # .replace() for an unknown key simply never matched.
                return match.group(0)
            value = var_dict[match.group(1)]
            sanitized = value.replace("\r", "").replace("\n", "")
            # Drop lone surrogates (e.g. from a CLI argument containing
            # invalid-UTF-8 bytes - argv is decoded with errors="surrogateescape",
            # so this is reachable from real command-line input, not just
            # crafted wordlist files). Left in, the final .encode("utf-8")
            # below would raise UnicodeEncodeError and crash the whole run.
            return sanitized.encode("utf-8", errors="ignore").decode("utf-8")

        # A single pass over the original template text, not one .replace()
        # call per placeholder chained over the accumulating result: chained
        # replacement meant a value substituted for an earlier placeholder
        # (from_user) that happened to contain the literal text of a later
        # one ("[[call_id]]") got re-substituted a second time by that later
        # placeholder's own real value, silently corrupting an unrelated
        # field. re.sub() with a callback only ever matches against the
        # original text, so a substituted value's contents are never
        # rescanned for further placeholders.
        text = re.sub(r"\[\[(\w+)\]\]", _substitute, text)
        return text.encode("utf-8")

    def generate_packet(self):
        int(self.client_port)  # Validate port type to catch programming errors early
        template_path = os.path.join(self.method_location, f"{self.method}.message")
        try:
            packet_data = _read_template(template_path)
        except FileNotFoundError as e:
            # An unsupported/misspelled --mt used to surface as a raw
            # "[Errno 2] No such file or directory: '/full/local/path/...'"
            # - technically caught (no traceback), but the message itself
            # leaked the local install path and gave no hint of what a
            # valid value looks like. --mt is free-text (any *.message file
            # name is accepted, including custom ones), so this can't be an
            # argparse choices= validator; list what's actually available
            # instead.
            available = ", ".join(sorted(p.stem for p in Path(self.method_location).glob("*.message")))
            raise errors.TemplateNotFoundError(
                f"Unknown message type: '{self.method}'. Available: {available}."
            ) from e
        except OSError as e:
            raise errors.TemplateNotFoundError(str(e)) from e

        if self.protocol not in ("socket", "scapy"):
            raise errors.PacketSendError(f"Unsupported protocol: {self.protocol}")

        try:
            if self.protocol == "socket":
                if self.client_socket is not None:
                    s = self.client_socket
                    self.client_port = s.getsockname()[1]
                else:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.settimeout(self.timeout)
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                    try:
                        s.bind(("0.0.0.0", 0))
                        self.client_port = s.getsockname()[1]
                    except OSError as e:
                        logger.debug("Failed to bind ephemeral port: %s", e)
                        raise errors.PacketSendError(f"Failed to bind local ephemeral port: {e}") from e
                
                packet_data = self.fill_packet_data(packet_data)
                s.connect((str(self.server_ip), int(self.server_port)))
                s.sendall(packet_data)
                if self.wait:
                    buff, srcaddr = s.recvfrom(8192)
                    if self.client_socket is None:
                        s.close()
                    status = self.getResponse(buff.decode("utf-8"))
                    return {"status": True, "response": status}
                else:
                    if self.client_socket is None:
                        s.close()
                    return {"status": True}

            elif self.protocol == "scapy":
                packet_data = self.fill_packet_data(packet_data)
                pkt = (
                    IP(src=self.client_ip, dst=self.server_ip)
                    / UDP(sport=int(self.client_port), dport=int(self.server_port))
                    / packet_data
                )
                if self.mtu is not None:
                    # is not None, not a truthy check: --mtu 0 must still hit
                    # the "at least 68 bytes" guard below instead of silently
                    # being treated the same as "no --mtu given at all".
                    if self.mtu < 68:
                        raise errors.PacketSendError("MTU size must be at least 68 bytes.")
                    from scapy.all import fragment
                    frags = fragment(pkt, fragsize=self.mtu)
                    for frag in frags:
                        send(frag, socket=self.scapy_socket, verbose=False)
                else:
                    send(pkt, socket=self.scapy_socket, verbose=False)
                return {"status": True}
        except (OSError, UnicodeDecodeError) as e:
            # Only the failure modes an actual send/receive cycle can raise
            # (network/socket/permission errors, a response that isn't valid
            # UTF-8) are treated as "packet send failed". A programming bug
            # (AttributeError, TypeError, ...) should surface as a real
            # traceback instead of being reported as a misleading
            # PacketSendError. errors.PacketSendError raised explicitly
            # above (unsupported protocol, MTU too small, bind failure) is
            # not an OSError, so it propagates through here untouched.
            raise errors.PacketSendError(str(e)) from e

    def getResponse(self, resp):
        nl = "\r\n\r\n"
        headers_nl = "\r*\n(?![\t\x20])"
        if nl in resp:
            header, body = resp.split(nl, 1)
        else:
            header = resp
            body = ""
        headers = re.split(headers_nl, header)

        if len(headers) >= 1:
            response = {}
            first_line = headers[0].split(" ", 2)
            if len(first_line) == 3:
                version, code, _ = first_line
            elif len(first_line) == 2:
                version, code = first_line
            else:
                logger.warning("Could not parse the first header line: %s", first_line)
                return response
            try:
                response["code"] = int(code)
            except ValueError:
                return response

            response["headers"] = {}
            for headerline in headers[1:]:
                nl = ":"
                if nl in headerline:
                    tmpname, tmpval = headerline.split(nl, 1)
                    name = tmpname.lower().strip()
                    val = [x.strip() for x in tmpval.split(",")]
                else:
                    name, val = headerline.lower(), None
                response["headers"][name] = val
            response["body"] = body
            return response
