class MrSipError(Exception):
    """Base class for all Mr.SIP errors.

    Setup/validation failures - TemplateNotFoundError, InvalidInterfaceError,
    and plain MrSipError raised by net_utils.check_value_errors() - are meant
    to abort the whole run and are caught once, centrally, in src.cli.main().

    PacketSendError is deliberately different: nes.py/enum.py/das.py each
    catch it locally, per work item, so one failed probe or dropped packet
    doesn't abort an entire scan/flood. It isn't expected to reach
    cli.main()'s handler in normal operation.
    """


class PacketSendError(MrSipError):
    """Raised when a SIP packet could not be sent or no response was received
    in time. Caught locally per work item by nes.py/enum.py/das.py, not by
    cli.main() - see MrSipError's docstring."""


class TemplateNotFoundError(MrSipError):
    """Raised when a method/*.message template file is missing or unreadable."""


class InvalidInterfaceError(MrSipError):
    """Raised when --if names an interface that doesn't exist on this system,
    or one that exists but has no usable IPv4 address."""
