import pytest

from src.core import errors


def test_hierarchy():
    assert issubclass(errors.PacketSendError, errors.MrSipError)
    assert issubclass(errors.TemplateNotFoundError, errors.MrSipError)
    assert issubclass(errors.InvalidInterfaceError, errors.MrSipError)
    assert issubclass(errors.MrSipError, Exception)


def test_subtypes_are_catchable_as_base():
    for exc_cls in (errors.PacketSendError, errors.TemplateNotFoundError, errors.InvalidInterfaceError):
        with pytest.raises(errors.MrSipError):
            raise exc_cls("boom")
