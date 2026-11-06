import pytest

from src.event_parser import parse_event
from src.event_normalizer import normalize_event


def test_parse_valid_event():
    event = parse_event(
        "sample_data/events/console_login_failed.json"
    )

    assert event["eventName"] == "ConsoleLogin"


def test_parse_missing_file():
    with pytest.raises(FileNotFoundError):
        parse_event("sample_data/events/missing.json")


def test_normalize_event():
    event = parse_event(
        "sample_data/events/console_login_failed.json"
    )

    normalized = normalize_event(event)

    assert normalized["event_name"] == "ConsoleLogin"
    assert normalized["username"] == "synthetic-test-user"
    assert normalized["identity_type"] == "IAMUser"


def test_normalize_missing_fields():
    event = {
        "eventName": "ConsoleLogin",
        "userIdentity": {
            "type": "IAMUser",
            "userName": "test-user"
        }
    }

    normalized = normalize_event(event)

    assert normalized["source_ip"] is None
    assert normalized["region"] is None
    assert normalized["account_id"] is None


def test_normalize_invalid_identity():
    event = {
        "eventName": "ConsoleLogin",
        "userIdentity": "invalid"
    }

    with pytest.raises(ValueError):
        normalize_event(event)
