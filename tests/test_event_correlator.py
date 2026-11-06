import pytest

from src.event_correlator import correlate_by_user


def test_group_events_by_username():
    events = [
        {"username": "user-a", "event_name": "ConsoleLogin"},
        {"username": "user-b", "event_name": "CreateAccessKey"},
        {"username": "user-a", "event_name": "PutUserPolicy"}
    ]

    result = correlate_by_user(events)

    assert len(result["user-a"]) == 2
    assert len(result["user-b"]) == 1


def test_preserve_event_order():
    events = [
        {"username": "user-a", "event_name": "ConsoleLogin"},
        {"username": "user-a", "event_name": "PutUserPolicy"}
    ]

    result = correlate_by_user(events)

    assert [
        event["event_name"] for event in result["user-a"]
    ] == ["ConsoleLogin", "PutUserPolicy"]


def test_skip_events_without_username():
    events = [
        {"username": "user-a", "event_name": "ConsoleLogin"},
        {"event_name": "UnknownEvent"}
    ]

    result = correlate_by_user(events)

    assert list(result.keys()) == ["user-a"]


def test_empty_event_list():
    assert correlate_by_user([]) == {}


def test_reject_non_list_input():
    with pytest.raises(ValueError):
        correlate_by_user({"username": "user-a"})


def test_reject_non_dictionary_event():
    with pytest.raises(ValueError):
        correlate_by_user(["invalid-event"])
