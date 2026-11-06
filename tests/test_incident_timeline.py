import pytest

from src.incident_timeline import build_timeline


def test_events_are_sorted_chronologically():
    events = [
        {"timestamp": "2026-11-03T05:00:00Z", "event_name": "DeleteLoginProfile"},
        {"timestamp": "2026-11-03T04:30:00Z", "event_name": "ConsoleLogin"},
        {"timestamp": "2026-11-03T04:45:00Z", "event_name": "PutUserPolicy"}
    ]

    timeline = build_timeline(events)

    assert [
        event["event_name"] for event in timeline
    ] == [
        "ConsoleLogin",
        "PutUserPolicy",
        "DeleteLoginProfile"
    ]


def test_timezone_offsets_are_compared_correctly():
    events = [
        {"timestamp": "2026-11-03T10:00:00+05:30", "event_name": "later"},
        {"timestamp": "2026-11-03T04:00:00Z", "event_name": "earlier"}
    ]

    timeline = build_timeline(events)

    assert timeline[0]["event_name"] == "earlier"


def test_original_events_are_not_modified():
    events = [
        {"timestamp": "2026-11-03T05:00:00Z", "event_name": "later"},
        {"timestamp": "2026-11-03T04:00:00Z", "event_name": "earlier"}
    ]

    original_first_event = events[0].copy()

    build_timeline(events)

    assert events[0] == original_first_event


def test_reject_non_list_input():
    with pytest.raises(ValueError):
        build_timeline({"timestamp": "2026-11-03T04:00:00Z"})


def test_reject_missing_timestamp():
    with pytest.raises(ValueError):
        build_timeline([{"event_name": "ConsoleLogin"}])


def test_reject_invalid_timestamp():
    with pytest.raises(ValueError):
        build_timeline([{"timestamp": "invalid-time"}])


def test_reject_timezone_naive_timestamp():
    with pytest.raises(ValueError):
        build_timeline([{"timestamp": "2026-11-03T04:00:00"}])


def test_reject_non_dictionary_event():
    with pytest.raises(ValueError):
        build_timeline(["invalid-event"])
