from pathlib import Path

from src.event_parser import parse_event
from src.event_normalizer import normalize_event
from src.pattern_detector import detect_repeated_failed_logins


EVENT_DIR = Path("sample_data/events/auth")


def load_login_events():
    files = sorted(EVENT_DIR.glob("*.json"))

    return [
        normalize_event(parse_event(file_path))
        for file_path in files
    ]


def test_detect_five_failed_logins():
    events = load_login_events()

    findings = detect_repeated_failed_logins(events)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AUTH-001"
    assert findings[0]["evidence"]["failure_count"] == 5


def test_four_failed_logins_do_not_trigger():
    events = load_login_events()[:4]

    assert detect_repeated_failed_logins(events) == []


def test_failures_spread_over_six_minutes_do_not_trigger():
    events = load_login_events()

    timestamps = [
        "2026-11-03T09:00:00Z",
        "2026-11-03T09:01:00Z",
        "2026-11-03T09:02:00Z",
        "2026-11-03T09:03:00Z",
        "2026-11-03T09:06:00Z",
    ]

    for event, timestamp in zip(events, timestamps):
        event["timestamp"] = timestamp

    assert detect_repeated_failed_logins(events) == []

def test_missing_timestamp_is_skipped():
    events = load_login_events()

    events[0]["timestamp"] = None

    findings = detect_repeated_failed_logins(events)

    assert findings == []


def test_invalid_timestamp_is_skipped():
    events = load_login_events()

    events[0]["timestamp"] = "not-a-valid-timestamp"

    findings = detect_repeated_failed_logins(events)

    assert findings == []

def test_non_string_timestamp_is_skipped():
    events = load_login_events()

    events[0]["timestamp"] = 12345

    findings = detect_repeated_failed_logins(events)

    assert findings == []


def test_timezone_naive_timestamp_is_skipped():
    events = load_login_events()

    events[0]["timestamp"] = "2026-11-03T09:00:00"

    findings = detect_repeated_failed_logins(events)

    assert findings == []
