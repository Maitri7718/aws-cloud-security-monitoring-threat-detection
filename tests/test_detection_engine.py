from pathlib import Path

from src.event_parser import parse_event
from src.event_normalizer import normalize_event
from src.detection_engine import detect_iam_activity


EVENT_DIR = Path("sample_data/events")


def load_normalized_event(filename):
    event = parse_event(EVENT_DIR / filename)
    return normalize_event(event)


def test_detect_access_key_creation():
    event = load_normalized_event("access_key_created.json")
    findings = detect_iam_activity(event)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "IAM-002"


def test_detect_inline_policy_modification():
    event = load_normalized_event("iam_policy_changed.json")
    findings = detect_iam_activity(event)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "IAM-001"


def test_detect_login_profile_deletion():
    event = load_normalized_event("iam_login_profile_deleted.json")
    findings = detect_iam_activity(event)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "IAM-003"


def test_ignore_console_login_event():
    event = load_normalized_event("console_login_failed.json")

    assert detect_iam_activity(event) == []


def test_ignore_s3_access_event():
    event = load_normalized_event("unusual_s3_access.json")

    assert detect_iam_activity(event) == []

def test_access_key_finding_contains_evidence():
    event = load_normalized_event("access_key_created.json")
    findings = detect_iam_activity(event)

    evidence = findings[0]["evidence"]

    assert evidence["actor"] == "synthetic-admin-user"
    assert evidence["target_user"] == "synthetic-test-user"
    assert evidence["source_ip"] == "192.0.2.80"
    assert evidence["timestamp"] == "2026-11-03T04:50:00Z"


def test_missing_evidence_fields_remain_none():
    event = {
        "event_name": "CreateAccessKey"
    }

    findings = detect_iam_activity(event)
    evidence = findings[0]["evidence"]

    assert evidence["actor"] is None
    assert evidence["target_user"] is None
    assert evidence["source_ip"] is None
    assert evidence["timestamp"] is None
