import pytest

from src.investigation_analysis import build_investigation_analysis


def test_filter_events_for_specific_actor():
    events = [
        {"username": "user-a", "event_name": "PutUserPolicy"},
        {"username": "user-b", "event_name": "ConsoleLogin"},
        {"username": "user-a", "event_name": "CreateAccessKey"}
    ]

    result = build_investigation_analysis(events, "user-a")

    assert result["case_actor"] == "user-a"
    assert result["event_count"] == 2


def test_observations_preserve_event_evidence():
    events = [
        {
            "username": "user-a",
            "event_name": "CreateAccessKey",
            "timestamp": "2026-11-03T04:50:00Z",
            "source_ip": "192.0.2.80"
        }
    ]

    result = build_investigation_analysis(events, "user-a")

    assert result["observations"][0] == {
        "event_name": "CreateAccessKey",
        "timestamp": "2026-11-03T04:50:00Z",
        "source_ip": "192.0.2.80"
    }


def test_actor_with_no_events():
    result = build_investigation_analysis([], "user-a")

    assert result["event_count"] == 0
    assert result["observations"] == []


def test_reject_non_list_events():
    with pytest.raises(ValueError):
        build_investigation_analysis("invalid", "user-a")


def test_reject_invalid_actor():
    with pytest.raises(ValueError):
        build_investigation_analysis([], "")


def test_reject_non_dictionary_event():
    with pytest.raises(ValueError):
        build_investigation_analysis(["invalid"], "user-a")

def test_policy_modification_hypothesis():
    events = [
        {"username": "user-a", "event_name": "PutUserPolicy"}
    ]

    result = build_investigation_analysis(events, "user-a")

    assert result["hypotheses"] == [
        "Possible unauthorized IAM policy modification."
    ]


def test_access_key_creation_hypothesis():
    events = [
        {"username": "user-a", "event_name": "CreateAccessKey"}
    ]

    result = build_investigation_analysis(events, "user-a")

    assert result["hypotheses"] == [
        "Possible unapproved IAM credential creation."
    ]


def test_login_profile_deletion_hypothesis():
    events = [
        {"username": "user-a", "event_name": "DeleteLoginProfile"}
    ]

    result = build_investigation_analysis(events, "user-a")

    assert result["hypotheses"] == [
        "Possible unexpected console credential change."
    ]


def test_console_login_does_not_create_iam_hypothesis():
    events = [
        {"username": "user-a", "event_name": "ConsoleLogin"}
    ]

    result = build_investigation_analysis(events, "user-a")

    assert result["hypotheses"] == []
