import pytest

from src.severity_classifier import classify_severity


def test_classify_iam_policy_modification():
    finding = {"rule_id": "IAM-001", "severity": "LOW"}

    assert classify_severity(finding) == "HIGH"


def test_classify_access_key_creation():
    finding = {"rule_id": "IAM-002"}

    assert classify_severity(finding) == "HIGH"


def test_classify_login_profile_deletion():
    finding = {"rule_id": "IAM-003"}

    assert classify_severity(finding) == "MEDIUM"


def test_classify_repeated_failed_logins():
    finding = {"rule_id": "AUTH-001"}

    assert classify_severity(finding) == "HIGH"


def test_reject_unknown_rule():
    finding = {"rule_id": "UNKNOWN-001"}

    with pytest.raises(ValueError):
        classify_severity(finding)


def test_reject_missing_rule_id():
    finding = {"severity": "HIGH"}

    with pytest.raises(ValueError):
        classify_severity(finding)


def test_reject_non_dictionary_finding():
    with pytest.raises(ValueError):
        classify_severity("IAM-001")
