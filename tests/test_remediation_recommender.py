import pytest

from src.remediation_recommender import recommend_remediation


def test_recommend_iam_policy_remediation():
    finding = {"rule_id": "IAM-001"}

    recommendations = recommend_remediation(finding)

    assert len(recommendations) == 4
    assert "approved change records" in recommendations[0]


def test_recommend_access_key_remediation():
    finding = {"rule_id": "IAM-002"}

    recommendations = recommend_remediation(finding)

    assert len(recommendations) == 4
    assert "authorized" in recommendations[0]


def test_recommend_login_profile_remediation():
    finding = {"rule_id": "IAM-003"}

    recommendations = recommend_remediation(finding)

    assert len(recommendations) == 3
    assert "expected" in recommendations[0]


def test_recommend_failed_login_remediation():
    finding = {"rule_id": "AUTH-001"}

    recommendations = recommend_remediation(finding)

    assert len(recommendations) == 4
    assert "identity" in recommendations[0]


def test_reject_unknown_rule():
    finding = {"rule_id": "UNKNOWN-001"}

    with pytest.raises(ValueError):
        recommend_remediation(finding)


def test_reject_invalid_finding():
    with pytest.raises(ValueError):
        recommend_remediation("invalid")
