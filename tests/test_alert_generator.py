import pytest

from src.alert_generator import generate_alerts


def test_generate_alert():
    findings = [
        {
            "rule_id": "IAM-001",
            "event_name": "PutUserPolicy",
            "title": "IAM policy modification detected",
            "severity": "LOW",
            "status": "REQUIRES_INVESTIGATION",
            "description": "Verify policy modification.",
            "evidence": {
                "actor": "synthetic-admin-user",
                "target_user": "synthetic-test-user"
            }
        }
    ]

    alerts = generate_alerts(findings)

    assert len(alerts) == 1
    assert alerts[0]["alert_id"] == "ALERT-001"
    assert alerts[0]["severity"] == "HIGH"
    assert alerts[0]["rule_id"] == "IAM-001"


def test_generate_multiple_alerts():
    findings = [
        {"rule_id": "IAM-001"},
        {"rule_id": "IAM-003"},
        {"rule_id": "AUTH-001"}
    ]

    alerts = generate_alerts(findings)

    assert len(alerts) == 3
    assert [alert["alert_id"] for alert in alerts] == [
        "ALERT-001",
        "ALERT-002",
        "ALERT-003"
    ]

    assert [alert["severity"] for alert in alerts] == [
        "HIGH",
        "MEDIUM",
        "HIGH"
    ]


def test_preserve_original_findings():
    findings = [
        {
            "rule_id": "IAM-002",
            "evidence": {"actor": "synthetic-admin-user"}
        }
    ]

    original_evidence = findings[0]["evidence"].copy()

    alerts = generate_alerts(findings)
    alerts[0]["evidence"]["actor"] = "changed-value"

    assert findings[0]["evidence"] == original_evidence


def test_default_investigation_status():
    findings = [{"rule_id": "IAM-003"}]

    alerts = generate_alerts(findings)

    assert alerts[0]["status"] == "REQUIRES_INVESTIGATION"


def test_reject_non_list_findings():
    with pytest.raises(ValueError):
        generate_alerts({"rule_id": "IAM-001"})


def test_reject_invalid_finding():
    with pytest.raises(ValueError):
        generate_alerts(["invalid-finding"])


def test_reject_unknown_rule():
    with pytest.raises(ValueError):
        generate_alerts([{"rule_id": "UNKNOWN-001"}])
