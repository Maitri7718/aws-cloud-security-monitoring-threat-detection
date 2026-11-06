import pytest

from src.report_generator import generate_security_report


@pytest.fixture
def sample_data():
    findings = [
        {
            "rule_id": "IAM-002",
            "event_name": "CreateAccessKey",
            "title": "IAM access key creation detected",
            "severity": "HIGH",
            "status": "REQUIRES_INVESTIGATION",
            "description": "Verify access-key creation.",
            "evidence": {
                "actor": "synthetic-admin-user",
                "target_user": "synthetic-test-user"
            }
        }
    ]

    alerts = [
        {
            "alert_id": "ALERT-001",
            "rule_id": "IAM-002",
            "severity": "HIGH"
        }
    ]

    investigation = {
        "case_actor": "synthetic-admin-user",
        "event_count": 4,
        "investigation_status": "REQUIRES_INVESTIGATION"
    }

    return findings, alerts, investigation


def test_generate_security_report(sample_data):
    findings, alerts, investigation = sample_data

    report = generate_security_report(
        findings, alerts, investigation
    )

    assert report["summary"]["total_findings"] == 1
    assert report["summary"]["total_alerts"] == 1


def test_report_contains_metadata(sample_data):
    findings, alerts, investigation = sample_data

    report = generate_security_report(
        findings, alerts, investigation
    )

    assert report["report_metadata"]["environment"] == "LOCAL_SIMULATION"
    assert report["report_metadata"]["data_source"] == (
        "Synthetic CloudTrail-style events"
    )


def test_report_contains_severity_distribution(sample_data):
    findings, alerts, investigation = sample_data

    report = generate_security_report(
        findings, alerts, investigation
    )

    assert report["summary"]["severity_distribution"]["HIGH"] == 1
    assert report["summary"]["severity_distribution"]["MEDIUM"] == 0


def test_report_contains_remediation(sample_data):
    findings, alerts, investigation = sample_data

    report = generate_security_report(
        findings, alerts, investigation
    )

    recommendations = report["findings"][0][
        "remediation_recommendations"
    ]

    assert len(recommendations) == 4


def test_report_preserves_investigation_status(sample_data):
    findings, alerts, investigation = sample_data

    report = generate_security_report(
        findings, alerts, investigation
    )

    assert report["summary"]["investigation_status"] == (
        "REQUIRES_INVESTIGATION"
    )


def test_reject_invalid_findings():
    with pytest.raises(ValueError):
        generate_security_report(
            "invalid",
            [],
            {}
        )
