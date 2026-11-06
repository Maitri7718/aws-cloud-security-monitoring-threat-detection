from pathlib import Path

from src.event_parser import parse_event
from src.event_normalizer import normalize_event
from src.detection_engine import detect_iam_activity
from src.pattern_detector import detect_repeated_failed_logins
from src.severity_classifier import classify_severity
from src.alert_generator import generate_alerts
from src.incident_timeline import build_timeline
from src.investigation_analysis import build_investigation_analysis
from src.report_generator import generate_security_report


EVENT_DIR = Path("sample_data/events")
AUTH_DIR = EVENT_DIR / "auth"


def load_events(directory):
    events = []

    for file_path in sorted(directory.glob("*.json")):
        event = parse_event(file_path)
        events.append(normalize_event(event))

    return events


def run_pipeline():
    # 1. Load synthetic events
    iam_events = load_events(EVENT_DIR)
    auth_events = load_events(AUTH_DIR)

    all_events = iam_events + auth_events

    # 2. Build chronological timeline
    timeline = build_timeline(all_events)

    # 3. Build investigation
    investigation = build_investigation_analysis(
        timeline,
        "synthetic-admin-user"
    )

    # 4. Detect IAM activity
    findings = []

    for event in iam_events:
        findings.extend(detect_iam_activity(event))

    # 5. Detect repeated failed logins
    findings.extend(
        detect_repeated_failed_logins(auth_events)
    )

    # 6. Classify severity
    for finding in findings:
        finding["severity"] = classify_severity(finding)

    # 7. Generate alerts
    alerts = generate_alerts(findings)

    # 8. Generate security report
    report = generate_security_report(
        findings,
        alerts,
        investigation
    )

    return all_events, timeline, findings, alerts, report


def test_complete_pipeline_event_count():
    events, timeline, findings, alerts, report = run_pipeline()

    assert len(events) == 11
    assert len(timeline) == 11


def test_complete_pipeline_finding_count():
    events, timeline, findings, alerts, report = run_pipeline()

    assert len(findings) == 4


def test_complete_pipeline_alert_count():
    events, timeline, findings, alerts, report = run_pipeline()

    assert len(alerts) == 4


def test_complete_pipeline_severity_distribution():
    events, timeline, findings, alerts, report = run_pipeline()

    assert report["summary"]["severity_distribution"] == {
        "HIGH": 3,
        "MEDIUM": 1,
        "LOW": 0
    }


def test_complete_pipeline_report_status():
    events, timeline, findings, alerts, report = run_pipeline()

    assert report["summary"]["investigation_status"] == (
        "REQUIRES_INVESTIGATION"
    )


def test_complete_pipeline_alert_ids():
    events, timeline, findings, alerts, report = run_pipeline()

    assert [alert["alert_id"] for alert in alerts] == [
        "ALERT-001",
        "ALERT-002",
        "ALERT-003",
        "ALERT-004"
    ]


def test_complete_pipeline_remediation_present():
    events, timeline, findings, alerts, report = run_pipeline()

    for finding in report["findings"]:
        assert len(finding["remediation_recommendations"]) > 0
