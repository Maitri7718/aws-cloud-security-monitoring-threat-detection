from pathlib import Path

import json

from src.report_generator import generate_security_report
from src.event_parser import parse_event
from src.event_normalizer import normalize_event
from src.detection_engine import detect_iam_activity
from src.pattern_detector import detect_repeated_failed_logins
from src.alert_generator import generate_alerts
from src.incident_timeline import build_timeline
from src.event_correlator import correlate_by_user
from src.investigation_analysis import build_investigation_analysis


EVENT_DIR = Path("sample_data/events")
AUTH_DIR = EVENT_DIR / "auth"


def load_events(directory):
    events = []

    for file_path in sorted(directory.glob("*.json")):
        event = parse_event(file_path)
        events.append(normalize_event(event))

    return events


def main():
    # Step 1: Load synthetic events
    iam_events = load_events(EVENT_DIR)
    auth_events = load_events(AUTH_DIR)

    all_events = iam_events + auth_events

    # Step 2: Build chronological evidence timeline
    timeline = build_timeline(all_events)

    # Step 3: Correlate events by identity
    correlated_events = correlate_by_user(timeline)

    print("\n=== IDENTITY ACTIVITY SUMMARY ===")

    for username, user_events in correlated_events.items():
        print(f"\nUser: {username}")
        print(f"Total events: {len(user_events)}")

        for event in user_events:
            print(
                f"  {event['timestamp']} | "
                f"{event['event_name']} | "
                f"Source IP: {event['source_ip']}"
            )

    # Step 4: Build evidence-led investigation
    investigation = build_investigation_analysis(
        timeline,
        "synthetic-admin-user"
    )

    print("\n=== EVIDENCE-LED INVESTIGATION ===")

    print(f"Case actor: {investigation['case_actor']}")
    print(f"Event count: {investigation['event_count']}")

    print("\nObservations:")

    for observation in investigation["observations"]:
        print(
            f"- {observation['timestamp']} | "
            f"{observation['event_name']} | "
            f"Source IP: {observation['source_ip']}"
        )

    print("\nHypotheses:")

    for hypothesis in investigation["hypotheses"]:
        print(f"- {hypothesis}")

    print("\nEvidence gaps:")

    for gap in investigation["evidence_gaps"]:
        print(f"- {gap}")

    print(
        f"\nInvestigation status: "
        f"{investigation['investigation_status']}"
    )

    # Step 5: Generate IAM findings
    findings = []

    for event in iam_events:
        findings.extend(detect_iam_activity(event))

    # Step 6: Generate authentication pattern findings
    findings.extend(
        detect_repeated_failed_logins(auth_events)
    )

    # Step 7: Generate structured alerts
    alerts = generate_alerts(findings)

    # Step 8: Generate structured security report
    report = generate_security_report(
        findings,
        alerts,
        investigation
    )

    report_dir = Path("sample_data/reports")
    report_dir.mkdir(parents=True, exist_ok=True)

    report_path = report_dir / "security_report.json"

    with report_path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print("\n=== SECURITY REPORT GENERATED ===")
    print(f"Report location: {report_path}")

    # Step 9: Print chronological timeline
    print("\n=== INCIDENT EVIDENCE TIMELINE (UTC) ===")

    for event in timeline:
        print(
            f"{event['timestamp']} | "
            f"{event['event_name']} | "
            f"Actor: {event['username']} | "
            f"Source IP: {event['source_ip']}"
        )

    # Step 10: Print investigation summary
    print("\n=== INVESTIGATION SUMMARY ===")

    print(f"Events processed: {len(all_events)}")
    print(f"Findings generated: {len(findings)}")
    print(f"Alerts generated: {len(alerts)}")

    # Step 11: Print security alerts
    print("\n=== SECURITY ALERTS ===")

    for alert in alerts:
        print(
            f"{alert['alert_id']} | "
            f"{alert['rule_id']} | "
            f"{alert['severity']} | "
            f"{alert['status']}"
        )


if __name__ == "__main__":
    main()
