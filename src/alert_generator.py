from copy import deepcopy

from src.severity_classifier import classify_severity


def generate_alerts(findings):
    """
    Convert security findings into structured alerts.
    Preserve original evidence and investigation status.
    """

    if not isinstance(findings, list):
        raise ValueError("Findings must be provided as a list.")

    alerts = []

    for finding in findings:
        if not isinstance(finding, dict):
            raise ValueError("Each finding must be a dictionary.")

        severity = classify_severity(finding)

        alert = {
            "alert_id": f"ALERT-{len(alerts) + 1:03d}",
            "rule_id": finding["rule_id"],
            "event_name": finding.get("event_name"),
            "title": finding.get("title"),
            "severity": severity,
            "status": finding.get(
                "status", "REQUIRES_INVESTIGATION"
            ),
            "description": finding.get("description"),
            "evidence": deepcopy(finding.get("evidence", {}))
        }

        alerts.append(alert)

    return alerts
