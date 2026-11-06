from datetime import datetime, timezone

from src.remediation_recommender import recommend_remediation


def generate_security_report(findings, alerts, investigation):
    """
    Generate a structured security investigation report.
    Uses synthetic findings and local investigation data.
    """

    if not isinstance(findings, list):
        raise ValueError("Findings must be provided as a list.")

    if not isinstance(alerts, list):
        raise ValueError("Alerts must be provided as a list.")

    if not isinstance(investigation, dict):
        raise ValueError("Investigation must be a dictionary.")

    report_findings = []

    severity_summary = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    for finding in findings:
        if not isinstance(finding, dict):
            raise ValueError("Each finding must be a dictionary.")

        rule_id = finding.get("rule_id")

        if not rule_id:
            raise ValueError("Finding must contain a rule_id.")

        recommendations = recommend_remediation(finding)

        severity = finding.get("severity", "UNKNOWN")

        if severity in severity_summary:
            severity_summary[severity] += 1

        report_findings.append({
            "rule_id": rule_id,
            "event_name": finding.get("event_name"),
            "title": finding.get("title"),
            "severity": severity,
            "status": finding.get(
                "status", "REQUIRES_INVESTIGATION"
            ),
            "description": finding.get("description"),
            "evidence": finding.get("evidence", {}),
            "remediation_recommendations": recommendations
        })

    return {
        "report_metadata": {
            "project": "AWS Cloud Security Monitoring & Threat Detection",
            "data_source": "Synthetic CloudTrail-style events",
            "report_generated_at": datetime.now(
                timezone.utc
            ).isoformat(),
            "environment": "LOCAL_SIMULATION"
        },

        "summary": {
            "total_findings": len(findings),
            "total_alerts": len(alerts),
            "severity_distribution": severity_summary,
            "investigation_status": investigation.get(
                "investigation_status",
                "REQUIRES_INVESTIGATION"
            )
        },

        "findings": report_findings,

        "investigation": investigation,

        "alerts": alerts
    }
