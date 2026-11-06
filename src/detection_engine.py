def detect_iam_activity(event):
    """
    Identify IAM operations that require security investigation.
    Include available event evidence in each finding.
    """

    findings = []
    event_name = event.get("event_name")

    rules = {
        "PutUserPolicy": {
            "rule_id": "IAM-001",
            "severity": "HIGH",
            "title": "IAM inline policy modification detected",
            "description": (
                "An IAM inline policy modification operation was invoked. "
                "Verify the change and its authorization."
            )
        },
        "CreateAccessKey": {
            "rule_id": "IAM-002",
            "severity": "HIGH",
            "title": "IAM access key creation detected",
            "description": (
                "An IAM access-key creation operation was invoked. "
                "Verify whether the action was authorized."
            )
        },
        "DeleteLoginProfile": {
            "rule_id": "IAM-003",
            "severity": "MEDIUM",
            "title": "IAM login profile deletion detected",
            "description": (
                "An IAM console password profile deletion operation "
                "was invoked. Verify whether this was expected."
            )
        }
    }

    if event_name in rules:
        rule = rules[event_name]

        findings.append({
            "rule_id": rule["rule_id"],
            "event_name": event_name,
            "severity": rule["severity"],
            "title": rule["title"],
            "description": rule["description"],
            "status": "REQUIRES_INVESTIGATION",

            "evidence": {
                "actor": event.get("username"),
                "target_user": event.get("target_user"),
                "source_ip": event.get("source_ip"),
                "timestamp": event.get("timestamp")
            }
        })

    return findings
