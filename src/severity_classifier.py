SEVERITY_MAPPING = {
    "IAM-001": "HIGH",
    "IAM-002": "HIGH",
    "IAM-003": "MEDIUM",
    "AUTH-001": "HIGH"
}


def classify_severity(finding):
    """
    Return the approved project severity for a known rule.
    """

    if not isinstance(finding, dict):
        raise ValueError("Finding must be a dictionary.")

    rule_id = finding.get("rule_id")

    if not rule_id:
        raise ValueError("Finding must contain a rule_id.")

    if rule_id not in SEVERITY_MAPPING:
        raise ValueError(f"Unknown detection rule: {rule_id}")

    return SEVERITY_MAPPING[rule_id]
