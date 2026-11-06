REMEDIATION_MAPPING = {
    "IAM-001": [
        "Verify the IAM policy modification against approved change records.",
        "Review the policy permissions and identify excessive access.",
        "Preserve relevant audit evidence before making changes.",
        "Remove unauthorized permissions only after validation."
    ],

    "IAM-002": [
        "Verify whether the access-key creation was authorized.",
        "Identify the intended owner and purpose of the access key.",
        "Review subsequent activity associated with the credential.",
        "Deactivate or rotate the key if unauthorized use is established."
    ],

    "IAM-003": [
        "Verify whether the login-profile deletion was expected.",
        "Check offboarding or credential-management records.",
        "Review remaining authentication methods and access paths."
    ],

    "AUTH-001": [
        "Verify the identity associated with repeated failed logins.",
        "Review source IP addresses and authentication context.",
        "Check MFA configuration and subsequent successful logins.",
        "Escalate for credential protection if compromise is established."
    ]
}


def recommend_remediation(finding):
    """
    Return remediation recommendations for a known finding.
    """

    if not isinstance(finding, dict):
        raise ValueError("Finding must be a dictionary.")

    rule_id = finding.get("rule_id")

    if not rule_id:
        raise ValueError("Finding must contain a rule_id.")

    if rule_id not in REMEDIATION_MAPPING:
        raise ValueError(f"Unknown detection rule: {rule_id}")

    return REMEDIATION_MAPPING[rule_id].copy()
