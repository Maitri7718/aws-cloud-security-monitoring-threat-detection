def normalize_event(event):
    """
    Convert a parsed CloudTrail-style event
    into a consistent internal format.
    """

    if not isinstance(event, dict):
        raise ValueError("Event must be a dictionary.")

    identity = event.get("userIdentity") or {}
    request_parameters = event.get("requestParameters") or {}
    response_elements = event.get("responseElements") or {}
    additional_data = event.get("additionalEventData") or {}

    if not isinstance(identity, dict):
        raise ValueError("userIdentity must be a dictionary.")

    if not isinstance(request_parameters, dict):
        raise ValueError("requestParameters must be a dictionary.")

    if not isinstance(response_elements, dict):
        raise ValueError("responseElements must be a dictionary.")

    if not isinstance(additional_data, dict):
        raise ValueError("additionalEventData must be a dictionary.")

    return {
        "timestamp": event.get("eventTime"),
        "event_name": event.get("eventName"),
        "event_source": event.get("eventSource"),
        "region": event.get("awsRegion"),
        "source_ip": event.get("sourceIPAddress"),
        "username": identity.get("userName"),
        "identity_type": identity.get("type"),
        "account_id": identity.get("accountId"),
        "target_user": request_parameters.get("userName"),
        "login_result": response_elements.get("ConsoleLogin"),
        "mfa_used": additional_data.get("MFAUsed"),
    }
