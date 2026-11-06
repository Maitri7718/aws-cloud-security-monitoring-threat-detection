def build_investigation_analysis(events, actor):
    """
    Build an evidence-led investigation summary
    for a specified synthetic actor.
    """

    if not isinstance(events, list):
        raise ValueError("Events must be provided as a list.")

    if not isinstance(actor, str) or not actor:
        raise ValueError("A valid actor is required.")

    actor_events = []

    for event in events:
        if not isinstance(event, dict):
            raise ValueError("Each event must be a dictionary.")

        if event.get("username") == actor:
            actor_events.append(event)

    observations = [
        {
            "event_name": event.get("event_name"),
            "timestamp": event.get("timestamp"),
            "source_ip": event.get("source_ip")
        }
        for event in actor_events
    ]

    return {
        "case_actor": actor,
        "event_count": len(actor_events),
        "observations": observations,
        "hypotheses": [
            hypothesis
            for event_name, hypothesis in [
                (
                    "PutUserPolicy",
                    "Possible unauthorized IAM policy modification."
                ),
                (
                    "CreateAccessKey",
                    "Possible unapproved IAM credential creation."
                ),
                (
                    "DeleteLoginProfile",
                    "Possible unexpected console credential change."
                )
            ]
            if any(
                event.get("event_name") == event_name
                for event in actor_events
            )
        ],
        "evidence_gaps": [
            "Change approval records",
            "Policy permissions and modifications",
            "Access-key creation outcome",
            "Subsequent credential usage",
            "Expected login-profile deletion context"
        ],
        "investigation_status": "REQUIRES_INVESTIGATION"
    }
