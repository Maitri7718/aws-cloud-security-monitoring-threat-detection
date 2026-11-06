from datetime import datetime, timezone


def build_timeline(events):
    """
    Return events sorted chronologically by timestamp.
    Preserve the original event dictionaries.
    """

    if not isinstance(events, list):
        raise ValueError("Events must be provided as a list.")

    timestamped_events = []

    for event in events:
        if not isinstance(event, dict):
            raise ValueError("Each event must be a dictionary.")

        timestamp = event.get("timestamp")

        if not isinstance(timestamp, str) or not timestamp:
            raise ValueError("Each event must have a valid timestamp.")

        try:
            parsed_time = datetime.fromisoformat(
                timestamp.replace("Z", "+00:00")
            )
        except ValueError as error:
            raise ValueError(
                f"Invalid event timestamp: {timestamp}"
            ) from error

        if parsed_time.tzinfo is None:
            raise ValueError(
                f"Timestamp must include a timezone: {timestamp}"
            )

        timestamped_events.append(
            (parsed_time.astimezone(timezone.utc), event)
        )

    timestamped_events.sort(key=lambda item: item[0])

    return [event for _, event in timestamped_events]
