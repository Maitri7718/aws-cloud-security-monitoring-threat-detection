
from collections import defaultdict
from datetime import datetime, timedelta, timezone


def detect_repeated_failed_logins(events):
    """
    Detect five or more failed console logins
    for the same user within a rolling five-minute window.
    """

    threshold = 5
    window = timedelta(minutes=5)

    grouped_events = defaultdict(list)

    for event in events:
        if (
            event.get("event_name") == "ConsoleLogin"
            and event.get("login_result") == "Failure"
            and event.get("username")
            and event.get("timestamp")
        ):
            if not isinstance(event["timestamp"], str):
                continue
            try:
                timestamp = datetime.fromisoformat(
                    event["timestamp"].replace("Z", "+00:00")
                )
            except (ValueError, TypeError):
                continue

            if timestamp.tzinfo is None:
                continue

            timestamp = timestamp.astimezone(timezone.utc)

            grouped_events[event["username"]].append(
                (timestamp, event)
            )

    findings = []

    for username, user_events in grouped_events.items():
        user_events.sort(key=lambda item: item[0])

        for current_index, (current_time, current_event) in enumerate(user_events):
            window_start = current_time - window

            matching_events = [
                item for item in user_events
                if window_start <= item[0] <= current_time
            ]

            if len(matching_events) >= threshold:
                first_observed = matching_events[0][0]
                last_observed = matching_events[-1][0]

                findings.append({
                    "rule_id": "AUTH-001",
                    "event_name": "ConsoleLogin",
                    "severity": "HIGH",
                    "title": "Repeated failed console logins detected",
                    "description": (
                        "Five or more failed console login attempts "
                        "were observed for the same user within five minutes."
                    ),
                    "status": "REQUIRES_INVESTIGATION",
                    "evidence": {
                        "username": username,
                        "failure_count": len(matching_events),

                        "window_start": window_start.isoformat(),
                        "window_end": current_time.isoformat(),

                        "first_observed_failure": (
                            first_observed.isoformat()
                        ),
                        "last_observed_failure": (
                            last_observed.isoformat()
                        ),

                        "source_ips": sorted({
                            item[1].get("source_ip")
                            for item in matching_events
                            if item[1].get("source_ip")
                        })
                    }
                })

                break

    return findings
