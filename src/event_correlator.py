from collections import defaultdict


def correlate_by_user(events):
    """
    Group timeline events by username.
    Preserve event order within each user's activity.
    """

    if not isinstance(events, list):
        raise ValueError("Events must be provided as a list.")

    correlated = defaultdict(list)

    for event in events:
        if not isinstance(event, dict):
            raise ValueError("Each event must be a dictionary.")

        username = event.get("username")

        if not username:
            continue

        correlated[username].append(event)

    return dict(correlated)
