import json
from pathlib import Path


def parse_event(file_path):
    """
    Read a JSON event file and return its contents as a Python dictionary.
    """

    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(f"Event file not found: {path}")

    try:
        with path.open("r", encoding="utf-8") as file:
            event = json.load(file)

    except json.JSONDecodeError as error:
        raise ValueError(f"Invalid JSON in {path}: {error}") from error

    if not isinstance(event, dict):
        raise ValueError("Event must be a JSON object.")

    return event
