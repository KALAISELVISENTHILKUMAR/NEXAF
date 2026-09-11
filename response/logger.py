import json
from datetime import datetime


LOG_FILE = "logs/security_events.json"


def log_security_event(event):
    try:
        with open(LOG_FILE, "r") as file:
            events = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        events = []

    event["timestamp"] = datetime.now().isoformat()

    events.append(event)

    with open(LOG_FILE, "w") as file:
        json.dump(events, file, indent=4)

    return event