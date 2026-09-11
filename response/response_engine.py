from asyncio import base_events
from asyncio import base_events
from response.remediation import generate_remediation
from response.logger import log_security_event
from healing.integration import verify_and_heal


def process_threat(threat, risk, confidence, source):
    if risk in ["HIGH", "CRITICAL"]:
        action = "BLOCK"
        reason = f"{risk}-risk {threat} detected"

    elif risk == "MEDIUM":
        action = "MONITOR"
        reason = f"Suspicious {threat} detected"

    else:
        action = "ALLOW"
        reason = "Low-risk traffic detected"

    remediation_result = generate_remediation(threat, action)

    event = {
        "threat": threat,
        "risk": risk,
        "confidence": confidence,
        "source": source,
        "action": action,
        "reason": reason,
        "remediation": remediation_result["remediation"]
    }

    log_security_event(event)

    healing_result = verify_and_heal(
    threat=threat,
    action=action,
    risk=risk
)

    event["verification"] = healing_result["verification"]
    event["healing"] = healing_result["healing"]

    log_security_event(event)

    return event