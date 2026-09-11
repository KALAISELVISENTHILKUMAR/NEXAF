from healing.verifier import verify_response
from healing.healer import self_heal


def verify_and_heal(threat, action, risk):
    verification = verify_response(
        threat=threat,
        action=action,
        risk=risk
    )

    healing = self_heal(
        threat=threat,
        verification_status=verification["status"]
    )

    return {
        "verification": verification,
        "healing": healing
    }