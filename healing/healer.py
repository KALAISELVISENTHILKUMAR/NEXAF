def self_heal(threat, verification_status):
    if verification_status == "VERIFIED":
        action = "NO_ACTION"
        message = f"{threat} response is healthy"

    else:
        action = "RECOVERY_REQUIRED"
        message = f"{threat} response requires recovery"

    return {
        "threat": threat,
        "verification_status": verification_status,
        "healing_action": action,
        "message": message
    }