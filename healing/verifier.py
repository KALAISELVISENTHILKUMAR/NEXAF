def verify_response(threat, action, risk):
    expected_action = "BLOCK" if risk in ["HIGH", "CRITICAL"] else "MONITOR" if risk == "MEDIUM" else "ALLOW"

    if action == expected_action:
        status = "VERIFIED"
        message = f"{threat} response verified successfully"
    else:
        status = "FAILED"
        message = f"{threat} response verification failed"

    return {
        "threat": threat,
        "risk": risk,
        "expected_action": expected_action,
        "actual_action": action,
        "status": status,
        "message": message
    }