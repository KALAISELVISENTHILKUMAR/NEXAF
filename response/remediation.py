def generate_remediation(threat, action):
    if threat == "SQL_INJECTION":
        steps = [
            "Block the malicious source",
            "Review the affected request",
            "Use parameterized SQL queries",
            "Validate and sanitize user input"
        ]

    elif threat == "XSS":
        steps = [
            "Block the malicious request",
            "Review the affected URL",
            "Sanitize user input",
            "Apply output encoding"
        ]

    elif threat == "PORT_SCAN":
        steps = [
            "Block the scanning source",
            "Review connection attempts",
            "Restrict unnecessary open ports",
            "Monitor the source for repeated activity"
        ]

    else:
        steps = [
            "Review the detected activity",
            "Monitor the source",
            "Check security logs"
        ]

    return {
        "threat": threat,
        "action": action,
        "remediation": steps
    }