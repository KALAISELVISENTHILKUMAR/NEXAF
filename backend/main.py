from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel
from typing import Optional, List
import urllib.parse
import re

app = FastAPI()

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    errors = []
    for error in exc.errors():
        field = ".".join(str(loc) for loc in error["loc"])
        errors.append(f"field '{field}' is invalid or missing: {error['msg']}")
    return JSONResponse(
        status_code=422,
        content={"detail": "Validation Error", "errors": errors}
    )

# ---------------------------------------------------------
# Pydantic Models for API Requests and Responses
# ---------------------------------------------------------
class AnalyzeRequest(BaseModel):
    url: str
    method: str
    source: str

class AnalyzeResponse(BaseModel):
    allowed: bool
    decision: str
    threat_detected: bool
    attack_type: Optional[str]
    risk_score: int
    risk_level: str
    confidence: int
    evidence: List[str]
    reason: str
    explanation: str
    recommendation: str

# ---------------------------------------------------------
# Threat Detection Engine
# ---------------------------------------------------------
# Signatures with associated base severity and confidence
# format: (pattern, risk_weight, confidence_weight, evidence_string)
THREAT_SIGNATURES = {
    "XSS": [
        (r"<script.*?>", 80, 95, "XSS script tag pattern detected"), 
        (r"javascript:", 70, 90, "JavaScript URI scheme detected"), 
        (r"onerror\s*=", 75, 95, "XSS inline event handler (onerror) detected"), 
        (r"onload\s*=", 75, 95, "XSS inline event handler (onload) detected"), 
        (r"alert\s*\(", 60, 85, "Suspicious alert function call detected")
    ],
    "SQL Injection": [
        (r"union\s+select", 85, 95, "SQLi UNION SELECT pattern detected"), 
        (r"or\s+\d+\s*=\s*\d+", 80, 95, "SQLi tautology (OR 1=1) pattern detected"), 
        (r"--\s*$", 70, 90, "SQLi comment sequence detected"), 
        (r"drop\s+table", 90, 100, "SQLi DROP TABLE command detected"), 
        (r"select\s+.*\s+from", 75, 85, "SQLi SELECT statement detected"),
        (r"'\s*or\s+'1'\s*=\s*'1", 80, 95, "SQLi tautology string pattern detected")
    ],
    "Path Traversal": [
        (r"\.\./", 80, 95, "Path traversal (../) sequence detected"), 
        (r"\.\.\\", 80, 95, "Path traversal (..\\) directory climbing detected"), 
        (r"/etc/passwd", 85, 100, "Access to sensitive file (/etc/passwd) requested"), 
        (r"c:\\windows", 75, 90, "Access to sensitive internal directory requested")
    ],
    "Command Injection": [
        (r";\s*cat\b", 80, 95, "Command injection (cat) pattern detected"), 
        (r";\s*ls\b", 75, 90, "Command injection (ls) pattern detected"), 
        (r"\|\s*bash", 90, 95, "Command injection (pipe to bash) pattern detected"), 
        (r"`.*`", 60, 70, "Suspicious backtick command execution detected"), 
        (r"&\s*ping\b", 70, 85, "Command injection (ping) pattern detected")
    ],
    "Suspicious URL patterns": [
        (r"php\?id=\d+.*%", 35, 60, "Suspicious PHP ID parameter encoding detected"),
        (r"base64_decode", 50, 80, "Base64 decode function in URL detected")
    ]
}

def analyze_url_for_threats(url: str):
    """
    Analyzes a URL for potential security threats.
    Normalizes the URL by decoding it before analysis.
    """
    # 1. Normalize
    decoded_url = urllib.parse.unquote(url).lower()
    
    total_risk = 0
    max_confidence = 0
    primary_attack_type = None
    max_type_risk = -1
    evidence_list = []

    # Record normalization as potential evidence of obfuscation
    if url.lower() != decoded_url:
        evidence_list.append("Encoded payload normalized before analysis")

    # 2. Check threat signatures
    for attack_type, signatures in THREAT_SIGNATURES.items():
        type_risk = 0
        for pattern, risk_weight, conf_weight, evidence_str in signatures:
            if re.search(pattern, decoded_url):
                total_risk += risk_weight
                type_risk += risk_weight
                if conf_weight > max_confidence:
                    max_confidence = conf_weight
                if evidence_str not in evidence_list:
                    evidence_list.append(evidence_str)
                    
        # Store primary attack type as highest scoring risk group
        if type_risk > max_type_risk:
            max_type_risk = type_risk
            primary_attack_type = attack_type if type_risk > 0 else primary_attack_type

    # 3. Deterministic risk calculation (0-100)
    risk_score = min(total_risk, 100)
    
    # 4. Risk Level and Decision logic
    if risk_score <= 19:
        risk_level = "LOW"
        decision = "ALLOW"
    elif risk_score <= 39:
        risk_level = "LOW"
        decision = "ALLOW"
    elif risk_score <= 59:
        risk_level = "MEDIUM"
        decision = "MONITOR"
    elif risk_score <= 79:
        risk_level = "HIGH"
        decision = "BLOCK"
    else:
        risk_level = "CRITICAL"
        decision = "BLOCK"
        
    # Decision flags
    allowed = (decision == "ALLOW" or decision == "MONITOR")
    threat_detected = risk_score > 0
    
    if not threat_detected:
        return {
            "allowed": True,
            "decision": "ALLOW",
            "threat_detected": False,
            "attack_type": None,
            "risk_score": 0,
            "risk_level": "LOW",
            "confidence": 100,
            "evidence": [],
            "reason": "No known malicious indicators detected",
            "explanation": "NEXAF did not detect known malicious indicators in this request.",
            "recommendation": "No immediate action is required."
        }
    else:
        if max_confidence >= 80:
            conf_str = "high"
        elif max_confidence >= 50:
            conf_str = "medium"
        else:
            conf_str = "low"
            
        reason = f"A {conf_str}-confidence {primary_attack_type} attack indicator was detected"
        
        # Construct explanation based on risk_level
        if risk_level == "LOW":
            risk_desc = "No significant malicious indicators were detected."
        elif risk_level == "MEDIUM":
            risk_desc = "NEXAF detected suspicious activity that requires monitoring but does not currently meet the blocking threshold."
        elif risk_level == "HIGH":
            risk_desc = "NEXAF detected a high-risk malicious pattern and blocked the request."
        elif risk_level == "CRITICAL":
            risk_desc = "NEXAF detected a critical-risk attack indicator and blocked the request."
        else:
            risk_desc = f"NEXAF made a {decision} decision based on a {risk_level} risk level."

        # Construct explanation based on all detected attack types
        detected_types = set()
        for attack_name, sigs in THREAT_SIGNATURES.items():
            for pattern, r_w, c_w, ev in sigs:
                if ev in evidence_list:
                    detected_types.add(attack_name)

        attack_descs = []
        if "XSS" in detected_types:
            attack_descs.append("script-injection indicators that could potentially cause unwanted JavaScript to execute in a user's browser")
        if "SQL Injection" in detected_types:
            attack_descs.append("SQL manipulation indicators that could potentially alter a database query")
        if "Path Traversal" in detected_types:
            attack_descs.append("path traversal indicators that could potentially attempt to access files outside the intended directory")
        if "Command Injection" in detected_types:
            attack_descs.append("command-injection indicators that could potentially attempt to execute operating-system commands")
        if "Suspicious URL patterns" in detected_types:
            attack_descs.append("suspicious characteristics that require caution or monitoring")

        if attack_descs:
            attack_desc = " and ".join(attack_descs)
        else:
            attack_desc = "suspicious patterns"

        # Combine explanation
        if evidence_list:
            explanation = f"{risk_desc} The request contains {attack_desc}. Specific indicators found: { ', '.join(evidence_list) }."
        else:
            explanation = f"{risk_desc} The request contains {attack_desc}."

        # Recommendation logic
        if decision == "BLOCK":
            recommendation = "Do not send the suspicious payload. Review and sanitize the affected input."
        elif decision == "MONITOR":
            recommendation = "Continue monitoring this request and verify the source before allowing similar activity."
        else:
            recommendation = "No immediate action is required."

        return {
            "allowed": allowed,
            "decision": decision,
            "threat_detected": True,
            "attack_type": primary_attack_type,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "confidence": max_confidence,
            "evidence": evidence_list,
            "reason": reason,
            "explanation": explanation,
            "recommendation": recommendation
        }

# ---------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------
@app.get("/")
def read_root():
    return {"message": "NEXAF AI Firewall Backend Running"}

@app.post("/analyze", response_model=AnalyzeResponse)
def analyze_request(request: AnalyzeRequest):
    """
    Endpoint for real-time risk analysis from the browser security layer.
    """
    # Analyze the incoming request for threats
    result = analyze_url_for_threats(request.url)
    
    # Advanced Security Logging (DO NOT log sensitive info)
    print("-" * 50)
    print(f"[NEXAF] URL        : {request.url}")
    print(f"[NEXAF] Threat     : {'YES' if result['threat_detected'] else 'NO'}")
    print(f"[NEXAF] Type       : {result['attack_type'] if result['attack_type'] else 'None'}")
    print(f"[NEXAF] Risk       : {result['risk_score']}")
    print(f"[NEXAF] Level      : {result['risk_level']}")
    print(f"[NEXAF] Confidence : {result['confidence']}")
    print(f"[NEXAF] Decision   : {result['decision']}")
    print("-" * 50)
    
    return result
