from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional, List
import urllib.parse
import re
from response.response_engine import process_threat

app = FastAPI()

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
    remediation: List[str]

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
            "remediation": []
        }
    else:
        if max_confidence >= 80:
            conf_str = "high"
        elif max_confidence >= 50:
            conf_str = "medium"
        else:
            conf_str = "low"
            
        reason = f"A {conf_str}-confidence {primary_attack_type} attack indicator was detected"
        
        return {
            "allowed": allowed,
            "decision": decision,
            "threat_detected": True,
            "attack_type": primary_attack_type,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "confidence": max_confidence,
            "evidence": evidence_list,
            "reason": reason
        }

# ---------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------
@app.get("/")
def root():
    return {
        "message": "NEXAF AI Firewall API is running"
    }


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(request: AnalyzeRequest):
    result = analyze_url_for_threats(request.url)

    if result["threat_detected"]:
        threat_name = result["attack_type"].upper().replace(" ", "_")

        response_result = process_threat(
            threat=threat_name,
            risk=result["risk_level"],
            confidence=result["confidence"] / 100,
            source=request.source
        )

        result["decision"] = response_result["action"]
        result["remediation"] = response_result["remediation"]

        if response_result["action"] == "BLOCK":
            result["allowed"] = False
        else:
            result["allowed"] = True

        print("-" * 50)
        print(f"[NEXAF] URL          : {request.url}")
        print(f"[NEXAF] Threat       : YES")
        print(f"[NEXAF] Type         : {result['attack_type']}")
        print(f"[NEXAF] Risk         : {result['risk_score']}")
        print(f"[NEXAF] Level        : {result['risk_level']}")
        print(f"[NEXAF] Confidence   : {result['confidence']}")
        print(f"[NEXAF] Decision     : {response_result['action']}")
        print(f"[NEXAF] Remediation  : {response_result['remediation']}")
        print("-" * 50)

    else:
        print("-" * 50)
        print(f"[NEXAF] URL          : {request.url}")
        print(f"[NEXAF] Threat       : NO")
        print(f"[NEXAF] Decision     : ALLOW")
        print("-" * 50)

    return result
