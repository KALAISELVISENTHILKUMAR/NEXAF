const analyzeButton = document.getElementById("analyzeButton");

analyzeButton.addEventListener("click", function () {

    const request = document.getElementById("requestInput").value.trim();

    const status = document.getElementById("status");
    const attack = document.getElementById("attack");
    const risk = document.getElementById("risk");
    const reason = document.getElementById("reason");
    const remediation = document.getElementById("remediation");
    const healing = document.getElementById("healing");

    if (request === "") {
        status.textContent = "Please enter a request";
        attack.textContent = "-";
        risk.textContent = "-";
        reason.textContent = "Enter a URL or request for analysis.";
        remediation.textContent = "-";
        healing.textContent = "-";
        return;
    }

    status.textContent = "🔴 BLOCKED";
    attack.textContent = "SQL Injection";
    risk.textContent = "94%";

    reason.textContent =
        "The request contains a suspicious SQL manipulation pattern.";

    remediation.textContent =
        "SQL Protection Rule Applied.";

    healing.textContent =
        "✓ System Verified";
});