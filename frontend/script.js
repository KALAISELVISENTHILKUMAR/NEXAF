document.addEventListener('DOMContentLoaded', () => {
  if (window.location.hash) {
    history.replaceState(null, null, window.location.pathname);
  }
  window.scrollTo(0, 0);

  const analyzeBtn = document.getElementById('analyze-btn');
  const requestInput = document.getElementById('request-input');

  if (!analyzeBtn) return;

  analyzeBtn.addEventListener('click', async (e) => {
    e.preventDefault();
    const inputPayload = requestInput ? requestInput.value : '';
    if (!inputPayload) return;

    if (document.getElementById('status-display')) document.getElementById('status-display').innerText = "ANALYZING...";

    try {
        const response = await fetch('http://127.0.0.1:8000/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ request: inputPayload })
        });

        if (!response.ok) throw new Error("Backend error");
        const data = await response.json();

        // Update UI Dashboard
        if (document.getElementById('status-display')) document.getElementById('status-display').innerText = data.status || "—";
        if (document.getElementById('attack-display')) document.getElementById('attack-display').innerText = data.attack_type || "None";
        if (document.getElementById('risk-display')) document.getElementById('risk-display').innerText = data.risk_score ? data.risk_score + "%" : "—";
        if (document.getElementById('reason-display')) document.getElementById('reason-display').innerText = data.reason || "—";
        if (document.getElementById('remediation-display')) document.getElementById('remediation-display').innerText = data.remediation || "—";
        
        if (document.getElementById('healing-display')) {
            document.getElementById('healing-display').innerText = data.status === "BLOCKED" ? "✓ System Verified Safe" : "No action required";
        }

        // Module 9: Update Event History
        const historyList = document.getElementById('history-list');
        if (historyList) {
            const listItem = document.createElement('li');
            listItem.className = 'history-item';
            let statusClass = data.status === 'BLOCKED' ? 'status-blocked' : 'status-allowed';
            const attackText = (data.attack_type && data.attack_type !== "None") ? ` — ${data.attack_type}` : '';
            listItem.innerHTML = `<strong>${inputPayload}</strong> — <span class="${statusClass}">${data.status || 'UNKNOWN'}</span>${attackText}`;
            historyList.prepend(listItem);
        }

    } catch (error) {
        console.error("Connection failed:", error);
        if (document.getElementById('status-display')) document.getElementById('status-display').innerText = "ERROR";
        if (document.getElementById('reason-display')) document.getElementById('reason-display').innerText = "Backend connection blocked by CORS or offline.";
    }
  });

  if (requestInput) {
    requestInput.addEventListener('keydown', (event) => {
      if (event.key === 'Enter') {
        event.preventDefault();
        analyzeBtn.click();
      }
    });
  }
});