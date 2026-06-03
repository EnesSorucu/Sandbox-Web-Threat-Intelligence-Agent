const API_BASE = "http://localhost:8000";

const urlInput = document.getElementById("urlInput");
const analyzeBtn = document.getElementById("analyzeBtn");
const resultArea = document.getElementById("resultArea");
const serverDot = document.getElementById("serverDot");
const serverText = document.getElementById("serverText");

// Check server health on popup open
async function checkServer() {
    try {
        const res = await fetch(`${API_BASE}/`, { method: "GET" });
        if (res.ok) {
            serverDot.className = "server-dot dot-online";
            serverText.textContent = "Server online";
        } else {
            throw new Error();
        }
    } catch {
        serverDot.className = "server-dot dot-offline";
        serverText.textContent = "Server offline";
    }
}

// Get current tab URL and pre-fill
chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0]?.url && tabs[0].url.startsWith("http")) {
        urlInput.value = tabs[0].url;
    }
});

// Analyze on click
analyzeBtn.addEventListener("click", async () => {
    const url = urlInput.value.trim();
    if (!url) return;

    analyzeBtn.disabled = true;
    analyzeBtn.textContent = "...";
    resultArea.innerHTML = `<div class="loading">⏳ Analyzing ${new URL(url).hostname}...</div>`;

    try {
        const res = await fetch(`${API_BASE}/api/analyze`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url })
        });

        if (!res.ok) throw new Error("API error");
        const data = await res.json();
        renderResult(data);
    } catch (e) {
        resultArea.innerHTML = `
            <div class="result-card">
                <div class="result-status malicious">
                    <span class="status-emoji">❌</span>
                    <div>
                        <div class="status-label text-danger">Connection Failed</div>
                        <div class="status-desc">Make sure SecSandbox server is running</div>
                    </div>
                </div>
            </div>
        `;
    } finally {
        analyzeBtn.disabled = false;
        analyzeBtn.textContent = "Scan";
    }
});

// Press Enter to analyze
urlInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") analyzeBtn.click();
});

function renderResult(data) {
    const statusMap = {
        safe: { emoji: "🛡️", label: "Site Appears Safe", color: "safe", textClass: "text-safe" },
        suspicious: { emoji: "⚠️", label: "Suspicious Activity", color: "suspicious", textClass: "text-warn" },
        malicious: { emoji: "🚨", label: "Malicious Site!", color: "malicious", textClass: "text-danger" }
    };

    const s = statusMap[data.overall_status] || statusMap.suspicious;
    const domain = data.domain?.domain || "";
    const ageText = data.domain?.age_days != null ? `${data.domain.age_days} days` : "Unknown";
    const ssl = data.ssl?.has_ssl;
    const alerts = data.alerts || [];
    const headers = data.security_headers?.grade || "?";
    const linkCount = data.link_analysis?.total_links || 0;

    let alertsHTML = "";
    if (alerts.length > 0) {
        alertsHTML = `<div class="alerts-list">` +
            alerts.slice(0, 3).map(a => `<div class="alert-item">${escapeHtml(a.text)}</div>`).join("") +
            `</div>`;
    }

    resultArea.innerHTML = `
        <div class="result-card">
            <div class="result-status ${s.color}">
                <span class="status-emoji">${s.emoji}</span>
                <div>
                    <div class="status-label ${s.textClass}">${s.label}</div>
                    <div class="status-desc">${escapeHtml(data.overall_description || "")}</div>
                </div>
            </div>
            <div class="result-rows">
                <div class="result-row">
                    <span class="result-key">Domain</span>
                    <span class="result-val">${escapeHtml(domain)}</span>
                </div>
                <div class="result-row">
                    <span class="result-key">Domain Age</span>
                    <span class="result-val">${ageText}</span>
                </div>
                <div class="result-row">
                    <span class="result-key">SSL/TLS</span>
                    <span class="result-val ${ssl ? 'text-safe' : 'text-danger'}">${ssl ? "✓ Secured" : "✗ No SSL"}</span>
                </div>
                <div class="result-row">
                    <span class="result-key">Security Headers</span>
                    <span class="result-val ${headers === 'A' || headers === 'B' ? 'text-safe' : 'text-warn'}">Grade ${headers}</span>
                </div>
                <div class="result-row">
                    <span class="result-key">Links Found</span>
                    <span class="result-val">${linkCount}</span>
                </div>
                <div class="result-row">
                    <span class="result-key">Alerts</span>
                    <span class="result-val ${alerts.length > 0 ? 'text-warn' : 'text-safe'}">${alerts.length} detected</span>
                </div>
            </div>
            ${alertsHTML}
        </div>
    `;
}

function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = String(str);
    return div.innerHTML;
}

// Initialize
checkServer();
