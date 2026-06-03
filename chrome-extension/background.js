/**
 * SecSandbox Background Service Worker
 * Handles context menu actions and background API queries.
 */

// Cache for analyzed URLs
const scarcityCache = {};

// Create context menu item on install
chrome.runtime.onInstalled.addListener(() => {
    chrome.contextMenus.create({
        id: "scanWithSecSandbox",
        title: "🛡️ SecSandbox ile Analiz Et",
        contexts: ["link"] // Shows up only when right-clicking links
    });
});

// Listen for context menu clicks
chrome.contextMenus.onClicked.addListener((info, tab) => {
    if (info.menuItemId === "scanWithSecSandbox" && info.linkUrl) {
        const targetUrl = info.linkUrl;
        const scanUrl = `http://localhost:8000/?url=${encodeURIComponent(targetUrl)}`;
        
        // Open the analyzer site in a new tab
        chrome.tabs.create({ url: scanUrl });
    }
});

// Cache query handler (for popup/direct queries)
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "ANALYZE_URL") {
        const url = message.url;

        if (scarcityCache[url]) {
            sendResponse({ success: true, data: scarcityCache[url] });
            return true;
        }

        fetch("http://localhost:8000/api/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url })
        })
        .then(res => res.json())
        .then(data => {
            scarcityCache[url] = data;
            sendResponse({ success: true, data });
        })
        .catch(err => {
            sendResponse({ success: false, error: err.message });
        });

        return true;
    }
});
