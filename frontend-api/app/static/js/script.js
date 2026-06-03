document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('analyze-form');
    const urlInput = document.getElementById('url-input');
    const searchSection = document.getElementById('search-section');
    const loadingSection = document.getElementById('loading-section');
    const resultsSection = document.getElementById('results-section');
    const errorSection = document.getElementById('error-section');

    const loadingText = document.getElementById('loading-text');
    const progressBar = document.getElementById('progress-bar');
    const retryBtn = document.getElementById('retry-btn');

    const loadingStages = [
        "Checking SSL/TLS certificate...",
        "Running WHOIS & domain analysis...",
        "Launching headless browser...",
        "Navigating to target URL...",
        "Monitoring for automatic downloads...",
        "Capturing page screenshot...",
        "Extracting links & cookies...",
        "Analyzing security headers...",
        "Analyzing page content...",
        "Running cookie security audit...",
        "Building link tree...",
        "Preparing data for AI models...",
        "Generating threat report..."
    ];

    // Loading animation
    let loadingInterval = null;

    function startLoadingAnimation() {
        let stage = 0;
        progressBar.style.width = '0%';
        loadingText.innerText = loadingStages[0];

        loadingInterval = setInterval(() => {
            stage++;
            if (stage < loadingStages.length) {
                loadingText.innerText = loadingStages[stage];
                progressBar.style.width = `${((stage + 1) / loadingStages.length) * 95}%`;
            } else {
                stage = 0;
            }
        }, 2500);
    }

    function stopLoadingAnimation() {
        if (loadingInterval) {
            clearInterval(loadingInterval);
            loadingInterval = null;
        }
        progressBar.style.width = '100%';
    }

    function showSection(section) {
        [searchSection, loadingSection, resultsSection, errorSection].forEach(s => {
            s.classList.add('hidden');
        });
        section.classList.remove('hidden');
    }

    // Retry button
    retryBtn.addEventListener('click', () => {
        showSection(searchSection);
    });

    // Form submission
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const targetUrl = urlInput.value.trim();
        if (!targetUrl) return;

        showSection(loadingSection);
        startLoadingAnimation();

        try {
            const response = await fetch('/api/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: targetUrl })
            });

            stopLoadingAnimation();

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.error || `Server error: ${response.status}`);
            }

            const data = await response.json();

            if (data.error && data.overall_status === 'error') {
                throw new Error(data.error);
            }

            renderResults(data);
            searchSection.classList.remove('hidden');
            resultsSection.classList.remove('hidden');
            loadingSection.classList.add('hidden');
            errorSection.classList.add('hidden');

        } catch (err) {
            stopLoadingAnimation();
            document.getElementById('error-text').innerText = err.message || 'An unexpected error occurred.';
            showSection(errorSection);
            searchSection.classList.remove('hidden');
        }
    });

    // =====================
    // RENDER FUNCTIONS
    // =====================

    function renderResults(data) {
        renderMainStatus(data);
        renderScreenshot(data.screenshot_b64 || "");
        renderAlerts(data.alerts || []);
        renderDetails(data);
        renderContentAnalysis(data.content || {});
        renderSecurityHeaders(data.security_headers || {});
        renderCookies(data.cookie_analysis || {});
        renderLinks(data.link_analysis || {});
        renderAI(data.ai_data || {});
        renderForms(data.forms || {});
        renderLogs(data.logs || []);
    }

    function renderMainStatus(data) {
        const panel = document.getElementById('main-status-panel');
        const icon = document.getElementById('status-icon-el');
        const label = document.getElementById('status-label');
        const desc = document.getElementById('status-description');

        panel.classList.remove('threat-high', 'threat-medium', 'threat-safe');

        if (data.overall_status === 'malicious') {
            panel.classList.add('threat-high');
            icon.className = 'fa-solid fa-triangle-exclamation';
            icon.style.color = 'var(--danger)';
            label.style.color = 'var(--danger)';
        } else if (data.overall_status === 'suspicious') {
            panel.classList.add('threat-medium');
            icon.className = 'fa-solid fa-exclamation-circle';
            icon.style.color = 'var(--warning)';
            label.style.color = 'var(--warning)';
        } else {
            panel.classList.add('threat-safe');
            icon.className = 'fa-solid fa-shield-check';
            icon.style.color = 'var(--success)';
            label.style.color = 'var(--success)';
        }

        label.innerText = data.overall_label || 'Analysis Complete';
        desc.innerText = data.overall_description || '';
    }

    function renderScreenshot(b64) {
        const content = document.getElementById('screenshot-content');
        if (!b64) {
            content.innerHTML = '<p style="color:var(--text-muted);text-align:center;">Screenshot not available.</p>';
            return;
        }
        content.innerHTML = `
            <div class="screenshot-wrapper">
                <img src="data:image/png;base64,${b64}" alt="Page Screenshot" class="screenshot-img">
            </div>
        `;
    }

    function renderAlerts(alerts) {
        const container = document.getElementById('badge-container');
        const noAlerts = document.getElementById('no-alerts');
        container.innerHTML = '';

        if (!alerts.length) {
            noAlerts.classList.remove('hidden');
            return;
        }

        noAlerts.classList.add('hidden');

        alerts.forEach(alert => {
            const badge = document.createElement('div');
            badge.className = `badge badge-${alert.type}`;
            badge.innerHTML = `<i class="fa-solid ${alert.icon}"></i> ${escapeHtml(alert.text)}`;
            container.appendChild(badge);
        });
    }

    function renderDetails(data) {
        const grid = document.getElementById('detail-grid');
        grid.innerHTML = '';

        const domain = data.domain || {};
        const ssl = data.ssl || {};

        const items = [
            { label: 'Domain', value: domain.domain || 'N/A' },
            { label: 'Domain Age', value: domain.age_days != null ? `${domain.age_days} days` : 'N/A' },
            { label: 'Registrar', value: domain.registrar || 'N/A' },
            { label: 'Created', value: domain.creation_date || 'N/A' },
            { label: 'SSL/TLS', value: ssl.has_ssl ? 'Yes ✓' : 'No ✗' },
            { label: 'Cert Issuer', value: ssl.issuer || 'N/A' },
            { label: 'Cert Age', value: ssl.age_days != null ? `${ssl.age_days} days` : 'N/A' },
            { label: 'Cert Expires', value: ssl.not_after || 'N/A' },
        ];

        items.forEach(item => {
            const row = document.createElement('div');
            row.className = 'detail-row';
            row.innerHTML = `<span class="detail-label">${item.label}</span><span class="detail-value">${escapeHtml(String(item.value))}</span>`;
            grid.appendChild(row);
        });
    }

    function renderContentAnalysis(contentData) {
        const content = document.getElementById('content-analysis-details');
        if (!contentData) {
            content.innerHTML = '<p style="color:var(--text-muted);text-align:center;">No content analysis data available.</p>';
            return;
        }

        const obfuscationScore = contentData.obfuscation_score || 0;
        const keywords = contentData.obfuscation_keywords_found || [];
        const totalScripts = contentData.total_scripts || 0;
        const extScriptsRatio = (contentData.external_script_ratio || 0) * 100;
        const hiddenElements = contentData.hidden_elements || [];

        let html = `
            <div class="content-summary-grid">
                <div class="ai-insight-item">
                    <div class="insight-header">
                        <span>JS Obfuscation Risk Score</span>
                        <span class="${obfuscationScore > 40 ? 'text-danger' : obfuscationScore > 15 ? 'text-warning' : 'text-success'}">${obfuscationScore.toFixed(0)}%</span>
                    </div>
                    <div class="insight-bar-bg">
                        <div class="insight-bar ${obfuscationScore > 40 ? 'fill-danger' : obfuscationScore > 15 ? 'fill-warning' : 'fill-success'}" style="width:${Math.max(obfuscationScore, 3)}%;"></div>
                    </div>
                </div>
                
                <div class="detail-row" style="margin-top:0.8rem;">
                    <span class="detail-label">Total JS Scripts</span>
                    <span class="detail-value">${totalScripts}</span>
                </div>
                <div class="detail-row" style="border-bottom:none;">
                    <span class="detail-label">External JS Ratio</span>
                    <span class="detail-value">${extScriptsRatio.toFixed(0)}%</span>
                </div>
            </div>
        `;

        if (keywords.length > 0) {
            html += `
                <div class="keywords-list-container" style="margin-top:1rem;">
                    <h4 class="link-subtitle text-warning" style="margin-bottom:0.5rem;"><i class="fa-solid fa-triangle-exclamation"></i> Suspicious JS Terms</h4>
                    <div class="ext-domain-list">
                        ${keywords.map(kw => `<span class="ext-domain-tag" style="background:rgba(255, 165, 2, 0.15);color:var(--warning);border-color:rgba(255, 165, 2, 0.3);">${escapeHtml(kw)}</span>`).join('')}
                    </div>
                </div>
            `;
        }

        if (hiddenElements.length > 0) {
            html += `
                <div class="hidden-elements-container" style="margin-top:1.5rem;">
                    <h4 class="link-subtitle text-danger" style="margin-bottom:0.5rem;"><i class="fa-solid fa-eye-slash"></i> Hidden Elements Breakdown (${hiddenElements.length})</h4>
                    <div class="hidden-elements-list" style="max-height: 250px; overflow-y: auto; display: flex; flex-direction: column; gap: 0.6rem; padding-right: 0.3rem;">
                        ${hiddenElements.map(el => `
                            <div class="cookie-issue-item" style="border-left: 3px solid var(--danger); padding-left: 0.8rem; background: rgba(255, 71, 87, 0.05); display: flex; flex-direction: column; gap: 0.2rem;">
                                <span class="cookie-name" style="color:var(--danger); font-family: monospace; font-size: 0.95rem;">&lt;${escapeHtml(el.tag)}&gt;</span>
                                <span style="font-size:0.8rem; word-break: break-all; color:var(--text-muted);">
                                    ${escapeHtml(el.info)}
                                </span>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
        } else {
            html += `
                <div class="hidden-elements-container" style="margin-top:1.5rem;">
                    <p style="color:var(--text-muted);text-align:center;font-size:0.9rem;">
                        <i class="fa-solid fa-eye text-success" style="margin-right:0.3rem;"></i> No hidden inputs, links, or forms detected.
                    </p>
                </div>
            `;
        }

        content.innerHTML = html;
    }

    function renderSecurityHeaders(headersData) {
        const content = document.getElementById('headers-content');
        const grade = headersData.grade || '?';
        const score = headersData.score || 0;
        const found = headersData.headers_found || [];
        const missing = headersData.headers_missing || [];

        const gradeColor = grade === 'A' ? 'var(--success)' :
                           grade === 'B' ? '#7bed9f' :
                           grade === 'C' ? 'var(--warning)' :
                           'var(--danger)';

        let html = `
            <div class="header-grade-row">
                <div class="header-grade" style="color:${gradeColor};border-color:${gradeColor};">${grade}</div>
                <div class="header-grade-info">
                    <span class="header-score">${score}%</span>
                    <span class="header-detail">${found.length} present / ${missing.length} missing</span>
                </div>
            </div>
        `;

        if (missing.length > 0) {
            html += '<div class="header-missing-list">';
            missing.forEach(h => {
                const sevColor = h.severity === 'high' ? 'var(--danger)' :
                                 h.severity === 'medium' ? 'var(--warning)' : 'var(--text-muted)';
                html += `
                    <div class="header-missing-item">
                        <span class="header-name"><i class="fa-solid fa-xmark" style="color:${sevColor};"></i> ${escapeHtml(h.name)}</span>
                        <span class="header-desc">${escapeHtml(h.description)}</span>
                    </div>
                `;
            });
            html += '</div>';
        }

        if (found.length > 0) {
            html += '<div class="header-found-list">';
            found.forEach(h => {
                html += `
                    <div class="header-found-item">
                        <span class="header-name"><i class="fa-solid fa-check" style="color:var(--success);"></i> ${escapeHtml(h.name)}</span>
                    </div>
                `;
            });
            html += '</div>';
        }

        content.innerHTML = html;
    }

    function renderCookies(cookieData) {
        const content = document.getElementById('cookie-content');
        const total = cookieData.total_cookies || 0;
        const secure = cookieData.secure_cookies || 0;
        const insecure = cookieData.insecure_cookies || [];
        const tracking = cookieData.tracking_cookies || [];
        const score = cookieData.score || 0;

        if (total === 0) {
            content.innerHTML = '<p style="color:var(--text-muted);text-align:center;">No cookies detected on this page.</p>';
            return;
        }

        let html = `
            <div class="cookie-summary">
                <div class="cookie-stat">
                    <span class="cookie-stat-value">${total}</span>
                    <span class="cookie-stat-label">Total</span>
                </div>
                <div class="cookie-stat">
                    <span class="cookie-stat-value text-success">${secure}</span>
                    <span class="cookie-stat-label">Secure</span>
                </div>
                <div class="cookie-stat">
                    <span class="cookie-stat-value ${insecure.length > 0 ? 'text-danger' : 'text-success'}">${insecure.length}</span>
                    <span class="cookie-stat-label">Insecure</span>
                </div>
                <div class="cookie-stat">
                    <span class="cookie-stat-value ${tracking.length > 0 ? 'text-warning' : 'text-success'}">${tracking.length}</span>
                    <span class="cookie-stat-label">Tracking</span>
                </div>
            </div>
        `;

        if (insecure.length > 0) {
            html += '<div class="cookie-issues">';
            insecure.slice(0, 5).forEach(c => {
                html += `
                    <div class="cookie-issue-item">
                        <span class="cookie-name">${escapeHtml(c.name)}</span>
                        <span class="cookie-issues-list">${c.issues.map(i => `<span class="cookie-issue-tag">${escapeHtml(i)}</span>`).join('')}</span>
                    </div>
                `;
            });
            html += '</div>';
        }

        content.innerHTML = html;
    }

    function renderLinks(linkData) {
        const content = document.getElementById('link-content');
        const total = linkData.total_links || 0;
        const internal = linkData.internal_links || 0;
        const external = linkData.external_links || 0;
        const downloads = linkData.download_links || [];
        const insecure = linkData.insecure_links || [];
        const suspicious = linkData.suspicious_links || [];
        const extDomains = linkData.external_domains || [];

        if (total === 0) {
            content.innerHTML = '<p style="color:var(--text-muted);text-align:center;">No links found on this page.</p>';
            return;
        }

        let html = `
            <div class="link-summary">
                <div class="link-stat">
                    <span class="link-stat-value">${total}</span>
                    <span class="link-stat-label">Total Links</span>
                </div>
                <div class="link-stat">
                    <span class="link-stat-value text-success">${internal}</span>
                    <span class="link-stat-label">Internal</span>
                </div>
                <div class="link-stat">
                    <span class="link-stat-value text-info">${external}</span>
                    <span class="link-stat-label">External</span>
                </div>
            </div>
        `;

        if (suspicious.length > 0) {
            html += '<h4 class="link-subtitle text-danger"><i class="fa-solid fa-link-slash"></i> Misleading Links</h4>';
            html += '<div class="link-issues">';
            suspicious.forEach(s => {
                html += `
                    <div class="link-issue-item link-issue-danger">
                        <div class="link-issue-text">Shows: <strong>${escapeHtml(s.displayed_text)}</strong></div>
                        <div class="link-issue-href">Goes to: <strong>${escapeHtml(s.actual_domain)}</strong></div>
                    </div>
                `;
            });
            html += '</div>';
        }

        if (downloads.length > 0) {
            html += '<h4 class="link-subtitle text-warning"><i class="fa-solid fa-file-arrow-down"></i> Download Links</h4>';
            html += '<div class="link-issues">';
            downloads.forEach(d => {
                html += `
                    <div class="link-issue-item link-issue-warning">
                        <span>${escapeHtml(d.text || d.href)}</span>
                        <span class="cookie-issue-tag">${escapeHtml(d.extension)}</span>
                    </div>
                `;
            });
            html += '</div>';
        }

        if (extDomains.length > 0) {
            html += '<h4 class="link-subtitle"><i class="fa-solid fa-globe"></i> External Domains</h4>';
            html += '<div class="ext-domain-list">';
            extDomains.slice(0, 10).forEach(d => {
                html += `<span class="ext-domain-tag">${escapeHtml(d)}</span>`;
            });
            html += '</div>';
        }

        content.innerHTML = html;
    }

    function renderAI(aiData) {
        const content = document.getElementById('ai-content');

        if (!aiData.ai_service_available) {
            content.innerHTML = `
                <div class="ai-placeholder">
                    <i class="fa-solid fa-plug-circle-xmark" style="font-size:1.5rem;color:var(--text-muted);margin-bottom:0.5rem;"></i>
                    <p style="color:var(--text-muted);margin-bottom:1rem;">AI Service not connected yet</p>
                    <div class="ai-insight-item">
                        <div class="insight-header">
                            <span>Preprocessed Text Length</span>
                            <span class="text-info">${aiData.page_text_length || 0} chars</span>
                        </div>
                    </div>
                    <div class="ai-insight-item">
                        <div class="insight-header">
                            <span>Form Features Extracted</span>
                            <span class="text-info">${Object.keys(aiData.form_features || {}).length} fields</span>
                        </div>
                    </div>
                    <p style="color:var(--text-muted);font-size:0.85rem;margin-top:1rem;">
                        <i class="fa-solid fa-info-circle"></i> Data is ready for AI inference. Connect AI service to get phishing & anomaly scores.
                    </p>
                </div>
            `;
        } else {
            const phishing = aiData.phishing_text_score || 0;
            const anomaly = aiData.form_anomaly_score || 0;

            content.innerHTML = `
                <div class="ai-insight-item">
                    <div class="insight-header">
                        <span>Phishing Text Risk</span>
                        <span class="${phishing > 60 ? 'text-danger' : phishing > 30 ? 'text-warning' : 'text-success'}">${phishing.toFixed(0)}%</span>
                    </div>
                    <div class="insight-bar-bg">
                        <div class="insight-bar ${phishing > 60 ? 'fill-danger' : phishing > 30 ? 'fill-warning' : 'fill-success'}" style="width:${phishing}%;"></div>
                    </div>
                </div>
                <div class="ai-insight-item">
                    <div class="insight-header">
                        <span>Form Anomaly & Redirection</span>
                        <span class="${anomaly > 60 ? 'text-danger' : anomaly > 30 ? 'text-warning' : 'text-success'}">${anomaly.toFixed(0)}%</span>
                    </div>
                    <div class="insight-bar-bg">
                        <div class="insight-bar ${anomaly > 60 ? 'fill-danger' : anomaly > 30 ? 'fill-warning' : 'fill-success'}" style="width:${anomaly}%;"></div>
                    </div>
                </div>
            `;
        }
    }

    function renderForms(formData) {
        const content = document.getElementById('form-content');

        if (!formData.total_forms) {
            content.innerHTML = '<p style="color:var(--text-muted);text-align:center;">No forms detected on this page.</p>';
            return;
        }

        let html = `
            <div class="form-summary">
                <span>Total Forms: <strong>${formData.total_forms}</strong></span>
                <span>Suspicious: <strong class="${formData.suspicious_forms > 0 ? 'text-danger' : 'text-success'}">${formData.suspicious_forms}</strong></span>
            </div>
        `;

        (formData.forms || []).forEach((f, i) => {
            const statusClass = f.redirects_external ? 'form-card-danger' : 'form-card-safe';
            html += `
                <div class="form-card ${statusClass}">
                    <div class="form-card-header">
                        <span>Form #${i + 1}</span>
                        <span class="form-method">${escapeHtml(f.method)}</span>
                    </div>
                    <div class="form-card-body">
                        <div class="detail-row"><span class="detail-label">Action</span><span class="detail-value">${escapeHtml(f.action || 'N/A')}</span></div>
                        <div class="detail-row"><span class="detail-label">Inputs</span><span class="detail-value">${escapeHtml(f.input_types.join(', ') || 'none')}</span></div>
                        <div class="detail-row"><span class="detail-label">Password Field</span><span class="detail-value">${f.has_password_field ? '<span class="text-warning">Yes</span>' : 'No'}</span></div>
                        <div class="detail-row"><span class="detail-label">External Redirect</span><span class="detail-value">${f.redirects_external ? '<span class="text-danger">Yes → ' + escapeHtml(f.external_domain || '') + '</span>' : '<span class="text-success">No</span>'}</span></div>
                    </div>
                </div>
            `;
        });

        content.innerHTML = html;
    }

    function renderLogs(logs) {
        const terminal = document.getElementById('terminal');
        terminal.innerHTML = '';

        let delay = 0;
        logs.forEach(log => {
            const line = document.createElement('div');
            line.className = 'log-line';
            line.style.opacity = '0';

            let colorClass = 'text-muted';
            let prefix = 'INFO';
            if (log.level === 'WARN') { colorClass = 'text-warning'; prefix = 'WARN'; }
            else if (log.level === 'ALERT') { colorClass = 'text-danger'; prefix = 'ALERT'; }
            else if (log.level === 'SUCCESS') { colorClass = 'text-success'; prefix = 'SUCCESS'; }
            else if (log.level === 'INFO') { colorClass = 'text-info'; prefix = 'INFO'; }

            line.classList.add(colorClass);
            line.textContent = `[${prefix}] ${log.message}`;
            terminal.appendChild(line);

            setTimeout(() => {
                line.style.transition = 'opacity 0.3s';
                line.style.opacity = '1';
                terminal.scrollTop = terminal.scrollHeight;
            }, delay);
            delay += 150;
        });
    }

    // Check if '?url=...' is passed in the URL parameters (context menu redirect)
    const urlParams = new URLSearchParams(window.location.search);
    const urlQuery = urlParams.get('url');
    if (urlQuery) {
        urlInput.value = urlQuery;
        // Trigger submit
        form.dispatchEvent(new Event('submit'));
    }

    // Utility: prevent XSS
    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }
});
