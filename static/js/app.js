/**
 * Linux Hardening Assistant - Dashboard JavaScript
 * Handles SSH connection, audit, AI analysis, and UI updates.
 */

(() => {
    "use strict";

    // --- State ---
    let isConnected = false;
    let isDemoMode = false;
    let hasAudit = false;
    let hasReport = false;
    let trendChart = null;

    // --- DOM Elements ---
    const connectForm = document.getElementById("connectForm");
    const connectBtn = document.getElementById("connectBtn");
    const demoBtn = document.getElementById("demoBtn");
    const auditBtn = document.getElementById("auditBtn");
    const analyzeBtn = document.getElementById("analyzeBtn");
    const downloadBtn = document.getElementById("downloadBtn");
    const exportPdfBtn = document.getElementById("exportPdfBtn");
    const disconnectBtn = document.getElementById("disconnectBtn");
    const refreshHistoryBtn = document.getElementById("refreshHistoryBtn");
    const darkModeToggle = document.getElementById("darkModeToggle");
    const chatForm = document.getElementById("chatForm");
    const chatInput = document.getElementById("chatInput");
    const chatBtn = document.getElementById("chatBtn");
    const connectionBadge = document.getElementById("connectionBadge");
    const loadingOverlay = document.getElementById("loadingOverlay");
    const loadingText = document.getElementById("loadingText");
    const alertArea = document.getElementById("alertArea");

    // --- Utility Functions ---

    function showLoading(text = "Processing...") {
        loadingText.textContent = text;
        loadingOverlay.style.display = "flex";
    }

    function hideLoading() {
        loadingOverlay.style.display = "none";
    }

    function showAlert(message, type = "danger") {
        const alert = document.createElement("div");
        alert.className = `alert alert-${type} alert-dismissible fade show`;
        alert.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        alertArea.appendChild(alert);
        setTimeout(() => alert.remove(), 8000);
    }

    async function apiCall(url, options = {}) {
        const response = await fetch(url, {
            headers: { "Content-Type": "application/json", ...options.headers },
            ...options,
        });
        const data = await response.json();
        if (!response.ok || !data.success) {
            throw new Error(data.error || `Request failed (${response.status})`);
        }
        return data;
    }

    function updateConnectionUI(connected, host = "", demo = false) {
        isConnected = connected;
        isDemoMode = demo;

        if (demo) {
            connectionBadge.className = "badge bg-info";
            connectionBadge.innerHTML = `<i class="bi bi-play-circle me-1"></i>Demo Mode: ${host}`;
        } else if (connected) {
            connectionBadge.className = "badge bg-success";
            connectionBadge.innerHTML = `<i class="bi bi-circle-fill me-1"></i>Connected: ${host}`;
        } else {
            connectionBadge.className = "badge bg-secondary";
            connectionBadge.innerHTML = `<i class="bi bi-circle-fill me-1"></i>Disconnected`;
        }

        auditBtn.disabled = !connected || demo;
        disconnectBtn.disabled = !connected && !demo;
        analyzeBtn.disabled = !hasAudit || demo;
    }

    function updateActionButtons() {
        analyzeBtn.disabled = !hasAudit;
        downloadBtn.disabled = !hasReport;
        exportPdfBtn.disabled = !hasReport;
        chatInput.disabled = !hasReport;
        chatBtn.disabled = !hasReport;
    }

    function getScoreColor(score) {
        if (score >= 80) return "#198754";
        if (score >= 60) return "#ffc107";
        if (score >= 40) return "#fd7e14";
        return "#dc3545";
    }

    function renderScore(score, summary = "") {
        const scoreValue = document.getElementById("scoreValue");
        const scoreRing = document.getElementById("scoreRing");
        const scoreSummary = document.getElementById("scoreSummary");

        scoreValue.textContent = score ?? "--";
        const color = getScoreColor(score || 0);
        scoreRing.style.setProperty("--score-color", color);
        scoreRing.style.background = `conic-gradient(${color} ${(score || 0) * 3.6}deg, var(--score-bg) 0deg)`;
        scoreSummary.textContent = summary;
    }

    function renderServerInfo(audit) {
        const container = document.getElementById("serverInfo");
        const info = audit?.server_info || {};
        const results = audit?.audit_results || {};

        container.innerHTML = `
            <div class="row g-3">
                <div class="col-md-6">
                    <strong>Host:</strong> ${audit?.host || "N/A"}<br>
                    <strong>User:</strong> ${audit?.username || "N/A"}<br>
                    <strong>OS:</strong> ${info.os_name || "Unknown"}<br>
                    <strong>Version:</strong> ${info.os_version || "Unknown"}
                </div>
                <div class="col-md-6">
                    <strong>Kernel:</strong><br>
                    <code class="small">${info.kernel || "N/A"}</code>
                </div>
            </div>
            <hr>
            <div class="accordion accordion-flush" id="auditAccordion">
                ${Object.entries(results).map(([key, val], i) => `
                    <div class="accordion-item">
                        <h2 class="accordion-header">
                            <button class="accordion-button collapsed py-2" type="button"
                                data-bs-toggle="collapse" data-bs-target="#audit-${key}">
                                ${val.description || key}
                            </button>
                        </h2>
                        <div id="audit-${key}" class="accordion-collapse collapse"
                            data-bs-parent="#auditAccordion">
                            <div class="accordion-body">
                                <code class="small d-block mb-2">${val.command}</code>
                                <pre class="audit-output p-2 rounded mb-0">${escapeHtml(val.output)}</pre>
                            </div>
                        </div>
                    </div>
                `).join("")}
            </div>
        `;
    }

    function escapeHtml(text) {
        const div = document.createElement("div");
        div.textContent = text;
        return div.innerHTML;
    }

    function renderFindingCard(finding) {
        const severityClass = {
            High: "danger",
            Medium: "warning",
            Low: "info",
        }[finding.severity] || "secondary";

        return `
            <div class="finding-card border-start border-${severityClass} border-4 p-3 mb-3 rounded">
                <h6 class="fw-bold mb-2">${escapeHtml(finding.issue_name)}</h6>
                <p class="mb-2">${escapeHtml(finding.explanation)}</p>
                <div class="mb-2">
                    <strong>Fix Command:</strong>
                    <code class="d-block mt-1 p-2 rounded">${escapeHtml(finding.fix_command)}</code>
                </div>
                <div>
                    <strong>Recommendation:</strong>
                    <span class="text-muted">${escapeHtml(finding.recommendation)}</span>
                </div>
            </div>
        `;
    }

    function renderFindings(report) {
        const bySeverity = report.findings_by_severity || {};
        const counts = { high: 0, medium: 0, low: 0 };

        ["High", "Medium", "Low"].forEach((sev) => {
            const key = sev.toLowerCase();
            const findings = bySeverity[sev] || [];
            counts[key] = findings.length;

            const container = document.getElementById(`${key}Findings`);
            if (findings.length === 0) {
                container.innerHTML = `<p class="text-muted">No ${key} risk findings.</p>`;
            } else {
                container.innerHTML = findings.map(renderFindingCard).join("");
            }
        });

        document.getElementById("highCount").textContent = counts.high;
        document.getElementById("mediumCount").textContent = counts.medium;
        document.getElementById("lowCount").textContent = counts.low;
    }

    function renderFixScript(script) {
        document.getElementById("fixCommands").innerHTML =
            `<code>${escapeHtml(script)}</code>`;
    }

    function renderWorkflow(steps) {
        const card = document.getElementById("workflowCard");
        const list = document.getElementById("workflowSteps");

        if (!steps || steps.length === 0) {
            card.style.display = "none";
            return;
        }

        card.style.display = "block";
        list.innerHTML = steps.map((step) => {
            const icon = step.status === "success"
                ? "bi-check-circle-fill text-success"
                : step.status === "failed"
                    ? "bi-x-circle-fill text-danger"
                    : "bi-exclamation-circle text-warning";

            return `
                <li class="list-group-item d-flex align-items-start gap-2 py-2">
                    <i class="bi ${icon} mt-1"></i>
                    <div>
                        <strong class="text-capitalize">${step.step.replace(/_/g, " ")}</strong>
                        <div class="small text-muted">${escapeHtml(step.message)}</div>
                    </div>
                </li>
            `;
        }).join("");
    }

    function renderHistory(history) {
        const tbody = document.getElementById("historyTable");

        if (!history || history.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" class="text-muted text-center py-3">No audit history yet.</td></tr>`;
            return;
        }

        tbody.innerHTML = history.map((record) => {
            const date = new Date(record.date).toLocaleString();
            const scoreColor = getScoreColor(record.security_score);
            const counts = record.findings_count || {};

            return `
                <tr>
                    <td class="small">${date}</td>
                    <td>${escapeHtml(record.server_ip)}</td>
                    <td><span class="badge" style="background:${scoreColor}">${record.security_score}</span></td>
                    <td><span class="badge bg-danger">${counts.high || 0}</span></td>
                    <td><span class="badge bg-warning text-dark">${counts.medium || 0}</span></td>
                    <td><span class="badge bg-info">${counts.low || 0}</span></td>
                </tr>
            `;
        }).join("");
    }

    function renderTrendChart(trend) {
        const ctx = document.getElementById("trendChart").getContext("2d");

        if (trendChart) {
            trendChart.destroy();
        }

        if (!trend || trend.length === 0) {
            trendChart = new Chart(ctx, {
                type: "line",
                data: {
                    labels: ["No data"],
                    datasets: [{
                        label: "Security Score",
                        data: [0],
                        borderColor: "#6c757d",
                    }],
                },
                options: { responsive: true, plugins: { legend: { display: false } } },
            });
            return;
        }

        trendChart = new Chart(ctx, {
            type: "line",
            data: {
                labels: trend.map((t) => {
                    const d = new Date(t.date);
                    return d.toLocaleDateString() + " " + d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
                }),
                datasets: [{
                    label: "Security Score",
                    data: trend.map((t) => t.score),
                    borderColor: "#0d6efd",
                    backgroundColor: "rgba(13, 110, 253, 0.1)",
                    fill: true,
                    tension: 0.3,
                    pointBackgroundColor: trend.map((t) => getScoreColor(t.score)),
                    pointRadius: 5,
                }],
            },
            options: {
                responsive: true,
                scales: {
                    y: { min: 0, max: 100, title: { display: true, text: "Score" } },
                },
                plugins: {
                    tooltip: {
                        callbacks: {
                            afterLabel(ctx) {
                                const item = trend[ctx.dataIndex];
                                return item ? `Server: ${item.server_ip}` : "";
                            },
                        },
                    },
                },
            },
        });
    }

    async function loadHistory() {
        try {
            const data = await apiCall("/history");
            renderHistory(data.history);
            renderTrendChart(data.trend);
        } catch (err) {
            console.error("Failed to load history:", err);
        }
    }

    function displayAnalysisResults(audit, report) {
        hasAudit = true;
        hasReport = true;
        updateActionButtons();

        renderServerInfo(audit);
        renderScore(report.security_score, report.executive_summary || report.summary);
        renderFindings(report);
        renderFixScript(report.fix_script);
        renderWorkflow(report.workflow_steps);
    }

    // --- Event Handlers ---

    demoBtn.addEventListener("click", async () => {
        showLoading("Loading demo audit data...");
        try {
            const data = await apiCall("/demo", { method: "POST", body: "{}" });

            displayAnalysisResults(data.audit, data.report);
            updateConnectionUI(true, data.audit.host, true);

            showAlert(
                `Demo mode loaded. Security score: ${data.report.security_score}/100 — no SSH required.`,
                "info"
            );

            await loadHistory();
        } catch (err) {
            showAlert(err.message);
        } finally {
            hideLoading();
        }
    });

    connectForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        showLoading("Connecting via SSH...");

        try {
            const data = await apiCall("/connect", {
                method: "POST",
                body: JSON.stringify({
                    host: document.getElementById("host").value.trim(),
                    username: document.getElementById("username").value.trim(),
                    password: document.getElementById("password").value,
                }),
            });

            updateConnectionUI(true, data.host);
            isDemoMode = false;
            showAlert(`Connected to ${data.host}`, "success");
        } catch (err) {
            showAlert(err.message);
            updateConnectionUI(false);
        } finally {
            hideLoading();
        }
    });

    auditBtn.addEventListener("click", async () => {
        showLoading("Running security audit commands...");
        try {
            const data = await apiCall("/audit", { method: "POST" });
            hasAudit = true;
            updateActionButtons();
            renderServerInfo(data.audit);
            showAlert("Audit completed successfully.", "success");
        } catch (err) {
            showAlert(err.message);
        } finally {
            hideLoading();
        }
    });

    analyzeBtn.addEventListener("click", async () => {
        showLoading("AI agent analyzing security configuration...");
        try {
            const data = await apiCall("/analyze", { method: "POST", body: "{}" });
            const report = data.report;

            displayAnalysisResults(report.audit_data || {}, report);

            showAlert(
                `Analysis complete. Security score: ${report.security_score}/100`,
                report.security_score >= 70 ? "success" : "warning"
            );

            await loadHistory();
        } catch (err) {
            showAlert(err.message);
        } finally {
            hideLoading();
        }
    });

    downloadBtn.addEventListener("click", () => {
        window.location.href = "/download-fix-script";
    });

    exportPdfBtn.addEventListener("click", () => {
        window.location.href = "/export-pdf";
    });

    disconnectBtn.addEventListener("click", async () => {
        try {
            const wasDemo = isDemoMode;
            await apiCall("/disconnect", { method: "POST" });
            isDemoMode = false;
            hasAudit = false;
            hasReport = false;
            updateConnectionUI(false);
            updateActionButtons();
            showAlert(wasDemo ? "Demo mode cleared." : "Disconnected.", "info");
        } catch (err) {
            showAlert(err.message);
        }
    });

    refreshHistoryBtn.addEventListener("click", loadHistory);

    chatForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const question = chatInput.value.trim();
        if (!question) return;

        const chatMessages = document.getElementById("chatMessages");
        chatMessages.innerHTML += `
            <div class="chat-msg user-msg p-2 mb-2 rounded">
                <strong>You:</strong> ${escapeHtml(question)}
            </div>
        `;
        chatInput.value = "";
        chatInput.disabled = true;
        chatBtn.disabled = true;

        try {
            const data = await apiCall("/chat", {
                method: "POST",
                body: JSON.stringify({ question }),
            });
            chatMessages.innerHTML += `
                <div class="chat-msg ai-msg p-2 mb-2 rounded">
                    <strong><i class="bi bi-robot"></i> Assistant:</strong>
                    <div class="mt-1">${escapeHtml(data.answer).replace(/\n/g, "<br>")}</div>
                </div>
            `;
        } catch (err) {
            chatMessages.innerHTML += `
                <div class="chat-msg error-msg p-2 mb-2 rounded text-danger">
                    Error: ${escapeHtml(err.message)}
                </div>
            `;
        } finally {
            chatInput.disabled = false;
            chatBtn.disabled = false;
            chatInput.focus();
            chatMessages.scrollTop = chatMessages.scrollHeight;
        }
    });

    // Dark Mode Toggle (Bonus)
    darkModeToggle.addEventListener("click", () => {
        const html = document.documentElement;
        const current = html.getAttribute("data-theme");
        const next = current === "dark" ? "light" : "dark";
        html.setAttribute("data-theme", next);
        localStorage.setItem("theme", next);

        const icon = darkModeToggle.querySelector("i");
        icon.className = next === "dark" ? "bi bi-sun" : "bi bi-moon-stars";
    });

    // Initialize
    function init() {
        const savedTheme = localStorage.getItem("theme") || "light";
        document.documentElement.setAttribute("data-theme", savedTheme);
        if (savedTheme === "dark") {
            darkModeToggle.querySelector("i").className = "bi bi-sun";
        }
        loadHistory();
    }

    init();
})();
