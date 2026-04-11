const requestInput = document.getElementById("requestInput");
const analyzeBtn = document.getElementById("analyzeBtn");
const scanBtn = document.getElementById("scanBtn");
const loadingState = document.getElementById("loadingState");
const resultCard = document.getElementById("resultCard");
const errorBanner = document.getElementById("errorBanner");
const attackType = document.getElementById("attackType");
const confidence = document.getElementById("confidence");
const severity = document.getElementById("severity");
const blockingDecision = document.getElementById("blockingDecision");
const detectionMode = document.getElementById("detectionMode");
const resultMessage = document.getElementById("resultMessage");
const recommendedAction = document.getElementById("recommendedAction");
const statusBadge = document.getElementById("statusBadge");
const preventionTips = document.getElementById("preventionTips");
const historyList = document.getElementById("historyList");
const manualHistoryList = document.getElementById("manualHistoryList");
const scanFindings = document.getElementById("scanFindings");
const scanRisk = document.getElementById("scanRisk");
const scanFindingsCount = document.getElementById("scanFindingsCount");
const metricTotalScans = document.getElementById("metricTotalScans");
const metricAttacks = document.getElementById("metricAttacks");
const metricBlocked = document.getElementById("metricBlocked");
const metricHighSeverity = document.getElementById("metricHighSeverity");
const analyticsPanel = document.querySelector(".analytics-panel");
const topEndpoint = document.getElementById("topEndpoint");
const topEndpointCount = document.getElementById("topEndpointCount");
const peakAttackHour = document.getElementById("peakAttackHour");
const peakAttackHourCount = document.getElementById("peakAttackHourCount");
const endpointEmptyState = document.getElementById("endpointEmptyState");
const timeEmptyState = document.getElementById("timeEmptyState");
let endpointChart = null;
let timeChart = null;

function setLoading(button, loadingNode, isLoading, idleLabel, loadingLabel) {
    if (!button || !loadingNode) {
        return;
    }

    button.disabled = isLoading;
    loadingNode.classList.toggle("hidden", !isLoading);
    button.textContent = isLoading ? loadingLabel : idleLabel;
}

function showError(message) {
    errorBanner.textContent = message;
    errorBanner.classList.remove("hidden");
}

function hideError() {
    errorBanner.classList.add("hidden");
    errorBanner.textContent = "";
}

function isLikelyUrl(value) {
    return /^https?:\/\//i.test(value.trim());
}

function handleAuthFailure() {
    showError("Authentication required. Please sign in again.");
    setTimeout(() => {
        window.location.href = "/login";
    }, 800);
}

function parseAnalyticsDataset(attributeName) {
    if (!analyticsPanel) {
        return {};
    }

    try {
        return JSON.parse(analyticsPanel.dataset[attributeName] || "{}");
    } catch (error) {
        return {};
    }
}

function formatHourRange(hourValue) {
    const hour = Number.parseInt(hourValue, 10) || 0;
    const nextHour = (hour + 1) % 24;
    return `${String(hour).padStart(2, "0")}:00-${String(nextHour).padStart(2, "0")}:00`;
}

function hasAnyAttack(data) {
    return Object.values(data || {}).some((value) => Number(value) > 0);
}

function chartOptions(highlightIndex = -1) {
    return {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                display: false,
            },
        },
        scales: {
            x: {
                ticks: { color: "#d6e5f5" },
                grid: { color: "rgba(255, 255, 255, 0.06)" },
            },
            y: {
                beginAtZero: true,
                ticks: {
                    color: "#d6e5f5",
                    precision: 0,
                },
                grid: { color: "rgba(255, 255, 255, 0.06)" },
            },
        },
        highlightIndex,
    };
}

function updateEndpointHighlight(data) {
    const entries = Object.entries(data || {});
    const [endpoint, count] = entries.length ? entries[0] : ["/", 0];
    topEndpoint.textContent = endpoint;
    topEndpointCount.textContent = `${count} ${Number(count) === 1 ? "attack" : "attacks"}`;
}

function updateTimeHighlight(data) {
    const entries = Object.entries(data || {});
    const [hour, count] = entries.reduce(
        (best, item) => (Number(item[1]) > Number(best[1]) ? item : best),
        ["0", 0]
    );
    peakAttackHour.textContent = formatHourRange(hour);
    peakAttackHourCount.textContent = `${count} ${Number(count) === 1 ? "attack" : "attacks"}`;
}

function renderEndpointChart(data) {
    const canvas = document.getElementById("endpointChart");
    if (!canvas || typeof Chart === "undefined") {
        return;
    }

    const entries = Object.entries(data || {});
    endpointEmptyState.classList.toggle("hidden", entries.length > 0 && hasAnyAttack(data));
    const labels = entries.length ? entries.map(([endpoint]) => endpoint) : ["No attacks"];
    const values = entries.length ? entries.map(([, count]) => count) : [0];
    const maxValue = Math.max(...values);
    const backgroundColor = values.map((value) => (value === maxValue && maxValue > 0 ? "#ff6b81" : "#6cf0c2"));

    if (endpointChart) {
        endpointChart.data.labels = labels;
        endpointChart.data.datasets[0].data = values;
        endpointChart.data.datasets[0].backgroundColor = backgroundColor;
        endpointChart.update();
        return;
    }

    endpointChart = new Chart(canvas, {
        type: "bar",
        data: {
            labels,
            datasets: [
                {
                    label: "Attacks",
                    data: values,
                    backgroundColor,
                    borderColor: "#ecf4ff",
                    borderWidth: 1,
                },
            ],
        },
        options: chartOptions(),
    });
}

function renderTimeChart(data) {
    const canvas = document.getElementById("timeChart");
    if (!canvas || typeof Chart === "undefined") {
        return;
    }

    const labels = Array.from({ length: 24 }, (_, hour) => String(hour));
    const values = labels.map((hour) => Number((data || {})[hour] || 0));
    const maxValue = Math.max(...values);
    timeEmptyState.classList.toggle("hidden", maxValue > 0);

    if (timeChart) {
        timeChart.data.labels = labels.map(formatHourRange);
        timeChart.data.datasets[0].data = values;
        timeChart.data.datasets[0].pointBackgroundColor = values.map((value) => (value === maxValue && maxValue > 0 ? "#ff6b81" : "#6cf0c2"));
        timeChart.data.datasets[0].pointRadius = values.map((value) => (value === maxValue && maxValue > 0 ? 6 : 3));
        timeChart.update();
        return;
    }

    timeChart = new Chart(canvas, {
        type: "line",
        data: {
            labels: labels.map(formatHourRange),
            datasets: [
                {
                    label: "Attacks",
                    data: values,
                    borderColor: "#6cf0c2",
                    backgroundColor: "rgba(108, 240, 194, 0.14)",
                    pointBackgroundColor: values.map((value) => (value === maxValue && maxValue > 0 ? "#ff6b81" : "#6cf0c2")),
                    pointRadius: values.map((value) => (value === maxValue && maxValue > 0 ? 6 : 3)),
                    fill: true,
                    tension: 0.32,
                },
            ],
        },
        options: chartOptions(),
    });
}

function renderAnalytics(endpoints, time) {
    updateEndpointHighlight(endpoints);
    updateTimeHighlight(time);
    renderEndpointChart(endpoints);
    renderTimeChart(time);
}

async function refreshAnalytics() {
    if (!analyticsPanel) {
        return;
    }

    try {
        const [endpointResponse, timeResponse] = await Promise.all([
            fetch("/analytics/endpoints"),
            fetch("/analytics/time"),
        ]);

        if (endpointResponse.status === 401 || timeResponse.status === 401) {
            handleAuthFailure();
            return;
        }

        if (!endpointResponse.ok || !timeResponse.ok) {
            return;
        }

        const endpointData = await endpointResponse.json();
        const timeData = await timeResponse.json();
        renderAnalytics(endpointData.endpoints || {}, timeData.time || {});
    } catch (error) {
        return;
    }
}

function showResult(data) {
    const isAttack = data.status === "Attack" || data.status === "Suspicious";

    attackType.textContent = data.attack_type;
    confidence.textContent = `${Math.round((data.confidence || 0) * 100)}%`;
    severity.textContent = data.severity || "-";
    blockingDecision.textContent = data.blocked ? "Block Request" : "Allow with Monitoring";
    detectionMode.textContent = data.detection_mode || "Interactive Payload Analysis";
    resultMessage.textContent = data.message || "Analysis completed.";
    recommendedAction.textContent = data.recommended_action || "No action suggested.";
    statusBadge.textContent = data.status;
    statusBadge.className = `status-badge ${isAttack ? "status-attack" : "status-safe"}`;
    preventionTips.innerHTML = (data.prevention_tips || [])
        .map((tip) => `<li>${tip}</li>`)
        .join("") || "<li>No prevention tips available.</li>";

    resultCard.classList.remove("hidden");
}

function updateMetrics(summary) {
    if (!summary) {
        return;
    }

    metricTotalScans.textContent = summary.total_scans;
    metricAttacks.textContent = summary.attacks_detected;
    metricBlocked.textContent = summary.requests_blocked;
    metricHighSeverity.textContent = summary.high_severity;
}

function prependHistoryItem(item) {
    if (!item || !historyList) {
        return;
    }

    const emptyState = historyList.querySelector(".empty-state");
    if (emptyState) {
        emptyState.remove();
    }

    const article = document.createElement("article");
    article.className = "history-item";
    article.innerHTML = `
        <div class="history-item-top">
            <strong>${item.attack_type}</strong>
            <span class="history-badge history-${item.status.toLowerCase()}">${item.status}</span>
        </div>
        <p>${item.request_excerpt}</p>
        <div class="history-meta">
            <span>${item.source || "manual"}</span>
            <span>${item.method || "POST"} ${item.path || "/predict"}</span>
            <span>${item.severity}</span>
            <span>${item.confidence}%</span>
            <span>${item.created_at}</span>
        </div>
    `;
    historyList.prepend(article);
    refreshAnalytics();

    while (historyList.children.length > 6) {
        historyList.removeChild(historyList.lastElementChild);
    }
}

function renderHistoryItems(items) {
    if (!historyList || !Array.isArray(items)) {
        return;
    }

    historyList.innerHTML = "";
    items.forEach((item) => {
        const article = document.createElement("article");
        article.className = "history-item";
        article.innerHTML = `
            <div class="history-item-top">
                <strong>${item.attack_type}</strong>
                <span class="history-badge history-${item.status.toLowerCase()}">${item.status}</span>
            </div>
            <p>${item.request_excerpt}</p>
            <div class="history-meta">
                <span>${item.source || "manual"}</span>
                <span>${item.method || "POST"} ${item.path || "/predict"}</span>
                <span>${item.severity}</span>
                <span>${item.confidence}%</span>
                <span>${item.created_at}</span>
            </div>
        `;
        historyList.append(article);
    });
}

function prependManualHistoryItem(item) {
    if (!item || !manualHistoryList) {
        return;
    }

    const emptyState = manualHistoryList.querySelector(".empty-state");
    if (emptyState) {
        emptyState.remove();
    }

    const article = document.createElement("article");
    article.className = "history-item";
    article.innerHTML = `
        <div class="history-item-top">
            <strong>${item.attack_type}</strong>
            <span class="history-badge history-${item.status.toLowerCase()}">${item.status}</span>
        </div>
        <p>${item.request_excerpt}</p>
        <div class="history-meta">
            <span>${item.severity}</span>
            <span>${item.confidence}%</span>
            <span>${item.created_at}</span>
        </div>
    `;
    manualHistoryList.prepend(article);

    while (manualHistoryList.children.length > 4) {
        manualHistoryList.removeChild(manualHistoryList.lastElementChild);
    }
}

function renderScanFindings(report) {
    if (!report || !scanFindings) {
        return;
    }

    scanRisk.textContent = report.overall_risk || "-";
    scanFindingsCount.textContent = report.total_findings || 0;
    scanFindings.innerHTML = (report.findings || [])
        .map(
            (finding) => `
                <article class="history-item">
                    <div class="history-item-top">
                        <strong>${finding.title}</strong>
                        <span class="history-badge history-${finding.severity.toLowerCase()}">${finding.severity}</span>
                    </div>
                    <p>${finding.impact}</p>
                    <div class="history-meta">
                        <span>${finding.recommendation}</span>
                    </div>
                </article>
            `
        )
        .join("");
}

async function analyzeRequest() {
    hideError();
    resultCard.classList.add("hidden");

    const payload = requestInput.value.trim();
    if (!payload) {
        showError("Please enter an HTTP request string before analyzing.");
        return;
    }

    setLoading(analyzeBtn, loadingState, true, "Analyze Payload", "Analyzing...");

    try {
        const response = await fetch("/predict", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ request_text: payload }),
        });

        let data;
        try {
            data = await response.json();
        } catch (parseError) {
            throw new Error("The server returned an unreadable response.");
        }

        if (response.status === 401) {
            handleAuthFailure();
            return;
        }
        if (!response.ok) {
            throw new Error(data.error || "The server could not analyze the request.");
        }

        if (data.url_converted) {
            showError("URL detected and converted to a raw HTTP request for analysis.");
        }
        showResult(data);
        updateMetrics(data.summary);
        prependManualHistoryItem(data.history_item);
        prependHistoryItem(data.event_item);
    } catch (error) {
        showError(error.message || "Unable to reach the detection service.");
    } finally {
        setLoading(analyzeBtn, loadingState, false, "Analyze Payload", "Analyzing...");
    }
}

async function runVulnerabilityScan() {
    hideError();

    if (scanBtn) {
        scanBtn.disabled = true;
        scanBtn.textContent = "Scanning...";
    }

    try {
        const response = await fetch("/scan");
        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "The scan could not be completed.");
        }

        renderScanFindings(data);
    } catch (error) {
        showError(error.message || "Unable to run the vulnerability scan.");
    } finally {
        if (scanBtn) {
            scanBtn.disabled = false;
            scanBtn.textContent = "Run Vulnerability Scan";
        }
    }
}

if (analyzeBtn) {
    analyzeBtn.addEventListener("click", analyzeRequest);
}

if (scanBtn) {
    scanBtn.addEventListener("click", runVulnerabilityScan);
}

if (requestInput) {
    requestInput.addEventListener("keydown", (event) => {
        if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
            analyzeRequest();
        }
    });
}

if (analyticsPanel) {
    renderAnalytics(parseAnalyticsDataset("analyticsEndpoints"), parseAnalyticsDataset("analyticsTime"));
    window.setInterval(refreshAnalytics, 5000);
}
