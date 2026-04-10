const requestInput = document.getElementById("requestInput");
const livePayloadInput = document.getElementById("livePayloadInput");
const analyzeBtn = document.getElementById("analyzeBtn");
const probeBtn = document.getElementById("probeBtn");
const scanBtn = document.getElementById("scanBtn");
const loadingState = document.getElementById("loadingState");
const probeLoadingState = document.getElementById("probeLoadingState");
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

async function sendLiveProbe() {
    hideError();
    resultCard.classList.add("hidden");

    const payload = livePayloadInput.value.trim();
    if (!payload) {
        showError("Enter a payload before sending it through the firewall.");
        return;
    }
    if (isLikelyUrl(payload)) {
        showError("Live probes do not fetch external URLs. Use Manual Request Analysis for URLs.");
        return;
    }

    setLoading(probeBtn, probeLoadingState, true, "Send Through Firewall", "Inspecting...");

    try {
        const response = await fetch("/traffic/ingest", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ payload }),
        });

        const data = await response.json();
        if (response.status === 401) {
            handleAuthFailure();
            return;
        }
        if (!response.ok) {
            showResult({
                attack_type: data.attack_type || "Blocked Request",
                confidence: 0.95,
                severity: data.severity || "High",
                blocked: true,
                status: "Attack",
                detection_mode: "Real-Time HTTP Firewall",
                recommended_action: data.recommended_action || "Review the blocked request and confirm the source is malicious.",
                prevention_tips: [
                    "Inspect the event log for the blocked payload.",
                    "Refine validation and rate limiting around the targeted route.",
                ],
                message: data.error || "The live firewall blocked the request before it reached the application route.",
            });
        } else {
            showResult({
                attack_type: "Allowed Request",
                confidence: 0.76,
                severity: "Low",
                blocked: false,
                status: "Safe",
                detection_mode: "Real-Time HTTP Firewall",
                recommended_action: "The request was allowed and logged for monitoring.",
                prevention_tips: [
                    "Continue monitoring repeat activity from the same client.",
                    "Review logs if the payload changes or escalates.",
                ],
                message: data.message || "The request passed live inspection.",
            });
        }

        const eventsResponse = await fetch("/events");
        const eventsData = await eventsResponse.json();
        if (Array.isArray(eventsData.events) && eventsData.events.length > 0) {
            renderHistoryItems(eventsData.events);
        }
        updateMetrics(eventsData.summary);
    } catch (error) {
        showError(error.message || "Unable to send the live request probe.");
    } finally {
        setLoading(probeBtn, probeLoadingState, false, "Send Through Firewall", "Inspecting...");
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

if (probeBtn) {
    probeBtn.addEventListener("click", sendLiveProbe);
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

if (livePayloadInput) {
    livePayloadInput.addEventListener("keydown", (event) => {
        if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
            sendLiveProbe();
        }
    });
}
