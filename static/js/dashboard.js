const requestInput = document.getElementById("requestInput");
const analyzeBtn = document.getElementById("analyzeBtn");
const loadingState = document.getElementById("loadingState");
const resultCard = document.getElementById("resultCard");
const errorBanner = document.getElementById("errorBanner");
const attackType = document.getElementById("attackType");
const confidence = document.getElementById("confidence");
const severity = document.getElementById("severity");
const blockingDecision = document.getElementById("blockingDecision");
const resultMessage = document.getElementById("resultMessage");
const recommendedAction = document.getElementById("recommendedAction");
const statusBadge = document.getElementById("statusBadge");
const preventionTips = document.getElementById("preventionTips");
const historyList = document.getElementById("historyList");
const metricTotalScans = document.getElementById("metricTotalScans");
const metricAttacks = document.getElementById("metricAttacks");
const metricBlocked = document.getElementById("metricBlocked");
const metricHighSeverity = document.getElementById("metricHighSeverity");

function setLoading(isLoading) {
    analyzeBtn.disabled = isLoading;
    loadingState.classList.toggle("hidden", !isLoading);
    analyzeBtn.textContent = isLoading ? "Analyzing..." : "Analyze Request";
}

function showError(message) {
    errorBanner.textContent = message;
    errorBanner.classList.remove("hidden");
}

function hideError() {
    errorBanner.classList.add("hidden");
    errorBanner.textContent = "";
}

function showResult(data) {
    const isAttack = data.status === "Attack" || data.status === "Suspicious";

    attackType.textContent = data.attack_type;
    confidence.textContent = `${Math.round((data.confidence || 0) * 100)}%`;
    severity.textContent = data.severity || "-";
    blockingDecision.textContent = data.blocked ? "Block Request" : "Allow with Monitoring";
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

async function analyzeRequest() {
    hideError();
    resultCard.classList.add("hidden");

    const payload = requestInput.value.trim();
    if (!payload) {
        showError("Please enter an HTTP request string before analyzing.");
        return;
    }

    setLoading(true);

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

        if (!response.ok) {
            throw new Error(data.error || "The server could not analyze the request.");
        }

        showResult(data);
        updateMetrics(data.summary);
        prependHistoryItem(data.history_item);
    } catch (error) {
        showError(error.message || "Unable to reach the detection service.");
    } finally {
        setLoading(false);
    }
}

analyzeBtn.addEventListener("click", analyzeRequest);

requestInput.addEventListener("keydown", (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
        analyzeRequest();
    }
});
