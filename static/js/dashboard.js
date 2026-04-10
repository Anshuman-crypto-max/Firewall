const requestInput = document.getElementById("requestInput");
const analyzeBtn = document.getElementById("analyzeBtn");
const loadingState = document.getElementById("loadingState");
const resultCard = document.getElementById("resultCard");
const errorBanner = document.getElementById("errorBanner");
const attackType = document.getElementById("attackType");
const confidence = document.getElementById("confidence");
const resultMessage = document.getElementById("resultMessage");
const statusBadge = document.getElementById("statusBadge");

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
    const isAttack = data.status === "Attack";

    attackType.textContent = data.attack_type;
    confidence.textContent = `${Math.round((data.confidence || 0) * 100)}%`;
    resultMessage.textContent = data.message || "Analysis completed.";
    statusBadge.textContent = data.status;
    statusBadge.className = `status-badge ${isAttack ? "status-attack" : "status-safe"}`;

    resultCard.classList.remove("hidden");
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
