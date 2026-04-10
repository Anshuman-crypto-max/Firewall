const requestInput = document.getElementById("requestInput");
const analyzeBtn = document.getElementById("analyzeBtn");
const loadingState = document.getElementById("loadingState");
const resultCard = document.getElementById("resultCard");
const errorBanner = document.getElementById("errorBanner");
const attackType = document.getElementById("attackType");
const confidence = document.getElementById("confidence");
const resultMessage = document.getElementById("resultMessage");
const statusBadge = document.getElementById("statusBadge");

if (analyzeBtn) {
    const previewRules = [
        { pattern: /union\s+select|or\s+1=1|drop\s+table/i, type: "SQL Injection", confidence: 95, status: "Attack" },
        { pattern: /<script|javascript:|onerror=|alert\(/i, type: "Cross-Site Scripting (XSS)", confidence: 92, status: "Attack" },
        { pattern: /(;|\|\|)\s*(cat|ls|curl|wget|powershell|cmd)|`.+`|\$\(.*\)/i, type: "Command Injection", confidence: 90, status: "Attack" },
        { pattern: /\.\.\/|\.\.\\|%2e%2e%2f/i, type: "Directory Traversal", confidence: 88, status: "Attack" }
    ];

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
        confidence.textContent = `${data.confidence}%`;
        resultMessage.textContent = data.message;
        statusBadge.textContent = data.status;
        statusBadge.className = `status-badge ${isAttack ? "status-attack" : "status-safe"}`;
        resultCard.classList.remove("hidden");
    }

    analyzeBtn.addEventListener("click", () => {
        hideError();
        resultCard.classList.add("hidden");

        const payload = requestInput.value.trim();
        if (!payload) {
            showError("Please enter an HTTP request string before analyzing.");
            return;
        }

        setLoading(true);

        window.setTimeout(() => {
            const match = previewRules.find((rule) => rule.pattern.test(payload));
            if (match) {
                showResult({
                    attack_type: match.type,
                    confidence: match.confidence,
                    status: match.status,
                    message: "Suspicious payload matched the preview detector."
                });
            } else {
                showResult({
                    attack_type: "No Threat Detected",
                    confidence: 82,
                    status: "Safe",
                    message: "No known attack signature was found in the request."
                });
            }

            setLoading(false);
        }, 700);
    });
}
