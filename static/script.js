
document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("analyzeForm");
    const messageInput = document.getElementById("messageInput");
    const analyzeButton = document.getElementById("analyzeButton");

    const errorMessage = document.getElementById("errorMessage");
    const resultSection = document.getElementById("resultSection");
    const resultBadge = document.getElementById("resultBadge");
    const verdict = document.getElementById("verdict");
    const resultDescription = document.getElementById("resultDescription");
    const riskPercentage = document.getElementById("riskPercentage");
    const riskBar = document.getElementById("riskBar");
    const flagsList = document.getElementById("flagsList");
    const adviceText = document.getElementById("adviceText");

    if (
        !form || !messageInput || !analyzeButton ||
        !errorMessage || !resultSection || !resultBadge ||
        !verdict || !resultDescription || !riskPercentage ||
        !riskBar || !flagsList || !adviceText
    ) {
        console.error("ScamPatrol: Check the element IDs in index.html.");
        return;
    }

    form.addEventListener("submit", async (event) => {
        event.preventDefault();

        const text = messageInput.value.trim();

        errorMessage.hidden = true;
        resultSection.hidden = true;

        if (!text) {
            errorMessage.textContent = "Please paste a message or link first.";
            errorMessage.hidden = false;
            return;
        }

        if (text.length > 5000) {
            errorMessage.textContent =
                "Please keep your message under 5000 characters.";
            errorMessage.hidden = false;
            return;
        }

        analyzeButton.disabled = true;
        analyzeButton.textContent = "Checking the red flags...";

        try {
            const response = await fetch("/analyze", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ text: text })
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(
                    data.error || data.advice || "The scan failed."
                );
            }

            const score = Number(data.score);

            if (!Number.isFinite(score)) {
                throw new Error("The server returned an invalid score.");
            }

            const safeScore = Math.max(0, Math.min(100, score));

            let level;
            let description;

            if (safeScore >= 60) {
                level = "HIGH RISK";
                description =
                    "Several warning signs were detected. Be very cautious.";
            } else if (safeScore >= 30) {
                level = "MEDIUM RISK";
                description =
                    "Some warning signs were detected. Verify before acting.";
            } else {
                level = "LOW RISK";
                description =
                    "Few configured warning signs were detected. This does not guarantee safety.";
            }

            resultBadge.textContent = level;
            verdict.textContent = data.verdict || "Analysis complete";
            resultDescription.textContent = description;
            riskPercentage.textContent = `${safeScore}%`;
            riskBar.style.width = `${safeScore}%`;

            if (safeScore >= 60) {
                riskBar.style.backgroundColor = "#e64251";
            } else if (safeScore >= 30) {
                riskBar.style.backgroundColor = "#d97706";
            } else {
                riskBar.style.backgroundColor = "#258451";
            }

            flagsList.replaceChildren();

            if (Array.isArray(data.flags) && data.flags.length > 0) {
                data.flags.forEach((flag) => {
                    const item = document.createElement("li");
                    item.textContent = String(flag);
                    flagsList.appendChild(item);
                });
            } else {
                const item = document.createElement("li");
                item.textContent = "No configured warning signs were found.";
                flagsList.appendChild(item);
            }

            adviceText.textContent = data.advice ||
                "Verify unexpected requests through official channels.";

            resultSection.hidden = false;
            resultSection.scrollIntoView({
                behavior: "smooth",
                block: "nearest"
            });

        } catch (error) {
            console.error("ScamPatrol analysis error:", error);

            errorMessage.textContent =
                error.message || "Something went wrong. Please try again.";
            errorMessage.hidden = false;

        } finally {
            analyzeButton.disabled = false;
            analyzeButton.innerHTML =
                'Analyze for red flags <span>→</span>';
        }
    });

    console.log("ScamPatrol JavaScript loaded successfully.");
});