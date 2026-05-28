document.addEventListener("DOMContentLoaded", async () => {
  // IMPORTANT: REPLACE THIS URL with your live Render backend URL once deployed.
  // Example: const API_URL = "https://url-dector-backend.onrender.com/predict";
  const API_URL = "http://127.0.0.1:5000/predict";

  const urlElement = document.getElementById("current-url");
  const loadingElement = document.getElementById("loading");
  const resultBox = document.getElementById("result-box");
  const predictionElement = document.getElementById("prediction");
  const confidenceElement = document.getElementById("confidence");
  const flagsContainer = document.getElementById("flags-container");
  const errorElement = document.getElementById("error");

  // Get current active tab
  chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
    let currentUrl = tabs[0].url;
    urlElement.textContent = currentUrl.length > 50 ? currentUrl.substring(0, 50) + "..." : currentUrl;

    try {
      const response = await fetch(API_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ url: currentUrl })
      });

      const data = await response.json();
      loadingElement.classList.add("hidden");

      if (response.ok) {
        resultBox.classList.remove("hidden");
        
        let predText = data.prediction.toUpperCase();
        predictionElement.textContent = predText;
        
        if (data.is_malicious) {
          predictionElement.className = "malicious";
        } else {
          predictionElement.className = "safe";
        }

        confidenceElement.textContent = "Confidence: " + (data.confidence * 100).toFixed(2) + "%";

        flagsContainer.innerHTML = "";
        if (data.top_flags && data.top_flags.length > 0) {
          data.top_flags.forEach(flag => {
            let div = document.createElement("div");
            div.className = "flag";
            div.innerHTML = `<strong>${flag.icon} ${flag.label}</strong><br><small>${flag.detail}</small>`;
            flagsContainer.appendChild(div);
          });
        }
      } else {
        errorElement.textContent = data.error || "An error occurred.";
        errorElement.classList.remove("hidden");
      }
    } catch (err) {
      loadingElement.classList.add("hidden");
      errorElement.textContent = "Could not connect to the backend API. Please make sure your server is running.";
      errorElement.classList.remove("hidden");
    }
  });
});
