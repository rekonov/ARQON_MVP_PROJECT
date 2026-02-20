const openSettingsButton = document.getElementById("open-settings");
const testApiButton = document.getElementById("test-api");
const popupResult = document.getElementById("popup-result");

openSettingsButton.addEventListener("click", () => {
  chrome.runtime.openOptionsPage();
});

testApiButton.addEventListener("click", () => {
  chrome.runtime.sendMessage({ type: "arqon-test-connection" }, (response) => {
    if (!response || response.ok === false) {
      popupResult.textContent = `Connection error: ${formatConnectionError(response?.error || "unknown")}`;
      return;
    }
    popupResult.textContent = formatConnectionResult(response.result);
  });
});

function formatConnectionResult(result) {
  const endpoint = result?.endpoint || "unknown";
  const healthStatus = result?.health?.status ?? "n/a";
  const evalStatus = result?.evaluate?.status ?? "n/a";
  const sampleAction = result?.evaluate?.action || "unknown";
  const sampleRisk = result?.evaluate?.risk_score ?? "n/a";
  const ready = result?.protection_ready ? "YES" : "NO";
  return [
    `Protection ready: ${ready}`,
    `Endpoint: ${endpoint}`,
    `Health: HTTP ${healthStatus}`,
    `Auth check: HTTP ${evalStatus}`,
    `Sample decision: ${sampleAction} (risk ${sampleRisk})`,
  ].join("\n");
}

function formatConnectionError(code) {
  const value = String(code || "unknown");
  if (value === "api_key_unauthorized") {
    return "API key rejected. Paste correct api_user_key in extension settings.";
  }
  if (value === "endpoint_empty") {
    return "API endpoint is empty.";
  }
  if (value === "request_timeout") {
    return "Local API timeout. Check that ARQON Browser Guard mode is running.";
  }
  return value;
}
