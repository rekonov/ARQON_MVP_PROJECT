const DEFAULTS = {
  endpoint: "http://127.0.0.1:8765",
  apiKey: "change-me-arqon",
  monitorTabs: true,
  monitorDownloads: true,
  blockOnWarn: false,
};

const els = {
  endpoint: document.getElementById("endpoint"),
  apiKey: document.getElementById("api-key"),
  monitorTabs: document.getElementById("monitor-tabs"),
  monitorDownloads: document.getElementById("monitor-downloads"),
  blockOnWarn: document.getElementById("block-on-warn"),
  save: document.getElementById("save"),
  test: document.getElementById("test"),
  result: document.getElementById("result"),
};

init();

function init() {
  chrome.storage.sync.get(DEFAULTS, (settings) => {
    els.endpoint.value = settings.endpoint;
    els.apiKey.value = settings.apiKey;
    els.monitorTabs.checked = Boolean(settings.monitorTabs);
    els.monitorDownloads.checked = Boolean(settings.monitorDownloads);
    els.blockOnWarn.checked = Boolean(settings.blockOnWarn);
  });

  els.save.addEventListener("click", saveSettings);
  els.test.addEventListener("click", testConnection);
}

function saveSettings() {
  const payload = {
    endpoint: els.endpoint.value.trim() || DEFAULTS.endpoint,
    apiKey: els.apiKey.value.trim(),
    monitorTabs: Boolean(els.monitorTabs.checked),
    monitorDownloads: Boolean(els.monitorDownloads.checked),
    blockOnWarn: Boolean(els.blockOnWarn.checked),
  };
  chrome.storage.sync.set(payload, () => {
    els.result.textContent = "Saved.";
  });
}

function testConnection() {
  chrome.runtime.sendMessage({ type: "arqon-test-connection" }, (response) => {
    if (!response || response.ok === false) {
      els.result.textContent = `Connection error: ${formatConnectionError(response?.error || "unknown")}`;
      return;
    }
    els.result.textContent = formatConnectionResult(response.result);
  });
}

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
    return "API key rejected. Paste correct api_user_key and click Save.";
  }
  if (value === "endpoint_empty") {
    return "API endpoint is empty.";
  }
  if (value === "request_timeout") {
    return "Local API timeout. Start ARQON in Browser Guard mode first.";
  }
  return value;
}
