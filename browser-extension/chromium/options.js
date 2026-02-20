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
      els.result.textContent = `Connection error: ${response?.error || "unknown"}`;
      return;
    }
    els.result.textContent = JSON.stringify(response.result, null, 2);
  });
}

