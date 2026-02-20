const els = {
  keyInput: document.getElementById("api-key"),
  adminKeyInput: document.getElementById("admin-key"),
  saveKey: document.getElementById("save-key"),
  refreshAll: document.getElementById("refresh-all"),
  connectionState: document.getElementById("connection-state"),
  healthCard: document.getElementById("health-card"),
  summaryCard: document.getElementById("summary-card"),
  refreshSelfCheck: document.getElementById("refresh-self-check"),
  selfCheckCard: document.getElementById("self-check-card"),
  exportFormat: document.getElementById("export-format"),
  exportMinLevel: document.getElementById("export-min-level"),
  exportLimit: document.getElementById("export-limit"),
  exportIncidentsBtn: document.getElementById("export-incidents-btn"),
  exportResult: document.getElementById("export-result"),
  scanUrlInput: document.getElementById("scan-url-input"),
  scanUrlBtn: document.getElementById("scan-url-btn"),
  scanUrlResult: document.getElementById("scan-url-result"),
  scanFileInput: document.getElementById("scan-file-input"),
  scanFileQuarantine: document.getElementById("scan-file-quarantine"),
  scanFileBtn: document.getElementById("scan-file-btn"),
  scanFileResult: document.getElementById("scan-file-result"),
  refreshEvents: document.getElementById("refresh-events"),
  refreshQuarantine: document.getElementById("refresh-quarantine"),
  eventsList: document.getElementById("events-list"),
  quarantineList: document.getElementById("quarantine-list"),
};

let autoRefreshTimer = null;
const runtimeAuth = {
  key: "change-me-arqon",
  admin: "",
};

function readApiKey() {
  return runtimeAuth.key;
}

function writeApiKey(value) {
  runtimeAuth.key = value || "";
}

function readAdminKey() {
  return runtimeAuth.admin;
}

function writeAdminKey(value) {
  runtimeAuth.admin = value || "";
}

function authHeaders() {
  const key = readApiKey();
  const admin = readAdminKey() || key;
  return {
    "X-ARQON-Key": key,
    "X-ARQON-Admin-Key": admin,
  };
}

function safeParseJson(value) {
  try {
    return value ? JSON.parse(value) : {};
  } catch {
    return {};
  }
}

async function getJson(url, authenticated = false) {
  const options = {};
  if (authenticated) {
    options.headers = authHeaders();
  }
  const response = await fetch(url, options);
  const text = await response.text();
  const payload = safeParseJson(text);
  if (!response.ok) {
    const message = payload.error || `HTTP ${response.status}`;
    throw new Error(message);
  }
  return payload;
}

async function postJson(url, body) {
  const response = await fetch(url, {
    method: "POST",
    headers: {
      ...authHeaders(),
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });
  const text = await response.text();
  const payload = safeParseJson(text);
  if (!response.ok) {
    const message = payload.error || `HTTP ${response.status}`;
    throw new Error(message);
  }
  return payload;
}

async function getRaw(url, authenticated = false) {
  const options = {};
  if (authenticated) {
    options.headers = authHeaders();
  }
  const response = await fetch(url, options);
  const text = await response.text();
  if (!response.ok) {
    const parsed = safeParseJson(text);
    const message = parsed.error || `HTTP ${response.status}`;
    throw new Error(message);
  }
  return {
    text,
    contentType: response.headers.get("Content-Type") || "",
  };
}

function pretty(value) {
  return JSON.stringify(value, null, 2);
}

function renderList(container, items, transform) {
  container.innerHTML = "";
  if (!items || items.length === 0) {
    const empty = document.createElement("div");
    empty.className = "list-item";
    empty.textContent = "No data.";
    container.appendChild(empty);
    return;
  }

  for (const item of items) {
    const node = document.createElement("article");
    node.className = "list-item";
    node.appendChild(transform(item));
    container.appendChild(node);
  }
}

function eventNode(item) {
  const wrapper = document.createElement("div");
  const head = document.createElement("div");
  head.className = "head";
  const title = document.createElement("strong");
  title.textContent = `${item.type || "event"} • ${item.timestamp_utc || "-"}`;
  const level = document.createElement("span");
  const normalized = String(item.level || "info").toLowerCase();
  level.className = `pill ${normalized === "warning" ? "warning" : normalized === "error" ? "error" : "info"}`;
  level.textContent = normalized;
  head.appendChild(title);
  head.appendChild(level);

  const msg = document.createElement("div");
  msg.textContent = item.message || "";
  const details = document.createElement("pre");
  details.className = "mono";
  details.textContent = pretty(item.data || {});

  wrapper.appendChild(head);
  wrapper.appendChild(msg);
  wrapper.appendChild(details);
  return wrapper;
}

function quarantineNode(item) {
  const wrapper = document.createElement("div");
  const head = document.createElement("div");
  head.className = "head";
  const title = document.createElement("strong");
  title.textContent = item.timestamp_utc || "unknown";
  const reason = document.createElement("span");
  reason.className = "pill warning";
  reason.textContent = "quarantined";
  head.appendChild(title);
  head.appendChild(reason);

  const path = document.createElement("div");
  path.textContent = item.original_path || "";
  const details = document.createElement("pre");
  details.className = "mono";
  details.textContent = pretty(item);

  wrapper.appendChild(head);
  wrapper.appendChild(path);
  wrapper.appendChild(details);
  return wrapper;
}

async function refreshHealth() {
  const payload = await getJson("/health", false);
  els.healthCard.textContent = pretty(payload);
  return payload;
}

async function refreshSummary() {
  const payload = await getJson("/v1/summary", true);
  els.summaryCard.textContent = pretty(payload);
  return payload;
}

async function refreshSelfCheck() {
  const payload = await getJson("/v1/self-check?skip_bind_check=true", true);
  els.selfCheckCard.textContent = pretty(payload);
  return payload;
}

async function refreshEvents() {
  const payload = await getJson("/v1/events?limit=60", true);
  renderList(els.eventsList, payload.events || [], eventNode);
}

async function refreshQuarantine() {
  const payload = await getJson("/v1/quarantine?limit=60", true);
  renderList(els.quarantineList, payload.records || [], quarantineNode);
}

async function refreshAll() {
  els.connectionState.textContent = "Refreshing...";
  try {
    await refreshHealth();
    await refreshSummary();
    await refreshSelfCheck();
    await refreshEvents();
    await refreshQuarantine();
    els.connectionState.textContent = "Connected";
    els.connectionState.classList.add("ok");
    els.connectionState.classList.remove("danger");
  } catch (error) {
    els.connectionState.textContent = `Error: ${error.message}`;
    els.connectionState.classList.add("danger");
    els.connectionState.classList.remove("ok");
  }
}

async function scanUrl() {
  const url = els.scanUrlInput.value.trim();
  if (!url) {
    return;
  }
  els.scanUrlResult.textContent = "Scanning...";
  try {
    const payload = await postJson("/v1/url/evaluate", { url });
    els.scanUrlResult.textContent = pretty(payload);
    await refreshEvents();
  } catch (error) {
    els.scanUrlResult.textContent = `Error: ${error.message}`;
  }
}

async function scanFile() {
  const path = els.scanFileInput.value.trim();
  if (!path) {
    return;
  }
  els.scanFileResult.textContent = "Scanning...";
  try {
    const payload = await postJson("/v1/file/evaluate", {
      path,
      quarantine: Boolean(els.scanFileQuarantine.checked),
    });
    els.scanFileResult.textContent = pretty(payload);
    await refreshEvents();
    await refreshQuarantine();
  } catch (error) {
    els.scanFileResult.textContent = `Error: ${error.message}`;
  }
}

function downloadContent(filename, content, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.style.display = "none";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

function buildExportFilename(format) {
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  return `arqon-incidents-${timestamp}.${format}`;
}

async function exportIncidents() {
  const format = String(els.exportFormat.value || "json").toLowerCase();
  const minLevel = String(els.exportMinLevel.value || "warning").toLowerCase();
  const limitRaw = Number.parseInt(els.exportLimit.value, 10);
  const limit = Number.isFinite(limitRaw) ? Math.max(1, Math.min(1000, limitRaw)) : 300;
  els.exportResult.textContent = "Exporting...";
  try {
    const query = new URLSearchParams({
      format,
      min_level: minLevel,
      limit: String(limit),
    });
    const { text, contentType } = await getRaw(`/v1/incidents/export?${query.toString()}`, true);

    if (format === "json") {
      const parsed = safeParseJson(text);
      downloadContent(
        buildExportFilename("json"),
        JSON.stringify(parsed, null, 2),
        "application/json; charset=utf-8",
      );
      const count = Number(parsed.count || 0);
      els.exportResult.textContent = `Export complete: ${count} incidents (json)`;
      return;
    }

    const mimeType = contentType.includes("text/csv")
      ? contentType
      : "text/csv; charset=utf-8";
    downloadContent(buildExportFilename("csv"), text, mimeType);
    const lineCount = text ? text.split(/\r?\n/).filter(Boolean).length : 0;
    const estimatedRows = Math.max(0, lineCount - 1);
    els.exportResult.textContent = `Export complete: ${estimatedRows} incidents (csv)`;
  } catch (error) {
    els.exportResult.textContent = `Error: ${error.message}`;
  }
}

function bootstrap() {
  els.keyInput.value = readApiKey();
  els.adminKeyInput.value = readAdminKey();

  els.saveKey.addEventListener("click", () => {
    writeApiKey(els.keyInput.value.trim());
    writeAdminKey(els.adminKeyInput.value.trim());
    refreshAll();
  });
  els.refreshAll.addEventListener("click", refreshAll);
  els.refreshSelfCheck.addEventListener("click", refreshSelfCheck);
  els.refreshEvents.addEventListener("click", refreshEvents);
  els.refreshQuarantine.addEventListener("click", refreshQuarantine);
  els.scanUrlBtn.addEventListener("click", scanUrl);
  els.scanFileBtn.addEventListener("click", scanFile);
  els.exportIncidentsBtn.addEventListener("click", exportIncidents);

  refreshAll();
  autoRefreshTimer = window.setInterval(refreshAll, 10000);
}

window.addEventListener("beforeunload", () => {
  if (autoRefreshTimer) {
    clearInterval(autoRefreshTimer);
  }
});

bootstrap();
