const DEFAULT_SETTINGS = {
  endpoint: "http://127.0.0.1:8765",
  apiKey: "change-me-arqon",
  monitorTabs: true,
  monitorDownloads: true,
  blockOnWarn: false,
};

const allowOnce = new Map();
const ALLOW_ONCE_TTL_MS = 120000;

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.sync.get(DEFAULT_SETTINGS, (data) => {
    chrome.storage.sync.set({ ...DEFAULT_SETTINGS, ...data });
  });
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "arqon-allow-once" && typeof message.target === "string") {
    allowOnce.set(message.target, Date.now() + ALLOW_ONCE_TTL_MS);
    sendResponse({ ok: true });
    return true;
  }
  if (message?.type === "arqon-get-settings") {
    chrome.storage.sync.get(DEFAULT_SETTINGS, (data) => sendResponse({ ok: true, settings: data }));
    return true;
  }
  if (message?.type === "arqon-test-connection") {
    testConnection().then(
      (result) => sendResponse({ ok: true, result }),
      (error) => sendResponse({ ok: false, error: String(error.message || error) }),
    );
    return true;
  }
  return false;
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (!changeInfo.url) {
    return;
  }
  handleNavigation(tabId, changeInfo.url).catch(() => {});
});

chrome.downloads.onCreated.addListener((item) => {
  handleDownload(item).catch(() => {});
});

async function getSettings() {
  return await chrome.storage.sync.get(DEFAULT_SETTINGS);
}

async function testConnection() {
  const settings = await getSettings();
  const endpoint = normalizeEndpoint(settings.endpoint);
  if (!endpoint) {
    throw new Error("endpoint_empty");
  }

  const healthResponse = await fetchWithTimeout(`${endpoint}/health`, { method: "GET" }, 3500);
  if (!healthResponse.ok) {
    throw new Error(`health_http_${healthResponse.status}`);
  }

  let healthJson = {};
  try {
    healthJson = await healthResponse.json();
  } catch (_error) {
    healthJson = {};
  }

  const evaluateResponse = await fetchWithTimeout(
    `${endpoint}/v1/url/evaluate`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ARQON-Key": settings.apiKey || "",
      },
      body: JSON.stringify({ url: "https://example.com/" }),
    },
    3500,
  );

  if (evaluateResponse.status === 401) {
    throw new Error("api_key_unauthorized");
  }
  if (!evaluateResponse.ok) {
    throw new Error(`evaluate_http_${evaluateResponse.status}`);
  }

  let evaluateJson = {};
  try {
    evaluateJson = await evaluateResponse.json();
  } catch (_error) {
    evaluateJson = {};
  }

  return {
    protection_ready: true,
    endpoint,
    health: {
      ok: true,
      status: healthResponse.status,
      service: healthJson.service || "",
    },
    evaluate: {
      ok: true,
      status: evaluateResponse.status,
      action: evaluateJson.action || "unknown",
      risk_score: Number(evaluateJson.risk_score || 0),
    },
  };
}

function shouldIgnoreUrl(url) {
  if (!url) return true;
  return (
    url.startsWith("chrome://") ||
    url.startsWith("edge://") ||
    url.startsWith("about:") ||
    url.startsWith("chrome-extension://")
  );
}

function isAllowOnce(url) {
  const expiresAt = allowOnce.get(url);
  if (!expiresAt) return false;
  if (Date.now() > expiresAt) {
    allowOnce.delete(url);
    return false;
  }
  return true;
}

async function handleNavigation(tabId, url) {
  if (shouldIgnoreUrl(url)) {
    return;
  }
  const settings = await getSettings();
  if (!settings.monitorTabs) {
    return;
  }
  if (isAllowOnce(url)) {
    return;
  }

  const decision = await evaluateUrl(settings, url);
  if (!decision) {
    return;
  }

  const shouldBlock = decision.action === "block" || (decision.action === "warn" && settings.blockOnWarn);
  if (!shouldBlock) {
    return;
  }

  const warningUrl = chrome.runtime.getURL(
    `warning.html?target=${encodeURIComponent(url)}&risk=${encodeURIComponent(String(decision.risk_score || 0))}&reasons=${encodeURIComponent((decision.reasons || []).join("|"))}`,
  );
  chrome.tabs.update(tabId, { url: warningUrl });
}

async function handleDownload(item) {
  const settings = await getSettings();
  if (!settings.monitorDownloads) {
    return;
  }
  const url = item.finalUrl || item.url || "";
  if (!url || shouldIgnoreUrl(url)) {
    return;
  }

  const decision = await evaluateUrl(settings, url);
  if (!decision) {
    return;
  }
  const shouldBlock = decision.action === "block" || (decision.action === "warn" && settings.blockOnWarn);
  if (!shouldBlock) {
    return;
  }

  chrome.downloads.cancel(item.id, () => {});
  chrome.downloads.erase({ id: item.id }, () => {});
  chrome.notifications.create({
    type: "basic",
    iconUrl: "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADElEQVR4nGNgYGD4DwABBAEAH1fVZwAAAABJRU5ErkJggg==",
    title: "ARQON blocked download",
    message: `Risk ${decision.risk_score}: ${url}`,
    priority: 2,
  });
}

async function evaluateUrl(settings, url) {
  const endpoint = normalizeEndpoint(settings.endpoint);
  if (!endpoint) return null;

  try {
    const response = await fetchWithTimeout(
      `${endpoint}/v1/url/evaluate`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-ARQON-Key": settings.apiKey || "",
        },
        body: JSON.stringify({ url }),
      },
      3500,
    );
    if (!response.ok) {
      return null;
    }
    return await response.json();
  } catch (_error) {
    return null;
  }
}

function normalizeEndpoint(value) {
  return (value || "").trim().replace(/\/+$/, "");
}

async function fetchWithTimeout(url, options, timeoutMs) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } catch (error) {
    if (error && error.name === "AbortError") {
      throw new Error("request_timeout");
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}
