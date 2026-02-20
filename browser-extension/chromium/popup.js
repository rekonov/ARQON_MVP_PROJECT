const openSettingsButton = document.getElementById("open-settings");
const testApiButton = document.getElementById("test-api");
const popupResult = document.getElementById("popup-result");

openSettingsButton.addEventListener("click", () => {
  chrome.runtime.openOptionsPage();
});

testApiButton.addEventListener("click", () => {
  chrome.runtime.sendMessage({ type: "arqon-test-connection" }, (response) => {
    if (!response || response.ok === false) {
      popupResult.textContent = `Error: ${response?.error || "unknown"}`;
      return;
    }
    popupResult.textContent = JSON.stringify(response.result, null, 2);
  });
});

