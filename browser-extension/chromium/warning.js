const params = new URLSearchParams(window.location.search);
const target = decodeURIComponent(params.get("target") || "");
const risk = Number(params.get("risk") || 0);
const reasons = decodeURIComponent(params.get("reasons") || "");

document.getElementById("warning-target").textContent = target || "Unknown URL";
document.getElementById("warning-risk").textContent = `Risk score: ${risk}`;
document.getElementById("warning-reasons").textContent = reasons
  ? reasons.split("|").join("\n")
  : "No reasons provided.";

document.getElementById("go-back").addEventListener("click", () => {
  history.back();
});

document.getElementById("proceed-once").addEventListener("click", () => {
  chrome.runtime.sendMessage({ type: "arqon-allow-once", target }, () => {
    window.location.href = target;
  });
});

