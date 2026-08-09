const toggle = document.getElementById("enabled");
const stateEl = document.getElementById("state");

function render(enabled) {
  toggle.checked = enabled;
  stateEl.textContent = enabled
    ? "On — finished downloads are scanned automatically."
    : "Off — downloads are not scanned.";
}

chrome.storage.sync.get({ enabled: true }, ({ enabled }) => render(enabled));

toggle.addEventListener("change", () => {
  chrome.storage.sync.set({ enabled: toggle.checked }, () => render(toggle.checked));
});

document.getElementById("openSettings").addEventListener("click", () => {
  chrome.runtime.openOptionsPage();
});
