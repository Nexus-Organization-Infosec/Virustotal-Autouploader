const typesInput = document.getElementById("excludedTypes");
const autoRemove = document.getElementById("autoRemove");
const headless = document.getElementById("headless");
const statusEl = document.getElementById("status");

const DEFAULTS = { excludedTypes: [], autoRemove: false, headless: false };

function parseTypes(raw) {
  return raw
    .split(",")
    .map((s) => s.trim().replace(/^\./, "").toLowerCase())
    .filter(Boolean);
}

chrome.storage.sync.get(DEFAULTS, ({ excludedTypes, autoRemove: ar, headless: hl }) => {
  typesInput.value = (excludedTypes || []).join(", ");
  autoRemove.checked = !!ar;
  headless.checked = !!hl;
});

document.getElementById("save").addEventListener("click", () => {
  const excludedTypes = parseTypes(typesInput.value);
  chrome.storage.sync.set({ excludedTypes, autoRemove: autoRemove.checked, headless: headless.checked }, () => {
    typesInput.value = excludedTypes.join(", ");
    statusEl.textContent = "Saved.";
    setTimeout(() => (statusEl.textContent = ""), 3000);
  });
});
