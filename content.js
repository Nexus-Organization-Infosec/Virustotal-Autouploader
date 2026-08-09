// Runs on https://www.virustotal.com/gui/* . Two phases, coordinated through storage
// so they survive the SPA/page navigation from the upload page to the file report:
//   Phase A (pendingUpload): inject the file + click confirm, then arm phase B.
//   Phase B (pendingResult): read the detections count from the report and report it.

(async () => {
  const store = await chrome.storage.local.get(["pendingUpload", "pendingResult"]);

  if (store.pendingUpload && fresh(store.pendingUpload)) {
    await chrome.storage.local.remove("pendingUpload");
    try {
      await runUpload(store.pendingUpload);
    } catch (err) {
      console.error("[VT Scanner] upload failed:", err);
      await chrome.storage.local.remove("pendingResult");
      chrome.runtime.sendMessage({ type: "scanError", name: store.pendingUpload.name, downloadId: store.pendingUpload.downloadId });
    }
  } else if (store.pendingResult && fresh(store.pendingResult, 600000)) {
    // Landed straight on the report page after a full navigation.
    try {
      await waitAndReport(store.pendingResult);
    } catch (err) {
      console.error("[VT Scanner] result read failed:", err);
      await chrome.storage.local.remove("pendingResult");
      chrome.runtime.sendMessage({ type: "scanError", name: store.pendingResult.name, downloadId: store.pendingResult.downloadId });
    }
  }
})();

function fresh(x, maxAgeMs = 120000) {
  return x && x.ts && Date.now() - x.ts < maxAgeMs;
}

function base64ToFile(b64, name, type) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new File([bytes], name, { type: type || "application/octet-stream" });
}

// Walk the whole DOM including every shadow root.
function* walkAll(root) {
  const els = root.querySelectorAll("*");
  for (const el of els) {
    yield el;
    if (el.shadowRoot) yield* walkAll(el.shadowRoot);
  }
}
function deepFind(predicate) {
  for (const el of walkAll(document)) {
    try { if (predicate(el)) return el; } catch (_) {}
  }
  return null;
}

function waitFor(getter, timeout, interval = 400) {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    (function tick() {
      let el = null;
      try { el = getter(); } catch (_) {}
      if (el) return resolve(el);
      if (Date.now() - start > timeout) return reject(new Error("timed out waiting for element"));
      setTimeout(tick, interval);
    })();
  });
}

function isConfirmButton(el) {
  if (el.id === "confirmUploadButton") return true;
  const tag = el.tagName || "";
  return /BUTTON/.test(tag) && /confirm upload/i.test(el.textContent || "");
}

async function runUpload(payload) {
  const file = base64ToFile(payload.b64, payload.name, payload.type);

  // 1. Find the file input anywhere in the (shadow) DOM. (Real requirement.)
  const input = await waitFor(() => deepFind((el) => el.tagName === "INPUT" && el.type === "file"), 30000);

  // 2. Drop our file in and let the form react.
  const dt = new DataTransfer();
  dt.items.add(file);
  input.files = dt.files;
  input.dispatchEvent(new Event("input", { bubbles: true }));
  input.dispatchEvent(new Event("change", { bubbles: true }));

  // 3. Arm phase B *now*, before anything else — a confirm dialog may or may not appear,
  //    and the page may fully navigate. Either way we still report the result.
  await chrome.storage.local.set({
    pendingResult: { downloadId: payload.downloadId, name: payload.name, ts: Date.now() }
  });

  // 4. Confirm-upload button is OPTIONAL. Some flows upload immediately on file-select.
  try {
    const confirmBtn = await waitFor(() => deepFind(isConfirmButton), 10000);
    confirmBtn.click();
  } catch (_) {
    console.log("[VT Scanner] no confirm button — assuming upload started automatically");
  }

  // 5. If this stayed a same-document SPA nav, finish reporting right here too.
  await waitAndReport({ downloadId: payload.downloadId, name: payload.name });
}

async function waitAndReport(info) {
  // The report shows a "#positives" element once analysis completes. Deep-search for it,
  // ignoring placeholders that render before a number is available.
  const posEl = await waitFor(() => {
    const el = deepFind((e) => e.id === "positives");
    if (!el) return null;
    const txt = (el.textContent || "").trim();
    return /^\d+$/.test(txt) ? el : null;
  }, 240000, 400);

  const positives = (posEl.textContent || "").trim();

  await chrome.storage.local.remove("pendingResult");
  chrome.runtime.sendMessage({
    type: "scanFinished",
    name: info.name,
    downloadId: info.downloadId,
    positives
  });
}
