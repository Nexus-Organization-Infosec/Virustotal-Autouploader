// VirusTotal Download Scanner - MV3 service worker
//
// Automatic flow:
//   download finishes -> (checks: enabled? type allowed? <=650MB?) -> upload to VT ->
//   confirm -> read detection count -> optionally auto-remove if too many hits.

const VT_UPLOAD_PAGE = "https://www.virustotal.com/gui/home/upload";
const NOTIF_PREFIX   = "vt-scan-";
const VT_MAX_BYTES   = 650 * 1024 * 1024; // VirusTotal hard limit: 650 MB
const AUTO_REMOVE_THRESHOLD = 5;          // remove if MORE THAN this many detections

const DEFAULTS = {
  enabled: true,
  excludedTypes: [],   // lowercase extensions without dot, e.g. ["iso","pdf"]
  autoRemove: false,   // delete the file if > 5 vendors flag it
  headless: false      // upload in a minimized background window, auto-closed when done
};

const NOTIF_TTL = 5000;      // auto-dismiss transient notifications after 5s
const NOTIF_TTL_DONE = 8000; // keep the result a little longer

// --- helpers ---------------------------------------------------------------

function basename(p) {
  return p.split(/[\\/]/).pop();
}

function extOf(name) {
  const b = basename(name);
  const i = b.lastIndexOf(".");
  return i >= 0 ? b.slice(i + 1).toLowerCase() : "";
}

function pathToFileUrl(p) {
  let norm = p.replace(/\\/g, "/");
  if (!norm.startsWith("/")) norm = "/" + norm;
  return "file://" + norm.split("/").map(encodeURIComponent).join("/");
}

async function blobToBase64(blob) {
  const bytes = new Uint8Array(await blob.arrayBuffer());
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

function getSettings() {
  return chrome.storage.sync.get(DEFAULTS);
}

function notify(id, title, message, ttl = NOTIF_TTL) {
  chrome.notifications.create(id, { type: "basic", iconUrl: "icon128.png", title, message });
  if (ttl > 0) setTimeout(() => chrome.notifications.clear(id), ttl);
}

function humanSize(bytes) {
  if (!bytes || bytes < 0) return "unknown size";
  const mb = bytes / (1024 * 1024);
  return mb >= 1024 ? (mb / 1024).toFixed(2) + " GB" : mb.toFixed(1) + " MB";
}

// --- set defaults on install ----------------------------------------------

chrome.runtime.onInstalled.addListener(async () => {
  const current = await chrome.storage.sync.get(DEFAULTS);
  await chrome.storage.sync.set(current); // writes any missing defaults
});

// --- download watcher ------------------------------------------------------

chrome.downloads.onChanged.addListener(async (delta) => {
  if (!delta.state || delta.state.current !== "complete") return;
  const [item] = await chrome.downloads.search({ id: delta.id });
  if (!item || !item.filename) return;

  const settings = await getSettings();
  if (!settings.enabled) return;

  const name = basename(item.filename);
  const ext = extOf(name);

  // Excluded file type -> skip silently-ish.
  if (ext && settings.excludedTypes.includes(ext)) {
    notify(NOTIF_PREFIX + "skip-" + delta.id, "Skipped scan", `"${name}" (.${ext}) is on your do-not-upload list.`);
    return;
  }

  // Size guard — VirusTotal max is 650 MB.
  const size = item.fileSize > 0 ? item.fileSize : item.totalBytes;
  if (size > VT_MAX_BYTES) {
    notify(
      NOTIF_PREFIX + "big-" + delta.id,
      "Too large — not uploaded",
      `"${name}" is ${humanSize(size)}. VirusTotal's max upload is 650 MB.`
    );
    return;
  }

  notify(NOTIF_PREFIX + delta.id, "Scanning in progress", `Uploading "${name}" to VirusTotal…`);
  startScan(delta.id);
});

// --- scan: read file, stash it, open the upload page -----------------------

async function startScan(downloadId) {
  const [item] = await chrome.downloads.search({ id: downloadId });
  if (!item || !item.filename) {
    notify(NOTIF_PREFIX + "err", "VirusTotal", "Could not locate the downloaded file.");
    return;
  }
  const name = basename(item.filename);

  try {
    const resp = await fetch(pathToFileUrl(item.filename));
    if (!resp.ok) throw new Error("read failed");
    const blob = await resp.blob();

    // Backstop size check against the real bytes.
    if (blob.size > VT_MAX_BYTES) {
      notify(NOTIF_PREFIX + "big2-" + downloadId, "Too large — not uploaded",
        `"${name}" is ${humanSize(blob.size)}. VirusTotal's max upload is 650 MB.`);
      return;
    }

    const b64 = await blobToBase64(blob);

    await chrome.storage.local.set({
      pendingUpload: {
        downloadId,
        name,
        type: blob.type || "application/octet-stream",
        b64,
        ts: Date.now()
      }
    });

    const { headless } = await getSettings();
    if (headless) {
      // No visible tab: a minimized background window that we auto-close when done.
      chrome.windows.create({ url: VT_UPLOAD_PAGE, state: "minimized" });
    } else {
      chrome.tabs.create({ url: VT_UPLOAD_PAGE });
    }
  } catch (err) {
    console.error("VT scan setup failed:", err);
    notify(
      NOTIF_PREFIX + "err",
      "Can't read the file",
      "Enable 'Allow access to file URLs' for this extension on chrome://extensions. Opening the upload page so you can drop it in manually."
    );
    chrome.tabs.create({ url: VT_UPLOAD_PAGE });
  }
}

// --- scan finished: content.js reports the detection count -----------------

chrome.runtime.onMessage.addListener((msg, sender) => {
  if (!msg) return;
  if (msg.type === "scanFinished") handleScanFinished(msg, sender);
  else if (msg.type === "scanError") handleScanError(msg, sender);
});

function closeHeadlessTab(settings, sender) {
  if (settings.headless && sender && sender.tab && sender.tab.id != null) {
    chrome.tabs.remove(sender.tab.id).catch(() => {});
  }
}

async function handleScanFinished(msg, sender) {
  const count = parseInt(msg.positives, 10);
  const shown = Number.isNaN(count) ? msg.positives : count;
  const clean = count === 0;

  const settings = await getSettings();
  const willRemove = settings.autoRemove && !Number.isNaN(count) && count > AUTO_REMOVE_THRESHOLD && msg.downloadId != null;

  let message = `"${msg.name}": ${shown} security vendor${shown === 1 ? "" : "s"} flagged this file` +
    (clean ? " — looks clean." : ".");

  if (willRemove) {
    try {
      // Deletes the actual file from disk. We deliberately do NOT call
      // chrome.downloads.erase() — the download-history entry is left intact.
      await chrome.downloads.removeFile(msg.downloadId);

      // Verify the file is really gone via the item's `exists` flag.
      const [after] = await chrome.downloads.search({ id: msg.downloadId });
      if (after && after.exists === false) {
        message += ` File deleted from disk (> ${AUTO_REMOVE_THRESHOLD} detections).`;
      } else {
        message += ` Tried to delete the file, but it may still be on disk.`;
      }
    } catch (e) {
      message += ` Couldn't delete the file: ${e && e.message ? e.message : e}.`;
    }
  }

  notify(NOTIF_PREFIX + "done-" + msg.downloadId, "Scan finished", message, NOTIF_TTL_DONE);
  closeHeadlessTab(settings, sender);
}

async function handleScanError(msg, sender) {
  const settings = await getSettings();
  notify(NOTIF_PREFIX + "readerr-" + (msg.downloadId || ""), "Scan result unavailable",
    `Couldn't read the VirusTotal result for "${msg.name}".`);
  closeHeadlessTab(settings, sender);
}
