# VirusTotal Download Scanner (Chrome extension)

When a download finishes, the extension automatically uploads it to
[VirusTotal](https://www.virustotal.com/gui/home/upload), confirms the upload, reads the
detection count, and notifies you — **no clicking required**.

## What it does

1. Download completes → **"Scanning in progress"** notification.
2. Reads the file, opens the VT upload page, drops the file into the form and clicks **Confirm upload**.
3. When the report loads, reads the detections count and shows **"Scan finished — N vendors flagged this file"**.

## Controls

- **Click the toolbar icon** → an **on/off toggle** for auto-scanning.
- **Settings** (toolbar popup → *Settings…*, or the extension's Details → Extension options):
  - **Do-not-upload file types** — comma-separated extensions (e.g. `iso, pdf, mp4`) that are skipped.
  - **Auto-remove risky files** — if checked, a downloaded file flagged by **more than 5** vendors
    is **deleted from disk**. The Chrome download-history entry is left intact (it just shows the
    file as deleted); the extension does not erase your download history. The notification confirms
    whether the file was actually removed.
  - **Headless mode** — scans in a minimized background window (no normal tab) that closes itself
    when the scan finishes. Note: a browser extension can't load an external site with *no* window
    at all, so a minimized auto-closing window is as headless as it gets.

Notifications auto-dismiss after a few seconds. The "Scan finished / auto-removed" notice can only
appear once VirusTotal finishes analyzing the file, so for freshly-seen files it may lag a bit —
that delay is VirusTotal's analysis time, not the extension.

## Limits & rules

- Files **over 650 MB** are never uploaded (VirusTotal's max) — you get a "Too large" notice instead.
- Uploading a file to VirusTotal makes it available to the VirusTotal community — don't upload
  files with private or sensitive data (use the do-not-upload list for those types).

## Install (unpacked)

1. Open `chrome://extensions`, turn on **Developer mode**.
2. **Load unpacked** → select this folder (`vt-download-scanner`).
3. Open the extension's **Details** → turn on **Allow access to file URLs** (required to read
   the downloaded file from disk).

## If it breaks

The auto-upload and result-reading rely on VirusTotal's page structure
(`#uploadForm` → `input[type=file]` → `#confirmUploadButton`, and
`file-view → #report → vt-ioc-score-widget → …#positives`). If VirusTotal changes those,
update the selectors in `content.js`.
