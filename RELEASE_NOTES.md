# 🔥 BurnBin v2.0.3 — Bare-Bones Security Hardening & Firestore Durability

📱 **[Download BurnBin.apk](https://github.com/imediax/burnbin/releases/download/v2.0.3/BurnBin.apk)**  
🌐 **Web App:** [https://burnbin.cloud.run](https://burnbin.cloud.run)

---

## 🛡️ Security Hardening in v2.0.3 (Tier 1)
- **Eliminated `?key=` Link Generation (`#key=` Only):** Web and Android now generate URL-fragment `#key=` links exclusively so decryption keys stay out of HTTP requests and edge access logs. Removed `?key=` from the Web Android `intent://` quick-open banner, and opening legacy `?key=` links on Web or Android strips `?key=` immediately and shows a transit-exposure warning.
- **SQLite & Firestore Storage Hardening (`db.py`):** Switched SQLite from `WAL` to `PRAGMA journal_mode=DELETE;` with `PRAGMA temp_store=MEMORY;` and `PRAGMA secure_delete=ON;` (eliminating persistent `-wal` files while zeroing freed pages on commit). Updated `FirestoreSecretDB.consume_secret()` to clean up parent and remaining chunk documents if a chunk subdocument is missing (`404`).
- **Accurate Deletion Copy & Threat Model (`README.md`):** Replaced overclaiming physical/memory impossibility copy across Web and Android with exact active-record deletion wording, and documented logical vs. physical deletion, keeping Firestore PITR/backups disabled, and using the PBKDF2-600k out-of-band passphrase for post-burn forward secrecy.
- **Backend HTTP & Validation Hardening (`app.py`):** Overrode `Server` header to `"BurnBin"`, enforced `Cache-Control: no-store, no-cache, must-revalidate` on `/secret/*`, tightened `Cross-Origin-Opener-Policy` to `same-origin`, expanded `Permissions-Policy`, enforced strict regex validation on `ciphertext`, `iv`, and `salt`, and bounded `RateLimiter._hits` via LRU tracking (`max_tracked_ips = 10,000`).
- **Android Platform Hardening (`android/`):** Locked `FLAG_SECURE` unconditionally across all screens, blocked cloud backups and Android 12+ Device-to-Device (`<device-transfer>`) migrations via `data_extraction_rules.xml` + `backup_rules.xml`, and moved cleartext `localhost`/`127.0.0.1`/`10.0.2.2` exceptions strictly to `src/debug/` so release builds disallow all cleartext traffic.

## ✂️ Bare-Bones Attack-Surface Removals (Tier 2)
- **Removed Embedded Android WebView (`WebVaultScreen`):** Dropped the Chromium WebView tab; all creation and reveal flows run natively in Jetpack Compose.
- **Removed Sent Secrets Tracker:** Removed `localStorage` / `SharedPreferences` secret tracking UI and cleared legacy local tracker entries on startup for zero persistent client-side storage.
- **Removed PWA Service Worker (`sw.js`):** Removed `/sw.js` and added automatic unregistration + `burnbin-shell*` cache deletion so clients always fetch fresh code directly over HTTPS.

## ⚙️ Reliability & Ops Improvements Since v2.0.1
- **Cloud Firestore Native TTL & Indexing:** Added UTC `expire_at` TTL timestamps, single-field index exemptions (`firestore.indexes.json`), and deny-all client rules (`firestore.rules`).
- **Operational Endpoints & Lifecycle:** Added `/api/config` client limit synchronization, minimized `/health` disclosure, and added graceful `SIGTERM` shutdown handling.

---

### APK Verification & Sideloading
- **Signing Certificate SHA-256 Fingerprint:**  
  `FE:44:EB:5B:68:84:F9:C7:5A:67:5F:E1:81:F1:EF:9B:21:0C:05:9E:6E:C6:4B:90:D2:83:C2:11:7B:A5:4D:A5`
- **Upgrade Note:** `v2.0.3` uses a new release signing certificate—if upgrading from an older `BurnBin.apk` (`v2.0.0`/`v2.0.1`), uninstall the previous app once before installing `v2.0.3`. Future updates signed with this key will install seamlessly in place.
- Enable **Install unknown apps** if prompted by Android when opening `BurnBin.apk`, and enable **Open supported links** in **App info → Open by default** so `burnbin.cloud.run/secret/...` links launch straight into the Reveal tab.
