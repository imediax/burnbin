# 🔥 BurnBin v2.0.1 — Payload Limit Fix & Security Hardening

📱 **[Download BurnBin.apk](https://github.com/imediax/burnbin/releases/download/v2.0.1/BurnBin.apk)**  
🌐 **Web App / PWA:** [https://burnbin.cloud.run](https://burnbin.cloud.run)

---

## 🛠️ Fixes & Hardening in v2.0.1
- **Large Text Secrets (> 64 KB) V2 Envelope Fix (Web & Android):** Raised `MAX_META_BYTES` from `64 KB` to `4 MB` (still strictly bounded under the `8 MB` decompressed zip-bomb cap) and enforced the same limit in `encodePayload` before upload, preventing > 64 KB text secrets from burning on reveal and failing to decode with `"Corrupted V2 metadata header."`.
- **Accurate Web Reveal Error Attribution (`static/view.js`):** Separated `PASSPHRASE_ERROR`, `KEY_ERROR`, and envelope/decoding errors so payload decode failures display directly instead of counting against passphrase retry limits or asking to re-enter the URL key.
- **Production-Only App Links by Default (`app.py`):** `/.well-known/assetlinks.json` now serves only the release SHA-256 certificate fingerprint by default. Debug builds can opt in with `ASSETLINKS_INCLUDE_DEBUG=1` (and extra fingerprints remain supported via `ASSETLINKS_RELEASE_SHA256`).
- **Configurable Durable Cloud Run Storage (`cloudbuild.yaml`):** Parameterized Cloud Build substitutions (`_STORAGE_BACKEND`, `_MAX_INSTANCES`, `_FIRESTORE_COLLECTION`, `_FIRESTORE_DATABASE`) so Cloud Run deployments can switch from ephemeral single-instance SQLite to durable multi-instance Firestore without editing the pipeline file.
- **Regression Tests:** Added automated tests for > 64 KB V2 text round-trips, 4 MB metadata bounds enforcement, and `ASSETLINKS_INCLUDE_DEBUG` gating across Python, Web JS, and Android unit test suites.

---

### APK Verification & Sideloading
- **Signing Certificate SHA-256 Fingerprint:**  
  `CD:1F:E7:33:69:1F:C9:93:BB:EF:A3:63:D4:B7:02:7D:91:1E:56:AA:31:B9:FE:9B:37:6E:FA:53:59:9C:6B:13`
- Enable **Install unknown apps** if prompted by Android when opening `BurnBin.apk`, and enable **Open supported links** in **App info → Open by default** so `burnbin.cloud.run/secret/...` links launch straight into the Reveal tab.
