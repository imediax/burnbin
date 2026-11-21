# 🔥 BurnBin v2.0.0 — Zero-Knowledge Self-Destructing Secrets & Encrypted File Sharing

📱 **[Download BurnBin.apk (v2.0.0 — 2.11 MB)](https://github.com/imediax/burnbin/releases/download/v2.0.0/BurnBin.apk)**  
🌐 **Web App / PWA:** [https://burnbin.cloud.run](https://burnbin.cloud.run)

---

## 🔒 Security & Cryptography Hardening
- **PBKDF2-HMAC-SHA256 V2 (600,000 Iterations):** Passphrase-protected secrets now use 600,000 PBKDF2 iterations (`v2$600000$`) while staying backwards-compatible with legacy `100,000`-iteration links.
- **Strict Content Security Policy & Fetch Metadata:** Zero `'unsafe-inline'` scripts or styles (`script-src 'self'`, `style-src 'self'`), `object-src 'none'`, `base-uri 'none'`, `form-action 'self'`, `frame-ancestors 'none'`, `Permissions-Policy`, COOP/CORP, HSTS over HTTPS, and `Sec-Fetch-Site` mutation protection.
- **Burn-on-Consume & Secure Wipe:** Dedicated `POST /api/secrets/<id>/consume` endpoint (with `GET` fallback for older clients), SQLite `PRAGMA secure_delete=ON`, proxy-aware right-most `X-Forwarded-For` rate limiting, and optional `FirestoreSecretDB` backend with a `950k`-char size guard.
- **Brute-Force Guard:** 5 incorrect passphrase attempts on Reveal automatically wipe the cached encrypted payload from memory.

## 📎 Encrypted Attachments (`BB2\0` Binary + Gzip)
- Encrypt and share binary files up to **1 MB** alongside secret notes using a compact gzip-compressed `BB2\0` binary wire format shared between Web and Android (`8 MB` decompressed zip-bomb safety ceiling), with direct download/save and no inline previews.

## ✨ UX & Sharing Workflows
- **QR Code Generation & In-App Scanner:** Offline SVG/PNG QR generator on Web (`qr.js`) and ZXing QR generator + camera scanner on Android.
- **Sent Secrets Tracker & Early Revocation:** Track non-secret metadata locally (`localStorage` / `SharedPreferences`) to inspect remaining views or burn unread links early (`DELETE /api/secrets/<id>`).
- **Generators & Strength Indicator:** Configurable CSPRNG password generator (`16 / 24 / 32` chars, optional symbols), 4-word shareable passphrase generator, passphrase strength meter, exact local expiration timestamps, and TTL presets from **5 minutes** to **30 days**.
- **PWA Support:** Installable Web App with static-shell Service Worker (network-only for `/api/` and `/secret/`).

## 📱 Android App v2.0.0 Highlights
- Refactored from a single screen file into clean MVVM (`BurnBinViewModel`, `BurnBinApiClient` on `kotlinx.serialization`, Compose feature modules).
- **Persistent 45s Clipboard Auto-Clear:** Switching tabs no longer cancels clipboard auto-wiping.
- **Share Files Directly to BurnBin:** `ACTION_SEND` now accepts `*/*` files and images in addition to text.
- **R8 Minification & Resource Shrinking:** Reduced APK size from `9.00 MB` down to **`2.11 MB`**.

---

### APK Verification & Sideloading
- **Signing Certificate SHA-256 Fingerprint:**  
  `CD:1F:E7:33:69:1F:C9:93:BB:EF:A3:63:D4:B7:02:7D:91:1E:56:AA:31:B9:FE:9B:37:6E:FA:53:59:9C:6B:13`
- Enable **Install unknown apps** if prompted by Android when opening `BurnBin.apk`, and enable **Open supported links** in **App info → Open by default** so `burnbin.cloud.run/secret/...` links launch straight into the Reveal tab.
