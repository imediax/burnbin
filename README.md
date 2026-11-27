# 🔥 BurnBin — Zero-Knowledge Self-Destructing Secret Pastebin

A lightweight, high-security secret and file sharing application designed for transmitting passwords, API credentials, confidential notes, and encrypted attachments up to 1 MB. Secrets automatically self-destruct once read or after a chosen expiration window (5 minutes to 30 days).

Built with **Zero External Python Dependencies** (stdlib HTTP server + SQLite `DELETE` journal with `secure_delete=ON` or optional Cloud Firestore REST backend), W3C Web Crypto API, and a native Jetpack Compose Android client.

---

## 🔒 Security Architecture: Zero-Knowledge

BurnBin operates under a zero-knowledge threat model:

```
[Sender Browser / Android App]
  1. Packs text + optional <= 1 MB file (compressed binary V2 "BB2\0" envelope)
  2. Generates random 256-bit AES-GCM master key
  3. (Optional) Encrypts again with PBKDF2-HMAC-SHA256 (600,000 iterations, "v2$600000$...")
  4. Sends ONLY ciphertext, IV, salt header, views & TTL to server
  5. URL generated: https://domain/secret/<id>#key=<hex>
                                               ▲
                                  Client-only fragment key

[Server Vault (Google Cloud Run)]
  - Stores only AES-256 ciphertext in SQLite (DELETE journal + secure_delete=ON + MEMORY temp_store) or Cloud Firestore
  - Has ZERO ability to decrypt the secret
  - Atomically counts views and deletes the active encrypted record upon limit or expiration
  - Enforces strict CSP (script-src 'self', style-src 'self'), COOP: same-origin, Cache-Control: no-store on /secret/*,
    Fetch Metadata guards, strict ciphertext/iv/salt validation, & bounded proxy-aware rate limiting

[Recipient Browser / Android App]
  1. Checks metadata (without burning) and displays exact expiration timestamp
  2. User clicks "Reveal Secret" (optionally gated by Android Biometric / Screen Lock)
  3. Consumes & deletes ciphertext via POST /api/secrets/<id>/consume
  4. Decrypts & decompresses locally, with 45s clipboard auto-clear & 5-attempt clear
```

### 🛡️ Storage & Deletion Threat Model

- **Logical deletion vs. physical media:** When a secret burns or expires, BurnBin deletes the active encrypted record so it can no longer be retrieved via the service. When using SQLite, `PRAGMA journal_mode=DELETE;`, `PRAGMA temp_store=MEMORY;`, and `PRAGMA secure_delete=ON;` eliminate persistent `-wal` journals, keep temporary B-trees in RAM, and immediately zero freed SQLite pages on commit. In Cloud Firestore, parent and chunk documents are deleted together. However, neither mode can guarantee immediate physical erasure across underlying cloud SSD wear-leveling blocks, hypervisor/managed database storage internals, or process/OS memory pages prior to reclamation.
- **Keep Firestore PITR and backups disabled:** Do not enable Firestore Point-in-Time Recovery (PITR) or scheduled backups/exports in production; otherwise deleted ciphertext snapshots could remain recoverable inside backup/rollback windows.
- **Use an out-of-band PBKDF2-600k passphrase for post-burn forward secrecy:** Because standard single-layer links place the 256-bit AES key in `#key=`, anyone who obtains historical storage media/snapshots AND the shared URL before burn could decrypt single-layer ciphertext offline. Enabling a passphrase adds a second AES-256-GCM encryption layer using PBKDF2-HMAC-SHA256 (600,000 iterations) sent out-of-band, protecting confidentiality even if both historical storage remnants and the link are exposed later.
- **Query-string `?key=` links removed:** BurnBin generates `#key=` URL-fragment links exclusively so decryption keys stay out of HTTP requests and edge access logs. Legacy `?key=` links opened on Web or Android immediately strip `?key=` and display a transit-exposure warning.

---

## ✨ Key Features

- **End-to-End Client Encryption (`AES-256-GCM` + `PBKDF2-HMAC-SHA256`):** 600,000 PBKDF2 iterations on new passphrase-protected secrets (with backwards compatibility for legacy 100,000-iteration links).
- **Encrypted File Attachments (up to 1 MB):** Gzip-compressed binary wire envelope (`BB2\0`) interoperable across Web and Android, with direct download/save.
- **QR Code Sharing & In-App Scanner:** Offline SVG/PNG QR generator on Web and ZXing QR generator + camera scanner on Android.
- **Zero Persistent Client Storage:** No Sent Secrets tracker, no `localStorage`, no browser Service Worker cache, and no embedded WebView attack surface.
- **Password & Passphrase Generators:** Configurable strong password length (`16 / 24 / 32`) + symbol toggle, 5-word shareable passphrase generator, and passphrase strength indicator.
- **Android Native Security:** Always-on `FLAG_SECURE` blocking screenshots and Recents thumbnails, Android 12+ `dataExtractionRules` + `fullBackupContent` blocking cloud backups and Device-to-Device (D2D) transfers, release builds enforcing zero cleartext HTTP exceptions, `ACTION_SEND` share target (`*/*` files and text), and Android App Links (`/.well-known/assetlinks.json`).

---

## 🚀 Quick Start (Local)

No virtual environment or `pip install` required!

```bash
# Start the server (default: port 8000, SQLite DELETE journal backend)
python3 app.py

# Or customize host/port/database:
python3 app.py --host 0.0.0.0 --port 8080 --db /path/to/secrets.db
```

Then visit `http://localhost:8000/` in your browser.

### Optional Cloud Firestore Backend

To persist secrets across multiple Cloud Run instances or cold starts using Google Cloud Firestore (`firestore.googleapis.com` REST API, zero Python packages required):

```bash
STORAGE_BACKEND=firestore \
FIRESTORE_PROJECT=your-gcp-project-id \
FIRESTORE_COLLECTION=burnbin_secrets \
FIRESTORE_DATABASE="(default)" \
python3 app.py
```

- **Native TTL & Index Exemptions:** Firestore stores a UTC `expire_at` timestamp alongside `expires_at` and relies on Firestore's native TTL policy (skipping the in-app 60s purger unless `ENABLE_IN_APP_PURGER=1`). Single-field index exemptions and TTL rules are tracked in [`firestore.indexes.json`](firestore.indexes.json), and deny-all client security rules live in [`firestore.rules`](firestore.rules).
- **Rate Limiting & Shared Config:** Per-IP rate limiting runs intentionally in-memory per instance (preventing Firestore write amplification during floods, bounded globally by Cloud Run `--max-instances`). Clients synchronize upload limits and presets from `GET /api/config`.

---

## 🧪 Running Automated Tests

```bash
# Python backend & database suite
python3 test_app.py -v

# Web JS crypto, V1/V2 bundle compression, shared helpers & QR suite (Node 22+)
node test_web.js

# Android unit tests, instrumentation compile check & lint
cd android && ./gradlew testDebugUnitTest compileDebugAndroidTestKotlin lintVitalRelease
```

---

## ☁️ Deploy to Google Cloud Run

```bash
gcloud run deploy burnbin \
  --source . \
  --project plasma-winter-169521 \
  --region europe-west1 \
  --max-instances 1 \
  --memory 512Mi \
  --allow-unauthenticated \
  --set-env-vars DB_PATH=/app/data/secrets.db
```

Artifact Registry Cloud Build configuration is in [`cloudbuild.yaml`](cloudbuild.yaml) (supports `_STORAGE_BACKEND=firestore` and `_MAX_INSTANCES` substitutions for durable multi-instance Cloud Run deployments), and CI/Release workflows are configured under [`.github/workflows/`](.github/workflows/).

> **App Links Note:** `/.well-known/assetlinks.json` serves only the release signing certificate by default. Set `ASSETLINKS_INCLUDE_DEBUG=1` for local debug builds or `ASSETLINKS_RELEASE_SHA256` to add extra fingerprints.

---

## 📱 Android App & Sideloading Guide

- **Direct Download:** [**BurnBin.apk**](https://github.com/imediax/burnbin/releases/latest/download/BurnBin.apk) (R8-minified Signed Release APK + `SHA256SUMS.txt` via [GitHub Releases](https://github.com/imediax/burnbin/releases))
- **Source Code:** Located in [`android/`](android/).
- **Link Association (Android 12+):** App info → **Open by default** → enable **Open supported links** (`burnbin.cloud.run`) so `https://burnbin.cloud.run/secret/...` links open directly in the Reveal tab.
- **Automated Signed Releases (GitHub Actions):** Configure the 4 signing secrets once so every `v*` tag compiles, signs, and publishes `BurnBin.apk`:
  ```bash
  base64 -w 0 /path/to/burnbin-release.jks | gh secret set BURNBIN_KEYSTORE_BASE64
  gh secret set BURNBIN_KEYSTORE_PASSWORD
  gh secret set BURNBIN_KEY_ALIAS
  gh secret set BURNBIN_KEY_PASSWORD
  ```

---

## 📁 Project Structure

```
├── app.py                   # Multi-threaded HTTP server, REST API, CSP/Fetch Metadata & App Links
├── db.py                    # SQLite (DELETE + secure_delete) & optional Firestore REST backend
├── test_app.py              # Python backend unit & integration tests
├── test_web.js              # Node JS Web Crypto, V1/V2 gzip bundle, generator & QR tests
├── Dockerfile               # Container specification for Cloud Run
├── cloudbuild.yaml          # Google Cloud Build pipeline (Artifact Registry)
├── .github/workflows/       # CI test workflow and signed APK GitHub Release workflow
├── BurnBin.apk              # Pre-built signed Android release APK
├── android/                 # Jetpack Compose Android source (MVVM + Kotlin Serialization + ZXing)
└── static/
    ├── index.html           # Secret creation UI (#key= links only)
    ├── view.html            # Secret reveal, transit-warning, passphrase & attachment download UI
    ├── shared.js            # Generators, passphrase strength, expiry formatting & clipboard helpers
    ├── crypto.js            # AES-256-GCM + PBKDF2-600k + V2 binary/gzip wire format
    ├── qr.js                # Zero-dependency ISO/IEC 18004 QR SVG/PNG generator
    ├── create.js            # Creation flow controller
    ├── view.js              # Reveal, consume, decrypt, clipboard auto-clear & clear controller
    ├── style.css            # Strict-CSP dark theme styling
    ├── manifest.webmanifest # Web app manifest
    └── icon.svg / *.png     # App icons
```
