# 🔥 BurnBin — Zero-Knowledge Self-Destructing Secret Pastebin

A lightweight, high-security secret and file sharing application designed for transmitting passwords, API credentials, confidential notes, and encrypted attachments up to 1 MB. Secrets automatically self-destruct once read or after a chosen expiration window (5 minutes to 30 days).

Built with **Zero External Python Dependencies** (stdlib HTTP server + SQLite WAL or optional Cloud Firestore REST backend), W3C Web Crypto API + PWA support, and a native Jetpack Compose Android client.

---

## 🔒 Security Architecture: Zero-Knowledge

BurnBin operates under a zero-knowledge threat model:

```
[Sender Browser / PWA / Android App]
  1. Packs text + optional <= 1 MB file (compressed binary V2 "BB2\0" envelope)
  2. Generates random 256-bit AES-GCM master key
  3. (Optional) Encrypts again with PBKDF2-HMAC-SHA256 (600,000 iterations, "v2$600000$...")
  4. Sends ONLY ciphertext, IV, salt header, views & TTL to server
  5. URL generated: https://domain/secret/<id>?key=<hex> or #key=<hex>
                                               ▲
                                  Client decryption key

[Server Vault (Google Cloud Run)]
  - Stores only AES-256 ciphertext in SQLite (WAL + secure_delete=ON) or Cloud Firestore
  - Has ZERO ability to decrypt the secret
  - Atomically counts views and purges ciphertext upon limit or early revocation
  - Enforces strict CSP (script-src 'self', style-src 'self'), Fetch Metadata guards, & proxy-aware rate limiting

[Recipient Browser / Android App]
  1. Checks metadata (without burning) and displays exact expiration timestamp
  2. User clicks "Reveal Secret" (optionally gated by Android Biometric / Screen Lock)
  3. Consumes & burns ciphertext via POST /api/secrets/<id>/consume
  4. Decrypts & decompresses locally, with 45s clipboard auto-clear & 5-attempt passphrase wipe
```

---

## ✨ Key Features

- **End-to-End Client Encryption (`AES-256-GCM` + `PBKDF2-HMAC-SHA256`):** 600,000 PBKDF2 iterations on new passphrase-protected secrets (with backwards compatibility for legacy 100,000-iteration links).
- **Encrypted File Attachments (up to 1 MB):** Gzip-compressed binary wire envelope (`BB2\0`) interoperable across Web and Android, with direct download/save.
- **QR Code Sharing & In-App Scanner:** Offline SVG/PNG QR generator on Web and ZXing QR generator + camera scanner on Android.
- **Sent Secrets Tracker & Early Revocation:** Tracks non-secret metadata locally (`localStorage` / `SharedPreferences`) to inspect remaining views or burn unread links immediately (`DELETE /api/secrets/<id>`).
- **Password & Passphrase Generators:** Configurable strong password length (`16 / 24 / 32`) + symbol toggle, 4-word shareable passphrase generator, and passphrase strength indicator.
- **PWA + Android Native Integration:** Installable Web App (`manifest.webmanifest` + shell-only Service Worker), Android `ACTION_SEND` share target (`*/*` files and text), and Android App Links (`/.well-known/assetlinks.json`).

---

## 🚀 Quick Start (Local)

No virtual environment or `pip install` required!

```bash
# Start the server (default: port 8000, SQLite WAL backend)
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

Artifact Registry Cloud Build configuration is in [`cloudbuild.yaml`](cloudbuild.yaml), and CI/Release workflows are configured under [`.github/workflows/`](.github/workflows/).

---

## 📱 Android App & Sideloading Guide

- **Direct Download:** [**BurnBin.apk**](https://github.com/imediax/burnbin/raw/main/BurnBin.apk) (R8-minified Signed Release APK)
- **Source Code:** Located in [`android/`](android/).
- **Link Association (Android 12+):** App info → **Open by default** → enable **Open supported links** (`burnbin.cloud.run`) so `https://burnbin.cloud.run/secret/...` links open directly in the Reveal tab.

---

## 📁 Project Structure

```
├── app.py                   # Multi-threaded HTTP server, REST API, CSP/Fetch Metadata & App Links
├── db.py                    # SQLite (WAL + secure_delete) & optional Firestore REST backend
├── test_app.py              # Python backend unit & integration tests
├── test_web.js              # Node JS Web Crypto, V1/V2 gzip bundle, generator & QR tests
├── Dockerfile               # Container specification for Cloud Run
├── cloudbuild.yaml          # Google Cloud Build pipeline (Artifact Registry)
├── .github/workflows/       # CI test workflow and signed APK GitHub Release workflow
├── BurnBin.apk              # Pre-built signed Android release APK
├── android/                 # Jetpack Compose Android source (MVVM + Kotlin Serialization + ZXing)
└── static/
    ├── index.html           # Secret creation & Sent Secrets tracker UI
    ├── view.html            # Secret reveal, warning, passphrase & attachment download UI
    ├── shared.js            # Generators, passphrase strength, expiry formatting & clipboard helpers
    ├── crypto.js            # AES-256-GCM + PBKDF2-600k + V2 binary/gzip wire format
    ├── qr.js                # Zero-dependency ISO/IEC 18004 QR SVG/PNG generator
    ├── create.js            # Creation flow & Sent Secrets tracker controller
    ├── view.js              # Reveal, consume, decrypt, clipboard auto-clear & attempt wipe controller
    ├── style.css            # Strict-CSP dark theme styling
    ├── manifest.webmanifest # PWA web app manifest
    ├── sw.js                # Static shell Service Worker (never caches /api/ or /secret/)
    └── icon.svg / *.png     # App & PWA icons
```
