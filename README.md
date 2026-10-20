# 🔥 BurnBin — Zero-Knowledge Self-Destructing Secret Pastebin

A lightweight, high-security secret sharing application designed for transmitting passwords, API credentials, and confidential notes. Secrets automatically self-destruct once read or after a chosen expiration window.

Built with **Zero External Dependencies** using Python 3's standard library and the W3C Web Crypto API.

---

## 🔒 Security Architecture: Zero-Knowledge

BurnBin operates under a zero-knowledge threat model:

```
[Sender Browser / Android App]
  1. Generates random 256-bit AES-GCM key
  2. Encrypts secret text in client
  3. (Optional) Encrypts again with PBKDF2 passphrase key
  4. Sends ONLY ciphertext & IV to server
  5. URL generated: https://domain/secret/<id>#key=<256-bit-key>
                           ▲                ▲
                  Sent to Server      NEVER sent to Server
                                     (Client-only fragment)

[Server Vault (Google Cloud Run)]
  - Stores only AES-256 ciphertext in SQLite (WAL mode)
  - Has ZERO ability to decrypt the secret
  - Atomically counts views and purges ciphertext upon limit

[Recipient Browser / Android App]
  1. Opens URL
  2. Client reads #key=... fragment locally
  3. Checks metadata (without burning)
  4. User clicks "Reveal Secret" -> retrieves ciphertext and burns it
  5. Decrypts locally using AES-GCM (and passphrase if required)
```

---

## 🚀 Quick Start (Local)

No virtual environment or `pip install` required!

```bash
# Start the server (default: port 8000)
python3 app.py

# Or customize host/port/database:
python3 app.py --host 0.0.0.0 --port 8080 --db /path/to/secrets.db
```

Then visit `http://localhost:8000/` in your browser.

---

## 🧪 Running Automated Tests

Run the test suite:

```bash
python3 test_app.py
```

---

## ☁️ Deploy to Google Cloud Run (Recommended)

Google Cloud Run is the recommended platform for BurnBin: serverless, scales to zero when idle (within Google Cloud's generous free tier), and provides automatic HTTPS with free SSL.

### Option 1: 3-Click Deploy via Google Cloud Console (No CLI needed)

1. Open the [Google Cloud Run Console](https://console.cloud.google.com/run).
2. Click **Create Service**.
3. Under **Deployment**, select **Continuously deploy from a repository** and connect your GitHub repository (`imediax/burnbin`).
4. Select **Dockerfile** as the build type.
5. In **Authentication**, select **Allow unauthenticated invocations**.
6. Click **Create**! Google Cloud will automatically build and deploy your service and give you a live URL like `https://burnbin-xxxxxx.a.run.app`.

### Option 2: 1-Command Deploy via Google Cloud Shell or CLI

Open [Google Cloud Shell](https://shell.cloud.google.com) (or your local terminal with `gcloud` installed) and run:

```bash
# Clone the repository (if in Cloud Shell)
git clone https://github.com/imediax/burnbin.git
cd burnbin

# Deploy directly from source to Cloud Run
gcloud run deploy burnbin \
  --source . \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars DB_PATH=/app/data/secrets.db
```

---

## 📱 Android App

BurnBin includes a native Jetpack Compose Android client with built-in zero-knowledge encryption, deep linking, native share sheet integration, and customizable server settings:

- Pre-built APK: [BurnBin.apk](BurnBin.apk)
- Source code: `android/`
- Connects to your Google Cloud Run instance or any custom vault URL in the in-app Settings (`⚙️`).

---

## 📁 Project Structure

```
├── app.py              # Multi-threaded HTTP server & REST API
├── db.py               # SQLite storage with atomic view consumption & TTL purge
├── test_app.py         # Automated test suite
├── Dockerfile          # Container specification optimized for Cloud Run
├── cloudbuild.yaml     # Google Cloud Build deployment pipeline
├── BurnBin.apk         # Pre-built Android application
├── android/            # Full Android project source (Jetpack Compose)
└── static/
    ├── index.html      # Secret creation UI
    ├── create.js       # Client-side encryption & link generation
    ├── view.html       # Secret reveal & pre-destruction warning UI
    ├── view.js         # Client-side local decryption & copy logic
    ├── crypto.js       # Web Crypto API wrapper (AES-GCM 256 + PBKDF2)
    └── style.css       # Cyber-minimal dark theme styling
```
