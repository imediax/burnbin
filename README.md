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

## 📱 Android App & Sideloading Guide

BurnBin includes a native Jetpack Compose Android client with built-in zero-knowledge encryption, deep linking, native share sheet integration, and customizable server settings.

### 📥 Download APK
- **Direct Download:** [**BurnBin.apk**](https://github.com/imediax/burnbin/raw/main/BurnBin.apk) (Signed Release APK)
- **Source Code:** Located in the [`android/`](android/) directory.

---

### 📲 How to Sideload & Install on Android

"Sideloading" is the process of installing an Android app package (`.apk`) directly without using the Google Play Store:

1. **Download the APK:**  
   On your Android phone, tap [BurnBin.apk](https://github.com/imediax/burnbin/raw/main/BurnBin.apk) to download the package.
2. **Enable Unknown App Installation:**  
   - When you tap the downloaded file in your browser (e.g. Chrome) or file manager, Android may display a prompt: *"For your security, your phone is not allowed to install unknown apps from this source."*
   - Tap **Settings** on the prompt and toggle **Allow from this source** to ON.
3. **Install the App:**  
   Return to the install dialog and tap **Install**.
4. **Play Protect Prompt (Optional):**  
   If Google Play Protect prompts *"Unrecognized app"*, tap **More details** → **Install anyway** (this is standard for self-built open-source APKs not distributed through Google Play).

---

### 🔗 How to Make BurnBin Links Open Automatically in the App

BurnBin supports **Android App Links** and web-to-app deep links for `https://burnbin.cloud.run/secret/*`:

#### Step 1: Enable Link Association (One-Time Setup on Android 12+)
Because sideloaded APKs are installed outside Google Play, modern Android versions (Android 12, 13, 14, and 15) allow you to assign domain links directly:
1. Long-press the **BurnBin** app icon on your home screen or app drawer.
2. Tap **App info** (the `ℹ️` icon).
3. Scroll down and tap **Open by default** (or **Supported web addresses** / **Opening links**).
4. Turn **Open supported links** to **ON**.
5. Tap **Add link** (or check supported addresses) and ensure `burnbin.cloud.run` is checked.

Now, whenever anyone sends you a BurnBin secret link via SMS, WhatsApp, Telegram, Signal, Slack, Gmail, or Discord, tapping the link will **instantly launch BurnBin directly into the Reveal tab**!

#### Step 2: In-Browser Smart Banner
If a recipient opens a secret link inside a mobile web browser (such as Chrome or Firefox on Android), BurnBin displays a prominent banner at the top:
- **"📱 Open Directly in BurnBin App"**
- Tapping this button activates the Android Intent and immediately switches to the app.

---

### 🛡️ Android App Features

- **Share Target:** Select or highlight text in any Android app and tap **Share → BurnBin** to encrypt and generate a one-time link in seconds.
- **Screenshot Protection:** Open the in-app settings gear (`⚙️`) to toggle `FLAG_SECURE`, preventing screenshots or screen recording of sensitive decrypted secrets.
- **Configurable Vault:** Easily switch between `https://burnbin.cloud.run/` and self-hosted instances from the settings menu.

---

## 📁 Project Structure

```
├── app.py              # Multi-threaded HTTP server, REST API & App Links handler
├── db.py               # SQLite storage with atomic view consumption & TTL purge
├── test_app.py         # Automated test suite
├── Dockerfile          # Container specification optimized for Cloud Run
├── cloudbuild.yaml     # Google Cloud Build deployment pipeline
├── BurnBin.apk         # Pre-built Android application
├── android/            # Full Android project source (Jetpack Compose)
└── static/
    ├── index.html      # Secret creation UI
    ├── create.js       # Client-side encryption & link generation
    ├── view.html       # Secret reveal, pre-destruction warning & App Link banner
    ├── view.js         # Client-side local decryption & Android intent launcher
    ├── crypto.js       # Web Crypto API wrapper (AES-GCM 256 + PBKDF2)
    └── style.css       # Cyber-minimal dark theme styling
```
