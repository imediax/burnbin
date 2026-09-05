# 🔥 BurnBin — Zero-Knowledge Self-Destructing Secret Pastebin

A lightweight, high-security secret sharing application designed for transmitting passwords, API credentials, and confidential notes. Secrets automatically self-destruct once read or after a chosen expiration window.

Built with **Zero External Dependencies** using Python 3's standard library and the W3C Web Crypto API.

---

## 🔒 Security Architecture: Zero-Knowledge

BurnBin operates under a zero-knowledge threat model:

```
[Sender Browser]
  1. Generates random 256-bit AES-GCM key
  2. Encrypts secret text in browser
  3. (Optional) Encrypts again with PBKDF2 passphrase key
  4. Sends ONLY ciphertext & IV to server
  5. URL generated: https://domain/secret/<id>#key=<256-bit-key>
                           ▲                ▲
                  Sent to Server      NEVER sent to Server
                                     (Browser-only fragment)

[Server Vault]
  - Stores only AES-256 ciphertext in SQLite (WAL mode)
  - Has ZERO ability to decrypt the secret
  - Atomically counts views and purges ciphertext upon limit

[Recipient Browser]
  1. Opens URL
  2. Browser reads #key=... fragment locally
  3. Checks metadata (without burning)
  4. User clicks "Reveal Secret" -> retrieves ciphertext and burns it
  5. Decrypts locally using AES-GCM (and passphrase if required)
```

---

## 🚀 Quick Start

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

## ☁️ Deploy to Render

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy)

1. Connect your repository on [Render.com](https://render.com).
2. Choose **Web Service**. Render will automatically detect `render.yaml`.
3. Click **Apply** or **Create Web Service** — deployment runs automatically with free SSL at `https://<your-service>.onrender.com`.

---

## 📁 Project Structure

```
├── app.py              # Multi-threaded HTTP server & REST API
├── db.py               # SQLite storage with atomic view consumption & TTL purge
├── test_app.py         # Automated test suite
└── static/
    ├── index.html      # Secret creation UI
    ├── create.js       # Client-side encryption & link generation
    ├── view.html       # Secret reveal & pre-destruction warning UI
    ├── view.js         # Client-side local decryption & copy logic
    ├── crypto.js       # Web Crypto API wrapper (AES-GCM 256 + PBKDF2)
    └── style.css       # Cyber-minimal dark theme styling
```
