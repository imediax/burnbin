document.addEventListener("DOMContentLoaded", () => {
  const BUNDLE_PREFIX = "__BURNBIN_BUNDLE_V1__:";
  const MAX_ATTACHMENT_BYTES = 1024 * 1024; // 1 MB binary attachment limit
  const SENT_STORAGE_KEY = "burnbin_sent_secrets_v1";
  const MAX_SENT_ITEMS = 25;

  const secretText = document.getElementById("secret-text");
  const generateSecretBtn = document.getElementById("generate-secret-btn");
  const charCount = document.getElementById("char-count");
  const attachmentInput = document.getElementById("attachment-input");
  const attachmentInfo = document.getElementById("attachment-info");
  const clearAttachmentBtn = document.getElementById("clear-attachment-btn");
  const ttlSelect = document.getElementById("ttl-select");
  const viewsSelect = document.getElementById("views-select");
  const passphraseToggle = document.getElementById("passphrase-toggle");
  const passphraseWrapper = document.getElementById("passphrase-wrapper");
  const passphraseInput = document.getElementById("passphrase-input");
  const togglePassphraseBtn = document.getElementById("toggle-passphrase-btn");
  const generatePassphraseBtn = document.getElementById("generate-passphrase-btn");
  const secretLabelInput = document.getElementById("secret-label");
  const secretForm = document.getElementById("secret-form");
  const submitBtn = document.getElementById("submit-btn");

  const createCard = document.getElementById("create-card");
  const resultCard = document.getElementById("result-card");
  const secretLinkInput = document.getElementById("secret-link-input");
  const copyBtn = document.getElementById("copy-btn");
  const copyText = document.getElementById("copy-text");
  const copyNoteBtn = document.getElementById("copy-note-btn");
  const newSecretBtn = document.getElementById("new-secret-btn");
  const formatQueryBtn = document.getElementById("format-query-btn");
  const formatHashBtn = document.getElementById("format-hash-btn");

  const qrDetails = document.getElementById("qr-details");
  const qrContainer = document.getElementById("qr-container");
  const downloadQrBtn = document.getElementById("download-qr-btn");

  const sentCount = document.getElementById("sent-count");
  const sentSecretsList = document.getElementById("sent-secrets-list");

  let lastSecretId = null;
  let lastUrlKey = null;
  let lastMaxViews = 1;
  let lastRequiredPassphrase = false;
  let useQueryFormat = true;
  let selectedFile = null;

  const PASSPHRASE_WORDS = [
    "amber", "anchor", "apple", "apron", "atlas", "badge", "bamboo", "beacon",
    "breeze", "bridge", "cactus", "canyon", "cedar", "cipher", "cloud", "clover",
    "cobalt", "comet", "copper", "coral", "crater", "crimson", "crystal", "cyclone",
    "desert", "dolphin", "ember", "emerald", "falcon", "flint", "forest", "fossil",
    "galaxy", "glacier", "granite", "harbor", "hazel", "horizon", "island", "ivory",
    "jasper", "juniper", "lantern", "lapis", "laurel", "lemon", "linen", "lotus",
    "lunar", "magnet", "mango", "marble", "meadow", "meteor", "mineral", "nebula",
    "nectar", "olive", "onyx", "orchid", "osprey", "pebble", "pepper", "photon"
  ];

  function randomInt(maxExclusive) {
    const buf = new Uint32Array(1);
    const limit = Math.floor(0x100000000 / maxExclusive) * maxExclusive;
    while (true) {
      crypto.getRandomValues(buf);
      if (buf[0] < limit) {
        return buf[0] % maxExclusive;
      }
    }
  }

  function generateStrongPassword(length = 24) {
    const upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
    const lower = "abcdefghijkmnopqrstuvwxyz";
    const digits = "23456789";
    const symbols = "!@#$%^&*()-_=+[]{}";
    const all = upper + lower + digits + symbols;

    const chars = [
      upper[randomInt(upper.length)],
      lower[randomInt(lower.length)],
      digits[randomInt(digits.length)],
      symbols[randomInt(symbols.length)]
    ];
    while (chars.length < length) {
      chars.push(all[randomInt(all.length)]);
    }
    for (let i = chars.length - 1; i > 0; i--) {
      const j = randomInt(i + 1);
      [chars[i], chars[j]] = [chars[j], chars[i]];
    }
    return chars.join("");
  }

  function generateShareablePassphrase() {
    const picked = [];
    for (let i = 0; i < 4; i++) {
      picked.push(PASSPHRASE_WORDS[randomInt(PASSPHRASE_WORDS.length)]);
    }
    const suffix = String(10 + randomInt(90));
    picked.push(suffix);
    return picked.join("-");
  }

  function formatBytes(bytes) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  }

  function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    const chunkSize = 8192;
    let binary = "";
    for (let i = 0; i < bytes.length; i += chunkSize) {
      const slice = bytes.subarray(i, i + chunkSize);
      binary += String.fromCharCode(...slice);
    }
    return btoa(binary);
  }

  function formatRemainingTime(expiresAtMs) {
    const diffSec = Math.floor((expiresAtMs - Date.now()) / 1000);
    if (diffSec <= 0) return "Expired";
    if (diffSec < 60) return `${diffSec}s left`;
    if (diffSec < 3600) return `${Math.ceil(diffSec / 60)}m left`;
    if (diffSec < 86400) return `${Math.ceil(diffSec / 3600)}h left`;
    return `${Math.ceil(diffSec / 86400)}d left`;
  }

  function loadSentSecrets() {
    try {
      const raw = localStorage.getItem(SENT_STORAGE_KEY);
      if (!raw) return [];
      const parsed = JSON.parse(raw);
      if (!Array.isArray(parsed)) return [];
      const cutoff = Date.now() - 7 * 24 * 60 * 60 * 1000;
      return parsed.filter((item) => item && item.id && (item.expiresAt || 0) > cutoff);
    } catch (_) {
      return [];
    }
  }

  function saveSentSecrets(items) {
    try {
      localStorage.setItem(SENT_STORAGE_KEY, JSON.stringify(items.slice(0, MAX_SENT_ITEMS)));
    } catch (_) {
      // Ignore storage quota errors cleanly
    }
  }

  function addTrackedSecret(entry) {
    const items = loadSentSecrets().filter((item) => item.id !== entry.id);
    items.unshift(entry);
    saveSentSecrets(items);
    renderSentSecrets();
  }

  function updateTrackedSecret(id, patch) {
    const items = loadSentSecrets().map((item) =>
      item.id === id ? { ...item, ...patch } : item
    );
    saveSentSecrets(items);
    renderSentSecrets();
  }

  function removeTrackedSecret(id) {
    const items = loadSentSecrets().filter((item) => item.id !== id);
    saveSentSecrets(items);
    renderSentSecrets();
  }

  function renderSentSecrets() {
    if (!sentSecretsList || !sentCount) return;
    const items = loadSentSecrets();
    sentCount.textContent = String(items.length);
    sentSecretsList.replaceChildren();

    if (items.length === 0) {
      const empty = document.createElement("p");
      empty.className = "sent-secret-meta";
      empty.textContent = "No secrets tracked on this browser yet.";
      sentSecretsList.appendChild(empty);
      return;
    }

    for (const item of items) {
      const row = document.createElement("div");
      row.className = "sent-secret-item";

      const top = document.createElement("div");
      top.className = "sent-secret-top";

      const title = document.createElement("span");
      title.className = "sent-secret-title";
      title.textContent = item.label ? `${item.label} (${item.id})` : `Secret #${item.id}`;

      const statusBadge = document.createElement("span");
      const isExpired = Date.now() >= (item.expiresAt || 0);
      const effectiveStatus = item.status === "burned"
        ? "burned"
        : isExpired
          ? "expired"
          : (item.status || "active");

      statusBadge.className = "sent-secret-status";
      if (effectiveStatus === "burned") {
        statusBadge.classList.add("status-burned");
        statusBadge.textContent = "🔥 Burned / Destroyed";
      } else if (effectiveStatus === "expired") {
        statusBadge.textContent = "⏱️ Expired";
      } else {
        statusBadge.classList.add("status-active");
        const viewsLeft = item.viewsLeft ?? item.maxViews ?? 1;
        statusBadge.textContent = `● Active (${viewsLeft} view${viewsLeft === 1 ? "" : "s"} left)`;
      }

      top.appendChild(title);
      top.appendChild(statusBadge);

      const meta = document.createElement("div");
      meta.className = "sent-secret-meta";
      const createdStr = item.createdAt ? new Date(item.createdAt).toLocaleString() : "";
      const attachNote = item.hasAttachment ? " • 📎 File" : "";
      meta.textContent = `Created ${createdStr} • ${formatRemainingTime(item.expiresAt || 0)}${attachNote}`;

      const actions = document.createElement("div");
      actions.className = "sent-secret-actions";

      const checkBtn = document.createElement("button");
      checkBtn.type = "button";
      checkBtn.className = "btn-mini";
      checkBtn.textContent = "🔄 Check Status";
      checkBtn.addEventListener("click", async () => {
        checkBtn.disabled = true;
        checkBtn.textContent = "Checking...";
        try {
          const resp = await fetch(`/api/secrets/${encodeURIComponent(item.id)}/meta`);
          if (resp.ok) {
            const metaData = await resp.json();
            updateTrackedSecret(item.id, {
              status: "active",
              viewsLeft: metaData.views_left,
              expiresAt: (metaData.expires_at || 0) * 1000
            });
          } else if (resp.status === 410) {
            updateTrackedSecret(item.id, { status: "expired" });
          } else {
            updateTrackedSecret(item.id, { status: "burned", viewsLeft: 0 });
          }
        } catch (err) {
          alert(`Could not check secret status: ${err.message}`);
          renderSentSecrets();
        }
      });

      const burnBtn = document.createElement("button");
      burnBtn.type = "button";
      burnBtn.className = "btn-mini btn-danger-mini";
      burnBtn.textContent = "🔥 Burn Now";
      burnBtn.disabled = effectiveStatus !== "active" || !item.deleteToken;
      burnBtn.addEventListener("click", async () => {
        burnBtn.disabled = true;
        burnBtn.textContent = "Burning...";
        try {
          const resp = await fetch(`/api/secrets/${encodeURIComponent(item.id)}`, {
            method: "DELETE",
            headers: { "X-BurnBin-Delete-Token": item.deleteToken }
          });
          if (resp.ok || resp.status === 404) {
            updateTrackedSecret(item.id, { status: "burned", viewsLeft: 0 });
          } else {
            const errData = await resp.json().catch(() => ({}));
            throw new Error(errData.error || `HTTP ${resp.status}`);
          }
        } catch (err) {
          alert(`Failed to burn secret: ${err.message}`);
          renderSentSecrets();
        }
      });

      const dismissBtn = document.createElement("button");
      dismissBtn.type = "button";
      dismissBtn.className = "btn-mini";
      dismissBtn.textContent = "✕ Dismiss";
      dismissBtn.addEventListener("click", () => removeTrackedSecret(item.id));

      actions.appendChild(checkBtn);
      actions.appendChild(burnBtn);
      actions.appendChild(dismissBtn);

      row.appendChild(top);
      row.appendChild(meta);
      row.appendChild(actions);
      sentSecretsList.appendChild(row);
    }
  }

  function renderShareQr() {
    if (!qrContainer || !secretLinkInput.value || !window.BurnBinQR) return;
    qrContainer.replaceChildren();
    try {
      const svg = window.BurnBinQR.toSvgElement(secretLinkInput.value, 210);
      qrContainer.appendChild(svg);
    } catch (err) {
      const msg = document.createElement("span");
      msg.className = "sent-secret-meta";
      msg.textContent = "QR code unavailable for this URL length.";
      qrContainer.appendChild(msg);
    }
  }

  function updateShareLinkDisplay() {
    if (!lastSecretId || !lastUrlKey) return;
    const sep = useQueryFormat ? "?key=" : "#key=";
    secretLinkInput.value = `${window.location.origin}/secret/${lastSecretId}${sep}${lastUrlKey}`;
    if (formatQueryBtn && formatHashBtn) {
      formatQueryBtn.classList.toggle("is-selected", useQueryFormat);
      formatQueryBtn.setAttribute("aria-pressed", String(useQueryFormat));
      formatHashBtn.classList.toggle("is-selected", !useQueryFormat);
      formatHashBtn.setAttribute("aria-pressed", String(!useQueryFormat));
    }
    renderShareQr();
  }

  if (formatQueryBtn && formatHashBtn) {
    formatQueryBtn.addEventListener("click", () => {
      useQueryFormat = true;
      updateShareLinkDisplay();
    });
    formatHashBtn.addEventListener("click", () => {
      useQueryFormat = false;
      updateShareLinkDisplay();
    });
  }

  // Character counter & password generator
  secretText.addEventListener("input", () => {
    charCount.textContent = secretText.value.length.toLocaleString();
  });

  if (generateSecretBtn) {
    generateSecretBtn.addEventListener("click", () => {
      secretText.value = generateStrongPassword(24);
      charCount.textContent = secretText.value.length.toLocaleString();
      secretText.focus();
    });
  }

  // Attachment picker
  function clearAttachment() {
    selectedFile = null;
    if (attachmentInput) attachmentInput.value = "";
    if (attachmentInfo) {
      attachmentInfo.textContent = "";
      attachmentInfo.style.display = "none";
    }
    if (clearAttachmentBtn) clearAttachmentBtn.style.display = "none";
  }

  if (attachmentInput) {
    attachmentInput.addEventListener("change", () => {
      const file = attachmentInput.files && attachmentInput.files[0];
      if (!file) {
        clearAttachment();
        return;
      }
      if (file.size > MAX_ATTACHMENT_BYTES) {
        alert(`File "${file.name}" (${formatBytes(file.size)}) exceeds the 1 MB attachment limit.`);
        clearAttachment();
        return;
      }
      selectedFile = file;
      if (attachmentInfo) {
        attachmentInfo.textContent = `Selected: ${file.name} (${formatBytes(file.size)})`;
        attachmentInfo.style.display = "block";
      }
      if (clearAttachmentBtn) clearAttachmentBtn.style.display = "inline-flex";
    });
  }

  if (clearAttachmentBtn) {
    clearAttachmentBtn.addEventListener("click", clearAttachment);
  }

  // Passphrase field toggle, show/hide & generate
  passphraseToggle.addEventListener("change", () => {
    if (passphraseToggle.checked) {
      passphraseWrapper.style.display = "block";
      passphraseInput.focus();
    } else {
      passphraseWrapper.style.display = "none";
      passphraseInput.value = "";
      passphraseInput.type = "password";
      if (togglePassphraseBtn) {
        togglePassphraseBtn.textContent = "Show";
        togglePassphraseBtn.setAttribute("aria-pressed", "false");
      }
    }
  });

  if (togglePassphraseBtn) {
    togglePassphraseBtn.addEventListener("click", () => {
      const reveal = passphraseInput.type === "password";
      passphraseInput.type = reveal ? "text" : "password";
      togglePassphraseBtn.textContent = reveal ? "Hide" : "Show";
      togglePassphraseBtn.setAttribute("aria-pressed", String(reveal));
    });
  }

  if (generatePassphraseBtn) {
    generatePassphraseBtn.addEventListener("click", () => {
      passphraseInput.value = generateShareablePassphrase();
      passphraseInput.type = "text";
      if (togglePassphraseBtn) {
        togglePassphraseBtn.textContent = "Hide";
        togglePassphraseBtn.setAttribute("aria-pressed", "true");
      }
      passphraseInput.focus();
    });
  }

  // Form submit
  secretForm.addEventListener("submit", async (e) => {
    e.preventDefault();

    const plaintext = secretText.value.trim();
    if (!plaintext && !selectedFile) {
      alert("Please enter a secret message or attach an encrypted file.");
      return;
    }

    const passphrase = passphraseToggle.checked ? passphraseInput.value.trim() : null;
    if (passphraseToggle.checked && !passphrase) {
      alert("Please enter a passphrase or uncheck the passphrase protection.");
      return;
    }

    const ttlSeconds = parseInt(ttlSelect.value, 10);
    const maxViews = parseInt(viewsSelect.value, 10);
    const localLabel = secretLabelInput ? secretLabelInput.value.trim() : "";

    submitBtn.disabled = true;
    submitBtn.innerHTML = `<span>Encrypting locally...</span>`;

    try {
      let payloadToEncrypt = plaintext;
      if (selectedFile) {
        const buffer = await selectedFile.arrayBuffer();
        const dataB64 = arrayBufferToBase64(buffer);
        payloadToEncrypt = BUNDLE_PREFIX + JSON.stringify({
          text: plaintext,
          file: {
            name: selectedFile.name || "attachment.bin",
            mime: selectedFile.type || "application/octet-stream",
            size: selectedFile.size,
            dataB64
          }
        });
      }

      // 1. Client-Side Zero-Knowledge Encryption
      const encrypted = await SecretCrypto.encrypt(payloadToEncrypt, passphrase);

      submitBtn.innerHTML = `<span>Saving to vault...</span>`;

      // 2. Transmit only ciphertext and metadata to the server
      const response = await fetch("/api/secrets", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ciphertext: encrypted.ciphertext,
          iv: encrypted.iv,
          salt: encrypted.salt,
          max_views: maxViews,
          ttl_seconds: ttlSeconds
        })
      });

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.error || `Server error (${response.status})`);
      }

      const result = await response.json();
      lastSecretId = result.id;
      lastUrlKey = encrypted.urlKey;
      lastMaxViews = result.max_views || maxViews;
      lastRequiredPassphrase = Boolean(passphrase);

      addTrackedSecret({
        id: result.id,
        label: localLabel,
        createdAt: Date.now(),
        expiresAt: (result.expires_at || (Math.floor(Date.now() / 1000) + ttlSeconds)) * 1000,
        maxViews: lastMaxViews,
        viewsLeft: lastMaxViews,
        deleteToken: result.delete_token || "",
        hasAttachment: Boolean(selectedFile),
        status: "active"
      });

      if (qrDetails) qrDetails.open = false;

      // 3. Assemble one-time link (default ?key= for chat-safety, or #key= for hash-only)
      updateShareLinkDisplay();
      createCard.style.display = "none";
      resultCard.style.display = "block";
      secretLinkInput.select();

    } catch (err) {
      console.error(err);
      alert(`Failed to create secret: ${err.message}`);
    } finally {
      submitBtn.disabled = false;
      submitBtn.innerHTML = `
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
        Create Encrypted Secret Link
      `;
    }
  });

  async function copyTextWithFeedback(textToCopy, buttonEl, labelEl, originalLabel) {
    let copied = false;
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(textToCopy);
        copied = true;
      }
    } catch (_) {
      copied = false;
    }

    if (!copied) {
      const ta = document.createElement("textarea");
      ta.value = textToCopy;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      copied = document.execCommand("copy");
      document.body.removeChild(ta);
    }

    if (copied) {
      labelEl.textContent = "Copied!";
      buttonEl.style.backgroundColor = "var(--accent-primary)";
      buttonEl.style.color = "#06241a";
      setTimeout(() => {
        labelEl.textContent = originalLabel;
        buttonEl.style.backgroundColor = "";
        buttonEl.style.color = "";
      }, 2500);
    }
  }

  // Copy Link Only button
  copyBtn.addEventListener("click", () => {
    copyTextWithFeedback(secretLinkInput.value, copyBtn, copyText, "Copy");
  });

  // Copy Link + Safety Note button
  if (copyNoteBtn) {
    copyNoteBtn.addEventListener("click", () => {
      const viewsNote = lastMaxViews === 1
        ? "This secret self-destructs after 1 view."
        : `This secret self-destructs after ${lastMaxViews} views.`;
      const passNote = lastRequiredPassphrase
        ? "\nA separate passphrase is required to unlock it."
        : "";
      const message =
        `I shared an end-to-end encrypted secret with you via BurnBin.\n` +
        `${viewsNote}${passNote}\n` +
        `${secretLinkInput.value}`;
      copyTextWithFeedback(message, copyNoteBtn, copyNoteBtn, "✉️ Copy + Note");
    });
  }

  // QR PNG Download
  if (downloadQrBtn) {
    downloadQrBtn.addEventListener("click", () => {
      if (!secretLinkInput.value || !window.BurnBinQR) return;
      try {
        const pngUrl = window.BurnBinQR.toPngDataUrl(secretLinkInput.value, 6);
        const link = document.createElement("a");
        link.href = pngUrl;
        link.download = `burnbin-${lastSecretId || "secret"}.png`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
      } catch (err) {
        alert(`Failed to export QR PNG: ${err.message}`);
      }
    });
  }

  // Create another secret
  newSecretBtn.addEventListener("click", () => {
    lastSecretId = null;
    lastUrlKey = null;
    secretText.value = "";
    charCount.textContent = "0";
    clearAttachment();
    if (secretLabelInput) secretLabelInput.value = "";
    passphraseInput.value = "";
    passphraseInput.type = "password";
    if (togglePassphraseBtn) {
      togglePassphraseBtn.textContent = "Show";
      togglePassphraseBtn.setAttribute("aria-pressed", "false");
    }
    passphraseToggle.checked = false;
    passphraseWrapper.style.display = "none";
    resultCard.style.display = "none";
    createCard.style.display = "block";
    secretText.focus();
  });

  // Initial render of tracked sent secrets
  renderSentSecrets();
});
