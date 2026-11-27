document.addEventListener("DOMContentLoaded", () => {
  const Shared = window.BurnBinShared;
  let maxAttachmentBytes = 1024 * 1024; // Synced from /api/config
  let maxTextBytes = 4 * 1024 * 1024; // Synced from /api/config

  // Clean up any legacy persistent client storage or Service Worker caches from earlier releases.
  try {
    localStorage.removeItem("burnbin_sent_secrets_v1");
  } catch (_) {}
  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.getRegistrations()
      .then((regs) => Promise.all(regs.map((r) => r.unregister())))
      .catch(() => {});
  }
  if (typeof caches !== "undefined" && caches.keys) {
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k.startsWith("burnbin-shell")).map((k) => caches.delete(k))))
      .catch(() => {});
  }

  const secretText = document.getElementById("secret-text");
  const pwLengthSelect = document.getElementById("pw-length-select");
  const pwSymbolsToggle = document.getElementById("pw-symbols-toggle");
  const generateSecretBtn = document.getElementById("generate-secret-btn");
  const charCount = document.getElementById("char-count");
  const attachmentLabel = document.getElementById("attachment-label");
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
  const passphraseStrengthRow = document.getElementById("passphrase-strength-row");
  const passphraseStrengthBar = document.getElementById("passphrase-strength-bar");
  const passphraseStrengthLabel = document.getElementById("passphrase-strength-label");
  const createErrorBanner = document.getElementById("create-error-banner");
  const createErrorText = document.getElementById("create-error-text");
  const secretForm = document.getElementById("secret-form");
  const submitBtn = document.getElementById("submit-btn");
  const submitBtnText = document.getElementById("submit-btn-text");

  const createCard = document.getElementById("create-card");
  const resultCard = document.getElementById("result-card");
  const resultExpiry = document.getElementById("result-expiry");
  const secretLinkInput = document.getElementById("secret-link-input");
  const copyBtn = document.getElementById("copy-btn");
  const copyText = document.getElementById("copy-text");
  const copyNoteBtn = document.getElementById("copy-note-btn");
  const newSecretBtn = document.getElementById("new-secret-btn");

  const qrDetails = document.getElementById("qr-details");
  const qrContainer = document.getElementById("qr-container");
  const downloadQrBtn = document.getElementById("download-qr-btn");

  let lastSecretId = null;
  let lastUrlKey = null;
  let lastMaxViews = 1;
  let lastRequiredPassphrase = false;
  let selectedFile = null;

  function showCreateError(msg, focusEl = null) {
    if (createErrorText) createErrorText.textContent = msg;
    if (createErrorBanner) createErrorBanner.classList.remove("is-hidden");
    if (focusEl) {
      focusEl.setAttribute("aria-invalid", "true");
      focusEl.focus();
    }
  }

  function clearCreateError() {
    if (createErrorBanner) createErrorBanner.classList.add("is-hidden");
    if (createErrorText) createErrorText.textContent = "";
    secretText.removeAttribute("aria-invalid");
    passphraseInput.removeAttribute("aria-invalid");
  }

  function updateStrengthMeter() {
    if (!passphraseStrengthRow || !passphraseStrengthBar || !passphraseStrengthLabel) return;
    const strength = Shared.evaluatePassphraseStrength(passphraseInput.value);
    passphraseStrengthBar.className = "strength-bar";
    if (strength.score === 0) {
      passphraseStrengthRow.classList.add("is-hidden");
      passphraseStrengthLabel.textContent = "";
      return;
    }
    passphraseStrengthRow.classList.remove("is-hidden");
    passphraseStrengthBar.classList.add(`strength-${strength.level}`);
    passphraseStrengthLabel.textContent = strength.label;
  }

  function renderShareQr() {
    if (!qrContainer || !secretLinkInput.value || !window.BurnBinQR) return;
    qrContainer.replaceChildren();
    try {
      const svg = window.BurnBinQR.toSvgElement(secretLinkInput.value, 240);
      qrContainer.appendChild(svg);
    } catch (_) {
      const msg = document.createElement("span");
      msg.className = "sent-secret-meta";
      msg.textContent = "QR code unavailable for this URL length.";
      qrContainer.appendChild(msg);
    }
  }

  function updateShareLinkDisplay() {
    if (!lastSecretId || !lastUrlKey) return;
    secretLinkInput.value = `${window.location.origin}/secret/${lastSecretId}#key=${lastUrlKey}`;
    renderShareQr();
  }

  // Clear inline validation errors cleanly while typing
  secretText.addEventListener("input", () => {
    charCount.textContent = secretText.value.length.toLocaleString();
    secretText.removeAttribute("aria-invalid");
    if (createErrorBanner && !createErrorBanner.classList.contains("is-hidden")) {
      clearCreateError();
    }
  });

  if (generateSecretBtn) {
    generateSecretBtn.addEventListener("click", () => {
      clearCreateError();
      const length = pwLengthSelect ? parseInt(pwLengthSelect.value, 10) : 24;
      const includeSymbols = pwSymbolsToggle ? pwSymbolsToggle.checked : true;
      secretText.value = Shared.generateStrongPassword({ length, includeSymbols });
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
      attachmentInfo.classList.add("is-hidden");
    }
    if (clearAttachmentBtn) clearAttachmentBtn.classList.add("is-hidden");
  }

  if (attachmentInput) {
    attachmentInput.addEventListener("change", () => {
      clearCreateError();
      const file = attachmentInput.files && attachmentInput.files[0];
      if (!file) {
        clearAttachment();
        return;
      }
      if (file.size > maxAttachmentBytes) {
        showCreateError(
          `File "${file.name}" (${Shared.formatBytes(file.size)}) exceeds the ${Shared.formatBytes(maxAttachmentBytes)} attachment limit.`
        );
        clearAttachment();
        return;
      }
      selectedFile = file;
      if (attachmentInfo) {
        attachmentInfo.textContent = `Selected: ${file.name} (${Shared.formatBytes(file.size)})`;
        attachmentInfo.classList.remove("is-hidden");
      }
      if (clearAttachmentBtn) clearAttachmentBtn.classList.remove("is-hidden");
    });
  }

  if (clearAttachmentBtn) {
    clearAttachmentBtn.addEventListener("click", clearAttachment);
  }

  // Passphrase toggle, show/hide, strength meter & generate
  passphraseToggle.addEventListener("change", () => {
    clearCreateError();
    if (passphraseToggle.checked) {
      passphraseWrapper.classList.remove("is-hidden");
      passphraseInput.focus();
    } else {
      passphraseWrapper.classList.add("is-hidden");
      passphraseInput.value = "";
      passphraseInput.type = "password";
      if (togglePassphraseBtn) {
        togglePassphraseBtn.textContent = "Show";
        togglePassphraseBtn.setAttribute("aria-pressed", "false");
      }
      updateStrengthMeter();
    }
  });

  passphraseInput.addEventListener("input", () => {
    passphraseInput.removeAttribute("aria-invalid");
    if (createErrorBanner && !createErrorBanner.classList.contains("is-hidden")) {
      clearCreateError();
    }
    updateStrengthMeter();
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
      clearCreateError();
      passphraseInput.value = Shared.generateShareablePassphrase();
      passphraseInput.type = "text";
      if (togglePassphraseBtn) {
        togglePassphraseBtn.textContent = "Hide";
        togglePassphraseBtn.setAttribute("aria-pressed", "true");
      }
      updateStrengthMeter();
      passphraseInput.focus();
    });
  }

  // Form submit
  secretForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    clearCreateError();

    const plaintext = secretText.value.trim();
    if (!plaintext && !selectedFile) {
      showCreateError("Please enter a secret message or attach an encrypted file.", secretText);
      return;
    }

    const textByteLength = new TextEncoder().encode(plaintext).byteLength;
    if (textByteLength > maxTextBytes) {
      showCreateError(
        `Secret text exceeds the maximum supported size (${Shared.formatBytes(maxTextBytes)}).`,
        secretText
      );
      return;
    }

    const passphrase = passphraseToggle.checked ? passphraseInput.value.trim() : null;
    if (passphraseToggle.checked && !passphrase) {
      showCreateError(
        "Please enter a passphrase or uncheck passphrase protection.",
        passphraseInput
      );
      return;
    }

    const ttlSeconds = parseInt(ttlSelect.value, 10);
    const maxViews = parseInt(viewsSelect.value, 10);

    submitBtn.disabled = true;
    if (submitBtnText) submitBtnText.textContent = "Encrypting locally...";

    try {
      let fileObj = null;
      if (selectedFile) {
        const buffer = await selectedFile.arrayBuffer();
        fileObj = {
          name: selectedFile.name || "attachment.bin",
          mime: selectedFile.type || "application/octet-stream",
          size: buffer.byteLength,
          bytes: new Uint8Array(buffer),
        };
      }

      const payloadBytes = await SecretCrypto.encodePayload(plaintext, fileObj);
      const encrypted = await SecretCrypto.encryptBytes(payloadBytes, passphrase);

      if (submitBtnText) submitBtnText.textContent = "Saving to vault...";

      const response = await fetch("/api/secrets", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ciphertext: encrypted.ciphertext,
          iv: encrypted.iv,
          salt: encrypted.salt,
          max_views: maxViews,
          ttl_seconds: ttlSeconds,
        }),
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

      const expiresAtMs = (result.expires_at || (Math.floor(Date.now() / 1000) + ttlSeconds)) * 1000;
      if (resultExpiry) {
        resultExpiry.textContent = `Expires ${Shared.formatAbsoluteExpiry(expiresAtMs)}`;
        resultExpiry.classList.remove("is-hidden");
      }

      if (qrDetails) qrDetails.open = false;

      updateShareLinkDisplay();
      createCard.classList.add("is-hidden");
      resultCard.classList.remove("is-hidden");
      secretLinkInput.select();
    } catch (err) {
      console.error(err);
      showCreateError(`Failed to create secret: ${err.message}`);
    } finally {
      submitBtn.disabled = false;
      if (submitBtnText) submitBtnText.textContent = "Create Encrypted Secret Link";
    }
  });

  // Copy Link Only
  copyBtn.addEventListener("click", () => {
    Shared.copyTextWithFeedback(secretLinkInput.value, copyBtn, copyText, "Copy");
  });

  // Copy Link + Safety Note
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
      Shared.copyTextWithFeedback(message, copyNoteBtn, copyNoteBtn, "✉️ Copy + Note");
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
        showCreateError(`Failed to export QR PNG: ${err.message}`);
      }
    });
  }

  // Create another secret
  newSecretBtn.addEventListener("click", () => {
    lastSecretId = null;
    lastUrlKey = null;
    clearCreateError();
    secretText.value = "";
    charCount.textContent = "0";
    clearAttachment();
    passphraseInput.value = "";
    passphraseInput.type = "password";
    if (togglePassphraseBtn) {
      togglePassphraseBtn.textContent = "Show";
      togglePassphraseBtn.setAttribute("aria-pressed", "false");
    }
    updateStrengthMeter();
    passphraseToggle.checked = false;
    passphraseWrapper.classList.add("is-hidden");
    if (resultExpiry) resultExpiry.classList.add("is-hidden");
    resultCard.classList.add("is-hidden");
    createCard.classList.remove("is-hidden");
    secretText.focus();
  });

  fetch("/api/config")
    .then((r) => (r.ok ? r.json() : null))
    .then((cfg) => {
      if (!cfg || typeof cfg !== "object") return;
      if (Number.isInteger(cfg.max_attachment_bytes) && cfg.max_attachment_bytes > 0) {
        maxAttachmentBytes = cfg.max_attachment_bytes;
        if (attachmentLabel) {
          attachmentLabel.textContent = `Optional Encrypted File Attachment (Max ${Shared.formatBytes(maxAttachmentBytes)})`;
        }
      }
      if (Number.isInteger(cfg.max_text_bytes) && cfg.max_text_bytes > 0) {
        maxTextBytes = cfg.max_text_bytes;
      }
    })
    .catch(() => {});
});
