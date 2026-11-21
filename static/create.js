document.addEventListener("DOMContentLoaded", () => {
  const Shared = window.BurnBinShared;
  const MAX_ATTACHMENT_BYTES = 1024 * 1024; // 1 MB binary attachment limit
  const SENT_STORAGE_KEY = "burnbin_sent_secrets_v1";
  const MAX_SENT_ITEMS = 25;

  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("/sw.js").catch(() => {});
  }

  const secretText = document.getElementById("secret-text");
  const pwLengthSelect = document.getElementById("pw-length-select");
  const pwSymbolsToggle = document.getElementById("pw-symbols-toggle");
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
  const passphraseStrengthRow = document.getElementById("passphrase-strength-row");
  const passphraseStrengthBar = document.getElementById("passphrase-strength-bar");
  const passphraseStrengthLabel = document.getElementById("passphrase-strength-label");
  const secretLabelInput = document.getElementById("secret-label");
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
  const formatQueryBtn = document.getElementById("format-query-btn");
  const formatHashBtn = document.getElementById("format-hash-btn");

  const qrDetails = document.getElementById("qr-details");
  const qrContainer = document.getElementById("qr-container");
  const downloadQrBtn = document.getElementById("download-qr-btn");

  const sentCount = document.getElementById("sent-count");
  const sentTrackerError = document.getElementById("sent-tracker-error");
  const sentSecretsList = document.getElementById("sent-secrets-list");

  let lastSecretId = null;
  let lastUrlKey = null;
  let lastMaxViews = 1;
  let lastRequiredPassphrase = false;
  let useQueryFormat = true;
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

  function showTrackerError(msg) {
    if (!sentTrackerError) return;
    if (msg) {
      sentTrackerError.textContent = msg;
      sentTrackerError.classList.remove("is-hidden");
    } else {
      sentTrackerError.textContent = "";
      sentTrackerError.classList.add("is-hidden");
    }
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
      // Ignore storage quota errors
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
      meta.textContent = `Created ${createdStr} • ${Shared.formatRemainingTime(item.expiresAt || 0)}${attachNote}`;

      const actions = document.createElement("div");
      actions.className = "sent-secret-actions";

      const checkBtn = document.createElement("button");
      checkBtn.type = "button";
      checkBtn.className = "btn-mini";
      checkBtn.textContent = "🔄 Check Status";
      checkBtn.addEventListener("click", async () => {
        showTrackerError("");
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
          } else if (resp.status === 404) {
            updateTrackedSecret(item.id, { status: "burned", viewsLeft: 0 });
          } else {
            const errData = await resp.json().catch(() => ({}));
            throw new Error(errData.error || `Server error (${resp.status})`);
          }
        } catch (err) {
          showTrackerError(`Could not check secret status: ${err.message}`);
          renderSentSecrets();
        }
      });

      const burnBtn = document.createElement("button");
      burnBtn.type = "button";
      burnBtn.className = "btn-mini btn-danger-mini";
      burnBtn.textContent = "🔥 Burn Now";
      burnBtn.disabled = effectiveStatus !== "active" || !item.deleteToken;
      burnBtn.addEventListener("click", async () => {
        showTrackerError("");
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
          showTrackerError(`Failed to burn secret: ${err.message}`);
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
      if (file.size > MAX_ATTACHMENT_BYTES) {
        showCreateError(
          `File "${file.name}" (${Shared.formatBytes(file.size)}) exceeds the 1 MB attachment limit.`
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
    const localLabel = secretLabelInput ? secretLabelInput.value.trim() : "";

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

      addTrackedSecret({
        id: result.id,
        label: localLabel,
        createdAt: Date.now(),
        expiresAt: expiresAtMs,
        maxViews: lastMaxViews,
        viewsLeft: lastMaxViews,
        deleteToken: result.delete_token || "",
        hasAttachment: Boolean(selectedFile),
        status: "active",
      });

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
    if (secretLabelInput) secretLabelInput.value = "";
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

  renderSentSecrets();
});
