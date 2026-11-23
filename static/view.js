document.addEventListener("DOMContentLoaded", async () => {
  const Shared = window.BurnBinShared;
  const MAX_PASSPHRASE_ATTEMPTS = 5;
  const CLIPBOARD_CLEAR_SECONDS = 45;

  const loadingCard = document.getElementById("loading-card");
  const errorCard = document.getElementById("error-card");
  const errorMessage = document.getElementById("error-message");
  const preRevealCard = document.getElementById("pre-reveal-card");
  const preRevealExpiry = document.getElementById("pre-reveal-expiry");
  const destructDetail = document.getElementById("destruct-detail");
  const passphraseContainer = document.getElementById("passphrase-container");
  const decryptPassphrase = document.getElementById("decrypt-passphrase");
  const passphraseError = document.getElementById("passphrase-error");
  const manualKeyContainer = document.getElementById("manual-key-container");
  const manualKeyInput = document.getElementById("manual-key-input");
  const keyError = document.getElementById("key-error");
  const revealBtn = document.getElementById("reveal-btn");
  const revealBtnText = document.getElementById("reveal-btn-text");

  const revealedCard = document.getElementById("revealed-card");
  const clearedCard = document.getElementById("cleared-card");
  const statusStamp = document.getElementById("status-stamp");
  const destructionText = document.getElementById("destruction-text");
  const secretContent = document.getElementById("secret-content");
  const attachmentCard = document.getElementById("attachment-card");
  const attachmentFilename = document.getElementById("attachment-filename");
  const attachmentDetails = document.getElementById("attachment-details");
  const downloadAttachmentBtn = document.getElementById("download-attachment-btn");
  const copySecretBtn = document.getElementById("copy-secret-btn");
  const copySecretText = document.getElementById("copy-secret-text");
  const clearSecretBtn = document.getElementById("clear-secret-btn");

  const clipboardStatusRow = document.getElementById("clipboard-status-row");
  const clipboardCountdown = document.getElementById("clipboard-countdown");
  const clearClipboardBtn = document.getElementById("clear-clipboard-btn");
  const clipboardAnnounce = document.getElementById("clipboard-announce");

  let activeAttachmentUrl = null;
  let cachedPayload = null;
  let failedPassphraseAttempts = 0;
  let clipboardInterval = null;
  let lastCopiedText = "";
  let lastAnnouncement = "";
  let copyFeedbackTimer = null;

  function revokeAttachmentUrl() {
    if (activeAttachmentUrl) {
      URL.revokeObjectURL(activeAttachmentUrl);
      activeAttachmentUrl = null;
    }
    if (downloadAttachmentBtn) {
      downloadAttachmentBtn.href = "#";
    }
  }

  window.addEventListener("pagehide", () => {
    revokeAttachmentUrl();
    cachedPayload = null;
  });

  // Extract Secret ID from URL path: /secret/<id>
  const pathParts = window.location.pathname.split("/").filter(Boolean);
  const secretId = pathParts[1];

  // Extract decryption key from URL hash (#key=<hex>) OR query param (?key=<hex>)
  const HEX_KEY_REGEX = /^[a-fA-F0-9]{64}$/;
  const hashParams = new URLSearchParams(window.location.hash.substring(1));
  const queryParams = new URLSearchParams(window.location.search);
  const rawUrlKey = (hashParams.get("key") || queryParams.get("key") || "").trim();
  const hasMalformedUrlKey = rawUrlKey.length > 0 && !HEX_KEY_REGEX.test(rawUrlKey);
  let urlKey = HEX_KEY_REGEX.test(rawUrlKey) ? rawUrlKey : null;

  // Strip ?key= from address bar cleanly into #key=
  if (rawUrlKey && window.location.search.includes("key=")) {
    try {
      window.history.replaceState({}, document.title, `${window.location.pathname}#key=${encodeURIComponent(rawUrlKey)}`);
    } catch (_) {}
  }

  // Android quick-open banner
  if (/android/i.test(navigator.userAgent)) {
    const androidBanner = document.getElementById("android-app-banner");
    const androidLink = document.getElementById("android-app-link");
    if (androidBanner && androidLink) {
      androidBanner.classList.remove("is-hidden");
      const keyParam = urlKey ? `?key=${urlKey}` : "";
      androidLink.href = `intent://${window.location.host}${window.location.pathname}${keyParam}#Intent;scheme=https;package=com.burnbin.app;end`;
    }
  }

  function showError(msg) {
    revokeAttachmentUrl();
    cachedPayload = null;
    loadingCard.classList.add("is-hidden");
    preRevealCard.classList.add("is-hidden");
    revealedCard.classList.add("is-hidden");
    if (clearedCard) clearedCard.classList.add("is-hidden");
    errorMessage.textContent = msg;
    errorCard.classList.remove("is-hidden");
  }

  if (!secretId) {
    showError("Invalid URL: Missing secret identifier.");
    return;
  }

  // 1. Check Secret Metadata without burning it
  let meta = null;
  try {
    const metaRes = await fetch(`/api/secrets/${encodeURIComponent(secretId)}/meta`);
    if (!metaRes.ok) {
      showError("This secret does not exist, has expired, or has already been burned.");
      return;
    }
    meta = await metaRes.json();
  } catch (_) {
    showError("Could not connect to the secret vault. Please verify your connection.");
    return;
  }

  loadingCard.classList.add("is-hidden");
  preRevealCard.classList.remove("is-hidden");

  if (preRevealExpiry && meta.expires_at) {
    const formatted = Shared.formatAbsoluteExpiry(meta.expires_at * 1000);
    if (formatted) {
      preRevealExpiry.textContent = `Expires ${formatted}`;
      preRevealExpiry.classList.remove("is-hidden");
    }
  }

  if (meta.views_left === 1) {
    destructDetail.textContent = "This is a single-use secret. It will be permanently burned from the server immediately when revealed.";
  } else {
    destructDetail.textContent = `This secret has ${meta.views_left} view(s) remaining before being permanently destroyed.`;
  }

  if (!urlKey) {
    manualKeyContainer.classList.remove("is-hidden");
    if (hasMalformedUrlKey) {
      manualKeyInput.value = rawUrlKey;
      keyError.textContent = "The decryption key in the link appears incomplete. Please verify or paste the full 64-character hex key.";
      keyError.classList.remove("is-hidden");
      manualKeyInput.setAttribute("aria-invalid", "true");
    }
    manualKeyInput.focus();
  }

  if (meta.requires_passphrase) {
    passphraseContainer.classList.remove("is-hidden");
    if (urlKey) decryptPassphrase.focus();
  }

  manualKeyInput.addEventListener("input", () => {
    keyError.classList.add("is-hidden");
    manualKeyInput.removeAttribute("aria-invalid");
  });

  decryptPassphrase.addEventListener("input", () => {
    passphraseError.classList.add("is-hidden");
    decryptPassphrase.removeAttribute("aria-invalid");
  });

  async function performDecryption(ciphertext, iv, salt, key, passphrase) {
    try {
      keyError.classList.add("is-hidden");
      passphraseError.classList.add("is-hidden");
      manualKeyInput.removeAttribute("aria-invalid");
      decryptPassphrase.removeAttribute("aria-invalid");

      const decryptedBytes = await SecretCrypto.decryptBytes(ciphertext, iv, salt, key, passphrase);
      return await SecretCrypto.decodePayload(decryptedBytes);
    } catch (err) {
      const msg = err.message || "Failed to decrypt secret.";
      if (err.code === "PASSPHRASE_ERROR") {
        failedPassphraseAttempts += 1;
        if (failedPassphraseAttempts >= MAX_PASSPHRASE_ATTEMPTS) {
          showError("Too many incorrect passphrase attempts. Encrypted payload has been wiped from browser memory.");
          return null;
        }
        passphraseError.textContent = `Incorrect passphrase (attempt ${failedPassphraseAttempts} of ${MAX_PASSPHRASE_ATTEMPTS}).`;
        passphraseError.classList.remove("is-hidden");
        decryptPassphrase.setAttribute("aria-invalid", "true");
        decryptPassphrase.focus();
      } else if (err.code === "KEY_ERROR") {
        urlKey = null;
        manualKeyContainer.classList.remove("is-hidden");
        keyError.textContent = msg;
        keyError.classList.remove("is-hidden");
        manualKeyInput.setAttribute("aria-invalid", "true");
        manualKeyInput.focus();
      } else {
        showError(msg);
      }
      return null;
    }
  }

  // 2. Reveal Secret Action
  revealBtn.addEventListener("click", async () => {
    let effectiveKey = urlKey;
    if (!effectiveKey) {
      const rawInput = manualKeyInput.value.trim();
      const hexMatch = rawInput.match(/([a-fA-F0-9]{64})/);
      effectiveKey = hexMatch ? hexMatch[1] : rawInput;

      if (!effectiveKey || !HEX_KEY_REGEX.test(effectiveKey)) {
        keyError.textContent = "Please enter a valid 64-character hexadecimal decryption key.";
        keyError.classList.remove("is-hidden");
        manualKeyInput.setAttribute("aria-invalid", "true");
        manualKeyInput.focus();
        return;
      }
    }

    const passphrase = meta.requires_passphrase ? decryptPassphrase.value.trim() : null;
    if (meta.requires_passphrase && !passphrase) {
      passphraseError.textContent = "Please enter the passphrase to unlock this secret.";
      passphraseError.classList.remove("is-hidden");
      decryptPassphrase.setAttribute("aria-invalid", "true");
      decryptPassphrase.focus();
      return;
    }

    revealBtn.disabled = true;
    if (revealBtnText) revealBtnText.textContent = "Retrieving & Decrypting...";

    try {
      if (!cachedPayload) {
        const response = await fetch(`/api/secrets/${encodeURIComponent(secretId)}/consume`, {
          method: "POST",
        });
        if (!response.ok) {
          showError("This secret could not be retrieved. It may have just been burned or expired.");
          return;
        }
        cachedPayload = await response.json();
      }

      const decoded = await performDecryption(
        cachedPayload.ciphertext,
        cachedPayload.iv,
        cachedPayload.salt,
        effectiveKey,
        passphrase
      );

      if (decoded === null) {
        if (!errorCard.classList.contains("is-hidden")) return;
        revealBtn.disabled = false;
        if (revealBtnText) revealBtnText.textContent = "Try Decrypting Again";
        return;
      }

      revokeAttachmentUrl();

      const displayText = decoded.text || "";
      const attachedFile = decoded.file;

      preRevealCard.classList.add("is-hidden");
      secretContent.textContent = displayText;
      secretContent.classList.toggle("is-hidden", !displayText);
      if (copySecretBtn) {
        copySecretBtn.classList.toggle("is-hidden", !displayText);
      }

      if (attachmentCard && attachedFile) {
        const safeMime = (attachedFile.mime || "application/octet-stream").trim() || "application/octet-stream";
        const blob = new Blob([attachedFile.bytes], { type: safeMime });
        activeAttachmentUrl = URL.createObjectURL(blob);

        const safeName = (attachedFile.name || "attachment.bin").replace(/[\\/]/g, "_");
        attachmentFilename.textContent = safeName;
        attachmentDetails.textContent = `${safeMime} • ${Shared.formatBytes(attachedFile.bytes.byteLength)}`;
        downloadAttachmentBtn.href = activeAttachmentUrl;
        downloadAttachmentBtn.download = safeName;
        attachmentCard.classList.remove("is-hidden");
      } else if (attachmentCard) {
        attachmentCard.classList.add("is-hidden");
      }

      if (cachedPayload.burned) {
        statusStamp.textContent = "🔥 DESTROYED";
        statusStamp.classList.remove("is-remaining");
        destructionText.textContent = "This secret has been burned and completely purged from the server database.";
      } else {
        statusStamp.textContent = `👁️ ${cachedPayload.views_left} VIEW(S) LEFT`;
        statusStamp.classList.add("is-remaining");
        destructionText.textContent = `This secret can still be viewed ${cachedPayload.views_left} more time(s) before burning.`;
      }

      revealedCard.classList.remove("is-hidden");
    } catch (err) {
      console.error(err);
      showError(`Error: ${err.message}`);
    }
  });

  function announceClipboardStatus(msg) {
    if (!clipboardAnnounce) return;
    let output = msg;
    if (output === lastAnnouncement) output += "\u00A0";
    lastAnnouncement = msg;
    clipboardAnnounce.textContent = output;
  }

  function stopClipboardTimer() {
    if (clipboardInterval !== null) {
      clearInterval(clipboardInterval);
      clipboardInterval = null;
    }
  }

  async function clearClipboardNow(isAuto = false) {
    stopClipboardTimer();
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText("");
      }
      if (clipboardCountdown) {
        clipboardCountdown.textContent = isAuto
          ? "🔒 Clipboard automatically cleared after 45s."
          : "✓ Clipboard cleared.";
      }
      if (clearClipboardBtn) clearClipboardBtn.classList.add("is-hidden");
      announceClipboardStatus("Clipboard cleared.");
      lastCopiedText = "";
    } catch (_) {
      if (clipboardCountdown) {
        clipboardCountdown.textContent =
          "Auto-clear requires browser tab focus — click Clear Clipboard Now to wipe it.";
      }
      if (clearClipboardBtn) clearClipboardBtn.classList.remove("is-hidden");
      announceClipboardStatus("Clipboard auto-clear requires tab focus.");
    }
  }

  function startClipboardCountdown(copiedText) {
    stopClipboardTimer();
    lastCopiedText = copiedText;
    let remaining = CLIPBOARD_CLEAR_SECONDS;
    if (clipboardStatusRow) clipboardStatusRow.classList.remove("is-hidden");
    if (clearClipboardBtn) clearClipboardBtn.classList.remove("is-hidden");
    if (clipboardCountdown) {
      clipboardCountdown.textContent = `🔒 Copied! Auto-clearing clipboard in ${remaining}s…`;
    }
    announceClipboardStatus(`Copied. Auto-clearing clipboard in ${CLIPBOARD_CLEAR_SECONDS} seconds.`);

    clipboardInterval = setInterval(() => {
      remaining -= 1;
      if (remaining <= 0) {
        clearClipboardNow(true);
      } else if (clipboardCountdown) {
        clipboardCountdown.textContent = `🔒 Auto-clearing clipboard in ${remaining}s…`;
      }
    }, 1000);
  }

  if (clearClipboardBtn) {
    clearClipboardBtn.addEventListener("click", () => {
      clearClipboardNow(false);
    });
  }

  copySecretBtn.addEventListener("click", async () => {
    const text = secretContent.textContent;
    if (!text) return;
    let copied = false;
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
        copied = true;
      } else {
        copied = Shared.legacyCopy(text);
      }
    } catch (_) {
      copied = Shared.legacyCopy(text);
    }

    clearTimeout(copyFeedbackTimer);
    if (copied) {
      copySecretText.textContent = "Copied!";
      copySecretBtn.classList.add("is-copied");
      startClipboardCountdown(text);
      copyFeedbackTimer = setTimeout(() => {
        copySecretText.textContent = "Copy to Clipboard";
        copySecretBtn.classList.remove("is-copied");
      }, 2500);
    } else {
      copySecretText.textContent = "Copy Failed";
      announceClipboardStatus("Copy failed.");
      copyFeedbackTimer = setTimeout(() => {
        copySecretText.textContent = "Copy to Clipboard";
      }, 2500);
    }
  });

  if (clearSecretBtn) {
    clearSecretBtn.addEventListener("click", () => {
      if (lastCopiedText && clipboardInterval !== null) {
        clearClipboardNow(false);
      } else {
        stopClipboardTimer();
      }
      cachedPayload = null;
      revokeAttachmentUrl();
      if (attachmentCard) attachmentCard.classList.add("is-hidden");
      secretContent.textContent = "";
      secretContent.classList.remove("is-hidden");
      if (copySecretBtn) copySecretBtn.classList.remove("is-hidden");
      decryptPassphrase.value = "";
      manualKeyInput.value = "";
      revealedCard.classList.add("is-hidden");
      preRevealCard.classList.add("is-hidden");
      if (clearedCard) {
        clearedCard.classList.remove("is-hidden");
      } else {
        showError("Secret cleared from view.");
      }
    });
  }
});
