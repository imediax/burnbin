document.addEventListener("DOMContentLoaded", async () => {
  const loadingCard = document.getElementById("loading-card");
  const errorCard = document.getElementById("error-card");
  const errorMessage = document.getElementById("error-message");
  const preRevealCard = document.getElementById("pre-reveal-card");
  const destructDetail = document.getElementById("destruct-detail");
  const passphraseContainer = document.getElementById("passphrase-container");
  const decryptPassphrase = document.getElementById("decrypt-passphrase");
  const passphraseError = document.getElementById("passphrase-error");
  const manualKeyContainer = document.getElementById("manual-key-container");
  const manualKeyInput = document.getElementById("manual-key-input");
  const keyError = document.getElementById("key-error");
  const revealBtn = document.getElementById("reveal-btn");

  const revealedCard = document.getElementById("revealed-card");
  const clearedCard = document.getElementById("cleared-card");
  const statusStamp = document.getElementById("status-stamp");
  const destructionBanner = document.getElementById("destruction-banner");
  const destructionText = document.getElementById("destruction-text");
  const secretContent = document.getElementById("secret-content");
  const copySecretBtn = document.getElementById("copy-secret-btn");
  const copySecretText = document.getElementById("copy-secret-text");

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

  // If key came from query parameter, replaceState with hash to keep clean URL bar
  if (rawUrlKey && window.location.search.includes("key=")) {
    try {
      window.history.replaceState({}, document.title, window.location.pathname + "#key=" + encodeURIComponent(rawUrlKey));
    } catch (_) {}
  }

  // Detect Android device and offer direct app launch via intent URI
  if (/android/i.test(navigator.userAgent)) {
    const androidBanner = document.getElementById("android-app-banner");
    const androidLink = document.getElementById("android-app-link");
    if (androidBanner && androidLink) {
      androidBanner.style.display = "block";
      const keyParam = urlKey ? `?key=${urlKey}` : "";
      const intentUri = `intent://${window.location.host}${window.location.pathname}${keyParam}#Intent;scheme=https;package=com.burnbin.app;end`;
      androidLink.href = intentUri;
    }
  }

  function showError(msg) {
    loadingCard.style.display = "none";
    preRevealCard.style.display = "none";
    revealedCard.style.display = "none";
    if (clearedCard) clearedCard.style.display = "none";
    errorMessage.textContent = msg;
    errorCard.style.display = "block";
  }

  if (!secretId) {
    showError("Invalid URL: Missing secret identifier.");
    return;
  }

  // 1. Check Secret Metadata without burning it
  let meta = null;
  try {
    const metaRes = await fetch(`/api/secrets/${secretId}/meta`);
    if (!metaRes.ok) {
      showError("This secret does not exist, has expired, or has already been burned.");
      return;
    }
    meta = await metaRes.json();
  } catch (err) {
    showError("Could not connect to the secret vault. Please verify your connection.");
    return;
  }

  // Render pre-reveal card
  loadingCard.style.display = "none";
  preRevealCard.style.display = "block";

  if (meta.views_left === 1) {
    destructDetail.textContent = "This is a single-use secret. It will be permanently burned from the server immediately when revealed.";
  } else {
    destructDetail.textContent = `This secret has ${meta.views_left} view(s) remaining before being permanently destroyed.`;
  }

  // If key was not in the URL (or was malformed/truncated), prompt for it
  if (!urlKey) {
    manualKeyContainer.style.display = "block";
    if (hasMalformedUrlKey) {
      manualKeyInput.value = rawUrlKey;
      keyError.textContent = "The decryption key in the link appears incomplete. Please verify or paste the full 64-character hex key.";
      keyError.style.display = "block";
    }
    manualKeyInput.focus();
  }

  if (meta.requires_passphrase) {
    passphraseContainer.style.display = "block";
    if (urlKey) {
      decryptPassphrase.focus();
    }
  }

  manualKeyInput.addEventListener("input", () => {
    keyError.style.display = "none";
  });

  decryptPassphrase.addEventListener("input", () => {
    passphraseError.style.display = "none";
  });

  // Cached secret data once fetched from server to allow key/passphrase re-tries
  let cachedPayload = null;

  async function performDecryption(ciphertext, iv, salt, key, passphrase) {
    try {
      keyError.style.display = "none";
      passphraseError.style.display = "none";
      const plaintext = await SecretCrypto.decrypt(ciphertext, iv, salt, key, passphrase);
      return plaintext;
    } catch (err) {
      const msg = err.message || "Failed to decrypt secret.";
      if (err.code === "KEY_ERROR" || !meta.requires_passphrase) {
        urlKey = null; // Allow user to enter corrected key on retry
        manualKeyContainer.style.display = "block";
        keyError.textContent = msg;
        keyError.style.display = "block";
        manualKeyInput.focus();
      } else {
        passphraseError.textContent = msg;
        passphraseError.style.display = "block";
        decryptPassphrase.focus();
      }
      return null;
    }
  }

  // 2. Reveal Secret Action
  revealBtn.addEventListener("click", async () => {
    // Check key
    let effectiveKey = urlKey;
    if (!effectiveKey) {
      const rawInput = manualKeyInput.value.trim();
      const hexMatch = rawInput.match(/([a-fA-F0-9]{64})/);
      effectiveKey = hexMatch ? hexMatch[1] : rawInput;

      if (!effectiveKey || !HEX_KEY_REGEX.test(effectiveKey)) {
        keyError.textContent = "Please enter a valid 64-character hexadecimal decryption key.";
        keyError.style.display = "block";
        manualKeyInput.focus();
        return;
      } else {
        keyError.style.display = "none";
      }
    }

    const passphrase = meta.requires_passphrase ? decryptPassphrase.value.trim() : null;

    if (meta.requires_passphrase && !passphrase) {
      passphraseError.textContent = "Please enter the passphrase to unlock this secret.";
      passphraseError.style.display = "block";
      decryptPassphrase.focus();
      return;
    }

    revealBtn.disabled = true;
    revealBtn.innerHTML = `<span>Retrieving & Decrypting...</span>`;

    try {
      // If we haven't fetched from server yet, consume the view
      if (!cachedPayload) {
        const response = await fetch(`/api/secrets/${secretId}`);
        if (!response.ok) {
          showError("This secret could not be retrieved. It may have just been burned or expired.");
          return;
        }
        cachedPayload = await response.json();
      }

      // Decrypt client-side
      const plaintext = await performDecryption(
        cachedPayload.ciphertext,
        cachedPayload.iv,
        cachedPayload.salt,
        effectiveKey,
        passphrase
      );

      if (plaintext === null) {
        // Key or passphrase was incorrect, let the user re-try without re-fetching
        revealBtn.disabled = false;
        revealBtn.innerHTML = `
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
          Try Decrypting Again
        `;
        return;
      }

      // Display decrypted content
      preRevealCard.style.display = "none";
      secretContent.textContent = plaintext;

      if (cachedPayload.burned) {
        statusStamp.textContent = "🔥 DESTROYED";
        statusStamp.style.color = "var(--danger-primary)";
        destructionText.textContent = "This secret has been burned and completely purged from the server database.";
      } else {
        statusStamp.textContent = `👁️ ${cachedPayload.views_left} VIEW(S) LEFT`;
        statusStamp.style.color = "var(--warning-primary)";
        statusStamp.style.borderColor = "var(--warning-primary)";
        destructionText.textContent = `This secret can still be viewed ${cachedPayload.views_left} more time(s) before burning.`;
      }

      revealedCard.style.display = "block";

    } catch (err) {
      console.error(err);
      showError(`Error: ${err.message}`);
    }
  });

  // Copy button & Auto-Clear Clipboard Timer (45s)
  const clipboardStatusRow = document.getElementById("clipboard-status-row");
  const clipboardCountdown = document.getElementById("clipboard-countdown");
  const clearClipboardBtn = document.getElementById("clear-clipboard-btn");
  const clipboardAnnounce = document.getElementById("clipboard-announce");
  const CLIPBOARD_CLEAR_SECONDS = 45;
  let clipboardInterval = null;
  let lastCopiedText = "";
  let lastAnnouncement = "";

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
      if (clearClipboardBtn) clearClipboardBtn.style.display = "none";
      announceClipboardStatus("Clipboard cleared.");
      lastCopiedText = "";
    } catch (_) {
      if (clipboardCountdown) {
        clipboardCountdown.textContent =
          "Auto-clear requires browser tab focus — click Clear Clipboard Now to wipe it.";
      }
      if (clearClipboardBtn) clearClipboardBtn.style.display = "inline-flex";
      announceClipboardStatus("Clipboard auto-clear requires tab focus.");
    }
  }

  function startClipboardCountdown(copiedText) {
    stopClipboardTimer();
    lastCopiedText = copiedText;
    let remaining = CLIPBOARD_CLEAR_SECONDS;
    if (clipboardStatusRow) clipboardStatusRow.style.display = "flex";
    if (clearClipboardBtn) clearClipboardBtn.style.display = "inline-flex";
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

  function legacyCopy(text) {
    const field = Object.assign(document.createElement("textarea"), { value: text });
    field.setAttribute("readonly", "");
    field.style.cssText = "position:fixed;inset-block-start:0;opacity:0";
    document.body.append(field);
    field.select();
    try {
      return document.execCommand("copy");
    } finally {
      field.remove();
    }
  }

  if (clearClipboardBtn) {
    clearClipboardBtn.addEventListener("click", () => {
      clearClipboardNow(false);
    });
  }

  let copyFeedbackTimer = null;
  copySecretBtn.addEventListener("click", async () => {
    const text = secretContent.textContent;
    if (!text) return;
    let copied = false;
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
        copied = true;
      } else {
        copied = legacyCopy(text);
      }
    } catch (_) {
      copied = legacyCopy(text);
    }

    clearTimeout(copyFeedbackTimer);
    if (copied) {
      copySecretText.textContent = "Copied!";
      copySecretBtn.style.backgroundColor = "var(--accent-primary)";
      copySecretBtn.style.color = "#06241a";
      startClipboardCountdown(text);
      copyFeedbackTimer = setTimeout(() => {
        copySecretText.textContent = "Copy to Clipboard";
        copySecretBtn.style.backgroundColor = "";
        copySecretBtn.style.color = "";
      }, 2500);
    } else {
      copySecretText.textContent = "Copy Failed";
      announceClipboardStatus("Copy failed.");
      copyFeedbackTimer = setTimeout(() => {
        copySecretText.textContent = "Copy to Clipboard";
      }, 2500);
    }
  });

  // Clear button
  const clearSecretBtn = document.getElementById('clear-secret-btn');
  if (clearSecretBtn) {
    clearSecretBtn.addEventListener('click', () => {
      if (lastCopiedText && clipboardInterval !== null) {
        clearClipboardNow(false);
      } else {
        stopClipboardTimer();
      }
      cachedPayload = null;
      secretContent.textContent = '';
      decryptPassphrase.value = '';
      manualKeyInput.value = '';
      revealedCard.style.display = 'none';
      preRevealCard.style.display = 'none';
      if (clearedCard) {
        clearedCard.style.display = 'block';
      } else {
        showError('Secret cleared from view.');
      }
    });
  }
});
