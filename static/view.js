document.addEventListener("DOMContentLoaded", async () => {
  const loadingCard = document.getElementById("loading-card");
  const errorCard = document.getElementById("error-card");
  const errorMessage = document.getElementById("error-message");
  const preRevealCard = document.getElementById("pre-reveal-card");
  const destructDetail = document.getElementById("destruct-detail");
  const passphraseContainer = document.getElementById("passphrase-container");
  const decryptPassphrase = document.getElementById("decrypt-passphrase");
  const passphraseError = document.getElementById("passphrase-error");
  const revealBtn = document.getElementById("reveal-btn");

  const revealedCard = document.getElementById("revealed-card");
  const statusStamp = document.getElementById("status-stamp");
  const destructionBanner = document.getElementById("destruction-banner");
  const destructionText = document.getElementById("destruction-text");
  const secretContent = document.getElementById("secret-content");
  const copySecretBtn = document.getElementById("copy-secret-btn");
  const copySecretText = document.getElementById("copy-secret-text");

  // Extract Secret ID from URL path: /secret/<id>
  const pathParts = window.location.pathname.split("/").filter(Boolean);
  const secretId = pathParts[1];

  // Extract decryption key from URL hash fragment: #key=<hex>
  const hashParams = new URLSearchParams(window.location.hash.substring(1));
  const urlKey = hashParams.get("key");

  function showError(msg) {
    loadingCard.style.display = "none";
    preRevealCard.style.display = "none";
    revealedCard.style.display = "none";
    errorMessage.textContent = msg;
    errorCard.style.display = "block";
  }

  if (!secretId) {
    showError("Invalid URL: Missing secret identifier.");
    return;
  }

  if (!urlKey) {
    showError(
      "Missing decryption key in the link. Make sure the entire URL (including the #key=... part) was copied correctly."
    );
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

  if (meta.requires_passphrase) {
    passphraseContainer.style.display = "block";
    decryptPassphrase.focus();
  }

  // Cached secret data once fetched from server to allow passphrase re-tries
  let cachedPayload = null;

  async function performDecryption(ciphertext, iv, salt, key, passphrase) {
    try {
      passphraseError.style.display = "none";
      const plaintext = await SecretCrypto.decrypt(ciphertext, iv, salt, key, passphrase);
      return plaintext;
    } catch (err) {
      passphraseError.textContent = err.message || "Failed to decrypt secret.";
      passphraseError.style.display = "block";
      decryptPassphrase.focus();
      return null;
    }
  }

  // 2. Reveal Secret Action
  revealBtn.addEventListener("click", async () => {
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
        urlKey,
        passphrase
      );

      if (plaintext === null) {
        // Passphrase was incorrect, let the user re-try without re-fetching
        revealBtn.disabled = false;
        revealBtn.innerHTML = `
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
          Try Passphrase Again
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

  // Copy button
  copySecretBtn.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(secretContent.textContent);
      copySecretText.textContent = "Copied!";
      copySecretBtn.style.backgroundColor = "var(--accent-primary)";
      copySecretBtn.style.color = "#06241a";
      setTimeout(() => {
        copySecretText.textContent = "Copy to Clipboard";
        copySecretBtn.style.backgroundColor = "";
        copySecretBtn.style.color = "";
      }, 2500);
    } catch (err) {
      // Fallback
      const range = document.createRange();
      range.selectNodeContents(secretContent);
      const sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
      document.execCommand("copy");
      copySecretText.textContent = "Copied!";
      setTimeout(() => {
        copySecretText.textContent = "Copy to Clipboard";
      }, 2500);
    }
  });
});
