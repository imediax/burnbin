document.addEventListener("DOMContentLoaded", () => {
  const secretText = document.getElementById("secret-text");
  const charCount = document.getElementById("char-count");
  const ttlSelect = document.getElementById("ttl-select");
  const viewsSelect = document.getElementById("views-select");
  const passphraseToggle = document.getElementById("passphrase-toggle");
  const passphraseWrapper = document.getElementById("passphrase-wrapper");
  const passphraseInput = document.getElementById("passphrase-input");
  const secretForm = document.getElementById("secret-form");
  const submitBtn = document.getElementById("submit-btn");

  const createCard = document.getElementById("create-card");
  const resultCard = document.getElementById("result-card");
  const secretLinkInput = document.getElementById("secret-link-input");
  const copyBtn = document.getElementById("copy-btn");
  const copyText = document.getElementById("copy-text");
  const newSecretBtn = document.getElementById("new-secret-btn");

  // Character counter
  secretText.addEventListener("input", () => {
    charCount.textContent = secretText.value.length.toLocaleString();
  });

  // Passphrase field toggle
  passphraseToggle.addEventListener("change", () => {
    if (passphraseToggle.checked) {
      passphraseWrapper.style.display = "block";
      passphraseInput.focus();
    } else {
      passphraseWrapper.style.display = "none";
      passphraseInput.value = "";
    }
  });

  // Form submit
  secretForm.addEventListener("submit", async (e) => {
    e.preventDefault();

    const plaintext = secretText.value.trim();
    if (!plaintext) {
      alert("Please enter a secret message.");
      return;
    }

    const passphrase = passphraseToggle.checked ? passphraseInput.value.trim() : null;
    if (passphraseToggle.checked && !passphrase) {
      alert("Please enter a passphrase or uncheck the passphrase protection.");
      return;
    }

    const ttlSeconds = parseInt(ttlSelect.value, 10);
    const maxViews = parseInt(viewsSelect.value, 10);

    submitBtn.disabled = true;
    submitBtn.innerHTML = `<span>Encrypting locally...</span>`;

    try {
      // 1. Client-Side Zero-Knowledge Encryption
      const encrypted = await SecretCrypto.encrypt(plaintext, passphrase);

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
      const secretId = result.id;

      // 3. Assemble one-time link with key exclusively in the URL hash fragment (#key=...)
      // The hash fragment is never transmitted in HTTP requests to the server
      const shareUrl = `${window.location.origin}/secret/${secretId}#key=${encrypted.urlKey}`;

      secretLinkInput.value = shareUrl;
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

  // Copy button
  copyBtn.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(secretLinkInput.value);
      copyText.textContent = "Copied!";
      copyBtn.style.backgroundColor = "var(--accent-primary)";
      copyBtn.style.color = "#06241a";
      setTimeout(() => {
        copyText.textContent = "Copy";
        copyBtn.style.backgroundColor = "";
        copyBtn.style.color = "";
      }, 2500);
    } catch (err) {
      secretLinkInput.select();
      document.execCommand("copy");
      copyText.textContent = "Copied!";
      setTimeout(() => {
        copyText.textContent = "Copy";
      }, 2500);
    }
  });

  // Create another secret
  newSecretBtn.addEventListener("click", () => {
    secretText.value = "";
    charCount.textContent = "0";
    passphraseInput.value = "";
    passphraseToggle.checked = false;
    passphraseWrapper.style.display = "none";
    resultCard.style.display = "none";
    createCard.style.display = "block";
    secretText.focus();
  });
});
