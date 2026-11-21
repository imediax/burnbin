(function (root) {
  "use strict";

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

  const copyFeedbackTimers = new WeakMap();

  function getCrypto() {
    const c = (typeof globalThis !== "undefined" && globalThis.crypto) || (root && root.crypto);
    if (!c || !c.getRandomValues) {
      throw new Error("Cryptographic RNG unavailable.");
    }
    return c;
  }

  function randomInt(maxExclusive) {
    const cryptoApi = getCrypto();
    const buf = new Uint32Array(1);
    const limit = Math.floor(0x100000000 / maxExclusive) * maxExclusive;
    while (true) {
      cryptoApi.getRandomValues(buf);
      if (buf[0] < limit) {
        return buf[0] % maxExclusive;
      }
    }
  }

  function generateStrongPassword(options = 24) {
    const opts = typeof options === "number" ? { length: options, includeSymbols: true } : (options || {});
    const length = Math.max(12, Math.min(64, parseInt(opts.length, 10) || 24));
    const includeSymbols = opts.includeSymbols !== false;

    const upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
    const lower = "abcdefghijkmnopqrstuvwxyz";
    const digits = "23456789";
    const symbols = "!@#$%^&*()-_=+[]{}";
    const all = upper + lower + digits + (includeSymbols ? symbols : "");

    const chars = [
      upper[randomInt(upper.length)],
      lower[randomInt(lower.length)],
      digits[randomInt(digits.length)],
    ];
    if (includeSymbols) {
      chars.push(symbols[randomInt(symbols.length)]);
    }
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
    picked.push(String(10 + randomInt(90)));
    return picked.join("-");
  }

  function evaluatePassphraseStrength(passphrase) {
    const value = (passphrase || "").trim();
    if (!value) {
      return { score: 0, label: "", level: "none" };
    }
    let pool = 0;
    if (/[a-z]/.test(value)) pool += 26;
    if (/[A-Z]/.test(value)) pool += 26;
    if (/[0-9]/.test(value)) pool += 10;
    if (/[^A-Za-z0-9]/.test(value)) pool += 32;
    const entropy = pool > 0 ? value.length * Math.log2(pool) : 0;

    if (value.length < 8 || entropy < 42) {
      return { score: 1, label: "Weak", level: "weak" };
    }
    if (entropy < 64) {
      return { score: 2, label: "Fair", level: "fair" };
    }
    if (entropy < 88) {
      return { score: 3, label: "Good", level: "good" };
    }
    return { score: 4, label: "Strong", level: "strong" };
  }

  function formatBytes(bytes) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  }

  function formatRemainingTime(expiresAtMs) {
    const diffSec = Math.floor((expiresAtMs - Date.now()) / 1000);
    if (diffSec <= 0) return "Expired";
    if (diffSec < 60) return `${diffSec}s left`;
    if (diffSec < 3600) return `${Math.ceil(diffSec / 60)}m left`;
    if (diffSec < 86400) return `${Math.ceil(diffSec / 3600)}h left`;
    return `${Math.ceil(diffSec / 86400)}d left`;
  }

  function formatAbsoluteExpiry(expiresAtMs) {
    if (!expiresAtMs || expiresAtMs <= 0) return "";
    try {
      return new Intl.DateTimeFormat(undefined, {
        dateStyle: "medium",
        timeStyle: "short",
      }).format(new Date(expiresAtMs));
    } catch (_) {
      return new Date(expiresAtMs).toLocaleString();
    }
  }

  function legacyCopy(text) {
    if (typeof document === "undefined") return false;
    const field = Object.assign(document.createElement("textarea"), { value: text });
    field.setAttribute("readonly", "");
    field.className = "offscreen-copy-buffer";
    document.body.append(field);
    field.select();
    try {
      return document.execCommand("copy");
    } catch (_) {
      return false;
    } finally {
      field.remove();
    }
  }

  async function copyTextWithFeedback(textToCopy, buttonEl, labelEl, originalLabel) {
    if (!textToCopy) return false;
    let copied = false;
    try {
      if (typeof navigator !== "undefined" && navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(textToCopy);
        copied = true;
      }
    } catch (_) {
      copied = false;
    }

    if (!copied) {
      copied = legacyCopy(textToCopy);
    }

    if (buttonEl && labelEl) {
      clearTimeout(copyFeedbackTimers.get(buttonEl));
      if (copied) {
        labelEl.textContent = "Copied!";
        buttonEl.classList.add("is-copied");
        const timerId = setTimeout(() => {
          labelEl.textContent = originalLabel;
          buttonEl.classList.remove("is-copied");
        }, 2500);
        copyFeedbackTimers.set(buttonEl, timerId);
      } else {
        labelEl.textContent = "Copy Failed";
        const timerId = setTimeout(() => {
          labelEl.textContent = originalLabel;
        }, 2500);
        copyFeedbackTimers.set(buttonEl, timerId);
      }
    }
    return copied;
  }

  const BurnBinShared = {
    randomInt,
    generateStrongPassword,
    generateShareablePassphrase,
    evaluatePassphraseStrength,
    formatBytes,
    formatRemainingTime,
    formatAbsoluteExpiry,
    legacyCopy,
    copyTextWithFeedback,
  };

  if (root) {
    root.BurnBinShared = BurnBinShared;
  }
  if (typeof module !== "undefined" && module.exports) {
    module.exports = BurnBinShared;
  }
})(typeof window !== "undefined" ? window : globalThis);
