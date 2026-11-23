/**
 * Client-side Zero-Knowledge Web Crypto Utilities.
 * Uses AES-256-GCM (128-bit auth tag, 12-byte IV) and PBKDF2-HMAC-SHA256
 * (600,000 iterations for new secrets; 100,000 legacy backwards compatibility).
 */
(function (root) {
  "use strict";

  const PBKDF2_ITERATIONS_V2 = 600000;
  const PBKDF2_ITERATIONS_LEGACY = 100000;
  const BUNDLE_V1_PREFIX = "__BURNBIN_BUNDLE_V1__:";
  const BUNDLE_V2_MAGIC = [0x42, 0x42, 0x32, 0x00]; // "BB2\0"
  const FLAG_GZIP = 0x01;
  const MAX_DECOMPRESSED_BYTES = 8 * 1024 * 1024; // 8 MB zip-bomb safety ceiling
  const MAX_META_BYTES = 4 * 1024 * 1024; // 4 MB V2 metadata+text ceiling (bounded below 8 MB decompressed cap)

  function getCrypto() {
    const c = (typeof globalThis !== "undefined" && globalThis.crypto) || (root && root.crypto);
    if (!c || !c.subtle || !c.getRandomValues) {
      throw new Error("Web Crypto API unavailable in this environment.");
    }
    return c;
  }

  function concatUint8Arrays(chunks, totalLength) {
    const len = typeof totalLength === "number"
      ? totalLength
      : chunks.reduce((acc, c) => acc + c.byteLength, 0);
    const out = new Uint8Array(len);
    let offset = 0;
    for (const chunk of chunks) {
      out.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return out;
  }

  async function gzipBytes(bytes) {
    if (typeof CompressionStream !== "function") {
      return null;
    }
    try {
      const cs = new CompressionStream("gzip");
      const writer = cs.writable.getWriter();
      const writePromise = writer.write(bytes).then(() => writer.close());
      const reader = cs.readable.getReader();
      const chunks = [];
      let total = 0;
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        chunks.push(value);
        total += value.byteLength;
      }
      await writePromise;
      return concatUint8Arrays(chunks, total);
    } catch (_) {
      return null;
    }
  }

  async function gunzipBytes(bytes) {
    if (typeof DecompressionStream !== "function") {
      throw new Error("This browser cannot decompress gzipped payloads.");
    }
    const ds = new DecompressionStream("gzip");
    const writer = ds.writable.getWriter();
    const writePromise = writer.write(bytes).then(() => writer.close()).catch(() => {});
    const reader = ds.readable.getReader();
    const chunks = [];
    let total = 0;
    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > MAX_DECOMPRESSED_BYTES) {
          await reader.cancel("Payload exceeds maximum decompressed size").catch(() => {});
          throw new Error("Decrypted payload exceeds maximum safe decompressed size (8 MB).");
        }
        chunks.push(value);
      }
      await writePromise;
      return concatUint8Arrays(chunks, total);
    } finally {
      reader.releaseLock();
    }
  }

  const SecretCrypto = {
    PBKDF2_ITERATIONS_V2,
    PBKDF2_ITERATIONS_LEGACY,
    BUNDLE_V1_PREFIX,

    buf2hex(buffer) {
      return Array.from(buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
    },

    hex2buf(hexString) {
      const clean = (hexString || "").trim();
      if (!clean || clean.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(clean)) {
        throw new Error("Invalid hex string");
      }
      const bytes = new Uint8Array(clean.length / 2);
      for (let i = 0; i < clean.length; i += 2) {
        bytes[i / 2] = parseInt(clean.slice(i, i + 2), 16);
      }
      return bytes;
    },

    buf2b64(buffer) {
      const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
      const chunkSize = 8192;
      let binary = "";
      for (let i = 0; i < bytes.length; i += chunkSize) {
        binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
      }
      return btoa(binary);
    },

    b642buf(base64) {
      const binary = atob((base64 || "").trim());
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
      return bytes;
    },

    parseSalt(saltStr) {
      const clean = (saltStr || "").trim();
      if (clean.startsWith("v2$")) {
        const parts = clean.split("$");
        if (parts.length !== 3) {
          throw new Error("Corrupted passphrase salt header.");
        }
        const iterations = parseInt(parts[1], 10);
        if (!Number.isInteger(iterations) || iterations < 10000 || iterations > 2000000) {
          throw new Error("Invalid PBKDF2 iteration count in salt.");
        }
        return {
          saltBytes: this.hex2buf(parts[2]),
          iterations,
        };
      }
      return {
        saltBytes: this.hex2buf(clean),
        iterations: PBKDF2_ITERATIONS_LEGACY,
      };
    },

    async derivePassphraseKey(passphrase, saltBytes, iterations = PBKDF2_ITERATIONS_V2) {
      const c = getCrypto();
      const enc = new TextEncoder();
      const baseKey = await c.subtle.importKey(
        "raw",
        enc.encode(passphrase),
        "PBKDF2",
        false,
        ["deriveKey"]
      );

      return await c.subtle.deriveKey(
        {
          name: "PBKDF2",
          salt: saltBytes,
          iterations,
          hash: "SHA-256",
        },
        baseKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
      );
    },

    /**
     * Encrypts raw Uint8Array/ArrayBuffer bytes directly using AES-256-GCM
     * plus optional outer PBKDF2-HMAC-SHA256 (v2$600000$) layer.
     */
    async encryptBytes(plaintextBytes, passphrase = null) {
      const c = getCrypto();
      const dataBytes = plaintextBytes instanceof Uint8Array
        ? plaintextBytes
        : new Uint8Array(plaintextBytes);

      const rawMasterKey = c.getRandomValues(new Uint8Array(32));
      const masterKey = await c.subtle.importKey(
        "raw",
        rawMasterKey,
        "AES-GCM",
        false,
        ["encrypt"]
      );

      const iv1 = c.getRandomValues(new Uint8Array(12));
      let encryptedData = await c.subtle.encrypt(
        { name: "AES-GCM", iv: iv1 },
        masterKey,
        dataBytes
      );

      let saltHeader = null;
      let combinedIv = this.buf2hex(iv1);

      const trimmedPass = passphrase ? passphrase.trim() : "";
      if (trimmedPass.length > 0) {
        const saltBytes = c.getRandomValues(new Uint8Array(16));
        saltHeader = `v2$${PBKDF2_ITERATIONS_V2}$${this.buf2hex(saltBytes)}`;

        const passKey = await this.derivePassphraseKey(trimmedPass, saltBytes, PBKDF2_ITERATIONS_V2);
        const iv2 = c.getRandomValues(new Uint8Array(12));

        encryptedData = await c.subtle.encrypt(
          { name: "AES-GCM", iv: iv2 },
          passKey,
          encryptedData
        );

        combinedIv = `${this.buf2hex(iv1)}:${this.buf2hex(iv2)}`;
      }

      return {
        ciphertext: this.buf2b64(encryptedData),
        iv: combinedIv,
        salt: saltHeader,
        urlKey: this.buf2hex(rawMasterKey),
      };
    },

    /**
     * Encrypts UTF-8 string plaintext.
     */
    async encrypt(plaintext, passphrase = null) {
      const dataBytes = new TextEncoder().encode(plaintext);
      return this.encryptBytes(dataBytes, passphrase);
    },

    /**
     * Decrypts envelope to raw Uint8Array bytes.
     */
    async decryptBytes(ciphertextB64, ivCombined, saltStr, urlKeyHex, passphrase = null) {
      const c = getCrypto();
      const cleanKey = (urlKeyHex || "").trim();
      if (!/^[0-9a-fA-F]{64}$/.test(cleanKey)) {
        const keyErr = new Error("Decryption key must be exactly 64 hexadecimal characters.");
        keyErr.code = "KEY_ERROR";
        throw keyErr;
      }

      let encryptedData = this.b642buf(ciphertextB64);
      const ivParts = String(ivCombined || "").split(":");

      if (saltStr && saltStr.length > 0) {
        const trimmedPass = passphrase ? passphrase.trim() : "";
        if (!trimmedPass) {
          const passErr = new Error("This secret is protected with a passphrase.");
          passErr.code = "PASSPHRASE_ERROR";
          throw passErr;
        }
        if (ivParts.length < 2) {
          throw new Error("Corrupted initialization vector.");
        }

        const { saltBytes, iterations } = this.parseSalt(saltStr);
        const passKey = await this.derivePassphraseKey(trimmedPass, saltBytes, iterations);
        const iv2 = this.hex2buf(ivParts[1]);

        try {
          encryptedData = await c.subtle.decrypt(
            { name: "AES-GCM", iv: iv2 },
            passKey,
            encryptedData
          );
        } catch (_) {
          const passErr = new Error("Incorrect passphrase. Please try again.");
          passErr.code = "PASSPHRASE_ERROR";
          throw passErr;
        }
      }

      const iv1 = this.hex2buf(ivParts[0]);
      const masterKeyBytes = this.hex2buf(cleanKey);
      const masterKey = await c.subtle.importKey(
        "raw",
        masterKeyBytes,
        "AES-GCM",
        false,
        ["decrypt"]
      );

      try {
        const decryptedBuffer = await c.subtle.decrypt(
          { name: "AES-GCM", iv: iv1 },
          masterKey,
          encryptedData
        );
        return new Uint8Array(decryptedBuffer);
      } catch (_) {
        const keyErr = new Error("Decryption failed: Invalid or corrupted key in link.");
        keyErr.code = "KEY_ERROR";
        throw keyErr;
      }
    },

    /**
     * Decrypts envelope directly to UTF-8 string.
     */
    async decrypt(ciphertextB64, ivCombined, saltStr, urlKeyHex, passphrase = null) {
      const decryptedBytes = await this.decryptBytes(
        ciphertextB64,
        ivCombined,
        saltStr,
        urlKeyHex,
        passphrase
      );
      return new TextDecoder().decode(decryptedBytes);
    },

    /**
     * Packs text + optional binary attachment into a compact V2 binary+gzip envelope.
     * Short plain-text secrets without files remain raw UTF-8 bytes for compatibility.
     */
    async encodePayload(text, fileObj = null) {
      const enc = new TextEncoder();
      const safeText = typeof text === "string" ? text : "";
      if (!fileObj) {
        const rawTextBytes = enc.encode(safeText);
        if (rawTextBytes.byteLength < 512) {
          return rawTextBytes;
        }
      }

      const fileBytes = fileObj && fileObj.bytes
        ? (fileObj.bytes instanceof Uint8Array ? fileObj.bytes : new Uint8Array(fileObj.bytes))
        : new Uint8Array(0);
      const meta = {
        text: safeText,
        file: fileObj
          ? {
              name: fileObj.name || "attachment.bin",
              mime: fileObj.mime || "application/octet-stream",
              size: fileBytes.byteLength,
            }
          : null,
      };
      const metaBytes = enc.encode(JSON.stringify(meta));
      if (metaBytes.byteLength > MAX_META_BYTES) {
        throw new Error("Secret text exceeds the maximum supported size (4 MB).");
      }
      const inner = new Uint8Array(4 + metaBytes.byteLength + fileBytes.byteLength);
      const view = new DataView(inner.buffer, inner.byteOffset, inner.byteLength);
      view.setUint32(0, metaBytes.byteLength, false); // Big-endian uint32
      inner.set(metaBytes, 4);
      inner.set(fileBytes, 4 + metaBytes.byteLength);

      const compressed = await gzipBytes(inner);
      const useGzip = compressed !== null && compressed.byteLength < inner.byteLength;
      const body = useGzip ? compressed : inner;

      const out = new Uint8Array(5 + body.byteLength);
      out.set(BUNDLE_V2_MAGIC, 0);
      out[4] = useGzip ? FLAG_GZIP : 0x00;
      out.set(body, 5);
      return out;
    },

    /**
     * Decodes decrypted bytes (supports V2 binary+gzip, V1 JSON, and plain UTF-8 text).
     */
    async decodePayload(decryptedBytes) {
      const bytes = decryptedBytes instanceof Uint8Array
        ? decryptedBytes
        : new Uint8Array(decryptedBytes);

      const isV2 =
        bytes.byteLength >= 9 &&
        bytes[0] === BUNDLE_V2_MAGIC[0] &&
        bytes[1] === BUNDLE_V2_MAGIC[1] &&
        bytes[2] === BUNDLE_V2_MAGIC[2] &&
        bytes[3] === BUNDLE_V2_MAGIC[3];

      if (isV2) {
        const flags = bytes[4];
        const rawBody = bytes.subarray(5);
        const inner = (flags & FLAG_GZIP) !== 0 ? await gunzipBytes(rawBody) : rawBody;
        if (inner.byteLength < 4) {
          throw new Error("Corrupted V2 secret envelope.");
        }
        const view = new DataView(inner.buffer, inner.byteOffset, inner.byteLength);
        const metaLen = view.getUint32(0, false);
        if (metaLen > MAX_META_BYTES || 4 + metaLen > inner.byteLength) {
          throw new Error("Corrupted V2 metadata header.");
        }
        const metaJson = new TextDecoder().decode(inner.subarray(4, 4 + metaLen));
        const meta = JSON.parse(metaJson);
        const fileBytes = inner.subarray(4 + metaLen);
        return {
          text: typeof meta.text === "string" ? meta.text : "",
          file: meta.file
            ? {
                name: meta.file.name || "attachment.bin",
                mime: meta.file.mime || "application/octet-stream",
                size: fileBytes.byteLength,
                bytes: fileBytes,
              }
            : null,
        };
      }

      const plaintext = new TextDecoder().decode(bytes);
      if (plaintext.startsWith(BUNDLE_V1_PREFIX)) {
        try {
          const parsed = JSON.parse(plaintext.slice(BUNDLE_V1_PREFIX.length));
          if (parsed && typeof parsed === "object") {
            const text = typeof parsed.text === "string" ? parsed.text : "";
            let file = null;
            if (parsed.file && parsed.file.dataB64) {
              const rawBytes = this.b642buf(parsed.file.dataB64);
              file = {
                name: parsed.file.name || "attachment.bin",
                mime: parsed.file.mime || "application/octet-stream",
                size: rawBytes.byteLength,
                bytes: rawBytes,
              };
            }
            return { text, file };
          }
        } catch (_) {
          return { text: plaintext, file: null };
        }
      }

      return { text: plaintext, file: null };
    },
  };

  if (typeof window !== "undefined") {
    window.SecretCrypto = SecretCrypto;
  } else if (root) {
    root.SecretCrypto = SecretCrypto;
  }
  if (typeof module !== "undefined" && module.exports) {
    module.exports = SecretCrypto;
  }
})(typeof window !== "undefined" ? window : globalThis);
