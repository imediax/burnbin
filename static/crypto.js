/**
 * Client-side Zero-Knowledge Web Crypto Utilities.
 * Uses native window.crypto.subtle for AES-256-GCM encryption and PBKDF2 key derivation.
 * 
 * The encryption key is stored ONLY in the URL hash fragment (#key=...)
 * and is never transmitted over HTTP to the server.
 */

const SecretCrypto = {
    // Convert ArrayBuffer to Hex string
    buf2hex(buffer) {
        return Array.from(new Uint8Array(buffer))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    },

    // Convert Hex string to Uint8Array
    hex2buf(hexString) {
        if (!hexString || hexString.length % 2 !== 0) {
            throw new Error("Invalid hex string");
        }
        const bytes = new Uint8Array(hexString.length / 2);
        for (let i = 0; i < hexString.length; i += 2) {
            bytes[i / 2] = parseInt(hexString.substr(i, 2), 16);
        }
        return bytes;
    },

    // Convert ArrayBuffer to Base64
    buf2b64(buffer) {
        let binary = '';
        const bytes = new Uint8Array(buffer);
        const len = bytes.byteLength;
        for (let i = 0; i < len; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return window.btoa(binary);
    },

    // Convert Base64 to Uint8Array
    b642buf(base64) {
        const binary = window.atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    },

    // Derive an AES-256-GCM key from a passphrase and salt using PBKDF2
    async derivePassphraseKey(passphrase, saltBytes) {
        const enc = new TextEncoder();
        const baseKey = await window.crypto.subtle.importKey(
            "raw",
            enc.encode(passphrase),
            "PBKDF2",
            false,
            ["deriveKey"]
        );

        return await window.crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: saltBytes,
                iterations: 100000,
                hash: "SHA-256"
            },
            baseKey,
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt", "decrypt"]
        );
    },

    /**
     * Encrypts plaintext message.
     * @param {string} plaintext 
     * @param {string} [passphrase] Optional password
     * @returns {Promise<{ ciphertext: string, iv: string, salt: string|null, urlKey: string }>}
     */
    async encrypt(plaintext, passphrase = null) {
        const enc = new TextEncoder();
        const dataBytes = enc.encode(plaintext);

        // 1. Generate random 256-bit AES master key
        const rawMasterKey = window.crypto.getRandomValues(new Uint8Array(32));
        const masterKey = await window.crypto.subtle.importKey(
            "raw",
            rawMasterKey,
            "AES-GCM",
            false,
            ["encrypt"]
        );

        // 2. Encrypt plaintext with master key
        const iv1 = window.crypto.getRandomValues(new Uint8Array(12));
        let encryptedData = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv1 },
            masterKey,
            dataBytes
        );

        let saltHex = null;
        let combinedIv = this.buf2hex(iv1);

        // 3. If passphrase provided, encrypt the encryptedData again using passphrase key
        if (passphrase && passphrase.trim().length > 0) {
            const saltBytes = window.crypto.getRandomValues(new Uint8Array(16));
            saltHex = this.buf2hex(saltBytes);

            const passKey = await this.derivePassphraseKey(passphrase.trim(), saltBytes);
            const iv2 = window.crypto.getRandomValues(new Uint8Array(12));

            encryptedData = await window.crypto.subtle.encrypt(
                { name: "AES-GCM", iv: iv2 },
                passKey,
                encryptedData
            );

            // Combined IV: iv1:iv2
            combinedIv = `${this.buf2hex(iv1)}:${this.buf2hex(iv2)}`;
        }

        return {
            ciphertext: this.buf2b64(encryptedData),
            iv: combinedIv,
            salt: saltHex,
            urlKey: this.buf2hex(rawMasterKey)
        };
    },

    /**
     * Decrypts ciphertext.
     * @param {string} ciphertextB64 
     * @param {string} ivCombined 
     * @param {string|null} saltHex 
     * @param {string} urlKeyHex 
     * @param {string} [passphrase] 
     * @returns {Promise<string>}
     */
    async decrypt(ciphertextB64, ivCombined, saltHex, urlKeyHex, passphrase = null) {
        let encryptedData = this.b642buf(ciphertextB64);
        const ivParts = ivCombined.split(":");

        // If secret was encrypted with a passphrase, decrypt outer layer first
        if (saltHex && saltHex.length > 0) {
            if (!passphrase || passphrase.trim().length === 0) {
                throw new Error("This secret is protected with a passphrase.");
            }
            if (ivParts.length < 2) {
                throw new Error("Corrupted initialization vector.");
            }

            const saltBytes = this.hex2buf(saltHex);
            const passKey = await this.derivePassphraseKey(passphrase.trim(), saltBytes);
            const iv2 = this.hex2buf(ivParts[1]);

            try {
                encryptedData = await window.crypto.subtle.decrypt(
                    { name: "AES-GCM", iv: iv2 },
                    passKey,
                    encryptedData
                );
            } catch (err) {
                throw new Error("Incorrect passphrase. Please try again.");
            }
        }

        // Decrypt inner layer with the master key from the URL fragment
        const iv1 = this.hex2buf(ivParts[0]);
        const masterKeyBytes = this.hex2buf(urlKeyHex);
        const masterKey = await window.crypto.subtle.importKey(
            "raw",
            masterKeyBytes,
            "AES-GCM",
            false,
            ["decrypt"]
        );

        const decryptedBuffer = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv1 },
            masterKey,
            encryptedData
        );

        const dec = new TextDecoder();
        return dec.decode(decryptedBuffer);
    }
};
