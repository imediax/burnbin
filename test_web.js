const assert = require("assert");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const SecretCrypto = require("./static/crypto.js");
const BurnBinShared = require("./static/shared.js");
const BurnBinQR = require("./static/qr.js");

async function runTests() {
  console.log("Running BurnBin Web JS tests...");

  // 1. Plain UTF-8 encrypt/decrypt (no passphrase)
  const plainMsg = "sk_live_51Msz9876543210_super_secret 🔥";
  const enc1 = await SecretCrypto.encrypt(plainMsg);
  assert.strictEqual(enc1.salt, null);
  assert.strictEqual(enc1.urlKey.length, 64);
  const dec1 = await SecretCrypto.decrypt(enc1.ciphertext, enc1.iv, enc1.salt, enc1.urlKey);
  assert.strictEqual(dec1, plainMsg);
  console.log("  [ok] plain text round-trip");

  // 2. Hardened PBKDF2 v2$600000$ round-trip & wrong passphrase error code
  const encPass = await SecretCrypto.encrypt("top-secret-with-pass", "hunter2-anchor-cloud");
  assert.ok(encPass.salt && encPass.salt.startsWith("v2$600000$"), `Expected v2 salt header, got: ${encPass.salt}`);
  const decPass = await SecretCrypto.decrypt(
    encPass.ciphertext,
    encPass.iv,
    encPass.salt,
    encPass.urlKey,
    "hunter2-anchor-cloud"
  );
  assert.strictEqual(decPass, "top-secret-with-pass");

  let caughtPassErr = null;
  try {
    await SecretCrypto.decrypt(encPass.ciphertext, encPass.iv, encPass.salt, encPass.urlKey, "wrong-pass");
  } catch (err) {
    caughtPassErr = err;
  }
  assert.ok(caughtPassErr && caughtPassErr.code === "PASSPHRASE_ERROR");
  console.log("  [ok] PBKDF2 v2$600000$ round-trip & PASSPHRASE_ERROR");

  // 3. Legacy 100,000-iteration salt format backwards compatibility
  const rawSalt = crypto.randomBytes(16);
  const legacySaltHex = SecretCrypto.buf2hex(rawSalt);
  const { saltBytes, iterations } = SecretCrypto.parseSalt(legacySaltHex);
  assert.strictEqual(iterations, 100000);
  assert.strictEqual(saltBytes.length, 16);
  const legacyKey = await SecretCrypto.derivePassphraseKey("legacy-pass", saltBytes, iterations);
  const iv1 = crypto.randomBytes(12);
  const iv2 = crypto.randomBytes(12);
  const rawMasterKey = crypto.randomBytes(32);
  const masterKey = await globalThis.crypto.subtle.importKey("raw", rawMasterKey, "AES-GCM", false, ["encrypt"]);
  const innerCt = await globalThis.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv1 },
    masterKey,
    new TextEncoder().encode("legacy-secret")
  );
  const outerCt = await globalThis.crypto.subtle.encrypt({ name: "AES-GCM", iv: iv2 }, legacyKey, innerCt);
  const legacyDecrypted = await SecretCrypto.decrypt(
    SecretCrypto.buf2b64(outerCt),
    `${SecretCrypto.buf2hex(iv1)}:${SecretCrypto.buf2hex(iv2)}`,
    legacySaltHex,
    SecretCrypto.buf2hex(rawMasterKey),
    "legacy-pass"
  );
  assert.strictEqual(legacyDecrypted, "legacy-secret");
  console.log("  [ok] legacy 100,000-iteration PBKDF2 compatibility");

  // 4. V1 bundle decoding backwards compatibility
  const rawV1File = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x00, 0x42]);
  const v1Envelope = "__BURNBIN_BUNDLE_V1__:" + JSON.stringify({
    text: "V1 note",
    file: {
      name: "legacy.bin",
      mime: "application/octet-stream",
      size: rawV1File.byteLength,
      dataB64: SecretCrypto.buf2b64(rawV1File),
    },
  });
  const decV1 = await SecretCrypto.decodePayload(new TextEncoder().encode(v1Envelope));
  assert.strictEqual(decV1.text, "V1 note");
  assert.strictEqual(decV1.file.name, "legacy.bin");
  assert.deepStrictEqual(Array.from(decV1.file.bytes), Array.from(rawV1File));
  console.log("  [ok] V1 bundle decode compatibility");

  // 5. V2 binary+gzip envelope round-trip + compression ratio verification
  const compressibleData = new TextEncoder().encode("config_entry=value_12345\n".repeat(120));
  const encodedV2 = await SecretCrypto.encodePayload("Check attached config", {
    name: "app-config.txt",
    mime: "text/plain",
    size: compressibleData.byteLength,
    bytes: compressibleData,
  });
  assert.strictEqual(encodedV2[0], 0x42);
  assert.strictEqual(encodedV2[1], 0x42);
  assert.strictEqual(encodedV2[2], 0x32);
  assert.strictEqual(encodedV2[3], 0x00);
  assert.strictEqual(encodedV2[4], 0x01, "Compressible payload should use GZIP flag 0x01");
  assert.ok(encodedV2.byteLength < compressibleData.byteLength / 4, "Gzip should substantially shrink repetitive text");

  const encV2 = await SecretCrypto.encryptBytes(encodedV2, "bridge-pass-42");
  const decBytes = await SecretCrypto.decryptBytes(encV2.ciphertext, encV2.iv, encV2.salt, encV2.urlKey, "bridge-pass-42");
  const decV2 = await SecretCrypto.decodePayload(decBytes);
  assert.strictEqual(decV2.text, "Check attached config");
  assert.strictEqual(decV2.file.name, "app-config.txt");
  assert.strictEqual(decV2.file.mime, "text/plain");
  assert.deepStrictEqual(Array.from(decV2.file.bytes), Array.from(compressibleData));
  console.log(`  [ok] V2 binary+gzip round-trip (${compressibleData.byteLength}B -> ${encodedV2.byteLength}B)`);

  // 5b. Large text (> 64 KB) V2 round-trip and > 4 MB metadata guard
  const largeText = "secret_line_0123456789_abcdef\n".repeat(3500); // ~105 KB
  assert.ok(largeText.length > 65536);
  const encodedLarge = await SecretCrypto.encodePayload(largeText, null);
  const encLarge = await SecretCrypto.encryptBytes(encodedLarge, null);
  const decLargeBytes = await SecretCrypto.decryptBytes(encLarge.ciphertext, encLarge.iv, encLarge.salt, encLarge.urlKey, null);
  const decLarge = await SecretCrypto.decodePayload(decLargeBytes);
  assert.strictEqual(decLarge.text, largeText);
  assert.strictEqual(decLarge.file, null);

  let oversizedErr = null;
  try {
    await SecretCrypto.encodePayload("a".repeat(4 * 1024 * 1024 + 1024), null);
  } catch (err) {
    oversizedErr = err;
  }
  assert.ok(oversizedErr && /maximum supported size/i.test(oversizedErr.message));
  console.log(`  [ok] Large text (>64 KB) V2 round-trip (${largeText.length}B -> ${encodedLarge.byteLength}B) & 4 MB guard`);

  // 6. BurnBinShared generators & strength evaluator
  const pw16NoSym = BurnBinShared.generateStrongPassword({ length: 16, includeSymbols: false });
  assert.strictEqual(pw16NoSym.length, 16);
  assert.ok(/^[A-Za-z0-9]+$/.test(pw16NoSym));
  const pw32Sym = BurnBinShared.generateStrongPassword({ length: 32, includeSymbols: true });
  assert.strictEqual(pw32Sym.length, 32);
  const phrase = BurnBinShared.generateShareablePassphrase();
  assert.strictEqual(phrase.split("-").length, 5);

  assert.strictEqual(BurnBinShared.evaluatePassphraseStrength("").score, 0);
  assert.strictEqual(BurnBinShared.evaluatePassphraseStrength("abc").level, "weak");
  assert.strictEqual(BurnBinShared.evaluatePassphraseStrength(phrase).level, "strong");
  console.log("  [ok] BurnBinShared generators & passphrase strength evaluator");

  // 7. BurnBinQR matrix generation for #key= URLs and hardened static UI checks
  const qrUrl = `https://burnbin.cloud.run/secret/AbCdEf1234567890#key=${"a".repeat(64)}`;
  const qrMatrix = BurnBinQR.createMatrix(qrUrl);
  assert.ok(qrMatrix.size >= 21 && qrMatrix.grid.length === qrMatrix.size);

  const staticDir = path.join(__dirname, "static");
  const indexHtml = fs.readFileSync(path.join(staticDir, "index.html"), "utf8");
  const viewHtml = fs.readFileSync(path.join(staticDir, "view.html"), "utf8");
  const createJs = fs.readFileSync(path.join(staticDir, "create.js"), "utf8");
  const viewJs = fs.readFileSync(path.join(staticDir, "view.js"), "utf8");

  assert.strictEqual(fs.existsSync(path.join(staticDir, "sw.js")), false, "sw.js must be removed");
  assert.ok(!indexHtml.includes("format-query-btn"), "index.html must not offer ?key= format button");
  assert.ok(!indexHtml.includes("sent-secrets-panel"), "index.html must not include Sent Secrets tracker");
  assert.ok(!createJs.includes("serviceWorker.register"), "create.js must not register sw.js");
  assert.ok(!createJs.includes("localStorage.setItem"), "create.js must not persist to localStorage");
  assert.ok(!createJs.includes("?key="), "create.js must not generate ?key= links");
  assert.ok(viewHtml.includes("query-key-warning"), "view.html must include transit exposure warning banner");
  assert.ok(viewJs.includes("query-key-warning"), "view.js must activate transit exposure warning on ?key=");
  assert.ok(!viewJs.includes("?key=${"), "view.js must not append ?key= to intent:// URLs");
  console.log("  [ok] BurnBinQR matrix & hardened static web assertions");

  // Print deterministic sample vector info if VERIFY_VECTOR=1
  if (process.env.PRINT_VECTOR === "1") {
    console.log("SAMPLE_V2_VECTOR=" + JSON.stringify(encV2));
  }
  console.log("All BurnBin Web JS tests passed!");
}

runTests().catch((err) => {
  console.error(err);
  process.exit(1);
});
