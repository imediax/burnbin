package com.burnbin.app.crypto

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.GeneralSecurityException
import java.security.SecureRandom
import java.util.Base64
import java.util.regex.Pattern
import java.util.zip.GZIPInputStream
import java.util.zip.GZIPOutputStream
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import kotlin.math.ln
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

class InvalidKeyException(message: String, cause: Throwable? = null) :
  IllegalArgumentException(message, cause)

class InvalidPassphraseException(message: String, cause: Throwable? = null) :
  IllegalArgumentException(message, cause)

data class EncryptedPayload(
  val ciphertext: String,
  val iv: String,
  val salt: String?,
  val urlKey: String,
)

data class ParsedSecretLink(
  val baseUrl: String,
  val secretId: String,
  val urlKey: String?,
)

@Serializable
data class SecretBundleFile(
  val name: String,
  val mime: String = "application/octet-stream",
  val size: Int = 0,
  val dataB64: String,
)

@Serializable
data class SecretBundlePayload(
  val text: String = "",
  val file: SecretBundleFile? = null,
)

@Serializable
data class SecretPayloadV2FileMeta(
  val name: String = "attachment.bin",
  val mime: String = "application/octet-stream",
  val size: Int = 0,
)

@Serializable
data class SecretPayloadV2Meta(
  val text: String = "",
  val file: SecretPayloadV2FileMeta? = null,
)

data class DecodedAttachment(
  val name: String,
  val mime: String,
  val size: Int,
  val bytes: ByteArray,
) {
  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is DecodedAttachment) return false
    return name == other.name &&
      mime == other.mime &&
      size == other.size &&
      bytes.contentEquals(other.bytes)
  }

  override fun hashCode(): Int {
    var result = name.hashCode()
    result = 31 * result + mime.hashCode()
    result = 31 * result + size
    result = 31 * result + bytes.contentHashCode()
    return result
  }
}

data class DecodedSecretContent(
  val text: String,
  val attachment: DecodedAttachment? = null,
)

data class PassphraseStrength(
  val score: Int,
  val label: String,
)

/**
 * Client-side Zero-Knowledge Crypto Utilities compatible with BurnBin's Web Crypto (crypto.js).
 * Uses AES-256-GCM (128-bit auth tag, 12-byte IV) and PBKDF2-HMAC-SHA256
 * (600,000 iterations for new secrets; 100,000 legacy backwards compatibility).
 */
object SecretCrypto {
  private const val GCM_TAG_BITS = 128
  private const val GCM_IV_BYTES = 12
  private const val MASTER_KEY_BYTES = 32
  private const val SALT_BYTES = 16
  const val PBKDF2_ITERATIONS_V2 = 600_000
  const val PBKDF2_ITERATIONS_LEGACY = 100_000

  const val BUNDLE_PREFIX = "__BURNBIN_BUNDLE_V1__:"
  const val MAX_ATTACHMENT_BYTES = 1024 * 1024 // 1 MB binary limit
  private const val MAX_DECOMPRESSED_BYTES = 8 * 1024 * 1024 // 8 MB zip-bomb safety limit
  private const val MAX_META_BYTES = 4 * 1024 * 1024 // 4 MB V2 metadata+text ceiling (bounded below 8 MB decompressed cap)
  private val BUNDLE_V2_MAGIC = byteArrayOf(0x42, 0x42, 0x32, 0x00) // "BB2\0"
  private const val FLAG_GZIP: Byte = 0x01

  private val secureRandom = SecureRandom()

  private val SECRET_ID_REGEX = Pattern.compile("""(?:/secret/|^)([A-Za-z0-9_-]{12,64})""")
  private val KEY_PARAM_REGEX = Pattern.compile("""(?:[#?&]key=)([A-Fa-f0-9]{64})""", Pattern.CASE_INSENSITIVE)
  private val STANDALONE_HEX_KEY_REGEX = Pattern.compile("""(?:#|\b)([A-Fa-f0-9]{64})\b""", Pattern.CASE_INSENSITIVE)
  private val BASE_URL_REGEX = Pattern.compile("""(https?://[^/\s?#]+)""", Pattern.CASE_INSENSITIVE)

  private val bundleJson = Json {
    ignoreUnknownKeys = true
    encodeDefaults = true
  }

  private val PASSPHRASE_WORDS = listOf(
    "amber", "anchor", "apple", "apron", "atlas", "badge", "bamboo", "beacon",
    "breeze", "bridge", "cactus", "canyon", "cedar", "cipher", "cloud", "clover",
    "cobalt", "comet", "copper", "coral", "crater", "crimson", "crystal", "cyclone",
    "desert", "dolphin", "ember", "emerald", "falcon", "flint", "forest", "fossil",
    "galaxy", "glacier", "granite", "harbor", "hazel", "horizon", "island", "ivory",
    "jasper", "juniper", "lantern", "lapis", "laurel", "lemon", "linen", "lotus",
    "lunar", "magnet", "mango", "marble", "meadow", "meteor", "mineral", "nebula",
    "nectar", "olive", "onyx", "orchid", "osprey", "pebble", "pepper", "photon",
  )

  fun buf2hex(bytes: ByteArray): String {
    val sb = StringBuilder(bytes.size * 2)
    for (b in bytes) {
      sb.append(String.format("%02x", b.toInt() and 0xFF))
    }
    return sb.toString()
  }

  fun hex2buf(hexString: String): ByteArray {
    val clean = hexString.trim()
    if (clean.isEmpty() || clean.length % 2 != 0) {
      throw IllegalArgumentException("Invalid hex string")
    }
    val bytes = ByteArray(clean.length / 2)
    for (i in clean.indices step 2) {
      val hi = Character.digit(clean[i], 16)
      val lo = Character.digit(clean[i + 1], 16)
      if (hi == -1 || lo == -1) {
        throw IllegalArgumentException("Invalid hex character in key or IV")
      }
      bytes[i / 2] = ((hi shl 4) + lo).toByte()
    }
    return bytes
  }

  fun buf2b64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)

  fun b642buf(base64: String): ByteArray = Base64.getDecoder().decode(base64.trim())

  internal fun parseSalt(saltStr: String): Pair<ByteArray, Int> {
    val clean = saltStr.trim()
    if (clean.startsWith("v2$")) {
      val parts = clean.split("$")
      if (parts.size != 3) {
        throw IllegalArgumentException("Corrupted passphrase salt header.")
      }
      val iterations = parts[1].toIntOrNull()
        ?: throw IllegalArgumentException("Invalid PBKDF2 iteration count in salt.")
      if (iterations !in 10_000..2_000_000) {
        throw IllegalArgumentException("PBKDF2 iteration count out of safe bounds.")
      }
      return hex2buf(parts[2]) to iterations
    }
    return hex2buf(clean) to PBKDF2_ITERATIONS_LEGACY
  }

  private fun derivePassphraseKey(
    passphrase: String,
    saltBytes: ByteArray,
    iterations: Int = PBKDF2_ITERATIONS_V2,
  ): ByteArray {
    val spec = PBEKeySpec(passphrase.toCharArray(), saltBytes, iterations, 256)
    val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
    return factory.generateSecret(spec).encoded
  }

  private fun aesGcmEncrypt(keyBytes: ByteArray, ivBytes: ByteArray, plaintext: ByteArray): ByteArray {
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(keyBytes, "AES"), GCMParameterSpec(GCM_TAG_BITS, ivBytes))
    return cipher.doFinal(plaintext)
  }

  private fun aesGcmDecrypt(keyBytes: ByteArray, ivBytes: ByteArray, ciphertext: ByteArray): ByteArray {
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(keyBytes, "AES"), GCMParameterSpec(GCM_TAG_BITS, ivBytes))
    return cipher.doFinal(ciphertext)
  }

  fun encryptBytes(dataBytes: ByteArray, passphrase: String? = null): EncryptedPayload {
    val rawMasterKey = ByteArray(MASTER_KEY_BYTES).also { secureRandom.nextBytes(it) }
    val iv1 = ByteArray(GCM_IV_BYTES).also { secureRandom.nextBytes(it) }
    var encryptedData = aesGcmEncrypt(rawMasterKey, iv1, dataBytes)

    var saltHeader: String? = null
    var combinedIv = buf2hex(iv1)

    val trimmedPass = passphrase?.trim()
    if (!trimmedPass.isNullOrEmpty()) {
      val saltBytes = ByteArray(SALT_BYTES).also { secureRandom.nextBytes(it) }
      saltHeader = "v2$" + PBKDF2_ITERATIONS_V2 + "$" + buf2hex(saltBytes)

      val passKeyBytes = derivePassphraseKey(trimmedPass, saltBytes, PBKDF2_ITERATIONS_V2)
      val iv2 = ByteArray(GCM_IV_BYTES).also { secureRandom.nextBytes(it) }

      encryptedData = aesGcmEncrypt(passKeyBytes, iv2, encryptedData)
      combinedIv = "${buf2hex(iv1)}:${buf2hex(iv2)}"
    }

    return EncryptedPayload(
      ciphertext = buf2b64(encryptedData),
      iv = combinedIv,
      salt = saltHeader,
      urlKey = buf2hex(rawMasterKey),
    )
  }

  /** Encrypts UTF-8 plaintext identically to BurnBin's browser Web Crypto implementation. */
  fun encrypt(plaintext: String, passphrase: String? = null): EncryptedPayload =
    encryptBytes(plaintext.toByteArray(Charsets.UTF_8), passphrase)

  fun decryptBytes(
    ciphertextB64: String,
    ivCombined: String,
    saltHex: String?,
    urlKeyHex: String,
    passphrase: String? = null,
  ): ByteArray {
    val cleanKey = urlKeyHex.trim()
    if (cleanKey.length != 64) {
      throw InvalidKeyException("Decryption key must be exactly 64 hexadecimal characters.")
    }

    var encryptedData = b642buf(ciphertextB64)
    val ivParts = ivCombined.split(":")

    if (!saltHex.isNullOrEmpty()) {
      val trimmedPass = passphrase?.trim()
      if (trimmedPass.isNullOrEmpty()) {
        throw InvalidPassphraseException("This secret is protected with a passphrase.")
      }
      if (ivParts.size < 2) {
        throw InvalidKeyException("Corrupted initialization vector.")
      }

      val (saltBytes, iterations) = parseSalt(saltHex)
      val passKeyBytes = derivePassphraseKey(trimmedPass, saltBytes, iterations)
      val iv2 =
        try {
          hex2buf(ivParts[1])
        } catch (e: Exception) {
          throw InvalidKeyException("Corrupted initialization vector.", e)
        }

      encryptedData =
        try {
          aesGcmDecrypt(passKeyBytes, iv2, encryptedData)
        } catch (e: GeneralSecurityException) {
          throw InvalidPassphraseException("Incorrect passphrase. Please try again.", e)
        }
    }

    val iv1 =
      try {
        hex2buf(ivParts[0])
      } catch (e: Exception) {
        throw InvalidKeyException("Corrupted initialization vector.", e)
      }
    val masterKeyBytes =
      try {
        hex2buf(cleanKey)
      } catch (e: Exception) {
        throw InvalidKeyException("Decryption key must be valid hex.", e)
      }

    return try {
      aesGcmDecrypt(masterKeyBytes, iv1, encryptedData)
    } catch (e: GeneralSecurityException) {
      throw InvalidKeyException("Decryption failed: Invalid or corrupted key in link.", e)
    }
  }

  /** Decrypts envelope to UTF-8 string. */
  fun decrypt(
    ciphertextB64: String,
    ivCombined: String,
    saltHex: String?,
    urlKeyHex: String,
    passphrase: String? = null,
  ): String = String(decryptBytes(ciphertextB64, ivCombined, saltHex, urlKeyHex, passphrase), Charsets.UTF_8)

  private fun gzip(input: ByteArray): ByteArray {
    val baos = ByteArrayOutputStream()
    GZIPOutputStream(baos).use { it.write(input) }
    return baos.toByteArray()
  }

  private fun gunzipBounded(compressed: ByteArray): ByteArray {
    val baos = ByteArrayOutputStream()
    val buf = ByteArray(8192)
    var total = 0
    GZIPInputStream(ByteArrayInputStream(compressed)).use { gzis ->
      while (true) {
        val read = gzis.read(buf)
        if (read <= 0) break
        total += read
        if (total > MAX_DECOMPRESSED_BYTES) {
          throw IllegalArgumentException("Decrypted payload exceeds maximum safe decompressed size (8 MB).")
        }
        baos.write(buf, 0, read)
      }
    }
    return baos.toByteArray()
  }

  /**
   * Encodes text + optional binary attachment into compact V2 binary+gzip format
   * compatible with Web crypto.js (short plain text without files remains unwrapped UTF-8).
   */
  fun encodePayload(text: String, attachment: DecodedAttachment? = null): ByteArray {
    if (attachment == null) {
      val rawText = text.toByteArray(Charsets.UTF_8)
      if (rawText.size < 512) return rawText
    }
    val fileBytes = attachment?.bytes ?: ByteArray(0)
    val meta =
      SecretPayloadV2Meta(
        text = text,
        file =
          attachment?.let {
            SecretPayloadV2FileMeta(
              name = it.name.ifBlank { "attachment.bin" },
              mime = it.mime.ifBlank { "application/octet-stream" },
              size = fileBytes.size,
            )
          },
      )
    val metaBytes = bundleJson.encodeToString(meta).toByteArray(Charsets.UTF_8)
    if (metaBytes.size > MAX_META_BYTES) {
      throw IllegalArgumentException("Secret text exceeds the maximum supported size (4 MB).")
    }
    val inner =
      ByteBuffer.allocate(4 + metaBytes.size + fileBytes.size)
        .order(ByteOrder.BIG_ENDIAN)
        .putInt(metaBytes.size)
        .put(metaBytes)
        .put(fileBytes)
        .array()

    val compressed = gzip(inner)
    val useGzip = compressed.size < inner.size
    val body = if (useGzip) compressed else inner
    val out = ByteArray(5 + body.size)
    System.arraycopy(BUNDLE_V2_MAGIC, 0, out, 0, 4)
    out[4] = if (useGzip) FLAG_GZIP else 0x00
    System.arraycopy(body, 0, out, 5, body.size)
    return out
  }

  fun decodePayload(decryptedBytes: ByteArray): DecodedSecretContent {
    val isV2 =
      decryptedBytes.size >= 9 &&
        decryptedBytes[0] == BUNDLE_V2_MAGIC[0] &&
        decryptedBytes[1] == BUNDLE_V2_MAGIC[1] &&
        decryptedBytes[2] == BUNDLE_V2_MAGIC[2] &&
        decryptedBytes[3] == BUNDLE_V2_MAGIC[3]

    if (isV2) {
      val flags = decryptedBytes[4]
      val rawBody = decryptedBytes.copyOfRange(5, decryptedBytes.size)
      val inner =
        if ((flags.toInt() and FLAG_GZIP.toInt()) != 0) gunzipBounded(rawBody) else rawBody
      if (inner.size < 4) {
        throw IllegalArgumentException("Corrupted V2 secret envelope.")
      }
      val metaLen = ByteBuffer.wrap(inner, 0, 4).order(ByteOrder.BIG_ENDIAN).int
      if (metaLen < 0 || metaLen > MAX_META_BYTES || 4 + metaLen > inner.size) {
        throw IllegalArgumentException("Corrupted V2 metadata header.")
      }
      val metaJson = String(inner, 4, metaLen, Charsets.UTF_8)
      val meta = bundleJson.decodeFromString<SecretPayloadV2Meta>(metaJson)
      val fileBytes = inner.copyOfRange(4 + metaLen, inner.size)
      val attachment =
        meta.file?.let {
          DecodedAttachment(
            name = it.name.ifBlank { "attachment.bin" },
            mime = it.mime.ifBlank { "application/octet-stream" },
            size = fileBytes.size,
            bytes = fileBytes,
          )
        }
      return DecodedSecretContent(text = meta.text, attachment = attachment)
    }

    return decodeBundle(String(decryptedBytes, Charsets.UTF_8))
  }

  fun encodeBundle(text: String, attachment: DecodedAttachment?): String {
    if (attachment == null) return text
    val b64 = Base64.getEncoder().encodeToString(attachment.bytes)
    val payload =
      SecretBundlePayload(
        text = text,
        file =
          SecretBundleFile(
            name = attachment.name,
            mime = attachment.mime.ifBlank { "application/octet-stream" },
            size = attachment.bytes.size,
            dataB64 = b64,
          ),
      )
    return BUNDLE_PREFIX + bundleJson.encodeToString(payload)
  }

  fun decodeBundle(decryptedPlaintext: String): DecodedSecretContent {
    if (!decryptedPlaintext.startsWith(BUNDLE_PREFIX)) {
      return DecodedSecretContent(text = decryptedPlaintext)
    }
    return try {
      val parsed = bundleJson.decodeFromString<SecretBundlePayload>(decryptedPlaintext.removePrefix(BUNDLE_PREFIX))
      val fileObj = parsed.file
      val attachment =
        if (fileObj != null && fileObj.dataB64.isNotBlank()) {
          val rawBytes = Base64.getDecoder().decode(fileObj.dataB64)
          DecodedAttachment(
            name = fileObj.name.ifBlank { "attachment.bin" },
            mime = fileObj.mime.ifBlank { "application/octet-stream" },
            size = rawBytes.size,
            bytes = rawBytes,
          )
        } else {
          null
        }
      DecodedSecretContent(text = parsed.text, attachment = attachment)
    } catch (_: Exception) {
      DecodedSecretContent(text = decryptedPlaintext)
    }
  }

  fun parseSecretLink(rawInput: String, defaultBaseUrl: String): Result<ParsedSecretLink> {
    val trimmed = rawInput.trim()
    if (trimmed.isEmpty()) {
      return Result.failure(IllegalArgumentException("Please enter or paste a BurnBin secret link."))
    }

    val baseMatcher = BASE_URL_REGEX.matcher(trimmed)
    val baseUrl =
      if (baseMatcher.find()) {
        baseMatcher.group(1)?.trimEnd('/') ?: defaultBaseUrl.trimEnd('/')
      } else {
        defaultBaseUrl.trimEnd('/')
      }

    val idMatcher = SECRET_ID_REGEX.matcher(trimmed)
    val secretId = if (idMatcher.find()) idMatcher.group(1) ?: "" else ""

    if (secretId.length < 12) {
      return Result.failure(
        IllegalArgumentException("Could not find a valid secret ID in the link. Expected /secret/<id>.")
      )
    }

    var urlKey: String? = null
    val keyParamMatcher = KEY_PARAM_REGEX.matcher(trimmed)
    if (keyParamMatcher.find()) {
      urlKey = keyParamMatcher.group(1)
    } else {
      val hexMatcher = STANDALONE_HEX_KEY_REGEX.matcher(trimmed)
      while (hexMatcher.find()) {
        val candidate = hexMatcher.group(1)
        if (candidate != null && candidate.length == 64 && candidate != secretId) {
          urlKey = candidate
          break
        }
      }
    }

    return Result.success(
      ParsedSecretLink(
        baseUrl = baseUrl,
        secretId = secretId,
        urlKey = urlKey?.lowercase(),
      )
    )
  }

  fun evaluatePassphraseStrength(passphrase: String): PassphraseStrength {
    val value = passphrase.trim()
    if (value.isEmpty()) return PassphraseStrength(score = 0, label = "")
    var pool = 0
    if (value.any { it in 'a'..'z' }) pool += 26
    if (value.any { it in 'A'..'Z' }) pool += 26
    if (value.any { it in '0'..'9' }) pool += 10
    if (value.any { !it.isLetterOrDigit() }) pool += 32
    val entropy = if (pool > 0) value.length * (ln(pool.toDouble()) / ln(2.0)) else 0.0
    return when {
      value.length < 8 || entropy < 42.0 -> PassphraseStrength(score = 1, label = "Weak")
      entropy < 64.0 -> PassphraseStrength(score = 2, label = "Fair")
      entropy < 88.0 -> PassphraseStrength(score = 3, label = "Good")
      else -> PassphraseStrength(score = 4, label = "Strong")
    }
  }

  fun generateStrongPassword(length: Int = 24, includeSymbols: Boolean = true): String {
    val targetLength = length.coerceIn(12, 64)
    val upper = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    val lower = "abcdefghijkmnopqrstuvwxyz"
    val digits = "23456789"
    val symbols = "!@#$%^&*()-_=+[]{}"
    val all = upper + lower + digits + if (includeSymbols) symbols else ""

    val chars = ArrayList<Char>(targetLength)
    chars += upper[secureRandom.nextInt(upper.length)]
    chars += lower[secureRandom.nextInt(lower.length)]
    chars += digits[secureRandom.nextInt(digits.length)]
    if (includeSymbols) {
      chars += symbols[secureRandom.nextInt(symbols.length)]
    }
    while (chars.size < targetLength) {
      chars += all[secureRandom.nextInt(all.length)]
    }
    for (i in chars.lastIndex downTo 1) {
      val j = secureRandom.nextInt(i + 1)
      val tmp = chars[i]
      chars[i] = chars[j]
      chars[j] = tmp
    }
    return chars.joinToString("")
  }

  fun generateShareablePassphrase(): String {
    val picked = (1..4).map { PASSPHRASE_WORDS[secureRandom.nextInt(PASSPHRASE_WORDS.size)] }
    val digits = (10 + secureRandom.nextInt(90)).toString()
    return (picked + digits).joinToString("-")
  }
}
