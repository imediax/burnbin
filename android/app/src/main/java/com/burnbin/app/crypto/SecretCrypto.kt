package com.burnbin.app.crypto

import java.net.URI
import java.security.GeneralSecurityException
import java.security.SecureRandom
import java.util.Base64
import java.util.regex.Pattern
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

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

data class DecodedAttachment(
  val name: String,
  val mime: String,
  val size: Int,
  val bytes: ByteArray,
)

data class DecodedSecretContent(
  val text: String,
  val attachment: DecodedAttachment? = null,
)

/**
 * Client-side Zero-Knowledge Crypto Utilities compatible with BurnBin's Web Crypto (crypto.js).
 * Uses AES-256-GCM (128-bit auth tag, 12-byte IV) and PBKDF2-HMAC-SHA256 (100,000 iterations).
 */
object SecretCrypto {
  private const val GCM_TAG_BITS = 128
  private const val GCM_IV_BYTES = 12
  private const val MASTER_KEY_BYTES = 32
  private const val SALT_BYTES = 16
  private const val PBKDF2_ITERATIONS = 100_000
  private const val PBKDF2_KEY_BITS = 256

  private val secureRandom = SecureRandom()

  private val SECRET_ID_REGEX = Pattern.compile("""(?:/secret/|^)([A-Za-z0-9_-]{12,64})""")
  private val KEY_PARAM_REGEX = Pattern.compile("""(?:[#?&]key=)([A-Fa-f0-9]{64})""", Pattern.CASE_INSENSITIVE)
  private val STANDALONE_HEX_KEY_REGEX = Pattern.compile("""(?:#|\b)([A-Fa-f0-9]{64})\b""", Pattern.CASE_INSENSITIVE)
  private val BASE_URL_REGEX = Pattern.compile("""(https?://[^/\s?#]+)""", Pattern.CASE_INSENSITIVE)

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

  fun buf2b64(bytes: ByteArray): String {
    return Base64.getEncoder().encodeToString(bytes)
  }

  fun b642buf(base64: String): ByteArray {
    return Base64.getDecoder().decode(base64.trim())
  }

  private fun derivePassphraseKey(passphrase: String, saltBytes: ByteArray): ByteArray {
    val spec = PBEKeySpec(passphrase.toCharArray(), saltBytes, PBKDF2_ITERATIONS, PBKDF2_KEY_BITS)
    val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
    return factory.generateSecret(spec).encoded
  }

  private fun aesGcmEncrypt(keyBytes: ByteArray, ivBytes: ByteArray, plaintext: ByteArray): ByteArray {
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    val keySpec = SecretKeySpec(keyBytes, "AES")
    val gcmSpec = GCMParameterSpec(GCM_TAG_BITS, ivBytes)
    cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)
    return cipher.doFinal(plaintext)
  }

  private fun aesGcmDecrypt(keyBytes: ByteArray, ivBytes: ByteArray, ciphertext: ByteArray): ByteArray {
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    val keySpec = SecretKeySpec(keyBytes, "AES")
    val gcmSpec = GCMParameterSpec(GCM_TAG_BITS, ivBytes)
    cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec)
    return cipher.doFinal(ciphertext)
  }

  /**
   * Encrypts plaintext message identically to BurnBin's browser Web Crypto implementation.
   */
  fun encrypt(plaintext: String, passphrase: String? = null): EncryptedPayload {
    val dataBytes = plaintext.toByteArray(Charsets.UTF_8)

    // 1. Generate random 256-bit AES master key
    val rawMasterKey = ByteArray(MASTER_KEY_BYTES).also { secureRandom.nextBytes(it) }

    // 2. Encrypt plaintext with master key
    val iv1 = ByteArray(GCM_IV_BYTES).also { secureRandom.nextBytes(it) }
    var encryptedData = aesGcmEncrypt(rawMasterKey, iv1, dataBytes)

    var saltHex: String? = null
    var combinedIv = buf2hex(iv1)

    // 3. If passphrase provided, encrypt the encryptedData again using PBKDF2 passphrase key
    val trimmedPass = passphrase?.trim()
    if (!trimmedPass.isNullOrEmpty()) {
      val saltBytes = ByteArray(SALT_BYTES).also { secureRandom.nextBytes(it) }
      saltHex = buf2hex(saltBytes)

      val passKeyBytes = derivePassphraseKey(trimmedPass, saltBytes)
      val iv2 = ByteArray(GCM_IV_BYTES).also { secureRandom.nextBytes(it) }

      encryptedData = aesGcmEncrypt(passKeyBytes, iv2, encryptedData)
      combinedIv = "${buf2hex(iv1)}:${buf2hex(iv2)}"
    }

    return EncryptedPayload(
      ciphertext = buf2b64(encryptedData),
      iv = combinedIv,
      salt = saltHex,
      urlKey = buf2hex(rawMasterKey),
    )
  }

  /**
   * Decrypts ciphertext identically to BurnBin's browser Web Crypto implementation.
   */
  fun decrypt(
    ciphertextB64: String,
    ivCombined: String,
    saltHex: String?,
    urlKeyHex: String,
    passphrase: String? = null,
  ): String {
    val cleanKey = urlKeyHex.trim()
    if (cleanKey.length != 64) {
      throw IllegalArgumentException("Decryption key must be exactly 64 hexadecimal characters.")
    }

    var encryptedData = b642buf(ciphertextB64)
    val ivParts = ivCombined.split(":")

    // If secret was encrypted with a passphrase, decrypt outer layer first
    if (!saltHex.isNullOrEmpty()) {
      val trimmedPass = passphrase?.trim()
      if (trimmedPass.isNullOrEmpty()) {
        throw IllegalArgumentException("This secret is protected with a passphrase.")
      }
      if (ivParts.size < 2) {
        throw IllegalArgumentException("Corrupted initialization vector.")
      }

      val saltBytes = hex2buf(saltHex)
      val passKeyBytes = derivePassphraseKey(trimmedPass, saltBytes)
      val iv2 = hex2buf(ivParts[1])

      encryptedData =
        try {
          aesGcmDecrypt(passKeyBytes, iv2, encryptedData)
        } catch (e: GeneralSecurityException) {
          throw IllegalArgumentException("Incorrect passphrase. Please try again.", e)
        }
    }

    // Decrypt inner layer with the master key from the URL fragment
    val iv1 = hex2buf(ivParts[0])
    val masterKeyBytes = hex2buf(cleanKey)

    val decryptedBytes =
      try {
        aesGcmDecrypt(masterKeyBytes, iv1, encryptedData)
      } catch (e: GeneralSecurityException) {
        throw IllegalArgumentException("Decryption failed: Invalid or corrupted key in link.", e)
      }

    return String(decryptedBytes, Charsets.UTF_8)
  }

  /**
   * Parses a BurnBin secret link robustly.
   * Supports:
   * - https://domain/secret/<id>#key=<hex>
   * - https://domain/secret/<id>?key=<hex>
   * - Raw secret links inside chat messages
   * - Links missing the key (returns urlKey = null so the UI can prompt for it gracefully)
   */
  fun parseSecretLink(rawInput: String, defaultBaseUrl: String): Result<ParsedSecretLink> {
    val trimmed = rawInput.trim()
    if (trimmed.isEmpty()) {
      return Result.failure(IllegalArgumentException("Please enter or paste a BurnBin secret link."))
    }

    // 1. Extract Base URL
    val baseMatcher = BASE_URL_REGEX.matcher(trimmed)
    val baseUrl =
      if (baseMatcher.find()) {
        baseMatcher.group(1)?.trimEnd('/') ?: defaultBaseUrl.trimEnd('/')
      } else {
        defaultBaseUrl.trimEnd('/')
      }

    // 2. Extract Secret ID
    val idMatcher = SECRET_ID_REGEX.matcher(trimmed)
    val secretId =
      if (idMatcher.find()) {
        idMatcher.group(1) ?: ""
      } else {
        ""
      }

    if (secretId.length < 12) {
      return Result.failure(
        IllegalArgumentException("Could not find a valid secret ID in the link. Expected /secret/<id>.")
      )
    }

    // 3. Extract Decryption Key (check ?key=, #key=, or standalone 64-hex string)
    var urlKey: String? = null
    val keyParamMatcher = KEY_PARAM_REGEX.matcher(trimmed)
    if (keyParamMatcher.find()) {
      urlKey = keyParamMatcher.group(1)
    } else {
      // Fallback: Check if there is a 64-char hex key anywhere in the input
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

  const val BUNDLE_PREFIX = "__BURNBIN_BUNDLE_V1__:"
  const val MAX_ATTACHMENT_BYTES = 1024 * 1024 // 1 MB binary limit

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

  fun generateStrongPassword(length: Int = 24): String {
    val upper = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    val lower = "abcdefghijkmnopqrstuvwxyz"
    val digits = "23456789"
    val symbols = "!@#$%^&*()-_=+[]{}"
    val all = upper + lower + digits + symbols
    val rng = SecureRandom()

    val chars = ArrayList<Char>(length.coerceAtLeast(12))
    chars += upper[rng.nextInt(upper.length)]
    chars += lower[rng.nextInt(lower.length)]
    chars += digits[rng.nextInt(digits.length)]
    chars += symbols[rng.nextInt(symbols.length)]
    while (chars.size < length.coerceAtLeast(12)) {
      chars += all[rng.nextInt(all.length)]
    }
    for (i in chars.lastIndex downTo 1) {
      val j = rng.nextInt(i + 1)
      val tmp = chars[i]
      chars[i] = chars[j]
      chars[j] = tmp
    }
    return chars.joinToString("")
  }

  fun generateShareablePassphrase(): String {
    val rng = SecureRandom()
    val picked = (1..4).map { PASSPHRASE_WORDS[rng.nextInt(PASSPHRASE_WORDS.size)] }
    val digits = (10 + rng.nextInt(90)).toString()
    return (picked + digits).joinToString("-")
  }
}
