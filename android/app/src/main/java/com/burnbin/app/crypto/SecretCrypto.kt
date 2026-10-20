package com.burnbin.app.crypto

import java.net.URI
import java.security.GeneralSecurityException
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

data class EncryptedPayload(
  val ciphertext: String,
  val iv: String,
  val salt: String?,
  val urlKey: String,
)

data class ParsedSecretLink(
  val baseUrl: String,
  val secretId: String,
  val urlKey: String,
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
    val masterKeyBytes = hex2buf(urlKeyHex)

    val decryptedBytes =
      try {
        aesGcmDecrypt(masterKeyBytes, iv1, encryptedData)
      } catch (e: GeneralSecurityException) {
        throw IllegalArgumentException("Decryption failed: Invalid or corrupted key in link.", e)
      }

    return String(decryptedBytes, Charsets.UTF_8)
  }

  /**
   * Parses a BurnBin secret link of the form:
   * https://domain/secret/<id>#key=<hex>
   */
  fun parseSecretLink(rawInput: String, defaultBaseUrl: String): Result<ParsedSecretLink> {
    val trimmed = rawInput.trim()
    if (trimmed.isEmpty()) {
      return Result.failure(IllegalArgumentException("Please paste a BurnBin secret link."))
    }

    return try {
      val fullUrl =
        when {
          trimmed.startsWith("http://") || trimmed.startsWith("https://") -> trimmed
          trimmed.startsWith("/secret/") -> "${defaultBaseUrl.trimEnd('/')}$trimmed"
          else -> "${defaultBaseUrl.trimEnd('/')}/secret/$trimmed"
        }

      val uri = URI(fullUrl)
      val baseUrl =
        if (uri.scheme != null && uri.authority != null) {
          "${uri.scheme}://${uri.authority}"
        } else {
          defaultBaseUrl.trimEnd('/')
        }

      val pathSegments = (uri.path ?: "").split("/").filter { it.isNotBlank() }
      val secretId =
        when {
          pathSegments.size >= 2 && pathSegments[0] == "secret" -> pathSegments[1]
          pathSegments.size == 1 -> pathSegments[0]
          else -> ""
        }

      if (secretId.length < 12) {
        return Result.failure(IllegalArgumentException("Invalid URL: Missing or invalid secret identifier."))
      }

      val fragment = uri.rawFragment ?: ""
      var urlKey: String? = null
      for (part in fragment.split("&")) {
        val kv = part.split("=", limit = 2)
        if (kv.size == 2 && kv[0] == "key") {
          urlKey = kv[1]
          break
        }
      }

      if (urlKey.isNullOrBlank()) {
        return Result.failure(
          IllegalArgumentException(
            "Missing decryption key in the link. Make sure the entire URL (including the #key=... part) was copied."
          )
        )
      }

      Result.success(
        ParsedSecretLink(
          baseUrl = baseUrl,
          secretId = secretId,
          urlKey = urlKey,
        )
      )
    } catch (e: Exception) {
      Result.failure(IllegalArgumentException("Invalid secret link format: ${e.message}"))
    }
  }
}
