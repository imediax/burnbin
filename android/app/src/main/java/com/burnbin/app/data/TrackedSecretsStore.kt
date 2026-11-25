package com.burnbin.app.data

import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.burnbin.app.crypto.SecretCrypto
import java.security.KeyStore
import java.text.DateFormat
import java.util.Base64
import java.util.Date
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

@Serializable
data class TrackedSecretItem(
  val id: String,
  val baseUrl: String,
  val label: String = "",
  val createdAtMs: Long,
  val expiresAtMs: Long,
  val maxViews: Int,
  val viewsLeft: Int,
  val deleteToken: String = "",
  val hasAttachment: Boolean = false,
  val status: String = "active",
)

interface TokenProtector {
  fun wrap(plain: String): String

  fun unwrap(stored: String): String
}

class AesGcmTokenProtector(
  private val keyProvider: () -> SecretKey? = ::getOrCreateAndroidKeystoreKey,
) : TokenProtector {
  companion object {
    const val ENC_PREFIX = "enc:v1:"
    private const val KEY_ALIAS = "burnbin_tracked_tokens_aes_v1"
    private const val GCM_TAG_BITS = 128

    private fun getOrCreateAndroidKeystoreKey(): SecretKey? {
      return try {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val existing = ks.getKey(KEY_ALIAS, null) as? SecretKey
        if (existing != null) return existing
        val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val spec =
          KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
          )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()
        keyGen.init(spec)
        keyGen.generateKey()
      } catch (_: Throwable) {
        null
      }
    }
  }

  override fun wrap(plain: String): String {
    if (plain.isBlank()) return ""
    if (plain.startsWith(ENC_PREFIX)) return plain
    val key = keyProvider() ?: return plain
    return try {
      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      // AndroidKeyStore enforces randomized IVs; never pass a caller GCMParameterSpec on ENCRYPT_MODE.
      cipher.init(Cipher.ENCRYPT_MODE, key)
      val iv = cipher.iv
      val ciphertext = cipher.doFinal(plain.toByteArray(Charsets.UTF_8))
      "$ENC_PREFIX${SecretCrypto.buf2hex(iv)}:${Base64.getEncoder().encodeToString(ciphertext)}"
    } catch (_: Exception) {
      plain
    }
  }

  override fun unwrap(stored: String): String {
    if (stored.isBlank()) return ""
    if (!stored.startsWith(ENC_PREFIX)) return stored
    val payload = stored.removePrefix(ENC_PREFIX)
    val parts = payload.split(":", limit = 2)
    if (parts.size != 2 || parts[0].isBlank() || parts[1].isBlank()) return ""
    val key = keyProvider() ?: return ""
    return try {
      val ivBytes = SecretCrypto.hex2buf(parts[0])
      val ctBytes = Base64.getDecoder().decode(parts[1])
      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, ivBytes))
      String(cipher.doFinal(ctBytes), Charsets.UTF_8)
    } catch (_: Exception) {
      ""
    }
  }
}

object TrackedSecretsStore {
  private const val SENT_SECRETS_PREF_KEY = "burnbin_sent_secrets"
  private const val MAX_ITEMS = 25
  private val json = Json { ignoreUnknownKeys = true }
  private val defaultProtector: TokenProtector = AesGcmTokenProtector()

  fun load(
    prefs: SharedPreferences,
    protector: TokenProtector = defaultProtector,
  ): List<TrackedSecretItem> {
    val raw = prefs.getString(SENT_SECRETS_PREF_KEY, null) ?: return emptyList()
    return try {
      val parsed = json.decodeFromString<List<TrackedSecretItem>>(raw)
      val cutoff = System.currentTimeMillis() - 7L * 24 * 60 * 60 * 1000
      val active = parsed.filter { it.expiresAtMs > cutoff }
      var needsMigration = false
      val unwrapped =
        active.map { item ->
          if (item.deleteToken.isNotBlank() && !item.deleteToken.startsWith(AesGcmTokenProtector.ENC_PREFIX)) {
            needsMigration = true
          }
          item.copy(deleteToken = protector.unwrap(item.deleteToken))
        }
      if (needsMigration) {
        save(prefs, unwrapped, protector)
      }
      unwrapped
    } catch (_: Exception) {
      emptyList()
    }
  }

  fun save(
    prefs: SharedPreferences,
    items: List<TrackedSecretItem>,
    protector: TokenProtector = defaultProtector,
  ) {
    val wrapped =
      items.take(MAX_ITEMS).map { item ->
        if (item.deleteToken.isBlank()) item
        else item.copy(deleteToken = protector.wrap(item.deleteToken))
      }
    val encoded = json.encodeToString(wrapped)
    prefs.edit().putString(SENT_SECRETS_PREF_KEY, encoded).apply()
  }

  fun formatExpiryCountdown(expiresAtMs: Long): String {
    val diffSec = (expiresAtMs - System.currentTimeMillis()) / 1000L
    return when {
      diffSec <= 0L -> "Expired"
      diffSec < 60L -> "${diffSec}s left"
      diffSec < 3600L -> "${(diffSec + 59) / 60}m left"
      diffSec < 86400L -> "${(diffSec + 3599) / 3600}h left"
      else -> "${(diffSec + 86399) / 86400}d left"
    }
  }

  fun formatAbsoluteExpiry(expiresAtSec: Long): String {
    if (expiresAtSec <= 0L) return ""
    return try {
      DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT)
        .format(Date(expiresAtSec * 1000L))
    } catch (_: Exception) {
      ""
    }
  }
}
