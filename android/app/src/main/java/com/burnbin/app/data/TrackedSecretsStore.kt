package com.burnbin.app.data

import android.content.SharedPreferences
import java.text.DateFormat
import java.util.Date
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

object TrackedSecretsStore {
  private const val SENT_SECRETS_PREF_KEY = "burnbin_sent_secrets"
  private const val MAX_ITEMS = 25
  private val json = Json { ignoreUnknownKeys = true }

  fun load(prefs: SharedPreferences): List<TrackedSecretItem> {
    val raw = prefs.getString(SENT_SECRETS_PREF_KEY, null) ?: return emptyList()
    return try {
      val parsed = json.decodeFromString<List<TrackedSecretItem>>(raw)
      val cutoff = System.currentTimeMillis() - 7L * 24 * 60 * 60 * 1000
      parsed.filter { it.expiresAtMs > cutoff }
    } catch (_: Exception) {
      emptyList()
    }
  }

  fun save(prefs: SharedPreferences, items: List<TrackedSecretItem>) {
    val encoded = json.encodeToString(items.take(MAX_ITEMS))
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
