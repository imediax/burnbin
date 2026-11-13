package com.burnbin.app.data

import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject

data class CreatedSecretResponse(
  val id: String,
  val expiresAt: Long,
  val maxViews: Int,
)

data class SecretMetaResponse(
  val id: String,
  val requiresPassphrase: Boolean,
  val viewsLeft: Int,
  val maxViews: Int,
  val expiresAt: Long,
)

data class ConsumedSecretResponse(
  val id: String,
  val ciphertext: String,
  val iv: String,
  val salt: String?,
  val viewsLeft: Int,
  val burned: Boolean,
)

object BurnBinApiClient {
  const val DEFAULT_SERVER_URL = "https://burnbin.cloud.run"
  private const val CONNECT_TIMEOUT_MS = 45_000
  private const val READ_TIMEOUT_MS = 45_000

  private fun normalizeAndValidateBaseUrl(baseUrl: String): String {
    val cleanBase = baseUrl.trim().trimEnd('/')
    if (!cleanBase.startsWith("https://", ignoreCase = true) && !cleanBase.startsWith("http://", ignoreCase = true)) {
      throw IllegalArgumentException("Vault URL must start with https:// or http://")
    }
    if (cleanBase.startsWith("http://", ignoreCase = true)) {
      val host = URL(cleanBase).host.lowercase()
      if (host != "localhost" && host != "127.0.0.1" && host != "10.0.2.2") {
        throw IllegalArgumentException("Unencrypted http:// is blocked for remote servers. Please use https://.")
      }
    }
    return cleanBase
  }

  suspend fun createSecret(
    baseUrl: String,
    ciphertext: String,
    iv: String,
    salt: String?,
    maxViews: Int,
    ttlSeconds: Int,
  ): Result<CreatedSecretResponse> =
    withContext(Dispatchers.IO) {
      var conn: HttpURLConnection? = null
      var cleanBase = baseUrl.trim().trimEnd('/')
      try {
        cleanBase = normalizeAndValidateBaseUrl(baseUrl)
        val endpoint = "$cleanBase/api/secrets"
        val url = URL(endpoint)
        conn =
          (url.openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            connectTimeout = CONNECT_TIMEOUT_MS
            readTimeout = READ_TIMEOUT_MS
            doInput = true
            doOutput = true
            setRequestProperty("Content-Type", "application/json; charset=utf-8")
            setRequestProperty("Accept", "application/json")
          }

        val payload =
          JSONObject().apply {
            put("ciphertext", ciphertext)
            put("iv", iv)
            if (salt != null) {
              put("salt", salt)
            } else {
              put("salt", JSONObject.NULL)
            }
            put("max_views", maxViews)
            put("ttl_seconds", ttlSeconds)
          }

        OutputStreamWriter(conn.outputStream, Charsets.UTF_8).use { writer ->
          writer.write(payload.toString())
          writer.flush()
        }

        val code = conn.responseCode
        val body = readStream(conn, code)
        if (code in 200..299) {
          val json = JSONObject(body)
          Result.success(
            CreatedSecretResponse(
              id = json.getString("id"),
              expiresAt = json.optLong("expires_at", 0L),
              maxViews = json.optInt("max_views", maxViews),
            )
          )
        } else {
          val errMsg = parseErrorMessage(body, "Server error ($code)")
          Result.failure(RuntimeException(errMsg))
        }
      } catch (e: Exception) {
        Result.failure(RuntimeException("Could not connect to vault ($cleanBase): ${e.localizedMessage ?: e.javaClass.simpleName}", e))
      } finally {
        conn?.disconnect()
      }
    }

  suspend fun getSecretMeta(baseUrl: String, secretId: String): Result<SecretMetaResponse> =
    withContext(Dispatchers.IO) {
      var conn: HttpURLConnection? = null
      try {
        val cleanBase = normalizeAndValidateBaseUrl(baseUrl)
        val endpoint = "$cleanBase/api/secrets/$secretId/meta"
        val url = URL(endpoint)
        conn =
          (url.openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = CONNECT_TIMEOUT_MS
            readTimeout = READ_TIMEOUT_MS
            setRequestProperty("Accept", "application/json")
          }

        val code = conn.responseCode
        val body = readStream(conn, code)
        if (code in 200..299) {
          val json = JSONObject(body)
          Result.success(
            SecretMetaResponse(
              id = json.getString("id"),
              requiresPassphrase = json.optBoolean("requires_passphrase", false),
              viewsLeft = json.optInt("views_left", 1),
              maxViews = json.optInt("max_views", 1),
              expiresAt = json.optLong("expires_at", 0L),
            )
          )
        } else if (code == 404) {
          Result.failure(RuntimeException("This secret does not exist, has expired, or has already been burned."))
        } else {
          val errMsg = parseErrorMessage(body, "Server error ($code)")
          Result.failure(RuntimeException(errMsg))
        }
      } catch (e: Exception) {
        Result.failure(RuntimeException("Could not connect to the secret vault: ${e.localizedMessage ?: e.javaClass.simpleName}", e))
      } finally {
        conn?.disconnect()
      }
    }

  suspend fun consumeSecret(baseUrl: String, secretId: String): Result<ConsumedSecretResponse> =
    withContext(Dispatchers.IO) {
      var conn: HttpURLConnection? = null
      try {
        val cleanBase = normalizeAndValidateBaseUrl(baseUrl)
        val endpoint = "$cleanBase/api/secrets/$secretId"
        val url = URL(endpoint)
        conn =
          (url.openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = CONNECT_TIMEOUT_MS
            readTimeout = READ_TIMEOUT_MS
            setRequestProperty("Accept", "application/json")
          }

        val code = conn.responseCode
        val body = readStream(conn, code)
        if (code in 200..299) {
          val json = JSONObject(body)
          val rawSalt = if (json.isNull("salt")) null else json.optString("salt", "").ifEmpty { null }
          Result.success(
            ConsumedSecretResponse(
              id = json.getString("id"),
              ciphertext = json.getString("ciphertext"),
              iv = json.getString("iv"),
              salt = rawSalt,
              viewsLeft = json.optInt("views_left", 0),
              burned = json.optBoolean("burned", true),
            )
          )
        } else {
          Result.failure(RuntimeException("This secret could not be retrieved. It may have just been burned or expired."))
        }
      } catch (e: Exception) {
        Result.failure(RuntimeException("Connection failed while retrieving secret: ${e.localizedMessage ?: "Network error"}", e))
      } finally {
        conn?.disconnect()
      }
    }

  private fun readStream(conn: HttpURLConnection, responseCode: Int): String {
    val stream = if (responseCode in 200..299) conn.inputStream else conn.errorStream
    if (stream == null) return ""
    return BufferedReader(InputStreamReader(stream, Charsets.UTF_8)).use { it.readText() }
  }

  private fun parseErrorMessage(body: String, fallback: String): String {
    return try {
      val json = JSONObject(body)
      json.optString("error", fallback).ifBlank { fallback }
    } catch (_: Exception) {
      fallback
    }
  }
}
