package com.burnbin.app.data

import java.io.BufferedReader
import java.io.IOException
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

sealed class ApiException(message: String, cause: Throwable? = null) : RuntimeException(message, cause) {
  class NotFound(message: String) : ApiException(message)
  class Forbidden(message: String) : ApiException(message)
  class PayloadTooLarge(message: String) : ApiException(message)
  class RateLimited(message: String, val retryAfterSeconds: Int? = null) : ApiException(message)
  class HttpError(val code: Int, message: String) : ApiException(message)
  class NetworkError(message: String, cause: Throwable? = null) : ApiException(message, cause)
}

@Serializable
private data class CreateSecretRequest(
  val ciphertext: String,
  val iv: String,
  val salt: String? = null,
  @SerialName("max_views") val maxViews: Int,
  @SerialName("ttl_seconds") val ttlSeconds: Int,
)

@Serializable
data class CreatedSecretResponse(
  val id: String,
  @SerialName("expires_at") val expiresAt: Long = 0L,
  @SerialName("max_views") val maxViews: Int = 1,
  @SerialName("delete_token") val deleteToken: String? = null,
)

@Serializable
data class SecretMetaResponse(
  val id: String,
  @SerialName("requires_passphrase") val requiresPassphrase: Boolean = false,
  @SerialName("views_left") val viewsLeft: Int = 1,
  @SerialName("max_views") val maxViews: Int = 1,
  @SerialName("expires_at") val expiresAt: Long = 0L,
)

@Serializable
data class ConsumedSecretResponse(
  val id: String,
  val ciphertext: String,
  val iv: String,
  val salt: String? = null,
  @SerialName("views_left") val viewsLeft: Int = 0,
  val burned: Boolean = true,
)

@Serializable
private data class ApiErrorBody(
  val error: String = "",
)

object BurnBinApiClient {
  const val DEFAULT_SERVER_URL = "https://burnbin.cloud.run"
  private const val CONNECT_TIMEOUT_MS = 45_000
  private const val READ_TIMEOUT_MS = 45_000

  private val apiJson = Json {
    ignoreUnknownKeys = true
    encodeDefaults = true
  }

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

  private fun encodeSegment(value: String): String = URLEncoder.encode(value.trim(), "UTF-8")

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
        val url = URL("$cleanBase/api/secrets")
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

        val payloadJson =
          apiJson.encodeToString(
            CreateSecretRequest(
              ciphertext = ciphertext,
              iv = iv,
              salt = salt,
              maxViews = maxViews,
              ttlSeconds = ttlSeconds,
            )
          )
        OutputStreamWriter(conn.outputStream, Charsets.UTF_8).use { writer ->
          writer.write(payloadJson)
          writer.flush()
        }

        val code = conn.responseCode
        val body = readStream(conn, code)
        if (code in 200..299) {
          Result.success(apiJson.decodeFromString<CreatedSecretResponse>(body))
        } else {
          Result.failure(mapHttpError(code, body, conn.getHeaderField("Retry-After")))
        }
      } catch (e: IOException) {
        Result.failure(
          ApiException.NetworkError(
            "Could not connect to vault ($cleanBase): ${e.localizedMessage ?: "Network error"}",
            e,
          )
        )
      } catch (e: Exception) {
        Result.failure(
          ApiException.HttpError(0, "Could not save secret: ${e.localizedMessage ?: e.javaClass.simpleName}")
        )
      } finally {
        conn?.disconnect()
      }
    }

  suspend fun getSecretMeta(baseUrl: String, secretId: String): Result<SecretMetaResponse> =
    withContext(Dispatchers.IO) {
      var conn: HttpURLConnection? = null
      try {
        val cleanBase = normalizeAndValidateBaseUrl(baseUrl)
        val url = URL("$cleanBase/api/secrets/${encodeSegment(secretId)}/meta")
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
          Result.success(apiJson.decodeFromString<SecretMetaResponse>(body))
        } else if (code == 404) {
          Result.failure(
            ApiException.NotFound("This secret does not exist, has expired, or has already been burned.")
          )
        } else {
          Result.failure(mapHttpError(code, body, conn.getHeaderField("Retry-After")))
        }
      } catch (e: IOException) {
        Result.failure(
          ApiException.NetworkError(
            "Could not connect to the secret vault: ${e.localizedMessage ?: "Network error"}",
            e,
          )
        )
      } catch (e: Exception) {
        Result.failure(
          ApiException.HttpError(0, e.localizedMessage ?: "Unexpected error")
        )
      } finally {
        conn?.disconnect()
      }
    }

  suspend fun consumeSecret(baseUrl: String, secretId: String): Result<ConsumedSecretResponse> =
    withContext(Dispatchers.IO) {
      var conn: HttpURLConnection? = null
      try {
        val cleanBase = normalizeAndValidateBaseUrl(baseUrl)
        val encodedId = encodeSegment(secretId)
        val endpoint = "$cleanBase/api/secrets/$encodedId/consume"
        conn =
          (URL(endpoint).openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            connectTimeout = CONNECT_TIMEOUT_MS
            readTimeout = READ_TIMEOUT_MS
            doInput = true
            doOutput = true
            setFixedLengthStreamingMode(0)
            setRequestProperty("Accept", "application/json")
          }
        conn.outputStream.close()

        val code = conn.responseCode
        val body = readStream(conn, code)
        if (code in 200..299) {
          Result.success(apiJson.decodeFromString<ConsumedSecretResponse>(body))
        } else {
          Result.failure(mapHttpError(code, body, conn.getHeaderField("Retry-After")))
        }
      } catch (e: IOException) {
        Result.failure(
          ApiException.NetworkError(
            "Connection failed while retrieving secret: ${e.localizedMessage ?: "Network error"}",
            e,
          )
        )
      } catch (e: Exception) {
        Result.failure(
          ApiException.HttpError(0, e.localizedMessage ?: "Failed to consume secret")
        )
      } finally {
        conn?.disconnect()
      }
    }

  suspend fun revokeSecret(
    baseUrl: String,
    secretId: String,
    deleteToken: String,
  ): Result<Unit> =
    withContext(Dispatchers.IO) {
      var conn: HttpURLConnection? = null
      try {
        val cleanBase = normalizeAndValidateBaseUrl(baseUrl)
        val url = URL("$cleanBase/api/secrets/${encodeSegment(secretId)}")
        conn =
          (url.openConnection() as HttpURLConnection).apply {
            requestMethod = "DELETE"
            connectTimeout = CONNECT_TIMEOUT_MS
            readTimeout = READ_TIMEOUT_MS
            setRequestProperty("Accept", "application/json")
            setRequestProperty("X-BurnBin-Delete-Token", deleteToken)
          }

        val code = conn.responseCode
        val body = readStream(conn, code)
        if (code in 200..299 || code == 404) {
          Result.success(Unit)
        } else {
          Result.failure(mapHttpError(code, body, conn.getHeaderField("Retry-After")))
        }
      } catch (e: IOException) {
        Result.failure(
          ApiException.NetworkError(
            "Connection failed while burning secret: ${e.localizedMessage ?: "Network error"}",
            e,
          )
        )
      } catch (e: Exception) {
        Result.failure(
          ApiException.HttpError(0, "Failed to revoke secret: ${e.localizedMessage ?: "Error"}")
        )
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
      apiJson.decodeFromString<ApiErrorBody>(body).error.ifBlank { fallback }
    } catch (_: Exception) {
      fallback
    }
  }

  private fun mapHttpError(code: Int, body: String, retryAfterHeader: String?): ApiException {
    val msg = parseErrorMessage(body, "Server error ($code)")
    return when (code) {
      403 -> ApiException.Forbidden(msg)
      404 -> ApiException.NotFound("This secret does not exist, has expired, or has already been burned.")
      413 -> ApiException.PayloadTooLarge(msg)
      429 -> ApiException.RateLimited(msg, retryAfterHeader?.trim()?.toIntOrNull())
      else -> ApiException.HttpError(code, msg)
    }
  }
}
