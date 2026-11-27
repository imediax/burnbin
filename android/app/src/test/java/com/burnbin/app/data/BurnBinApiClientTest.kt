package com.burnbin.app.data

import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress
import java.net.ServerSocket
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BurnBinApiClientTest {

  private fun startMockServer(
    handler: (method: String, path: String, headers: Map<String, String>) -> Pair<Int, String>
  ): Pair<HttpServer, String> {
    val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
    server.createContext("/") { exchange ->
      exchange.requestBody.readBytes()
      val headerMap = exchange.requestHeaders.mapKeys { it.key.lowercase() }.mapValues { it.value.firstOrNull().orEmpty() }
      val (status, body) = handler(exchange.requestMethod, exchange.requestURI.path, headerMap)
      val bytes = body.toByteArray(Charsets.UTF_8)
      exchange.responseHeaders.add("Content-Type", "application/json; charset=utf-8")
      exchange.sendResponseHeaders(status, bytes.size.toLong())
      exchange.responseBody.use { it.write(bytes) }
    }
    server.start()
    return server to "http://127.0.0.1:${server.address.port}"
  }

  @Test
  fun createAndRevokeSecret_succeedsAndMapsForbidden() = runTest {
    val (server, baseUrl) = startMockServer { method, path, headers ->
      when {
        method == "POST" && path == "/api/secrets" ->
          201 to """{"id":"secretId123456","expires_at":1999999999,"max_views":2,"delete_token":"del-tok-1"}"""
        method == "DELETE" && path == "/api/secrets/secretId123456" -> {
          val tok = headers["x-burnbin-delete-token"]
          if (tok == "del-tok-1") 200 to """{"revoked":true,"id":"secretId123456"}"""
          else 403 to """{"error":"Invalid revocation token"}"""
        }
        else -> 404 to """{"error":"Not found"}"""
      }
    }
    try {
      val created = BurnBinApiClient.createSecret(baseUrl, "ct", "iv", null, 2, 3600).getOrThrow()
      assertEquals("secretId123456", created.id)
      assertEquals("del-tok-1", created.deleteToken)

      assertTrue(BurnBinApiClient.revokeSecret(baseUrl, "secretId123456", "del-tok-1").isSuccess)

      val badRevoke = BurnBinApiClient.revokeSecret(baseUrl, "secretId123456", "wrong")
      assertTrue(badRevoke.isFailure)
      assertTrue(badRevoke.exceptionOrNull() is ApiException.Forbidden)
    } finally {
      server.stop(0)
    }
  }

  @Test
  fun getSecretMeta_distinguishes404FromNetworkError() = runTest {
    val (server, baseUrl) = startMockServer { _, path, _ ->
      when (path) {
        "/api/secrets/activeId123456/meta" ->
          200 to """{"id":"activeId123456","requires_passphrase":true,"views_left":3,"max_views":5,"expires_at":1999999999}"""
        else -> 404 to """{"error":"Secret not found"}"""
      }
    }
    val okMeta: SecretMetaResponse
    val notFoundRes: Result<SecretMetaResponse>
    try {
      okMeta = BurnBinApiClient.getSecretMeta(baseUrl, "activeId123456").getOrThrow()
      notFoundRes = BurnBinApiClient.getSecretMeta(baseUrl, "missingId12345")
    } finally {
      server.stop(0)
    }
    assertTrue(okMeta.requiresPassphrase)
    assertEquals(3, okMeta.viewsLeft)
    assertTrue(notFoundRes.exceptionOrNull() is ApiException.NotFound)

    // Pick an unused closed port to verify NetworkError classification
    val unusedPort = ServerSocket(0).use { it.localPort }
    val networkRes = BurnBinApiClient.getSecretMeta("http://127.0.0.1:$unusedPort", "activeId123456")
    assertTrue(networkRes.exceptionOrNull() is ApiException.NetworkError)
  }

  @Test
  fun consumeSecret_usesPostOnlyAndNeverFallsBackToGet() = runTest {
    val methodsSeen = mutableListOf<String>()
    val (server, baseUrl) = startMockServer { method, path, _ ->
      methodsSeen += "$method $path"
      when {
        method == "POST" && path == "/api/secrets/modernSecret12/consume" ->
          200 to """{"id":"modernSecret12","ciphertext":"ct","iv":"iv","salt":null,"views_left":0,"burned":true}"""
        method == "POST" && path == "/api/secrets/legacySecret12/consume" ->
          405 to """{"error":"Method not allowed"}"""
        else -> 404 to """{"error":"Not found"}"""
      }
    }
    try {
      val modern = BurnBinApiClient.consumeSecret(baseUrl, "modernSecret12").getOrThrow()
      assertTrue(modern.burned)
      assertEquals(listOf("POST /api/secrets/modernSecret12/consume"), methodsSeen.toList())

      val legacyRes = BurnBinApiClient.consumeSecret(baseUrl, "legacySecret12")
      assertTrue(legacyRes.isFailure)
      val err = legacyRes.exceptionOrNull() as? ApiException.HttpError
      assertEquals(405, err?.code)
      assertFalse(methodsSeen.any { it.startsWith("GET ") })
    } finally {
      server.stop(0)
    }
  }

  @Test
  fun getServerConfig_parsesLimitsAndPresets() = runTest {
    val (server, baseUrl) = startMockServer { method, path, _ ->
      if (method == "GET" && path == "/api/config") {
        200 to
          """{"version":"2.0.3","max_payload_bytes":2097152,"max_attachment_bytes":1048576,"max_text_bytes":4194304,"min_ttl_seconds":60,"max_ttl_seconds":2592000,"ttl_presets":[300,3600,86400],"max_views_presets":[1,3,5],"max_views":20}"""
      } else {
        404 to """{"error":"Not found"}"""
      }
    }
    try {
      val cfg = BurnBinApiClient.getServerConfig(baseUrl).getOrThrow()
      assertEquals("2.0.3", cfg.version)
      assertEquals(1048576, cfg.maxAttachmentBytes)
      assertEquals(4194304, cfg.maxTextBytes)
      assertEquals(listOf(300, 3600, 86400), cfg.ttlPresets)
      assertEquals(listOf(1, 3, 5), cfg.maxViewsPresets)
      assertEquals(20, cfg.maxViews)
    } finally {
      server.stop(0)
    }
  }
}
