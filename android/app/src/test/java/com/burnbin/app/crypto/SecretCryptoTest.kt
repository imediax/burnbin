package com.burnbin.app.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SecretCryptoTest {
  private val sampleKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

  @Test
  fun encryptAndDecrypt_withoutPassphrase_roundTrips() {
    val message = "sk_live_51Msz9876543210_super_secret_token 🔥"
    val encrypted = SecretCrypto.encrypt(message, passphrase = null)

    assertNull(encrypted.salt)
    assertEquals(64, encrypted.urlKey.length) // 32 bytes = 64 hex chars
    assertEquals(24, encrypted.iv.length) // 12 bytes = 24 hex chars

    val decrypted =
      SecretCrypto.decrypt(
        ciphertextB64 = encrypted.ciphertext,
        ivCombined = encrypted.iv,
        saltHex = encrypted.salt,
        urlKeyHex = encrypted.urlKey,
        passphrase = null,
      )
    assertEquals(message, decrypted)
  }

  @Test
  fun encryptAndDecrypt_withPassphrase_roundTrips() {
    val message = "Top secret launch codes: 0000-1111"
    val passphrase = "correct-horse-battery-staple"
    val encrypted = SecretCrypto.encrypt(message, passphrase = passphrase)

    assertNotNull(encrypted.salt)
    assertEquals(32, encrypted.salt!!.length) // 16 bytes = 32 hex chars
    assertTrue(encrypted.iv.contains(":"))

    val decrypted =
      SecretCrypto.decrypt(
        ciphertextB64 = encrypted.ciphertext,
        ivCombined = encrypted.iv,
        saltHex = encrypted.salt,
        urlKeyHex = encrypted.urlKey,
        passphrase = passphrase,
      )
    assertEquals(message, decrypted)
  }

  @Test(expected = IllegalArgumentException::class)
  fun decrypt_withWrongPassphrase_throwsException() {
    val encrypted = SecretCrypto.encrypt("My Secret", passphrase = "right-password")
    SecretCrypto.decrypt(
      ciphertextB64 = encrypted.ciphertext,
      ivCombined = encrypted.iv,
      saltHex = encrypted.salt,
      urlKeyHex = encrypted.urlKey,
      passphrase = "wrong-password",
    )
  }

  @Test
  fun parseSecretLink_withFragmentKey_extractsAll() {
    val link = "https://burnbin.cloud.run/secret/AbCdEf1234567890#key=$sampleKey"
    val parsed = SecretCrypto.parseSecretLink(link, "https://burnbin.cloud.run").getOrThrow()

    assertEquals("https://burnbin.cloud.run", parsed.baseUrl)
    assertEquals("AbCdEf1234567890", parsed.secretId)
    assertEquals(sampleKey, parsed.urlKey)
  }

  @Test
  fun parseSecretLink_withQueryKey_extractsAll() {
    val link = "https://burnbin.cloud.run/secret/AbCdEf1234567890?key=$sampleKey"
    val parsed = SecretCrypto.parseSecretLink(link, "https://burnbin.cloud.run").getOrThrow()

    assertEquals("https://burnbin.cloud.run", parsed.baseUrl)
    assertEquals("AbCdEf1234567890", parsed.secretId)
    assertEquals(sampleKey, parsed.urlKey)
  }

  @Test
  fun parseSecretLink_missingKey_returnsNullKeyWithoutFailing() {
    val link = "https://burnbin.cloud.run/secret/c6e-rdxrCFN3abc123"
    val parsed = SecretCrypto.parseSecretLink(link, "https://burnbin.cloud.run").getOrThrow()

    assertEquals("https://burnbin.cloud.run", parsed.baseUrl)
    assertEquals("c6e-rdxrCFN3abc123", parsed.secretId)
    assertNull(parsed.urlKey)
  }

  @Test
  fun parseSecretLink_inTextMessage_extractsSuccessfully() {
    val text = "Hey here is your secret: https://burnbin.cloud.run/secret/c6e-rdxrCFN3abc123#key=$sampleKey please burn it!"
    val parsed = SecretCrypto.parseSecretLink(text, "https://burnbin.cloud.run").getOrThrow()

    assertEquals("https://burnbin.cloud.run", parsed.baseUrl)
    assertEquals("c6e-rdxrCFN3abc123", parsed.secretId)
    assertEquals(sampleKey, parsed.urlKey)
  }
}
