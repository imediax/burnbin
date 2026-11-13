package com.burnbin.app.crypto

import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.EncodeHintType
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import org.junit.Assert.assertArrayEquals
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

  @Test
  fun bundleRoundTrip_preservesTextAndBinaryAttachment() {
    val rawBytes = byteArrayOf(0x00, 0x1A, 0x7F, -128, -1, 0x42, 0x6B)
    val attachment = DecodedAttachment(
      name = "keyfile.bin",
      mime = "application/octet-stream",
      size = rawBytes.size,
      bytes = rawBytes,
    )
    val encoded = SecretCrypto.encodeBundle("Install note", attachment)
    assertTrue(encoded.startsWith(SecretCrypto.BUNDLE_PREFIX))

    val encrypted = SecretCrypto.encrypt(encoded, passphrase = "clip-passphrase")
    val decrypted = SecretCrypto.decrypt(
      ciphertextB64 = encrypted.ciphertext,
      ivCombined = encrypted.iv,
      saltHex = encrypted.salt,
      urlKeyHex = encrypted.urlKey,
      passphrase = "clip-passphrase",
    )
    val decoded = SecretCrypto.decodeBundle(decrypted)
    assertEquals("Install note", decoded.text)
    assertNotNull(decoded.attachment)
    assertEquals("keyfile.bin", decoded.attachment!!.name)
    assertEquals("application/octet-stream", decoded.attachment!!.mime)
    assertArrayEquals(rawBytes, decoded.attachment!!.bytes)
  }

  @Test
  fun decodeBundle_plainTextRemainsUnwrapped() {
    val decoded = SecretCrypto.decodeBundle("plain-secret-only")
    assertEquals("plain-secret-only", decoded.text)
    assertNull(decoded.attachment)
  }

  @Test
  fun generators_produceExpectedFormats() {
    val pw = SecretCrypto.generateStrongPassword(24)
    assertEquals(24, pw.length)
    assertTrue(pw.any { it.isUpperCase() })
    assertTrue(pw.any { it.isLowerCase() })
    assertTrue(pw.any { it.isDigit() })
    assertTrue(pw.any { !it.isLetterOrDigit() })

    val phrase = SecretCrypto.generateShareablePassphrase()
    val parts = phrase.split("-")
    assertEquals(5, parts.size)
    assertTrue(parts.last().toInt() in 10..99)
  }

  @Test
  fun zxingQrEncodeDecode_preservesFullSecretUrl() {
    val secretUrl = "https://burnbin.cloud.run/secret/AbCdEf1234567890?key=$sampleKey"
    val hints =
      mapOf(
        EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.L,
        EncodeHintType.MARGIN to 2,
        EncodeHintType.CHARACTER_SET to "UTF-8",
      )
    val matrix = QRCodeWriter().encode(secretUrl, BarcodeFormat.QR_CODE, 256, 256, hints)
    val width = matrix.width
    val height = matrix.height
    val pixels = IntArray(width * height) { i ->
      val x = i % width
      val y = i / width
      if (matrix[x, y]) 0xFF000000.toInt() else 0xFFFFFFFF.toInt()
    }
    val bitmap = BinaryBitmap(HybridBinarizer(RGBLuminanceSource(width, height, pixels)))
    val decoded = QRCodeReader().decode(bitmap)
    assertEquals(secretUrl, decoded.text)
  }
}
