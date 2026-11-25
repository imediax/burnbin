package com.burnbin.app.security

import android.app.KeyguardManager
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.content.ContextWrapper
import android.graphics.Bitmap
import android.graphics.Color
import android.net.Uri
import android.os.Build
import android.os.PersistableBundle
import android.provider.OpenableColumns
import android.widget.Toast
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.burnbin.app.crypto.DecodedAttachment
import com.burnbin.app.crypto.SecretCrypto
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import java.io.ByteArrayOutputStream

private tailrec fun Context.findFragmentActivity(): FragmentActivity? =
  when (this) {
    is FragmentActivity -> this
    is ContextWrapper -> baseContext.findFragmentActivity()
    else -> null
  }

fun canAuthenticateDeviceOrBiometric(context: Context): Boolean {
  val authenticators =
    BiometricManager.Authenticators.BIOMETRIC_WEAK or
      BiometricManager.Authenticators.DEVICE_CREDENTIAL
  val biometricStatus = BiometricManager.from(context).canAuthenticate(authenticators)
  if (biometricStatus == BiometricManager.BIOMETRIC_SUCCESS) return true

  val keyguard = context.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager
  return keyguard?.isDeviceSecure == true
}

fun authenticateForReveal(
  context: Context,
  onSuccess: () -> Unit,
  onErrorOrCancel: (String) -> Unit,
) {
  val activity = context.findFragmentActivity()
  if (activity == null) {
    onErrorOrCancel("Device authentication prompt is unavailable in this host.")
    return
  }
  if (!canAuthenticateDeviceOrBiometric(context)) {
    onErrorOrCancel(
      "No biometrics or device screen lock configured. Set a lock in Android Settings or disable this requirement in Vault Settings."
    )
    return
  }

  val executor = ContextCompat.getMainExecutor(activity)
  val prompt =
    BiometricPrompt(
      activity,
      executor,
      object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
          onSuccess()
        }

        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
          if (
            errorCode == BiometricPrompt.ERROR_USER_CANCELED ||
              errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON ||
              errorCode == BiometricPrompt.ERROR_CANCELED
          ) {
            onErrorOrCancel("Authentication canceled. Secret was NOT burned.")
          } else {
            onErrorOrCancel("Authentication failed: $errString (Secret was NOT burned.)")
          }
        }
      },
    )

  val promptInfo =
    BiometricPrompt.PromptInfo.Builder()
      .setTitle("Unlock BurnBin Secret")
      .setSubtitle("Authenticate before fetching & burning this one-time secret")
      .setAllowedAuthenticators(
        BiometricManager.Authenticators.BIOMETRIC_WEAK or
          BiometricManager.Authenticators.DEVICE_CREDENTIAL
      )
      .build()

  prompt.authenticate(promptInfo)
}

fun copyToClipboard(
  context: Context,
  label: String,
  text: String,
  sensitive: Boolean = false,
) {
  val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
  val clip = ClipData.newPlainText(label, text)
  if (sensitive && Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
    clip.description.extras =
      PersistableBundle().apply {
        putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
      }
  }
  clipboard.setPrimaryClip(clip)
  Toast.makeText(context, "Copied to clipboard", Toast.LENGTH_SHORT).show()
}

fun clearClipboard(context: Context) {
  val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
  if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
    clipboard.clearPrimaryClip()
  } else {
    clipboard.setPrimaryClip(ClipData.newPlainText("", ""))
  }
}

fun readClipboard(context: Context): String? {
  val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
  val item = clipboard.primaryClip?.getItemAt(0)
  return item?.coerceToText(context)?.toString()
}

fun generateQrBitmap(content: String, sizePx: Int = 512): Bitmap? {
  if (content.isBlank()) return null
  return try {
    val hints =
      mapOf(
        EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.L,
        EncodeHintType.MARGIN to 1,
        EncodeHintType.CHARACTER_SET to "UTF-8",
      )
    val matrix = QRCodeWriter().encode(content, BarcodeFormat.QR_CODE, sizePx, sizePx, hints)
    val width = matrix.width
    val height = matrix.height
    val pixels = IntArray(width * height)
    for (y in 0 until height) {
      val rowOffset = y * width
      for (x in 0 until width) {
        pixels[rowOffset + x] = if (matrix[x, y]) Color.BLACK else Color.WHITE
      }
    }
    Bitmap.createBitmap(width, height, Bitmap.Config.RGB_565).apply {
      setPixels(pixels, 0, width, 0, 0, width, height)
    }
  } catch (_: Exception) {
    null
  }
}

fun formatByteSize(bytes: Int): String {
  if (bytes < 1024) return "$bytes B"
  if (bytes < 1024 * 1024) return String.format(java.util.Locale.US, "%.1f KB", bytes / 1024.0)
  return String.format(java.util.Locale.US, "%.2f MB", bytes / (1024.0 * 1024.0))
}

fun readAttachmentFromUri(
  context: Context,
  uri: Uri,
  maxBytes: Int = SecretCrypto.MAX_ATTACHMENT_BYTES,
): Result<DecodedAttachment> {
  return try {
    val resolver = context.contentResolver
    var fileName = "attachment.bin"
    var declaredSize = -1L
    resolver
      .query(uri, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE), null, null, null)
      ?.use { cursor ->
        if (cursor.moveToFirst()) {
          val nameIdx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
          if (nameIdx >= 0) {
            cursor.getString(nameIdx)?.takeIf { it.isNotBlank() }?.let { fileName = it }
          }
          val sizeIdx = cursor.getColumnIndex(OpenableColumns.SIZE)
          if (sizeIdx >= 0 && !cursor.isNull(sizeIdx)) {
            declaredSize = cursor.getLong(sizeIdx)
          }
        }
      }
    if (declaredSize > maxBytes) {
      return Result.failure(
        IllegalArgumentException("File \"$fileName\" exceeds the ${formatByteSize(maxBytes)} attachment limit.")
      )
    }
    val bytes =
      resolver.openInputStream(uri)?.use { stream ->
        val out = ByteArrayOutputStream()
        val buf = ByteArray(8192)
        var total = 0
        while (true) {
          val read = stream.read(buf)
          if (read <= 0) break
          total += read
          if (total > maxBytes) {
            return Result.failure(
              IllegalArgumentException("File \"$fileName\" exceeds the ${formatByteSize(maxBytes)} attachment limit.")
            )
          }
          out.write(buf, 0, read)
        }
        out.toByteArray()
      } ?: return Result.failure(IllegalArgumentException("Could not open selected file."))

    val mime = resolver.getType(uri)?.takeIf { it.isNotBlank() } ?: "application/octet-stream"
    Result.success(
      DecodedAttachment(
        name = fileName,
        mime = mime,
        size = bytes.size,
        bytes = bytes,
      )
    )
  } catch (e: Exception) {
    Result.failure(IllegalArgumentException("Failed to read file: ${e.message ?: "Unknown error"}"))
  }
}
