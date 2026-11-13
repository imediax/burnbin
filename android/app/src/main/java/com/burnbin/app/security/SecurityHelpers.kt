package com.burnbin.app.security

import android.app.KeyguardManager
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.content.ContextWrapper
import android.os.Build
import android.os.PersistableBundle
import android.widget.Toast
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity

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
