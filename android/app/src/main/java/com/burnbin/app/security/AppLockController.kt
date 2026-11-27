package com.burnbin.app.security

/**
 * Immutable snapshot of BurnBin's app lock state exposed to the UI.
 */
data class AppLockSnapshot(
  val enabled: Boolean,
  val isLocked: Boolean,
  val promptTrigger: Long,
  val errorMessage: String?,
)

/**
 * Pure Kotlin state machine coordinating app-level biometric/PIN lock across
 * cold starts, foreground/background transitions, and external activity launches.
 */
class AppLockController(initialEnabled: Boolean) {
  private var enabled: Boolean = initialEnabled
  private var isLocked: Boolean = initialEnabled
  private var promptTrigger: Long = if (initialEnabled) 1L else 0L
  private var errorMessage: String? = null
  private var isBiometricPromptActive: Boolean = false
  private var suppressNextAutoLock: Boolean = false
  private var shouldPromptOnForeground: Boolean = false
  private var lastAutoPromptedTrigger: Long = 0L

  fun snapshot(): AppLockSnapshot =
    AppLockSnapshot(
      enabled = enabled,
      isLocked = isLocked,
      promptTrigger = promptTrigger,
      errorMessage = errorMessage,
    )

  fun setEnabled(newEnabled: Boolean): AppLockSnapshot {
    enabled = newEnabled
    if (!newEnabled) {
      isLocked = false
      errorMessage = null
      shouldPromptOnForeground = false
    }
    return snapshot()
  }

  fun disableWhenUnavailable(): AppLockSnapshot {
    enabled = false
    isLocked = false
    errorMessage = null
    shouldPromptOnForeground = false
    isBiometricPromptActive = false
    return snapshot()
  }

  fun suppressNextAutoLockOnce() {
    suppressNextAutoLock = true
  }

  fun onAppBackgrounded(): AppLockSnapshot {
    if (isBiometricPromptActive || suppressNextAutoLock) {
      return snapshot()
    }
    if (enabled) {
      isLocked = true
      errorMessage = null
      shouldPromptOnForeground = true
    }
    return snapshot()
  }

  fun onAppForegrounded(): AppLockSnapshot {
    if (suppressNextAutoLock) {
      suppressNextAutoLock = false
      return snapshot()
    }
    if (isBiometricPromptActive) {
      return snapshot()
    }
    if (isLocked && shouldPromptOnForeground) {
      shouldPromptOnForeground = false
      promptTrigger += 1L
    }
    return snapshot()
  }

  fun tryBeginAutoPrompt(): Boolean {
    if (!isLocked || isBiometricPromptActive || promptTrigger <= lastAutoPromptedTrigger) {
      return false
    }
    lastAutoPromptedTrigger = promptTrigger
    isBiometricPromptActive = true
    errorMessage = null
    return true
  }

  fun tryBeginManualPrompt(): Boolean {
    if (!isLocked || isBiometricPromptActive) {
      return false
    }
    lastAutoPromptedTrigger = maxOf(lastAutoPromptedTrigger, promptTrigger)
    isBiometricPromptActive = true
    errorMessage = null
    return true
  }

  fun onRevealPromptStarted() {
    isBiometricPromptActive = true
  }

  fun onRevealPromptFinished() {
    isBiometricPromptActive = false
  }

  fun onUnlockSucceeded(): AppLockSnapshot {
    isBiometricPromptActive = false
    isLocked = false
    errorMessage = null
    shouldPromptOnForeground = false
    return snapshot()
  }

  fun onUnlockFailed(message: String): AppLockSnapshot {
    isBiometricPromptActive = false
    errorMessage = message
    return snapshot()
  }
}
