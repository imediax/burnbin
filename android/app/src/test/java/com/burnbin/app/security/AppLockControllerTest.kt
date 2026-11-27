package com.burnbin.app.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AppLockControllerTest {

  @Test
  fun coldStart_disabled_startsUnlockedWithZeroTrigger() {
    val controller = AppLockController(initialEnabled = false)
    val snap = controller.snapshot()

    assertFalse(snap.enabled)
    assertFalse(snap.isLocked)
    assertEquals(0L, snap.promptTrigger)
    assertNull(snap.errorMessage)
    assertFalse(controller.tryBeginAutoPrompt())
  }

  @Test
  fun coldStart_enabled_startsLockedAndAutoPromptsOnce() {
    val controller = AppLockController(initialEnabled = true)
    val snap = controller.snapshot()

    assertTrue(snap.enabled)
    assertTrue(snap.isLocked)
    assertEquals(1L, snap.promptTrigger)

    assertTrue(controller.tryBeginAutoPrompt())
    assertFalse(controller.tryBeginAutoPrompt())

    val unlocked = controller.onUnlockSucceeded()
    assertFalse(unlocked.isLocked)
    assertNull(unlocked.errorMessage)
  }

  @Test
  fun setEnabled_true_keepsActiveSessionUnlockedUntilBackgrounded() {
    val controller = AppLockController(initialEnabled = false)
    val afterEnable = controller.setEnabled(true)

    assertTrue(afterEnable.enabled)
    assertFalse(afterEnable.isLocked)
    assertFalse(controller.tryBeginAutoPrompt())

    val bg = controller.onAppBackgrounded()
    assertTrue(bg.isLocked)

    val fg = controller.onAppForegrounded()
    assertTrue(fg.isLocked)
    assertEquals(1L, fg.promptTrigger)
    assertTrue(controller.tryBeginAutoPrompt())
  }

  @Test
  fun setEnabled_false_immediatelyUnlocks() {
    val controller = AppLockController(initialEnabled = true)
    val snap = controller.setEnabled(false)

    assertFalse(snap.enabled)
    assertFalse(snap.isLocked)
    assertNull(snap.errorMessage)
  }

  @Test
  fun backgroundDuringActiveBiometricOrRevealPrompt_doesNotLock() {
    val controller = AppLockController(initialEnabled = false)
    controller.setEnabled(true)
    controller.onRevealPromptStarted()

    val bgDuringReveal = controller.onAppBackgrounded()
    assertFalse(bgDuringReveal.isLocked)

    controller.onRevealPromptFinished()
    val bgNormal = controller.onAppBackgrounded()
    assertTrue(bgNormal.isLocked)
  }

  @Test
  fun backgroundDuringActiveUnlockPrompt_doesNotResetOrIncrementTrigger() {
    val controller = AppLockController(initialEnabled = true)
    assertTrue(controller.tryBeginAutoPrompt())

    val bg = controller.onAppBackgrounded()
    assertTrue(bg.isLocked)
    val fg = controller.onAppForegrounded()
    assertEquals(1L, fg.promptTrigger)
    assertFalse(controller.tryBeginAutoPrompt())
  }

  @Test
  fun suppressNextAutoLockOnce_skipsSingleExternalActivityRoundTrip() {
    val controller = AppLockController(initialEnabled = false)
    controller.setEnabled(true)
    controller.suppressNextAutoLockOnce()

    val bg = controller.onAppBackgrounded()
    assertFalse(bg.isLocked)
    val fg = controller.onAppForegrounded()
    assertFalse(fg.isLocked)
    assertEquals(0L, fg.promptTrigger)

    // Subsequent normal backgrounding locks as expected
    val bg2 = controller.onAppBackgrounded()
    assertTrue(bg2.isLocked)
    val fg2 = controller.onAppForegrounded()
    assertEquals(1L, fg2.promptTrigger)
    assertTrue(controller.tryBeginAutoPrompt())
  }

  @Test
  fun failedUnlock_setsErrorWithoutAutoRePrompting_andManualRetryUnlocks() {
    val controller = AppLockController(initialEnabled = true)
    assertTrue(controller.tryBeginAutoPrompt())

    val failed = controller.onUnlockFailed("Unlock canceled. Tap Unlock BurnBin to try again.")
    assertTrue(failed.isLocked)
    assertEquals("Unlock canceled. Tap Unlock BurnBin to try again.", failed.errorMessage)
    assertFalse(controller.tryBeginAutoPrompt())

    assertTrue(controller.tryBeginManualPrompt())
    assertNull(controller.snapshot().errorMessage)
    val unlocked = controller.onUnlockSucceeded()
    assertFalse(unlocked.isLocked)
    assertNull(unlocked.errorMessage)
  }

  @Test
  fun disableWhenUnavailable_unlocksAndDisables() {
    val controller = AppLockController(initialEnabled = true)
    assertTrue(controller.tryBeginAutoPrompt())
    controller.onUnlockFailed("No biometrics or device PIN/screen lock configured.")

    val snap = controller.disableWhenUnavailable()
    assertFalse(snap.enabled)
    assertFalse(snap.isLocked)
    assertNull(snap.errorMessage)
  }
}
