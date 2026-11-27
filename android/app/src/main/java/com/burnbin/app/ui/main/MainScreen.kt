package com.burnbin.app.ui.main

import android.net.Uri
import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.tooling.preview.Preview
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.burnbin.app.security.canAuthenticateDeviceOrBiometric
import com.burnbin.app.security.isChangingConfigurations
import com.burnbin.app.theme.BgPrimary
import com.burnbin.app.theme.BurnBinTheme
import com.burnbin.app.ui.components.AppLockScreen
import com.burnbin.app.ui.components.BurnBinHeader
import com.burnbin.app.ui.components.BurnBinTab
import com.burnbin.app.ui.components.BurnBinTabBar
import com.burnbin.app.ui.create.CreateSecretScreen
import com.burnbin.app.ui.reveal.RevealSecretScreen
import com.burnbin.app.ui.settings.VaultSettingsDialog

@Composable
fun MainScreen(
  modifier: Modifier = Modifier,
  initialSharedText: String? = null,
  sharedTextTrigger: Long = 0L,
  initialSharedFileUri: Uri? = null,
  sharedFileTrigger: Long = 0L,
  initialDeepLinkUrl: String? = null,
  deepLinkTrigger: Long = 0L,
  viewModel: BurnBinViewModel = viewModel(),
) {
  val context = LocalContext.current
  val lifecycleOwner = LocalLifecycleOwner.current
  val state by viewModel.uiState.collectAsStateWithLifecycle()
  var showSettingsDialog by rememberSaveable { mutableStateOf(false) }

  DisposableEffect(lifecycleOwner, viewModel) {
    val observer =
      LifecycleEventObserver { _, event ->
        when (event) {
          Lifecycle.Event.ON_STOP -> {
            if (!context.isChangingConfigurations()) {
              viewModel.onAppBackgrounded()
            }
          }
          Lifecycle.Event.ON_START -> {
            viewModel.onAppForegrounded()
          }
          else -> Unit
        }
      }
    lifecycleOwner.lifecycle.addObserver(observer)
    onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
  }

  LaunchedEffect(initialDeepLinkUrl, deepLinkTrigger, state.isAppLocked) {
    if (!state.isAppLocked) {
      viewModel.handleDeepLink(initialDeepLinkUrl, deepLinkTrigger)
    }
  }

  LaunchedEffect(initialSharedText, sharedTextTrigger, state.isAppLocked) {
    if (!state.isAppLocked) {
      viewModel.handleSharedText(initialSharedText, sharedTextTrigger)
    }
  }

  LaunchedEffect(initialSharedFileUri, sharedFileTrigger, state.isAppLocked) {
    if (!state.isAppLocked) {
      viewModel.handleSharedFile(initialSharedFileUri, sharedFileTrigger)
    }
  }

  LaunchedEffect(state.isAppLocked, state.appLockPromptTrigger) {
    if (state.isAppLocked) {
      showSettingsDialog = false
      viewModel.autoPromptAppUnlockIfNeeded(context)
    }
  }

  if (state.isAppLocked) {
    val deviceLockAvailable = canAuthenticateDeviceOrBiometric(context)
    AppLockScreen(
      modifier = modifier,
      errorMessage = state.appLockError,
      deviceLockAvailable = deviceLockAvailable,
      onUnlockClick = { viewModel.unlockApp(context) },
      onDisableLockWhenUnavailable = viewModel::disableAppLockWhenUnavailable,
    )
    return
  }

  Column(
    modifier = modifier.fillMaxSize().background(BgPrimary),
  ) {
    BurnBinHeader(
      onLogoClick = { viewModel.selectTab(BurnBinTab.CREATE) },
      onSettingsClick = { showSettingsDialog = true },
    )

    BurnBinTabBar(
      activeTab = state.activeTab,
      onTabSelected = viewModel::selectTab,
    )

    Box(modifier = Modifier.weight(1f).fillMaxWidth()) {
      when (state.activeTab) {
        BurnBinTab.CREATE -> {
          CreateSecretScreen(
            state = state,
            onSecretTextChange = viewModel::updateSecretText,
            onPasswordOptionsChange = viewModel::updatePasswordOptions,
            onGenerateStrongPassword = viewModel::generateStrongPassword,
            onAttachFileUri = viewModel::attachFileFromUri,
            onRemoveAttachment = viewModel::removeAttachment,
            onSelectTtl = viewModel::selectTtl,
            onSelectMaxViews = viewModel::selectMaxViews,
            onToggleUsePassphrase = viewModel::toggleUsePassphrase,
            onPassphraseChange = viewModel::updatePassphrase,
            onToggleShowPassphrase = viewModel::toggleShowPassphraseText,
            onGeneratePassphrase = viewModel::generateShareablePassphrase,
            onSubmitSecret = viewModel::submitSecret,
            onCopyGeneratedLink = viewModel::copyGeneratedLink,
            onOpenGeneratedInReveal = viewModel::openGeneratedInReveal,
            onResetCreateForm = viewModel::resetCreateForm,
            onBeforeExternalActivity = viewModel::suppressNextAppLockOnce,
          )
        }
        BurnBinTab.REVEAL -> {
          RevealSecretScreen(
            state = state,
            onLinkInputChange = viewModel::updateRevealLinkInput,
            onCheckSecretLink = viewModel::checkSecretLink,
            onManualKeyChange = viewModel::updateManualKeyInput,
            onDecryptPassphraseChange = viewModel::updateDecryptPassphrase,
            onToggleShowDecryptPassphrase = viewModel::toggleShowDecryptPassphrase,
            onRevealSecretClick = { viewModel.revealCurrentSecret(context) },
            onCopySecretClick = viewModel::copyRevealedSecret,
            onClearClipboardNow = viewModel::clearClipboardNow,
            onClearReveal = viewModel::clearRevealState,
            onCreateNewClick = viewModel::switchToCreateFromReveal,
            onBeforeExternalActivity = viewModel::suppressNextAppLockOnce,
          )
        }
      }
    }
  }

  if (showSettingsDialog) {
    VaultSettingsDialog(
      currentServerUrl = state.serverUrl,
      autoClearClipboardEnabled = state.autoClearClipboardEnabled,
      appLockEnabled = state.appLockEnabled,
      biometricRevealEnabled = state.biometricRevealEnabled,
      onDismiss = { showSettingsDialog = false },
      onSave = { newUrl, newAutoClear, newAppLock, newBiometric ->
        viewModel.saveSettings(newUrl, newAutoClear, newAppLock, newBiometric)
        showSettingsDialog = false
        Toast.makeText(context, "Settings saved", Toast.LENGTH_SHORT).show()
      },
    )
  }
}

@Preview(showBackground = true)
@Composable
fun MainScreenPreview() {
  BurnBinTheme { MainScreen() }
}
